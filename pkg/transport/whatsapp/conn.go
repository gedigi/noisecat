package whatsapp

import (
	"crypto/cipher"
	"fmt"
	"net"
	"sync"
	"time"
)

// Conn is a WhatsApp Noise transport connection (net.Conn). After the
// handshake completes, each application message is AES-256-GCM encrypted
// under the derived write key with an incrementing big-endian counter nonce
// and wrapped in a 3-byte length frame (no protobuf), mirroring whatsmeow's
// NoiseSocket.
type Conn struct {
	conn   net.Conn
	framed *framedConn

	// Deferred handshake (responder side): when hsFn is non-nil the
	// handshake runs on the first Read/Write under hsOnce, so a slow or
	// non-noisecat peer cannot block the listener's accept loop. The client
	// side passes a completed handshakeResult and leaves hsFn nil.
	hsOnce    sync.Once
	hsFn      func(*framedConn) (*handshakeResult, error)
	hsTimeout time.Duration
	hsErr     error

	writeKey   cipher.AEAD
	readKey    cipher.AEAD
	peerStatic []byte

	writeMu      sync.Mutex
	writeCounter uint32

	readMu      sync.Mutex
	readCounter uint32
	readBuf     []byte
}

// newConn builds a Conn from an already-completed handshake (client side).
func newConn(conn net.Conn, framed *framedConn, hs *handshakeResult) *Conn {
	return &Conn{
		conn:       conn,
		framed:     framed,
		writeKey:   hs.writeKey,
		readKey:    hs.readKey,
		peerStatic: hs.peerStatic,
	}
}

// newDeferredServerConn returns a Conn whose responder handshake runs lazily
// on first use, bounded by timeout.
func newDeferredServerConn(conn net.Conn, framed *framedConn, serverStatic dhKeypair, timeout time.Duration) *Conn {
	c := &Conn{conn: conn, framed: framed, hsTimeout: timeout}
	c.hsFn = func(f *framedConn) (*handshakeResult, error) {
		return serverHandshake(f, serverStatic, []byte{})
	}
	return c
}

// ensureHandshake runs the deferred responder handshake exactly once. It is a
// no-op for client connections (whose handshake already completed in Dial).
func (c *Conn) ensureHandshake() error {
	if c.hsFn == nil {
		return nil
	}
	c.hsOnce.Do(func() {
		if c.hsTimeout > 0 {
			_ = c.conn.SetDeadline(time.Now().Add(c.hsTimeout))
		}
		hs, err := c.hsFn(c.framed)
		if err != nil {
			c.hsErr = err
			return
		}
		c.writeKey = hs.writeKey
		c.readKey = hs.readKey
		c.peerStatic = hs.peerStatic
		if c.hsTimeout > 0 {
			_ = c.conn.SetDeadline(time.Time{})
		}
	})
	return c.hsErr
}

// PeerStaticKey returns the remote peer's Noise static public key. For a
// real-WhatsApp connection this is the server static bound to the verified
// certificate; for a peer-to-peer connection it is the other noisecat's key.
// It is nil until the handshake has run (i.e. until the first Read/Write on a
// freshly accepted connection).
func (c *Conn) PeerStaticKey() []byte { return c.peerStatic }

// Write encrypts p and sends it as one or more transport frames.
func (c *Conn) Write(p []byte) (int, error) {
	if err := c.ensureHandshake(); err != nil {
		return 0, err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	const maxPlain = maxFrameLen - 16 // leave room for the GCM tag
	total := 0
	for len(p) > 0 {
		n := min(len(p), maxPlain)
		ciphertext := c.writeKey.Seal(nil, generateIV(c.writeCounter), p[:n], nil)
		c.writeCounter++
		if err := c.framed.writeFrame(ciphertext); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// Read returns decrypted application bytes from the next transport frame(s).
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := c.ensureHandshake(); err != nil {
		return 0, err
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		if n == len(c.readBuf) {
			c.readBuf = nil // release the backing array once fully drained
		} else {
			c.readBuf = c.readBuf[n:]
		}
		return n, nil
	}
	ciphertext, err := c.framed.readFrame()
	if err != nil {
		return 0, err
	}
	plaintext, err := c.readKey.Open(nil, generateIV(c.readCounter), ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("whatsapp: decrypt transport frame: %w", err)
	}
	c.readCounter++
	n := copy(p, plaintext)
	if n < len(plaintext) {
		// readBuf is empty here, so this allocates exactly the leftover.
		c.readBuf = append(c.readBuf, plaintext[n:]...)
	}
	return n, nil
}

// Close closes the underlying connection.
func (c *Conn) Close() error { return c.conn.Close() }

// CloseWrite forwards a half-close if the underlying conn supports it
// (peer-to-peer TCP), or falls back to a full Close otherwise (e.g. the
// websocket-backed real-backend connection), matching the other transports.
func (c *Conn) CloseWrite() error {
	if cw, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.conn.Close()
}

func (c *Conn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
