package bolt8

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Conn is a BOLT-8 connection. It implements net.Conn.
type Conn struct {
	conn         net.Conn
	isInitiator  bool
	localStatic  *secp256k1.PrivateKey
	remoteStatic *secp256k1.PublicKey // populated for initiator before handshake; for responder after act 3

	hsMu          sync.Mutex
	handshakeDone bool

	// Post-handshake state, per BOLT-8 §3. Send and receive directions
	// each have their own (key, nonce, chaining key) that rotates
	// independently.
	sk, rk   [32]byte
	sck, rck [32]byte
	sn, rn   uint64

	outLock, inLock sync.Mutex
	readBuf         []byte
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// SetDeadline applies to the underlying conn.
func (c *Conn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

// SetReadDeadline applies to the underlying conn.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// SetWriteDeadline applies to the underlying conn.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// Close closes the underlying connection.
func (c *Conn) Close() error { return c.conn.Close() }

// CloseWrite half-closes the write side if the underlying transport
// supports it. Falls back to a full Close.
func (c *Conn) CloseWrite() error {
	if cw, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.conn.Close()
}

// RemoteStatic returns the BOLT-8 remote static public key. For the
// initiator this is the value supplied at construction. For the
// responder it is populated after a successful handshake.
func (c *Conn) RemoteStatic() *secp256k1.PublicKey { return c.remoteStatic }

// Client wraps an existing net.Conn into a BOLT-8 initiator.
// localStatic is the local node's secp256k1 static key. remoteStatic
// is the destination node's compressed public key (the "node ID").
func Client(conn net.Conn, localStatic *secp256k1.PrivateKey, remoteStatic *secp256k1.PublicKey) *Conn {
	return &Conn{conn: conn, isInitiator: true, localStatic: localStatic, remoteStatic: remoteStatic}
}

// Server wraps an existing net.Conn into a BOLT-8 responder.
func Server(conn net.Conn, localStatic *secp256k1.PrivateKey) *Conn {
	return &Conn{conn: conn, isInitiator: false, localStatic: localStatic}
}

// Handshake runs the BOLT-8 three-act exchange. Idempotent; called
// automatically on first Read or Write.
func (c *Conn) Handshake() error {
	c.hsMu.Lock()
	defer c.hsMu.Unlock()
	if c.handshakeDone {
		return nil
	}
	var (
		ck  [32]byte
		err error
	)
	if c.isInitiator {
		if c.remoteStatic == nil {
			return errors.New("bolt8: initiator missing remote static key")
		}
		ck, err = runInitiator(c.conn, c.localStatic, c.remoteStatic, nil)
	} else {
		var rs *secp256k1.PublicKey
		ck, rs, err = runResponder(c.conn, c.localStatic, nil)
		if err == nil {
			c.remoteStatic = rs
		}
	}
	if err != nil {
		return err
	}
	// Split: BOLT-8 §3 step 7. Per the spec, the initiator sets
	// (sk, rk) = HKDF(ck, ""); the responder swaps them — its sk is
	// the initiator's rk and vice-versa.
	a, b := hkdfExpand(ck, nil)
	if c.isInitiator {
		c.sk, c.rk = a, b
	} else {
		c.rk, c.sk = a, b
	}
	c.sck = ck
	c.rck = ck
	c.handshakeDone = true
	return nil
}

// Write encrypts p as one or more BOLT-8 transport frames.
func (c *Conn) Write(p []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	c.outLock.Lock()
	defer c.outLock.Unlock()

	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > MaxMessageLen {
			n = MaxMessageLen
		}
		if err := c.writeMessage(p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// writeMessage emits one BOLT-8 frame: encrypted-length (2 plaintext + 16
// MAC = 18 bytes on wire) followed by encrypted-body (N plaintext + 16
// MAC). Caller must hold outLock.
func (c *Conn) writeMessage(m []byte) error {
	// len(m) is bounded by MaxMessageLen above; safe to encode as 2 bytes.
	mlen := uint16(len(m)) //nolint:gosec // bounded by Write
	lenBytes := []byte{byte(mlen >> 8), byte(mlen & 0xFF)}
	lc, err := encryptWithAD(c.sk, c.sn, nil, lenBytes)
	if err != nil {
		return err
	}
	c.sn++
	pc, err := encryptWithAD(c.sk, c.sn, nil, m)
	if err != nil {
		return err
	}
	c.sn++
	if _, err := c.conn.Write(append(lc, pc...)); err != nil {
		return err
	}
	c.maybeRekeySend()
	return nil
}

// Read decrypts one BOLT-8 frame and copies the plaintext body to p.
// Surplus bytes are buffered for the next Read.
func (c *Conn) Read(p []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	c.inLock.Lock()
	defer c.inLock.Unlock()

	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Encrypted length frame: 2 plaintext bytes + 16 MAC = 18 bytes.
	lc := make([]byte, 2+macSize)
	if _, err := io.ReadFull(c.conn, lc); err != nil {
		return 0, err
	}
	lenPlain, err := decryptWithAD(c.rk, c.rn, nil, lc)
	if err != nil {
		return 0, fmt.Errorf("bolt8: decrypt length: %w", err)
	}
	c.rn++
	bodyLen := int(lenPlain[0])<<8 | int(lenPlain[1])
	body := make([]byte, bodyLen+macSize)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		return 0, err
	}
	plaintext, err := decryptWithAD(c.rk, c.rn, nil, body)
	if err != nil {
		return 0, fmt.Errorf("bolt8: decrypt body: %w", err)
	}
	c.rn++
	c.maybeRekeyRecv()
	n := copy(p, plaintext)
	if n < len(plaintext) {
		c.readBuf = append(c.readBuf, plaintext[n:]...)
	}
	return n, nil
}

// maybeRekeySend rotates the send key when the nonce hits the rekey
// interval. Per BOLT-8 §3: "once the nonce reaches 1000" rotate the
// key via HKDF(ck, k) and reset nonce to 0.
func (c *Conn) maybeRekeySend() {
	if c.sn < rekeyInterval {
		return
	}
	c.sck, c.sk = hkdfExpand(c.sck, c.sk[:])
	c.sn = 0
}

func (c *Conn) maybeRekeyRecv() {
	if c.rn < rekeyInterval {
		return
	}
	c.rck, c.rk = hkdfExpand(c.rck, c.rk[:])
	c.rn = 0
}
