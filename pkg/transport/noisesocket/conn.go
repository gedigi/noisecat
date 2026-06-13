// Package noisesocket implements the NoiseSocket spec
// (https://noiseprotocol.org/noisesocket) on top of github.com/flynn/noise.
//
// Differences from pkg/transport/raw:
//
//   - Handshake message frame: 2-byte BE negotiation_data_len + negotiation_data +
//     2-byte BE noise_message_len + noise_message. Either field may be empty.
//   - Transport message frame: 2-byte BE noise_message_len + noise_message.
//   - Encrypted payload contents: 2-byte BE body_len + body + arbitrary padding
//     (ignored on read).
//   - Prologue: "NoiseSocketInit1" || initial_negotiation_data_len (2 B BE) ||
//     initial_negotiation_data || application_prologue. The application_prologue
//     is whatever the caller passed in transport.Options.Prologue.
//
// The default path implements only the Accept outcome (responder reads the
// initiator's negotiation_data, accepts, replies with empty negotiation_data
// on every subsequent message) and stays spec-interoperable.
//
// When a transport.Options.Negotiation is supplied, the connection instead
// runs the noisecat v1 negotiation layer (see negotiation.go and
// handshake_neg.go), which adds the Reject, Retry, and Switch outcomes on
// top of a noisecat-specific, downgrade-bound negotiation_data convention.
// That layer is noisecat-to-noisecat only.
package noisesocket

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
	"github.com/gedigi/noisecat/pkg/transport"
)

const (
	// MaxMessageLen mirrors noise.MaxMsgLen — both negotiation_data and
	// noise_message are constrained to 16-bit lengths on the wire.
	MaxMessageLen = 0xFFFF

	// prologueMagic is the literal prefix required by the spec.
	prologueMagic = "NoiseSocketInit1"
)

// Conn is a NoiseSocket-secured connection that implements net.Conn.
type Conn struct {
	conn     net.Conn
	isClient bool

	cfg            *noise.Config
	initialNegData []byte
	appPrologue    []byte
	hs             *noise.HandshakeState
	handshakeDone  bool
	handshakeMu    sync.Mutex

	// neg, when non-nil, activates the noisecat v1 negotiation layer
	// (Reject/Retry/Switch). When nil, Handshake runs the legacy
	// Accept-only path. In negotiation mode cfg is built per attempt via
	// neg.BuildConfig rather than supplied up front.
	neg *transport.Negotiation

	in, out         *noise.CipherState
	inLock, outLock sync.Mutex
	inputBuffer     []byte
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// SetDeadline applies to both reads and writes on the underlying conn.
func (c *Conn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

// SetReadDeadline applies to the underlying conn.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// SetWriteDeadline applies to the underlying conn.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// Close closes the underlying network connection.
func (c *Conn) Close() error { return c.conn.Close() }

// CloseWrite signals end-of-stream on the write half if the underlying
// transport supports it; otherwise falls back to a full Close.
func (c *Conn) CloseWrite() error {
	if cw, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.conn.Close()
}

// Fingerprint returns the Noise handshake hash after handshake
// completion. See the raw transport's docs for usage; both peers
// compute the same value and it is suitable for channel binding.
func (c *Conn) Fingerprint() [32]byte {
	c.handshakeMu.Lock()
	defer c.handshakeMu.Unlock()
	var out [32]byte
	if !c.handshakeDone || c.hs == nil {
		return out
	}
	h := c.hs.ChannelBinding()
	copy(out[:], h)
	return out
}

// Server wraps an existing net.Conn into a NoiseSocket server-side conn.
// initialNegData and appPrologue are mixed into the handshake hash via
// the spec's prologue formula.
func Server(c net.Conn, cfg *noise.Config, initialNegData, appPrologue []byte) *Conn {
	return &Conn{conn: c, cfg: cfg, initialNegData: initialNegData, appPrologue: appPrologue, isClient: false}
}

// Client wraps an existing net.Conn into a NoiseSocket client-side conn.
func Client(c net.Conn, cfg *noise.Config, initialNegData, appPrologue []byte) *Conn {
	return &Conn{conn: c, cfg: cfg, initialNegData: initialNegData, appPrologue: appPrologue, isClient: true}
}

// ClientWithNegotiation wraps c as a client-side conn that runs the
// noisecat v1 negotiation layer (Reject/Retry/Switch) instead of the
// Accept-only legacy path. cfg is built per attempt via neg.BuildConfig.
func ClientWithNegotiation(c net.Conn, neg *transport.Negotiation, appPrologue []byte) *Conn {
	return &Conn{conn: c, neg: neg, appPrologue: appPrologue, isClient: true}
}

// ServerWithNegotiation wraps c as a server-side conn that runs the
// noisecat v1 negotiation layer.
func ServerWithNegotiation(c net.Conn, neg *transport.Negotiation, appPrologue []byte) *Conn {
	return &Conn{conn: c, neg: neg, appPrologue: appPrologue, isClient: false}
}

// Handshake performs the NoiseSocket handshake on first call; subsequent
// calls return nil immediately. Called automatically by Read/Write.
func (c *Conn) Handshake() error {
	c.handshakeMu.Lock()
	defer c.handshakeMu.Unlock()
	if c.handshakeDone {
		return nil
	}

	if c.neg != nil {
		return c.handshakeNegotiated()
	}

	// Per the spec, prologue = "NoiseSocketInit1" || neg_data_len ||
	// neg_data || application_prologue. The neg_data here is the
	// initial one — for the Accept case, only the initiator's first
	// message carries non-empty negotiation_data, so both sides hash
	// the same value.
	prologue := buildPrologue(c.initialNegData, c.appPrologue)
	cfg := *c.cfg
	cfg.Prologue = prologue
	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return fmt.Errorf("noisesocket: NewHandshakeState: %w", err)
	}
	c.hs = hs

	state := c.isClient
	first := true
	for range cfg.Pattern.Messages {
		if state {
			var negData []byte
			if first && c.isClient {
				negData = c.initialNegData
			}
			msg, c1, c2, werr := c.hs.WriteMessage(nil, nil)
			if werr != nil {
				return fmt.Errorf("noisesocket: WriteMessage: %w", werr)
			}
			if err := writeHandshakeFrame(c.conn, negData, msg); err != nil {
				return err
			}
			if c1 != nil {
				c.assignCipherStates(c1, c2)
			}
		} else {
			negData, noiseMsg, rerr := readHandshakeFrame(c.conn)
			if rerr != nil {
				return rerr
			}
			// Responder must see the same initial negotiation_data its
			// caller anticipated for the prologue to match. Mismatch =
			// downgrade attack; fail the handshake.
			if first && !c.isClient {
				if !bytesEqual(negData, c.initialNegData) {
					return errors.New("noisesocket: negotiation_data does not match expected")
				}
			}
			_, c1, c2, perr := c.hs.ReadMessage(nil, noiseMsg)
			if perr != nil {
				return fmt.Errorf("noisesocket: ReadMessage: %w", perr)
			}
			if c1 != nil {
				c.assignCipherStates(c1, c2)
			}
		}
		state = !state
		first = false
	}

	c.handshakeDone = true
	return nil
}

func (c *Conn) assignCipherStates(c1, c2 *noise.CipherState) {
	if c.isClient {
		c.out, c.in = c1, c2
	} else {
		c.out, c.in = c2, c1
	}
}

// Write encrypts p as a single NoiseSocket transport message and sends
// it. Per the spec, the encrypted payload is body_len + body + padding;
// we pad zero bytes (callers that want length-hiding can prepend a
// padding wrapper themselves in a future revision).
func (c *Conn) Write(p []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	c.outLock.Lock()
	defer c.outLock.Unlock()

	// We never write more than MaxMessageLen at a time; chunk if needed.
	// Each chunk is body_len (2 B) + body + AEAD tag (16 B), the whole
	// of which must fit in the 2-byte transport length frame.
	const maxBody = MaxMessageLen - 2 - 16
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxBody {
			n = maxBody
		}
		plaintext := putUint16(make([]byte, 0, 2+n), n)
		plaintext = append(plaintext, p[:n]...)

		ciphertext, err := c.out.Encrypt(nil, nil, plaintext)
		if err != nil {
			if errors.Is(err, noise.ErrMaxNonce) {
				_ = c.conn.Close()
			}
			return total, fmt.Errorf("noisesocket: Encrypt: %w", err)
		}
		if err := writeLengthPrefixed(c.conn, ciphertext); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// Read decrypts one NoiseSocket transport message at a time and copies
// the decoded body into p. Padding past body_len is silently discarded
// per the spec.
func (c *Conn) Read(p []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	c.inLock.Lock()
	defer c.inLock.Unlock()

	if len(c.inputBuffer) > 0 {
		n := copy(p, c.inputBuffer)
		c.inputBuffer = c.inputBuffer[n:]
		return n, nil
	}

	ciphertext, err := readLengthPrefixed(c.conn)
	if err != nil {
		return 0, err
	}
	plaintext, err := c.in.Decrypt(nil, nil, ciphertext)
	if err != nil {
		if errors.Is(err, noise.ErrMaxNonce) {
			_ = c.conn.Close()
		}
		return 0, fmt.Errorf("noisesocket: Decrypt: %w", err)
	}
	if len(plaintext) < 2 {
		return 0, errors.New("noisesocket: payload too short for body_len header")
	}
	bodyLen := int(plaintext[0])<<8 | int(plaintext[1])
	if 2+bodyLen > len(plaintext) {
		return 0, errors.New("noisesocket: body_len exceeds payload")
	}
	body := plaintext[2 : 2+bodyLen]
	n := copy(p, body)
	if n < len(body) {
		c.inputBuffer = append(c.inputBuffer, body[n:]...)
	}
	return n, nil
}

// ---- framing helpers (exported only as needed) ----

func buildPrologue(initialNegData, appPrologue []byte) []byte {
	out := make([]byte, 0, len(prologueMagic)+2+len(initialNegData)+len(appPrologue))
	out = append(out, prologueMagic...)
	out = putUint16(out, len(initialNegData))
	out = append(out, initialNegData...)
	out = append(out, appPrologue...)
	return out
}

// putUint16 writes a big-endian uint16 length header. The caller is
// responsible for bounding the length to <= MaxMessageLen; this helper
// just performs the encoding.
func putUint16(dst []byte, n int) []byte {
	v := uint16(n) //nolint:gosec // caller guarantees 0 <= n <= 0xFFFF
	return append(dst, byte(v>>8), byte(v&0xFF))
}

func writeHandshakeFrame(w io.Writer, negData, noiseMsg []byte) error {
	if len(negData) > MaxMessageLen {
		return errors.New("noisesocket: negotiation_data exceeds 16-bit length")
	}
	if len(noiseMsg) > MaxMessageLen {
		return errors.New("noisesocket: noise_message exceeds 16-bit length")
	}
	buf := make([]byte, 0, 4+len(negData)+len(noiseMsg))
	buf = putUint16(buf, len(negData))
	buf = append(buf, negData...)
	buf = putUint16(buf, len(noiseMsg))
	buf = append(buf, noiseMsg...)
	_, err := w.Write(buf)
	return err
}

func readHandshakeFrame(r io.Reader) (negData, noiseMsg []byte, err error) {
	negData, err = readLengthPrefixed(r)
	if err != nil {
		return nil, nil, err
	}
	noiseMsg, err = readLengthPrefixed(r)
	if err != nil {
		return nil, nil, err
	}
	return negData, noiseMsg, nil
}

func writeLengthPrefixed(w io.Writer, payload []byte) error {
	if len(payload) > MaxMessageLen {
		return errors.New("noisesocket: payload exceeds 16-bit length frame")
	}
	frame := putUint16(make([]byte, 0, 2+len(payload)), len(payload))
	frame = append(frame, payload...)
	_, err := w.Write(frame)
	return err
}

func readLengthPrefixed(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
