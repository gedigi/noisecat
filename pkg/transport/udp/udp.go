// Package udp implements a noisecat transport that runs the Noise Protocol
// Framework over UDP. Because Noise needs a reliable, ordered byte stream
// (for both the handshake and the data phase), the datagrams are carried by
// KCP (github.com/xtaci/kcp-go), an ARQ protocol that provides a reliable
// stream over UDP. The Noise layer itself is the existing "raw" framing
// (2-byte length prefix), reused unchanged on top of the KCP stream — so a
// UDP connection is wire-compatible with raw-over-TCP at the Noise layer,
// only the underlying transport differs.
//
// KCP provides reliability/ordering only; it carries no encryption of its
// own (BlockCrypt is nil) — confidentiality and authentication come entirely
// from Noise.
package udp

import (
	"net"
	"time"

	"github.com/flynn/noise"
	kcp "github.com/xtaci/kcp-go/v5"

	"github.com/gedigi/noisecat/pkg/transport"
	"github.com/gedigi/noisecat/pkg/transport/raw"
)

// Transport implements transport.Transport over reliable UDP (KCP).
type Transport struct{}

// New returns a Transport ready to dial/listen.
func New() *Transport { return &Transport{} }

// Name returns "udp".
func (Transport) Name() string { return "udp" }

// Dial opens a KCP session to addr and runs the raw Noise handshake over it.
func (Transport) Dial(_, addr, _ string, cfg *noise.Config, opts transport.Options) (net.Conn, error) {
	applyPrologue(cfg, opts.Prologue)
	// nil BlockCrypt and 0/0 shards: no KCP-level crypto or FEC — Noise
	// provides confidentiality/authentication.
	session, err := kcp.DialWithOptions(addr, nil, 0, 0)
	if err != nil {
		return nil, err
	}
	tuneSession(session)

	c := raw.Client(session, cfg)
	if opts.DialTimeout > 0 {
		_ = session.SetDeadline(time.Now().Add(opts.DialTimeout))
	}
	if err := c.Handshake(); err != nil {
		_ = session.Close()
		return nil, err
	}
	_ = session.SetDeadline(time.Time{})
	return c, nil
}

// Listen binds a KCP listener; accepted sessions run the raw Noise handshake
// as the responder (lazily, on first I/O).
func (Transport) Listen(_, laddr string, cfg *noise.Config, opts transport.Options) (net.Listener, error) {
	applyPrologue(cfg, opts.Prologue)
	l, err := kcp.ListenWithOptions(laddr, nil, 0, 0)
	if err != nil {
		return nil, err
	}
	return &listener{l: l, cfg: cfg}, nil
}

// listener wraps a KCP listener, wrapping each accepted session as a raw
// Noise responder.
type listener struct {
	l   *kcp.Listener
	cfg *noise.Config
}

// Accept returns the next KCP session wrapped for the Noise handshake. The
// handshake itself runs on first Read/Write (raw.Conn is lazy), so a slow
// peer cannot block the accept loop.
func (ln *listener) Accept() (net.Conn, error) {
	session, err := ln.l.AcceptKCP()
	if err != nil {
		return nil, err
	}
	tuneSession(session)
	return raw.Server(session, ln.cfg), nil
}

func (ln *listener) Close() error   { return ln.l.Close() }
func (ln *listener) Addr() net.Addr { return ln.l.Addr() }

// tuneSession configures a KCP session for noisecat's needs: stream mode (so
// the session is a byte stream like TCP, which the raw framing requires —
// message mode would split reads on KCP message boundaries) and a low-latency
// ARQ profile.
func tuneSession(s *kcp.UDPSession) {
	// SetStreamMode is the only API to enable KCP stream mode, which we
	// require so the session behaves as a byte stream for the raw framing.
	// It is deprecated upstream but still functional with no replacement.
	s.SetStreamMode(true)     //nolint:staticcheck // no non-deprecated alternative for stream mode
	s.SetNoDelay(1, 10, 2, 1) // nodelay, 10ms interval, fast resend, no congestion window
	s.SetWindowSize(1024, 1024)
	_ = s.SetMtu(1350)
}

// applyPrologue mixes the application prologue into the handshake hash,
// matching the raw transport's behavior.
func applyPrologue(cfg *noise.Config, prologue []byte) {
	if cfg != nil && len(prologue) > 0 && len(cfg.Prologue) == 0 {
		cfg.Prologue = prologue
	}
}
