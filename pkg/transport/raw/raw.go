package raw

import (
	"net"

	"github.com/flynn/noise"
	"github.com/gedigi/noisecat/pkg/transport"
)

// Transport implements the noisecat Transport interface using the historical
// "raw" framing: a 2-byte big-endian length prefix in front of every Noise
// message. No negotiation, no padding, prologue is passed through unchanged.
type Transport struct{}

// New returns a Transport ready to dial/listen.
func New() *Transport { return &Transport{} }

// Name returns "raw".
func (Transport) Name() string { return "raw" }

// Dial opens a noise connection using the raw transport's framing.
func (Transport) Dial(network, addr, localAddr string, cfg *noise.Config, opts transport.Options) (net.Conn, error) {
	if len(opts.Prologue) > 0 {
		applyPrologue(cfg, opts.Prologue)
	}
	// DialWithDialer applies dialer.Timeout across both the TCP connect
	// and the Noise handshake, which is exactly the -w semantics we want.
	return DialWithDialer(&net.Dialer{Timeout: opts.DialTimeout}, network, addr, localAddr, cfg)
}

// Listen creates a noise listener using the raw transport's framing.
func (Transport) Listen(network, laddr string, cfg *noise.Config, opts transport.Options) (net.Listener, error) {
	if len(opts.Prologue) > 0 {
		applyPrologue(cfg, opts.Prologue)
	}
	return Listen(network, laddr, cfg)
}

// applyPrologue is a tiny helper that does not mutate the caller's noise.Config
// shared instance — it sets the field only if the caller has not already.
// (flynn/noise honors cfg.Prologue at NewHandshakeState time.)
func applyPrologue(cfg *noise.Config, prologue []byte) {
	if len(cfg.Prologue) == 0 {
		cfg.Prologue = prologue
	}
}
