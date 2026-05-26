package noisesocket

import (
	"errors"
	"net"

	"github.com/flynn/noise"
	"github.com/gedigi/noisecat/pkg/transport"
)

// Transport implements transport.Transport for NoiseSocket.
type Transport struct{}

// New returns a Transport ready to dial/listen.
func New() *Transport { return &Transport{} }

// Name returns "noisesocket".
func (Transport) Name() string { return "noisesocket" }

// Dial opens a NoiseSocket-secured connection. opts.NegotiationData is
// sent with the first handshake message; opts.Prologue is appended to
// the spec-mandated "NoiseSocketInit1" || neg_len || neg_data prefix.
func (Transport) Dial(network, addr, localAddr string, cfg *noise.Config, opts transport.Options) (net.Conn, error) {
	if cfg == nil {
		return nil, errors.New("noisesocket: nil noise.Config")
	}
	var dialer net.Dialer
	if localAddr != "" {
		laddr, err := net.ResolveTCPAddr(network, localAddr)
		if err != nil {
			return nil, err
		}
		dialer.LocalAddr = laddr
	}
	raw, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return Client(raw, cfg, opts.NegotiationData, opts.Prologue), nil
}

// Listen creates a NoiseSocket listener. opts is captured and applied to
// every accepted connection.
func (Transport) Listen(network, laddr string, cfg *noise.Config, opts transport.Options) (net.Listener, error) {
	if cfg == nil {
		return nil, errors.New("noisesocket: nil noise.Config")
	}
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return &Listener{Listener: l, cfg: cfg, opts: opts}, nil
}

// Listener wraps a net.Listener and wraps every accepted conn as a
// NoiseSocket Conn.
type Listener struct {
	net.Listener
	cfg  *noise.Config
	opts transport.Options
}

// Accept returns a NoiseSocket-wrapped *Conn (as net.Conn).
func (l *Listener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(raw, l.cfg, l.opts.NegotiationData, l.opts.Prologue), nil
}
