// Package whatsapp implements a noisecat transport that speaks WhatsApp's
// multi-device Noise wire protocol: a Noise_XX_25519_AESGCM_SHA256 handshake
// whose messages are wrapped in protobuf and framed with a one-time "WA"
// header plus 3-byte length prefixes.
//
// It operates in two modes:
//
//   - Real-backend mode (Dial with no address): connects over WebSocket to
//     wss://web.whatsapp.com/ws/chat and verifies the server certificate
//     chain against WhatsApp's pinned root key. This proves protocol-level
//     interoperability with the live backend but does NOT log in (the
//     ClientFinish payload is sent empty; real login needs account
//     credentials / QR pairing and the Signal app protocol, out of scope).
//
//   - Peer-to-peer mode (Dial with an address, or Listen): two noisecat
//     instances speak the same WhatsApp framing to each other over plain TCP,
//     exactly like the raw/noisesocket/bolt8 transports. No certificate is
//     exchanged or verified. This is what enables, e.g., a bind shell:
//     `noisecat -transport whatsapp -l -p 4444 -e /bin/sh`.
package whatsapp

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/flynn/noise"

	"github.com/gedigi/noisecat/pkg/transport"
)

// defaultHandshakeTimeout bounds the connect + handshake when the caller
// supplies no -w timeout (matches whatsmeow's NoiseHandshakeResponseTimeout).
const defaultHandshakeTimeout = 20 * time.Second

// Transport implements transport.Transport for WhatsApp.
type Transport struct {
	// rootKey is the pinned certificate anchor for real-backend mode;
	// defaults to WACertPubKey.
	rootKey [32]byte
}

// New returns a Transport ready to dial the live WhatsApp backend or peer
// with another noisecat instance.
func New() *Transport { return &Transport{rootKey: WACertPubKey} }

// Name returns "whatsapp".
func (Transport) Name() string { return "whatsapp" }

// Dial connects either to the real WhatsApp backend (when addr has no host —
// the endpoint is the fixed wss URL, and the server certificate is verified)
// or, when addr names a host:port, to another noisecat over plain TCP
// (peer-to-peer, no certificate).
func (t *Transport) Dial(network, addr, localAddr string, cfg *noise.Config, opts transport.Options) (net.Conn, error) {
	clientStatic, err := keypairFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	timeout := opts.DialTimeout
	if timeout <= 0 {
		timeout = defaultHandshakeTimeout
	}

	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		return t.dialBackend(clientStatic, timeout)
	}
	return dialPeer(network, addr, localAddr, clientStatic, timeout)
}

// dialBackend connects to the live WhatsApp websocket and verifies the
// pinned certificate chain.
func (t *Transport) dialBackend(clientStatic dhKeypair, timeout time.Duration) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ws, _, err := websocket.Dial(dialCtx, endpointURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": {originHeader}},
	})
	if err != nil {
		return nil, err
	}
	ws.SetReadLimit(maxFrameLen)
	// Background context so the connection outlives the dial; Close tears it down.
	nc := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	_ = nc.SetDeadline(time.Now().Add(timeout))

	rootKey := t.rootKey
	framed := newClientFramedConn(nc)
	hs, err := clientHandshake(framed, clientStatic, []byte{}, &rootKey)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	return newConn(nc, framed, hs), nil
}

// dialPeer connects to another noisecat over TCP and runs the p2p handshake
// (no certificate verification).
func dialPeer(network, addr, localAddr string, clientStatic dhKeypair, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	if localAddr != "" && localAddr != ":0" {
		if la, err := net.ResolveTCPAddr(network, localAddr); err == nil {
			d.LocalAddr = la
		}
	}
	raw, err := d.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(timeout))
	framed := newClientFramedConn(raw)
	hs, err := clientHandshake(framed, clientStatic, []byte{}, nil)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return newConn(raw, framed, hs), nil
}

// Listen binds a TCP listener whose accepted connections run the WhatsApp
// p2p handshake as the responder. (You cannot impersonate WhatsApp's real
// servers, so this is noisecat-to-noisecat only.)
func (t *Transport) Listen(network, laddr string, cfg *noise.Config, opts transport.Options) (net.Listener, error) {
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return &listener{Listener: l, cfg: cfg, timeout: opts.DialTimeout}, nil
}

// listener performs the responder handshake on each accepted connection.
type listener struct {
	net.Listener
	cfg     *noise.Config
	timeout time.Duration
}

// Accept returns the next connection with its responder handshake deferred to
// the first Read/Write. Running the handshake lazily (rather than inline here)
// keeps the accept loop responsive: a slow or non-noisecat peer cannot block
// other incoming connections, and a failed handshake simply surfaces as an
// I/O error on that one connection.
func (l *listener) Accept() (net.Conn, error) {
	timeout := l.timeout
	if timeout <= 0 {
		timeout = defaultHandshakeTimeout
	}
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	serverStatic, err := keypairFromConfig(l.cfg)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	framed := &framedConn{rw: raw, readHeader: true}
	return newDeferredServerConn(raw, framed, serverStatic, timeout), nil
}

// keypairFromConfig uses the configured Noise static keypair, or generates an
// ephemeral one when none is set.
func keypairFromConfig(cfg *noise.Config) (dhKeypair, error) {
	var kp dhKeypair
	if cfg != nil && len(cfg.StaticKeypair.Private) == 32 && len(cfg.StaticKeypair.Public) == 32 {
		copy(kp.priv[:], cfg.StaticKeypair.Private)
		copy(kp.pub[:], cfg.StaticKeypair.Public)
		return kp, nil
	}
	return generateKeypair()
}
