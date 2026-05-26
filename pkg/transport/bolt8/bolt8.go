package bolt8

import (
	"errors"
	"net"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/flynn/noise"
	"github.com/gedigi/noisecat/pkg/transport"
)

// Transport implements transport.Transport for BOLT-8. The noise.Config
// passed via the Transport interface is interpreted as follows:
//
//   - cfg.StaticKeypair.Private must be the local node's 32-byte
//     secp256k1 static key.
//   - cfg.PeerStatic, when present, must be a 33-byte compressed
//     secp256k1 public key (the destination node ID for an initiator).
//   - cfg.Pattern and cipher/hash selections are not consulted —
//     BOLT-8 fixes the protocol to Noise_XK_secp256k1_ChaChaPoly_SHA256.
type Transport struct{}

// New returns a Transport ready for use.
func New() *Transport { return &Transport{} }

// Name returns "bolt8".
func (Transport) Name() string { return "bolt8" }

// Dial opens a BOLT-8 connection. localAddr is forwarded to net.Dialer.
func (Transport) Dial(network, addr, localAddr string, cfg *noise.Config, _ transport.Options) (net.Conn, error) {
	priv, err := localPrivFromCfg(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.PeerStatic == nil {
		return nil, errors.New("bolt8: initiator requires -rstatic (33-byte compressed secp256k1 pubkey)")
	}
	remote, err := secp256k1.ParsePubKey(cfg.PeerStatic)
	if err != nil {
		return nil, errors.New("bolt8: invalid -rstatic; want 33-byte compressed secp256k1")
	}
	var d net.Dialer
	if localAddr != "" {
		laddr, err := net.ResolveTCPAddr(network, localAddr)
		if err != nil {
			return nil, err
		}
		d.LocalAddr = laddr
	}
	raw, err := d.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return Client(raw, priv, remote), nil
}

// Listen creates a BOLT-8 listener.
func (Transport) Listen(network, laddr string, cfg *noise.Config, _ transport.Options) (net.Listener, error) {
	priv, err := localPrivFromCfg(cfg)
	if err != nil {
		return nil, err
	}
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return &Listener{Listener: l, priv: priv}, nil
}

// Listener wraps a net.Listener and Server-wraps each accepted conn.
type Listener struct {
	net.Listener
	priv *secp256k1.PrivateKey
}

// Accept returns a BOLT-8 Conn as net.Conn.
func (l *Listener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(raw, l.priv), nil
}

// localPrivFromCfg extracts a 32-byte secp256k1 private key from the
// noise.Config. BOLT-8 uses fixed-length keys (no curve cofactor games),
// so we accept any 32 bytes and reject anything else.
func localPrivFromCfg(cfg *noise.Config) (*secp256k1.PrivateKey, error) {
	if cfg == nil {
		return nil, errors.New("bolt8: nil noise.Config")
	}
	if len(cfg.StaticKeypair.Private) != 32 {
		return nil, errors.New("bolt8: missing 32-byte local static key (use -lstatic)")
	}
	return secp256k1.PrivKeyFromBytes(cfg.StaticKeypair.Private), nil
}
