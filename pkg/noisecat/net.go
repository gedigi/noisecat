package noisecat

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/flynn/noise"
	"github.com/gedigi/noisecat/pkg/transport"
	"github.com/gedigi/noisecat/pkg/transport/bolt8"
	"github.com/gedigi/noisecat/pkg/transport/noisesocket"
	"github.com/gedigi/noisecat/pkg/transport/raw"
)

// Noisecat defines the main network configuration
type Noisecat struct {
	Config      *Config
	NoiseConfig *noise.Config
	Log         Verbose
}

// resolveTransport selects a Transport implementation based on the
// noisecat Config and validates that the chosen transport is
// compatible with the Noise protocol's DH function. An empty / "raw"
// Transport field defaults to the historical framing.
//
// Compatibility rules:
//   - bolt8 only speaks Noise_XK_secp256k1_ChaChaPoly_SHA256, so it
//     requires DHFunc == NOISE_DH_SECP256K1.
//   - raw and noisesocket sit on top of flynn/noise's DH primitives
//     and therefore cannot accept secp256k1 (which BOLT-8 implements
//     directly, outside flynn/noise).
func resolveTransport(cfg *Config) (transport.Transport, error) {
	name := cfg.Transport
	if name == "" {
		name = "raw"
	}
	switch name {
	case "raw":
		if cfg.DHFunc == NOISE_DH_SECP256K1 {
			return nil, fmt.Errorf("transport=raw cannot speak secp256k1; use -transport bolt8")
		}
		return raw.New(), nil
	case "noisesocket":
		if cfg.DHFunc == NOISE_DH_SECP256K1 {
			return nil, fmt.Errorf("transport=noisesocket cannot speak secp256k1; use -transport bolt8")
		}
		return noisesocket.New(), nil
	case "bolt8":
		if cfg.DHFunc != NOISE_DH_SECP256K1 {
			return nil, fmt.Errorf("transport=bolt8 only supports secp256k1; the chosen DH function is not")
		}
		return bolt8.New(), nil
	default:
		return nil, fmt.Errorf("unknown transport %q (expected: raw, noisesocket, bolt8)", name)
	}
}

// transportOptions packs the noisecat-level CLI flags into the
// transport-level Options the chosen Transport understands.
func (n *Noisecat) transportOptions() transport.Options {
	prologue := n.Config.Prologue
	// BOLT-8 mandates the literal prologue "lightning"; supply it
	// transparently if the user has not overridden -prologue.
	if prologue == "" && n.Config.Transport == "bolt8" {
		prologue = "lightning"
	}
	return transport.Options{
		Prologue:        []byte(prologue),
		NegotiationData: []byte(n.Config.NegotiationData),
	}
}

// StartClient starts a noisecat client
func (n *Noisecat) StartClient() {
	tp, err := resolveTransport(n.Config)
	if err != nil {
		n.Log.Fatalf("%s", err)
	}
	netAddress := net.JoinHostPort(n.Config.DstHost, n.Config.DstPort)
	localAddress := net.JoinHostPort(n.Config.SrcHost, n.Config.SrcPort)

	conn, err := tp.Dial("tcp", netAddress, localAddress, n.NoiseConfig, n.transportOptions())
	if err != nil {
		n.Log.Fatalf("can't connect to %s/tcp: %s", netAddress, err)
	}
	n.Log.Verb("Connected to %s using transport=%s", conn.RemoteAddr().String(), tp.Name())
	if pub := n.NoiseConfig.StaticKeypair.Public; pub != nil {
		n.Log.Verb("Local static key: %s", base64.StdEncoding.EncodeToString(pub))
	}
	n.newParams(conn).Router()
}

// StartServer starts a noisecat server
func (n *Noisecat) StartServer() {
	tp, err := resolveTransport(n.Config)
	if err != nil {
		n.Log.Fatalf("%s", err)
	}
	netAddress := net.JoinHostPort(n.Config.SrcHost, n.Config.SrcPort)

	listener, err := tp.Listen("tcp", netAddress, n.NoiseConfig, n.transportOptions())
	if err != nil {
		n.Log.Fatalf("can't listen: %s", err)
	}
	defer func() { _ = listener.Close() }()

	n.Log.Verb("Listening on %s/tcp using transport=%s", listener.Addr(), tp.Name())
	if pub := n.NoiseConfig.StaticKeypair.Public; pub != nil {
		n.Log.Verb("Local static key: %s", base64.StdEncoding.EncodeToString(pub))
	}

	if !n.Config.Daemon {
		conn, err := listener.Accept()
		if err != nil {
			n.Log.Fatalf("can't accept connection: %s", err)
		}
		n.Log.Verb("Connection from %s", conn.RemoteAddr().String())
		n.newParams(conn).Router()
		return
	}

	// Daemon mode: accept loop with graceful shutdown on SIGINT/SIGTERM.
	var wg sync.WaitGroup
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		n.Log.Verb("Shutting down")
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// listener closed (graceful shutdown) or real error; either way, stop accepting.
			break
		}
		n.Log.Verb("Connection from %s", conn.RemoteAddr().String())
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			n.newParams(c).Router()
		}(conn)
	}
	wg.Wait()
}

// newParams builds a per-connection Params from the noisecat config.
// Each connection gets its own struct so daemon-mode goroutines cannot
// race on shared state.
func (n *Noisecat) newParams(conn net.Conn) *Params {
	return &Params{
		Conn:       conn,
		Proxy:      n.Config.Proxy,
		ExecuteCmd: n.Config.ExecuteCmd,
		Log:        n.Log,
	}
}
