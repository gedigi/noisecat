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
// noisecat Config. An empty / "raw" Transport field defaults to the
// historical framing.
func resolveTransport(cfg *Config) (transport.Transport, error) {
	name := cfg.Transport
	if name == "" {
		name = "raw"
	}
	switch name {
	case "raw":
		return raw.New(), nil
	case "noisesocket":
		return noisesocket.New(), nil
	default:
		return nil, fmt.Errorf("unknown transport %q (expected: raw, noisesocket)", name)
	}
}

// transportOptions packs the noisecat-level CLI flags into the
// transport-level Options the chosen Transport understands.
func (n *Noisecat) transportOptions() transport.Options {
	return transport.Options{
		Prologue:        []byte(n.Config.Prologue),
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
