package noisecat

import (
	"encoding/base64"
	"net"

	"github.com/flynn/noise"
	"github.com/gedigi/noisecat/pkg/noisenet"
)

// Noisecat defines the main network configuration
type Noisecat struct {
	Config      *Config
	NoiseConfig *noise.Config
	Log         Verbose
}

var commonParams = new(Params)

// StartClient starts a noisecat client
func (n *Noisecat) StartClient() {
	netAddress := net.JoinHostPort(n.Config.DstHost, n.Config.DstPort)
	localAddress := net.JoinHostPort(n.Config.SrcHost, n.Config.SrcPort)

	conn, err := noisenet.Dial("tcp", netAddress, localAddress, n.NoiseConfig)
	if err != nil {
		n.Log.Fatalf("Can't connect to %s/tcp: %s", netAddress, err)
	}
	n.Log.Verb("Connected to %s", conn.RemoteAddr().String())
	localPublicKey := n.NoiseConfig.StaticKeypair.Public
	if localPublicKey != nil {
		n.Log.Verb("Local static key: %s", base64.StdEncoding.EncodeToString(localPublicKey))
	}
	commonParams.Proxy = n.Config.Proxy
	commonParams.ExecuteCmd = n.Config.ExecuteCmd
	commonParams.Conn = conn
	commonParams.Log = Verbose(n.Config.Verbose)
	commonParams.Router()
}

// StartServer starts a noisecat server
func (n *Noisecat) StartServer() {
	netAddress := net.JoinHostPort(n.Config.SrcHost, n.Config.SrcPort)

	listener, err := noisenet.Listen("tcp", netAddress, n.NoiseConfig)
	if err != nil {
		n.Log.Fatalf("Can't listen: %s", err)
	}

	n.Log.Verb("Listening on %s/tcp", listener.Addr())
	localPublicKey := n.NoiseConfig.StaticKeypair.Public
	if localPublicKey != nil {
		n.Log.Verb("Local static key: %s", base64.StdEncoding.EncodeToString(localPublicKey))
	}

	acceptConnections := func() net.Conn {
		conn, err := listener.Accept()
		if err != nil {
			n.Log.Fatalf("Can't accept connection: %s", err)
		}
		n.Log.Verb("Connection from %s", conn.RemoteAddr().String())
		return conn
	}
	commonParams.Proxy = n.Config.Proxy
	commonParams.ExecuteCmd = n.Config.ExecuteCmd
	commonParams.Log = Verbose(n.Config.Verbose)

	if n.Config.Daemon {
		for {
			commonParams.Conn = acceptConnections()
			go commonParams.Router()
		}
	} else {
		commonParams.Conn = acceptConnections()
		commonParams.Router()
	}
}
