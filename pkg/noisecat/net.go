package noisecat

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"

	"github.com/gedigi/noise"
	"github.com/gedigi/noisecat/pkg/common"
)

// Noisecat is the main tool structure containing log facility and configuration
type Noisecat struct {
	Config      *common.Configuration
	NoiseConfig *noise.Config
	Log         common.Verbose
}

var commonParams = new(common.Params)

// GenerateKeypair generates and outputs private and public keys based on the
// provided configuration
func (n *Noisecat) GenerateKeypair() []byte {
	keypair, err := n.NoiseConfig.CipherSuite.GenerateKeypair(rand.Reader)
	if err != nil {
		n.Log.Fatalf("Can't geneate keypair")
	}
	output, _ := json.Marshal(keypair)
	if err != nil {
		n.Log.Fatalf("Can't convert to json")
	}
	return output
}

// StartClient starts a noisecat client
func (n *Noisecat) StartClient() {
	netAddress := net.JoinHostPort(n.Config.DstHost, n.Config.DstPort)
	localAddress := net.JoinHostPort(n.Config.SrcHost, n.Config.SrcPort)

	conn, err := noise.Dial("tcp", netAddress, localAddress, n.NoiseConfig)
	if err != nil {
		n.Log.Fatalf("Can't connect to %s/tcp: %s", netAddress, err)
	}
	n.Log.Verb("Connected to %s", conn.RemoteAddr().String())
	if n.NoiseConfig.StaticKeypair.Public != nil {
		n.Log.Verb("Local static key: %s", base64.StdEncoding.EncodeToString(n.NoiseConfig.StaticKeypair.Public))
	}
	commonParams.Proxy = n.Config.Proxy
	commonParams.ExecuteCmd = n.Config.ExecuteCmd
	commonParams.Conn = conn
	commonParams.Router()
}

// StartServer starts a noisecat server
func (n *Noisecat) StartServer() {
	netAddress := net.JoinHostPort(n.Config.SrcHost, n.Config.SrcPort)

	listener, err := noise.Listen("tcp", netAddress, n.NoiseConfig)
	if err != nil {
		n.Log.Fatalf("Can't listen: %s", err)
	}

	n.Log.Verb("Listening on %s/tcp", listener.Addr())
	if n.NoiseConfig.StaticKeypair.Public != nil {
		n.Log.Verb("Local static key: %s", base64.StdEncoding.EncodeToString(n.NoiseConfig.StaticKeypair.Public))
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
