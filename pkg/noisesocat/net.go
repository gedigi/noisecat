package noisesocat

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"

	"github.com/gedigi/noise"
	"github.com/gedigi/noisecat/pkg/common"
	"github.com/gedigi/noisesocket"
)

// Noisesocat is the main tool structure containing log facility and configuration
type Noisesocat struct {
	Config      *common.Configuration
	NoiseConfig *noisesocket.ConnectionConfig
	Log         common.Verbose
}

var commonParams = new(common.Params)

// GenerateKeypair generates and outputs private and public keys based on the
// provided configuration
func (n *Noisesocat) GenerateKeypair() []byte {
	cs := noise.NewCipherSuite(
		common.DHByteObj[n.NoiseConfig.DHFunc],
		common.CipherByteObj[n.NoiseConfig.CipherFunc],
		common.HashByteObj[n.NoiseConfig.HashFunc],
	)
	keypair, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		n.Log.Fatalf("Can't geneate keypair")
	}
	output, err := json.Marshal(keypair)
	if err != nil {
		n.Log.Fatalf("Can't convert to json")
	}
	return output
}

// StartClient starts a noisesocat client
func (n *Noisesocat) StartClient() {
	netAddress := net.JoinHostPort(n.Config.DstHost, n.Config.DstPort)
	localAddress := net.JoinHostPort(n.Config.SrcHost, n.Config.SrcPort)

	conn, err := noisesocket.Dial(netAddress, localAddress, n.NoiseConfig)
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

// StartServer starts a noisesocat server
func (n *Noisesocat) StartServer() {
	netAddress := net.JoinHostPort(n.Config.SrcHost, n.Config.SrcPort)

	listener, err := noisesocket.Listen(netAddress, n.NoiseConfig)
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
