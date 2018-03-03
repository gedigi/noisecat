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
	Config *Configuration
	L      common.Log
}

var commonParams = new(common.Params)

// GenerateKeypair generates and outputs private and public keys based on the
// provided configuration
func (n *Noisesocat) GenerateKeypair() []byte {
	keypair, err := keyGenerator()
	if err != nil {
		n.L.Fatalf("Can't geneate keypair")
	}
	output, err := json.Marshal(keypair)
	if err != nil {
		n.L.Fatalf("Can't convert to json")
	}
	return output
}

// StartClient starts a noisesocat client
func (n *Noisesocat) StartClient() {
	netAddress := net.JoinHostPort(n.Config.DstHost, n.Config.DstPort)
	localAddress := net.JoinHostPort(n.Config.SrcHost, n.Config.SrcPort)

	conn, err := noisesocket.Dial(netAddress, localAddress, n.Config.NoiseConfig)
	if err != nil {
		n.L.Fatalf("Can't connect to %s/tcp: %s", netAddress, err)
	}
	n.L.Verb("Connected to %s", conn.RemoteAddr().String())
	if n.Config.NoiseConfig.StaticKey.Public != nil {
		n.L.Verb("Local static key: %s", base64.StdEncoding.EncodeToString(n.Config.NoiseConfig.StaticKey.Public))
	}
	commonParams.Proxy = n.Config.Proxy
	commonParams.ExecuteCmd = n.Config.ExecuteCmd
	commonParams.Conn = conn
	commonParams.Router()
}

// StartServer starts a noisesocat server
func (n *Noisesocat) StartServer() {
	netAddress := net.JoinHostPort(n.Config.SrcHost, n.Config.SrcPort)

	listener, err := noisesocket.Listen(netAddress, n.Config.NoiseConfig)
	if err != nil {
		n.L.Fatalf("Can't listen: %s", err)
	}

	n.L.Verb("Listening on %s/tcp", listener.Addr())
	if n.Config.NoiseConfig.StaticKey.Public != nil {
		n.L.Verb("Local static key: %s", base64.StdEncoding.EncodeToString(n.Config.NoiseConfig.StaticKey.Public))
	}

	acceptConnections := func() net.Conn {
		conn, err := listener.Accept()
		if err != nil {
			n.L.Fatalf("Can't accept connection: %s", err)
		}
		n.L.Verb("Connection from %s", conn.RemoteAddr().String())
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

// -- Key Generator
func keyGenerator() (noise.DHKey, error) {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashBLAKE2b)
	keypair, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		return noise.DHKey{}, err
	}
	return keypair, nil
}
