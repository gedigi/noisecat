package noisecat

import (
	"encoding/base64"
	"errors"
	"net"

	"github.com/gedigi/noise"
	"github.com/gedigi/noisesocket"
)

// Noisecat defines the main network configuration
type Noisecat struct {
	Config      *Configuration
	NoiseConfig NoiseInterface
	Log         Verbose
}

var commonParams = new(Params)

// StartClient starts a noisecat or noisesocat client
func (n *Noisecat) StartClient() {
	netAddress := net.JoinHostPort(n.Config.DstHost, n.Config.DstPort)
	localAddress := net.JoinHostPort(n.Config.SrcHost, n.Config.SrcPort)

	conn, err := connectTo("tcp", netAddress, localAddress, n.NoiseConfig)
	if err != nil {
		n.Log.Fatalf("Can't connect to %s/tcp: %s", netAddress, err)
	}
	n.Log.Verb("Connected to %s", conn.RemoteAddr().String())
	localPublicKey := n.NoiseConfig.GetLocalStaticPublic()
	if localPublicKey != nil {
		n.Log.Verb("Local static key: %s", base64.StdEncoding.EncodeToString(localPublicKey))
	}
	commonParams.Proxy = n.Config.Proxy
	commonParams.ExecuteCmd = n.Config.ExecuteCmd
	commonParams.Conn = conn
	commonParams.Log = Verbose(n.Config.Verbose)
	commonParams.Router()
}

// StartServer starts a noisecat or noisesocat server
func (n *Noisecat) StartServer() {
	netAddress := net.JoinHostPort(n.Config.SrcHost, n.Config.SrcPort)

	listener, err := listenOn("tcp", netAddress, n.NoiseConfig)
	if err != nil {
		n.Log.Fatalf("Can't listen: %s", err)
	}

	n.Log.Verb("Listening on %s/tcp", listener.Addr())
	localPublicKey := n.NoiseConfig.GetLocalStaticPublic()
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

func connectTo(protocol, netAddress, localAddress string, config interface{}) (net.Conn, error) {
	noiseConf, ok := config.(*NoiseConfig)
	if ok {
		noiseConfigCasted := noise.Config(*noiseConf)
		noiseConn, err := noise.Dial(protocol, netAddress, localAddress, &noiseConfigCasted)
		if err != nil {
			return nil, err
		}
		return noiseConn, nil
	}
	noisesocketConf, ok := config.(*NoisesocketConfig)
	if ok {
		noisesocketConfCasted := noisesocket.ConnectionConfig(*noisesocketConf)
		noisesocketConn, err := noisesocket.Dial(netAddress, localAddress, &noisesocketConfCasted)
		if err != nil {
			return nil, err
		}
		return noisesocketConn, nil
	}
	return nil, errors.New("impossible")
}

func listenOn(protocol, netAddress string, config interface{}) (net.Listener, error) {
	noiseConf, ok := config.(*NoiseConfig)
	if ok {
		noiseConfCasted := noise.Config(*noiseConf)
		noiseListener, err := noise.Listen(protocol, netAddress, &noiseConfCasted)
		if err != nil {
			return nil, err
		}
		return noiseListener, nil
	}
	noisesocketConf, ok := config.(*NoisesocketConfig)
	if ok {
		noiseoscketConfCasted := noisesocket.ConnectionConfig(*noisesocketConf)
		noisesocketListener, err := noisesocket.Listen(netAddress, &noiseoscketConfCasted)
		if err != nil {
			return nil, err
		}
		return noisesocketListener, nil
	}
	return nil, errors.New("impossible")
}
