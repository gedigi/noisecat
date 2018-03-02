package noisecat

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/gedigi/noise"
	"github.com/gedigi/noisecat/pkg/common"
)

// Noisecat is the main tool structure containing log facility and configuration
type Noisecat struct {
	Config *Configuration
	L      common.Log
}

// GenerateKeypair generates and outputs private and public keys based on the
// provided configuration
func (n *Noisecat) GenerateKeypair() []byte {
	cs := noise.NewCipherSuite(n.Config.DH, n.Config.Cipher, n.Config.Hash)
	keypair, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		n.L.Fatalf("Can't geneate keypair")
	}
	output, _ := json.Marshal(keypair)
	if err != nil {
		n.L.Fatalf("Can't convert to json")
	}
	return output
}

// StartClient starts a noisecat client
func (n *Noisecat) StartClient() {

	netAddress := net.JoinHostPort(n.Config.DstHost, n.Config.DstPort)
	localAddress := net.JoinHostPort(n.Config.SrcHost, n.Config.SrcPort)

	conn, err := noise.Dial("tcp", netAddress, localAddress, n.Config.NoiseConfig)
	if err != nil {
		n.L.Fatalf("Can't connect to %s/tcp: %s", netAddress, err)
	}
	n.L.Verb("Connected to %s", conn.RemoteAddr().String())
	if n.Config.NoiseConfig.StaticKeypair.Public != nil {
		n.L.Verb("Local static key: %s", base64.StdEncoding.EncodeToString(n.Config.NoiseConfig.StaticKeypair.Public))
	}
	n.router(conn)
}

func (n *Noisecat) StartServer() {
	netAddress := net.JoinHostPort(n.Config.SrcHost, n.Config.SrcPort)

	listener, err := noise.Listen("tcp", netAddress, n.Config.NoiseConfig)
	if err != nil {
		n.L.Fatalf("Can't listen: %s", err)
	}

	n.L.Verb("Listening on %s/tcp", listener.Addr())
	if n.Config.NoiseConfig.StaticKeypair.Public != nil {
		n.L.Verb("Local static key: %s", base64.StdEncoding.EncodeToString(n.Config.NoiseConfig.StaticKeypair.Public))
	}

	acceptConnections := func() *noise.Conn {
		conn, err := listener.Accept()
		if err != nil {
			n.L.Fatalf("Can't accept connection: %s", err)
		}
		n.L.Verb("Connection from %s", conn.RemoteAddr().String())
		return conn
	}

	if n.Config.Daemon {
		for {
			go n.router(acceptConnections())
		}
	} else {
		n.router(acceptConnections())
	}
}

func (n *Noisecat) router(conn *noise.Conn) {
	var w io.WriteCloser
	var r io.ReadCloser

	if n.Config.Proxy != "" {
		pConn, err := net.Dial("tcp", n.Config.Proxy)
		if err != nil {
			n.L.Fatalf("Can't connect to remote host: %s", err)
		}
		w, r = pConn, pConn
	} else {
		r = os.Stdin
		w = os.Stdout
	}

	if n.Config.ExecuteCmd != "" {
		n.executeCmd(conn)
	} else {
		n.handleIO(conn, w, r)
	}
}

// -- Network helper functions
func (n *Noisecat) executeCmd(conn net.Conn) {
	defer func() {
		conn.Close()
	}()
	cmdParse := strings.Split(n.Config.ExecuteCmd, " ")
	cmdName := cmdParse[0]
	var cmdArgs []string
	if len(cmdParse[1:]) > 0 {
		cmdArgs = cmdParse[1:]
	}
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = conn, conn, conn
	if err := cmd.Run(); err != nil {
		n.L.Fatalf("Can't execut command: %s", err)
	}
}

func (n *Noisecat) handleIO(conn net.Conn, w io.WriteCloser, r io.ReadCloser) {
	c := make(chan common.Progress)

	copyIO := func(writer io.WriteCloser, reader io.ReadCloser, dir string) {
		defer func() {
			reader.Close()
			writer.Close()
		}()
		numBytes, _ := io.Copy(writer, reader)
		c <- common.Progress{Bytes: numBytes, Dir: dir}
	}

	go copyIO(conn, r, "SNT")
	go copyIO(w, conn, "RCV")

	for i := 0; i < 2; i++ {
		s := <-c
		n.L.Verb("%s: %d", s.Dir, s.Bytes)
	}
}
