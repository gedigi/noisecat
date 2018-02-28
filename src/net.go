package main

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
)

type noisecat struct {
	config *Configuration
}

// -- Generate keypar
func (n *noisecat) generateKeypair() []byte {
	cs := noise.NewCipherSuite(n.config.dh, n.config.cipher, n.config.hash)
	keypair, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		l.fatalf("Can't geneate keypair")
	}
	output, err := json.Marshal(keypair)
	if err != nil {
		l.fatalf("Can't convert to json")
	}
	return output
}

// -- Network functions
func (n *noisecat) startClient() {
	netAddress := net.JoinHostPort(n.config.dstHost, n.config.dstPort)
	localAddress := net.JoinHostPort(n.config.srcHost, n.config.srcPort)

	conn, err := noise.Dial("tcp", netAddress, localAddress, n.config.noiseConfig)
	if err != nil {
		l.fatalf("Can't connect to %s/tcp: %s", netAddress, err)
	}
	l.verb("Connected to %s", conn.RemoteAddr().String())
	if n.config.noiseConfig.StaticKeypair.Public != nil {
		l.verb("Local static key: %s", base64.StdEncoding.EncodeToString(n.config.noiseConfig.StaticKeypair.Public))
	}
	n.router(conn)
}

func (n *noisecat) startServer() {
	netAddress := net.JoinHostPort(n.config.srcHost, n.config.srcPort)

	listener, err := noise.Listen("tcp", netAddress, n.config.noiseConfig)
	if err != nil {
		l.fatalf("Can't listen: %s", err)
	}

	l.verb("Listening on %s/tcp", listener.Addr())
	if n.config.noiseConfig.StaticKeypair.Public != nil {
		l.verb("Local static key: %s", base64.StdEncoding.EncodeToString(n.config.noiseConfig.StaticKeypair.Public))
	}

	acceptConnections := func() *noise.Conn {
		conn, err := listener.Accept()
		if err != nil {
			l.fatalf("Can't accept connection: %s", err)
		}
		l.verb("Connection from %s", conn.RemoteAddr().String())
		return conn
	}

	if n.config.daemon {
		for {
			go n.router(acceptConnections())
		}
	} else {
		n.router(acceptConnections())
	}
}

// -- Network helper functions
func (n *noisecat) router(conn *noise.Conn) {
	var w io.WriteCloser
	var r io.ReadCloser

	if n.config.proxy != "" {
		pConn, err := net.Dial("tcp", n.config.proxy)
		if err != nil {
			l.fatalf("Can't connect to remote host: %s", err)
		}
		w, r = pConn, pConn
	} else {
		r = os.Stdin
		w = os.Stdout
	}

	if n.config.executeCmd != "" {
		n.executeCmd(conn)
	} else {
		n.handleIO(conn, w, r)
	}
}

func (n *noisecat) executeCmd(conn net.Conn) {
	defer func() {
		conn.Close()
	}()
	cmdParse := strings.Split(n.config.executeCmd, " ")
	cmdName := cmdParse[0]
	var cmdArgs []string
	if len(cmdParse[1:]) > 0 {
		cmdArgs = cmdParse[1:]
	}
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = conn, conn, conn
	if err := cmd.Run(); err != nil {
		l.fatalf("Can't execut command: %s", err)
	}
}

func (n *noisecat) handleIO(conn net.Conn, w io.WriteCloser, r io.ReadCloser) {
	c := make(chan progress)

	copyIO := func(writer io.WriteCloser, reader io.ReadCloser, dir string) {
		defer func() {
			reader.Close()
			writer.Close()
		}()
		numBytes, _ := io.Copy(writer, reader)
		c <- progress{bytes: numBytes, dir: dir}
	}

	go copyIO(conn, r, "SNT")
	go copyIO(w, conn, "RCV")

	for i := 0; i < 2; i++ {
		s := <-c
		l.verb("%s: %d", s.dir, s.bytes)
	}
}
