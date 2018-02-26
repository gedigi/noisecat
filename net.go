package main

import (
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

// -- Network functions
func (n *noisecat) startClient() {

	netAddress := net.JoinHostPort(n.config.dstHost, n.config.dstPort)
	localAddress := net.JoinHostPort(n.config.srcHost, n.config.srcPort)

	conn, err := noise.Dial("tcp", netAddress, localAddress, n.config.noiseConfig)
	if err != nil {
		fatalf("Can't connect to %s/tcp: %s", netAddress, err)
	}
	if n.config.verbose {
		verb("Connected to %s", conn.RemoteAddr().String())
	}
	if n.config.noiseConfig.StaticKeypair.Public != nil {
		if n.config.verbose {
			verb("Local static key: %x", n.config.noiseConfig.StaticKeypair.Public)
		}
	}
	if n.config.executeCmd != "" {
		n.executeCmd(conn)
	} else {
		n.handleIO(conn)
	}
}

func (n *noisecat) startServer() {
	netAddress := net.JoinHostPort(n.config.srcHost, n.config.srcPort)

	listener, err := noise.Listen("tcp", netAddress, n.config.noiseConfig)
	if err != nil {
		fatalf("Can't listen: %s", err)
	}

	if n.config.verbose {
		verb("Listening on %s/tcp", listener.Addr())
	}
	if n.config.noiseConfig.StaticKeypair.Public != nil {
		if n.config.verbose {
			verb("Local static key: %x", n.config.noiseConfig.StaticKeypair.Public)
		}
	}

	acceptConnections := func() {
		conn, err := listener.Accept()
		if err != nil {
			fatalf("Can't accept connection: %s", err)
		}
		if n.config.verbose {
			verb("Connection from %s", conn.RemoteAddr().String())
		}
		if n.config.daemon {
			if n.config.executeCmd != "" {
				go n.executeCmd(conn)

			} else {
				go n.handleIO(conn)
			}
		} else {
			if n.config.executeCmd != "" {
				n.executeCmd(conn)

			} else {
				n.handleIO(conn)
			}
		}

	}

	if n.config.daemon {
		for {
			acceptConnections()
		}
	} else {
		acceptConnections()
	}
}

// -- Network helper functions
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
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn
	if err := cmd.Run(); err != nil {
		fatalf("Can't execut command: %s", err)
	}
}

func (n *noisecat) handleIO(conn net.Conn) {
	c := make(chan progress)
	var w io.WriteCloser
	var r io.ReadCloser

	if n.config.proxy != "" {
		pConn, err := net.Dial("tcp", n.config.proxy)
		if err != nil {
			fatalf("Can't connect to remote host: %s", err)
		}
		w, r = pConn, pConn
	} else {
		r = os.Stdin
		w = os.Stdout
	}
	go n.copyIO(conn, r, "SNT", &c)
	go n.copyIO(w, conn, "RCV", &c)

	for i := 0; i < 2; i++ {
		select {
		case s := <-c:
			if n.config.verbose {
				verb("%s: %d", s.dir, s.bytes)
			}
		}
	}
}

func (n *noisecat) copyIO(writer io.WriteCloser, reader io.ReadCloser, dir string, c *chan progress) {
	defer func() {
		reader.Close()
		writer.Close()
	}()
	numBytes, _ := io.Copy(writer, reader)

	*c <- progress{bytes: numBytes, dir: dir}
}
