package main

import (
	"io"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/gedigi/noise"
)

// -- Network functions
func startClient() {
	netAddress := net.JoinHostPort(config.dstHost, config.dstPort)
	localAddress := net.JoinHostPort(config.srcHost, config.srcPort)

	conn, err := noise.Dial("tcp", netAddress, localAddress, &noiseconfig)
	if err != nil {
		fatalf("Can't connect to %s/tcp: %s", netAddress, err)
	}
	verb("Connected to %s", conn.RemoteAddr().String())
	if noiseconfig.StaticKeypair.Public != nil {
		verb("Local static key: %x", noiseconfig.StaticKeypair.Public)
	}
	if config.executeCmd != "" {
		executeCmd(conn)
	} else {
		handleIO(conn)
	}
}

func startServer() {
	netAddress := net.JoinHostPort(config.srcHost, config.srcPort)

	listener, err := noise.Listen("tcp", netAddress, &noiseconfig)
	if err != nil {
		fatalf("Can't listen: %s", err)
	}

	verb("Listening on %s/tcp", listener.Addr())
	if noiseconfig.StaticKeypair.Public != nil {
		verb("Local static key: %x", noiseconfig.StaticKeypair.Public)
	}

	if config.daemon {
		for {
			conn, err := listener.Accept()
			if err != nil {
				fatalf("Can't accept connection: %s", err)
			}
			remoteAddr := conn.RemoteAddr().String()
			verb("Connection from %s", remoteAddr)
			if config.executeCmd != "" {
				go executeCmd(conn)
			} else {
				go handleIO(conn)
			}
		}
	} else {
		conn, err := listener.Accept()
		if err != nil {
			fatalf("Can't accept connection: %s", err)
		}

		verb("Connection from %s", conn.RemoteAddr().String())
		if config.executeCmd != "" {
			executeCmd(conn)
		} else {
			handleIO(conn)
		}
	}
}

// -- Network helper functions
func executeCmd(conn net.Conn) {
	defer func() {
		conn.Close()
	}()
	cmdParse := strings.Split(config.executeCmd, " ")
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

func handleIO(conn net.Conn) {
	c := make(chan progress)
	var w io.WriteCloser
	var r io.ReadCloser

	if config.proxy != "" {
		pConn, err := net.Dial("tcp", config.proxy)
		if err != nil {
			fatalf("Can't connect to remote host: %s", err)
		}
		w, r = pConn, pConn
	} else {
		r = os.Stdin
		w = os.Stdout
	}
	go copyIO(conn, r, "SNT", &c)
	go copyIO(w, conn, "RCV", &c)

	for i := 0; i < 2; i++ {
		select {
		case s := <-c:
			verb("%s: %d", s.dir, s.bytes)
		}
	}
}

func copyIO(writer io.WriteCloser, reader io.ReadCloser, dir string, c *chan progress) {
	defer func() {
		reader.Close()
		writer.Close()
	}()
	n, _ := io.Copy(writer, reader)

	*c <- progress{bytes: n, dir: dir}
}
