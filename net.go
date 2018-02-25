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
		executeCmd(config.executeCmd, conn)
	}
	handleIO(conn)
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
				go executeCmd(config.executeCmd, conn)
			} else if config.proxy != "" {
				go proxyConn(config.proxy, conn)
			}
		}
	} else {
		conn, err := listener.Accept()
		if err != nil {
			fatalf("Can't accept connection: %s", err)
		}

		verb("Connection from %s", conn.RemoteAddr().String())
		if config.executeCmd != "" {
			executeCmd(config.executeCmd, conn)
		} else if config.proxy != "" {
			proxyConn(config.proxy, conn)
		} else {
			handleIO(conn)
		}
	}
}

// -- Network helper functions
func executeCmd(command string, conn net.Conn) {
	defer func() {
		conn.Close()
	}()
	cmdParse := strings.Split(command, " ")
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

	copyIO := func(writer io.WriteCloser, reader io.ReadCloser, dir string) {
		defer func() {
			reader.Close()
			writer.Close()
		}()
		n, err := io.Copy(writer, reader)
		if err != nil {
			fatalf("%s", err)
		}

		c <- progress{bytes: n, dir: dir}
	}

	go copyIO(os.Stdout, conn, "RCV")
	go copyIO(conn, os.Stdin, "SNT")

	select {
	case s := <-c:
		verb("%s: %d", s.dir, s.bytes)
	}
}

func proxyConn(address string, conn net.Conn) {
	pConn, err := net.Dial("tcp", address)
	if err != nil {
		fatalf("Can't connect to remote host: %s", err)
	}
	defer func() {
		conn.Close()
		pConn.Close()
	}()
	c1 := makeChan(conn)
	c2 := makeChan(pConn)
	for {
		select {
		case b1 := <-c1:
			if b1 != nil {
				pConn.Write(b1)
			} else {
				return
			}
		case b2 := <-c2:
			if b2 != nil {
				conn.Write(b2)
			} else {
				return
			}
		}
	}
}

func makeChan(conn io.ReadCloser) chan []byte {
	c := make(chan []byte)
	go func() {
		b := make([]byte, 1024)
		for {
			n, err := conn.Read(b)
			if err != nil {
				c <- nil
			}
			if n > 0 {
				res := make([]byte, n)
				copy(res, b[:n])
				c <- res
			}
		}
	}()
	return c
}
