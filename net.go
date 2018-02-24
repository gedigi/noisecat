package main

import (
	"net"

	"github.com/gedigi/noise"
)

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

	verb("Listening on %s/tcp", netAddress)
	if noiseconfig.StaticKeypair.Public != nil {
		verb("Local static key: %x", noiseconfig.StaticKeypair.Public)
	}

	if config.daemon {
		for {
			conn, err := listener.Accept()
			if err != nil {
				fatalf("Can't accept connection: %s", err)
			}

			verb("Connection from %s", conn.RemoteAddr().String())
			if config.executeCmd != "" {
				go executeCmd(config.executeCmd, &conn)
			} else {
				go handleIO(&conn)
			}
		}
	} else {
		conn, err := listener.Accept()
		if err != nil {
			fatalf("Can't accept connection: %s", err)
		}

		verb("Connection from %s", conn.RemoteAddr().String())
		if config.executeCmd != "" {
			executeCmd(config.executeCmd, &conn)
		} else {
			handleIO(&conn)
		}
	}
}
