package main

import (
	"crypto/rand"
	"net"

	"github.com/gedigi/noise"
)

func start() {
	var err error
	var noiseconfig noise.Config

	cs := noise.NewCipherSuite(config.dh, config.cipher, config.hash)

	noiseconfig = noise.Config{
		CipherSuite: cs,
		Random:      rand.Reader,
		Pattern:     config.pattern,
		Initiator:   !config.listen,
	}

	if config.psk != "" {
		noiseconfig.PresharedKey = []byte(config.psk)
	}
	if noiseconfig.Initiator {
		switch noiseconfig.Pattern.Name[0] {
		case 'X', 'I', 'K':
			noiseconfig.StaticKeypair, err = cs.GenerateKeypair(rand.Reader)
			if err != nil {
				fatalf("Can't generate keys")
			}
		}
		switch noiseconfig.Pattern.Name[1] {
		case 'K':
			if config.rStatic == "" {
				fatalf("You need to provide the remote peer static key (-rstatic)")
			}
			noiseconfig.PeerStatic = []byte(config.rStatic)
		}
	} else {
		switch noiseconfig.Pattern.Name[0] {
		case 'K':
			if config.rStatic == "" {
				fatalf("You need to provide the remote peer static key (-rstatic)")
			}
			noiseconfig.PeerStatic = []byte(config.rStatic)
		}
		switch noiseconfig.Pattern.Name[1] {
		case 'X', 'K':
			noiseconfig.StaticKeypair, err = cs.GenerateKeypair(rand.Reader)
			if err != nil {
				fatalf("Can't generate keys")
			}
		}
	}

	if config.listen == false {
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
	} else {
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

}
