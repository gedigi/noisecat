package main

import (
	"encoding/hex"
	"flag"
	"os"
	"strings"

	"github.com/gedigi/noise"
)

// Configuration parameters
type Configuration struct {
	srcPort string
	srcHost string
	dstPort string
	dstHost string

	executeCmd string
	listen     bool
	verbose    bool
	daemon     bool

	protocol string
	pattern  noise.HandshakePattern
	dh       noise.DHFunc
	cipher   noise.CipherFunc
	hash     noise.HashFunc

	psk     string
	rStatic string
}

var config Configuration

func init() {
	var err error
	flag.Usage = noisecatUsage
	flag.StringVar(&config.executeCmd, "e", "", "Executes the given `command`")
	flag.BoolVar(&config.listen, "l", false, "listens for incoming connections")
	flag.BoolVar(&config.verbose, "v", false, "more verbose output")
	flag.BoolVar(&config.daemon, "d", false, "run as daemon (accepts multiple connections)")
	flag.StringVar(&config.srcPort, "p", "0", "source `port` to use")
	flag.StringVar(&config.srcHost, "s", "", "source `host` to use")
	flag.StringVar(&config.protocol, "proto", "Noise_NN_25519_AESGCM_SHA256", "`protocol name` to use")
	flag.StringVar(&config.psk, "psk", "", "`pre-shared key` to use (max 32 bytes)")
	flag.StringVar(&config.rStatic, "rstatic", "", "`static key` of the remote peer (32 bytes, hex-encoded)")
	flag.Parse()

	config.pattern, config.dh, config.cipher, config.hash, err = parseProtocol(config.protocol)
	if err != nil {
		fatalf("%s", err)
	}

	if config.psk != "" {
		if len(config.psk) > 32 {
			fatalf("Pre-shared key can be 32 bytes maximum")
		} else if len(config.psk) < 32 {
			config.psk += strings.Repeat("\x00", 32-len(config.psk))
		}
	}

	if config.rStatic != "" {
		if len(config.rStatic) != 64 {
			fatalf("Remote static needs to be 32 bytes")
		} else {
			rStatic, err := hex.DecodeString(config.rStatic)
			if err != nil {
				fatalf("Invalid remote static key")
			}
			config.rStatic = string(rStatic)
		}

	}

	if config.listen == false {
		if flag.NArg() != 2 {
			flag.Usage()
			os.Exit(-1)
		} else {
			if config.daemon {
				fatalf("Daemon mode is only possible with -l")
			}
			config.dstHost = flag.Arg(0)
			config.dstPort = flag.Arg(1)
		}
	}
}

func main() {
	start()
}
