package main

import (
	"crypto/rand"
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
	proxy      string
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
var noiseconfig noise.Config

func init() {
	flag.Usage = noisecatUsage
	flag.StringVar(&config.executeCmd, "e", "", "Executes the given `command`")
	flag.StringVar(&config.proxy, "proxy", "", "`address:port` combination to forward connections to (-l required)")
	flag.BoolVar(&config.listen, "l", false, "listens for incoming connections")
	flag.BoolVar(&config.verbose, "v", false, "more verbose output")
	flag.BoolVar(&config.daemon, "k", false, "accepts multiple connections (-l, -e or -proxy required)")
	flag.StringVar(&config.srcPort, "p", "0", "source `port` to use")
	flag.StringVar(&config.srcHost, "s", "", "source `IP address` to use")
	flag.StringVar(&config.protocol, "proto", "Noise_NN_25519_AESGCM_SHA256", "`protocol name` to use")
	flag.StringVar(&config.psk, "psk", "", "`pre-shared key` to use (max 32 bytes)")
	flag.StringVar(&config.rStatic, "rstatic", "", "`static key` of the remote peer (32 bytes, hex-encoded)")
	flag.Parse()
}

func main() {
	var err error

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

	if config.daemon && (!config.listen && (config.proxy != "" || config.executeCmd != "")) {
		fatalf("-k requires -l and either -proxy or -e")
	}
	prepareNoiseConfig()

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
			startClient()
		}
	} else {
		startServer()
	}
}

func prepareNoiseConfig() {
	var err error

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
}
