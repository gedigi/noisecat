package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/gedigi/noise"
	"github.com/gedigi/noisecat/pkg/common"
	"github.com/gedigi/noisecat/pkg/noisecat"
)

var version = "1.0"

func parseFlags() common.Configuration {
	config := common.Configuration{}

	flag.Usage = Usage
	flag.StringVar(&config.ExecuteCmd, "e", "", "Executes the given `command`")
	flag.StringVar(&config.Proxy, "proxy", "", "`address:port` combination to forward connections to (-l required)")
	flag.BoolVar(&config.Listen, "l", false, "listens for incoming connections")
	flag.BoolVar(&config.Verbose, "v", false, "more verbose output")
	flag.BoolVar(&config.Daemon, "k", false, "accepts multiple connections (-l && (-e || -proxy) required)")
	flag.StringVar(&config.SrcPort, "p", "0", "source `port` to use")
	flag.StringVar(&config.SrcHost, "s", "", "source `address` to use")
	flag.StringVar(&config.Protocol, "proto", "Noise_NN_25519_AESGCM_SHA256", "`protocol name` to use")
	flag.StringVar(&config.PSK, "psk", "", "`pre-shared key` to use")
	flag.StringVar(&config.RStatic, "rstatic", "", "`static key` of the remote peer (32 bytes, base64)")
	flag.StringVar(&config.LStatic, "lstatic", "", "`file` containing local keypair (use -keygen to generate)")
	flag.BoolVar(&config.Keygen, "keygen", false, "generates 25519 keypair and prints it to stdout")
	flag.Parse()
	if config.Keygen {
		return config
	}
	if !config.Listen && flag.NArg() != 2 {
		flag.Usage()
		os.Exit(-1)
	} else {
		config.DstHost = flag.Arg(0)
		config.DstPort = flag.Arg(1)
	}
	return config
}

func main() {
	var err error

	config := parseFlags()
	l := common.Verbose(config.Verbose)

	noiseConfigInterface, err := config.ParseConfig()
	if err != nil {
		l.Fatalf("%s", err)
	}
	noiseConfig, ok := noiseConfigInterface.(noise.Config)
	if !ok {
		l.Fatalf("%s", err)
	}

	nc := noisecat.Noisecat{
		Config:      &config,
		Log:         l,
		NoiseConfig: &noiseConfig,
	}

	if config.Keygen {
		fmt.Printf("%s\n", nc.GenerateKeypair())
		os.Exit(0)
	}

	if config.Listen == false {
		nc.StartClient()
	} else {
		nc.StartServer()
	}
}

// Usage prints noisecat help
func Usage() {
	showBanner()
	fmt.Printf("\nUsage: %s [options] [address] [port]\n\n", os.Args[0])
	fmt.Println("Options:")
	flag.PrintDefaults()
	listSupportedProtocols()
}

func showBanner() {
	fmt.Println()
	fmt.Printf("noisecat %s - the noise swiss army knife\n", version)
	fmt.Println(" (c) Gerardo Di Giacomo 2018")
}

func listSupportedProtocols() {
	fmt.Print("\nProtocol name format: Noise_PT_DH_CP_HS\n\n")
	fmt.Print("Where:\n  PT: Handshake pattern\n  DH: Diffie-Hellman handshake function\n")
	fmt.Print("  CP: Cipher function\n  HS: Hash function\n\n")
	fmt.Print("  e.g. Noise_NN_25519_AESGCM_SHA256\n\n")

	fmt.Print("Available handshake patterns:\n")
	listDetails(common.PatternStrByte)

	fmt.Print("Available DH functions:\n")
	listDetails(common.DHStrByte)

	fmt.Print("Available Cipher functions:\n")
	listDetails(common.CipherStrByte)

	fmt.Print("Available Hash functions:\n")
	listDetails(common.HashStrByte)
}

func listDetails(m map[string]byte) {
	i := 0
	fmt.Print(" ")
	for v := range m {
		fmt.Print(" ", v)
		if (i+1)%5 == 0 || i == len(m)-1 {
			fmt.Print("\n ")
		} else if i < len(m)-1 {
			fmt.Print(",")
		}
		i++
	}
	fmt.Println()
}
