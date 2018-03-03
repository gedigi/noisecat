package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/gedigi/noisecat/pkg/common"
	"github.com/gedigi/noisecat/pkg/noisesocat"
	"github.com/gedigi/noisesocket"
)

var version = "1.0"

func parseFlags() common.Configuration {
	config := common.Configuration{}

	flag.Usage = noisesocatUsage
	flag.StringVar(&config.ExecuteCmd, "e", "", "Executes the given `command`")
	flag.StringVar(&config.Proxy, "proxy", "", "`address:port` combination to forward connections to (-l required)")
	flag.BoolVar(&config.Listen, "l", false, "listens for incoming connections")
	flag.BoolVar(&config.Verbose, "v", false, "more verbose output")
	flag.BoolVar(&config.Daemon, "k", false, "accepts multiple connections (-l && (-e || -proxy) required)")
	flag.StringVar(&config.SrcPort, "p", "0", "source `port` to use")
	flag.StringVar(&config.SrcHost, "s", "", "source `address` to use")
	flag.StringVar(&config.RStatic, "rstatic", "", "`static key` of the remote peer (32 bytes, base64)")
	flag.StringVar(&config.LStatic, "lstatic", "", "`file` containing local keypair (use -keygen to generate)")
	flag.BoolVar(&config.Keygen, "keygen", false, "generates 25519 keypair and prints it to stdout")
	flag.Parse()
	config.Protocol = "Noise_XX_25510_ChaChaPoly_BLAKE2b"
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
	noiseConfig, ok := noiseConfigInterface.(noisesocket.ConnectionConfig)
	if !ok {
		l.Fatalf("%s", err)
	}

	nc := noisesocat.Noisesocat{
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

// -- Help/Usage
func noisesocatUsage() {
	showBanner()
	fmt.Printf("\nUsage: %s [options] [address] [port]\n\n", os.Args[0])
	fmt.Println("Options:")
	flag.PrintDefaults()
	fmt.Println("\nThe connection will automatically use:")
	fmt.Print("  Noise_XX_25519_ChaChaPoly_BLAKE2b (IK if -rstatic)\n\n")
}

func showBanner() {
	fmt.Println()
	fmt.Printf("noisesocat %s\n", version)
	fmt.Println(" (c) Gerardo Di Giacomo 2018")
}
