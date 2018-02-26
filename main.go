package main

import (
	"flag"
	"os"
)

func parseFlags() Configuration {
	var config Configuration

	flag.Usage = noisecatUsage
	flag.StringVar(&config.executeCmd, "e", "", "Executes the given `command`")
	flag.StringVar(&config.proxy, "proxy", "", "`address:port` combination to forward connections to (-l required)")
	flag.BoolVar(&config.listen, "l", false, "listens for incoming connections")
	flag.BoolVar(&config.verbose, "v", false, "more verbose output")
	flag.BoolVar(&config.daemon, "k", false, "accepts multiple connections (-l && (-e || -proxy) required)")
	flag.StringVar(&config.srcPort, "p", "0", "source `port` to use")
	flag.StringVar(&config.srcHost, "s", "", "source `address` to use")
	flag.StringVar(&config.protocol, "proto", "Noise_NN_25519_AESGCM_SHA256", "`protocol name` to use")
	flag.StringVar(&config.psk, "psk", "", "`pre-shared key` to use (max 32 bytes)")
	flag.StringVar(&config.rStatic, "rstatic", "", "`static key` of the remote peer (32 bytes, hex-encoded)")
	flag.Parse()
	if !config.listen && flag.NArg() != 2 {
		flag.Usage()
		os.Exit(-1)
	} else {
		config.dstHost = flag.Arg(0)
		config.dstPort = flag.Arg(1)
	}
	return config
}

func main() {
	var err error

	config := parseFlags()

	if err = config.parseConfig(); err != nil {
		fatalf("%s", err)
	}

	if err = config.parseNoiseConfig(); err != nil {
		fatalf("%s", err)
	}

	nc := noisecat{
		config: &config,
	}

	if config.listen == false {
		nc.startClient()
	} else {
		nc.startServer()
	}
}
