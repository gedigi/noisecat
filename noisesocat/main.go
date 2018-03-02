package main

import (
	"flag"
	"fmt"
	"os"
)

var version = "1.0"

func parseFlags() Configuration {
	var config Configuration

	flag.Usage = noisesocatUsage
	flag.StringVar(&config.executeCmd, "e", "", "Executes the given `command`")
	flag.StringVar(&config.proxy, "proxy", "", "`address:port` combination to forward connections to (-l required)")
	flag.BoolVar(&config.listen, "l", false, "listens for incoming connections")
	flag.BoolVar(&config.verbose, "v", false, "more verbose output")
	flag.BoolVar(&config.daemon, "k", false, "accepts multiple connections (-l && (-e || -proxy) required)")
	flag.StringVar(&config.srcPort, "p", "0", "source `port` to use")
	flag.StringVar(&config.srcHost, "s", "", "source `address` to use")
	flag.StringVar(&config.rStatic, "rstatic", "", "`static key` of the remote peer (32 bytes, base64)")
	flag.StringVar(&config.lStatic, "lstatic", "", "`file` containing local keypair (use -keygen to generate)")
	flag.BoolVar(&config.keygen, "keygen", false, "generates 25519 keypair and prints it to stdout")
	flag.StringVar(&config.dhFunc, "dhFunc", "25519", "`DH` function to use")
	flag.StringVar(&config.cipherFunc, "cipherFunc", "AESGCM", "`cipher` function to use")
	flag.StringVar(&config.hashFunc, "hashFunc", "SHA256", "`hash` function to use")

	flag.Parse()
	if config.keygen {
		return config
	}
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
	l = verbose(config.verbose)

	if err = config.parseConfig(); err != nil {
		l.fatalf("%s", err)
	}

	nc := noisesocat{
		config: &config,
	}

	if config.keygen {
		fmt.Printf("%s\n", nc.generateKeypair())
		os.Exit(0)
	}

	if config.listen == false {
		nc.startClient()
	} else {
		nc.startServer()
	}
}
