package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/gedigi/noisecat/pkg/noisecat"
)

// version is the default reported by `noisecat -h` when the binary is
// not built through goreleaser. Releases override this via
// `-ldflags '-X main.version=<tag>'` (see .goreleaser.yml). When
// bumping for a release, keep this in sync with the most recent tag
// so `go install` builds report a sensible value too.
var version = "1.1.0"

func parseFlags() noisecat.Config {
	// PSKPlacement's zero value (0) is a valid PSK placement index per
	// the Noise spec; initialize the field to the NoPSK sentinel so a
	// Config that never goes through parseProtocolName cannot
	// accidentally install a PSK at placement 0.
	config := noisecat.Config{PSKPlacement: noisecat.NoPSK}

	flag.Usage = usage
	flag.StringVar(&config.ExecuteCmd, "e", "", "executes the given `command`")
	flag.StringVar(&config.Proxy, "proxy", "", "forwards packets to `address:port` (-l required)")
	flag.BoolVar(&config.Listen, "l", false, "listens for incoming connections")
	flag.BoolVar(&config.Verbose, "v", false, "prints verbose output")
	flag.BoolVar(&config.Daemon, "k", false, "accepts multiple connections (-l && (-e || -proxy) required)")
	flag.StringVar(&config.SrcPort, "p", "0", "uses source `port`")
	flag.StringVar(&config.SrcHost, "s", "", "uses source `address`")
	flag.StringVar(&config.Protocol, "proto", "Noise_NN_25519_AESGCM_SHA256", "sets `protocol name`")
	flag.StringVar(&config.PSK, "psk", "", "uses `pre-shared key` in handshake")
	flag.StringVar(&config.RStatic, "rstatic", "", "defines remote `static key` (32 bytes, base64)")
	flag.StringVar(&config.LStatic, "lstatic", "", "loads local keypair from `file` (use -keygen to generate)")
	flag.BoolVar(&config.Keygen, "keygen", false, "generates \"-proto\" appropriate keypair and prints it to stdout")
	flag.StringVar(&config.Transport, "transport", "raw", "wire `transport`: raw (default), noisesocket, bolt8 (auto-selected for secp256k1), or whatsapp")
	flag.StringVar(&config.Prologue, "prologue", "", "application `prologue` mixed into the handshake hash")
	flag.StringVar(&config.NegotiationData, "negotiation", "", "NoiseSocket negotiation_`data` (only used with -transport noisesocket)")
	flag.StringVar(&config.Validate, "validate", "", "validate that the base64 `key` is well-formed for -proto's DH function, then exit")
	flag.BoolVar(&config.IPv4Only, "4", false, "use IPv4 only")
	flag.BoolVar(&config.IPv6Only, "6", false, "use IPv6 only")
	flag.IntVar(&config.TimeoutSeconds, "w", 0, "timeout in `seconds` for connect/handshake and idle connections (0 = none)")
	flag.StringVar(&config.NSFallback, "ns-fallback", "", "noisesocket client: comma-separated fallback `protocols` accepted on retry/switch")
	flag.StringVar(&config.NSSupport, "ns-support", "", "noisesocket listener: comma-separated supported `protocols` (enables negotiation)")
	flag.StringVar(&config.NSPolicy, "ns-policy", "", "noisesocket listener action on unsupported proposal: reject|retry|switch (default reject)")
	flag.Parse()
	if config.Keygen || config.Validate != "" {
		return config
	}
	if !config.Listen {
		// The whatsapp transport accepts either no address (connect to the
		// real WhatsApp backend) or a host+port (peer-to-peer to another
		// noisecat); other transports always require host+port.
		if config.Transport == "whatsapp" {
			switch flag.NArg() {
			case 0:
				// real WhatsApp backend, fixed endpoint
			case 2:
				config.DstHost = flag.Arg(0)
				config.DstPort = flag.Arg(1)
			default:
				fmt.Fprintln(os.Stderr, "noisecat: -transport whatsapp takes either no address (real backend) or host+port (peer-to-peer)")
				flag.Usage()
				os.Exit(2)
			}
		} else if flag.NArg() != 2 {
			flag.Usage()
			os.Exit(2)
		} else {
			config.DstHost = flag.Arg(0)
			config.DstPort = flag.Arg(1)
		}
	} else if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "noisecat: positional arguments are not used with -l")
		flag.Usage()
		os.Exit(2)
	}
	return config
}

func main() {
	var err error

	config := parseFlags()
	l := noisecat.Verbose(config.Verbose)

	if config.Validate != "" {
		if err := noisecat.ValidateStaticKeyForProtocol(config.Validate, config.Protocol); err != nil {
			fmt.Fprintf(os.Stderr, "noisecat: invalid key: %s\n", err)
			os.Exit(1)
		}
		fmt.Println("OK")
		os.Exit(0)
	}

	noiseConfig, err := config.ParseConfig()
	if err != nil {
		l.Fatalf("%s", err)
	}

	nc := noisecat.Noisecat{
		Config:      &config,
		Log:         l,
		NoiseConfig: noiseConfig,
	}

	if config.Keygen {
		var keypair []byte
		var err error
		if config.DHFunc == noisecat.NOISE_DH_SECP256K1 {
			keypair, err = noisecat.GenerateSecp256k1Keypair()
		} else {
			keypair, err = noisecat.GenerateKeypair(config.DHFunc, config.CipherFunc, config.HashFunc)
		}
		if err != nil {
			l.Fatalf("%s", err)
		}
		fmt.Printf("%s\n", keypair)
		os.Exit(0)
	}

	if !config.Listen {
		nc.StartClient()
	} else {
		nc.StartServer()
	}
}

func usage() {
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
	listDetails(noisecat.PatternStrByte)

	fmt.Print("Available DH functions:\n")
	listDetails(noisecat.DHStrByte)

	fmt.Print("Available Cipher functions:\n")
	listDetails(noisecat.CipherStrByte)

	fmt.Print("Available Hash functions:\n")
	listDetails(noisecat.HashStrByte)

	fmt.Print("Available transports:\n")
	fmt.Print("  raw, noisesocket, bolt8, whatsapp\n")
	fmt.Print("\n  bolt8 is auto-selected when -proto uses secp256k1 (Lightning BOLT-8).\n")
	fmt.Print("  whatsapp (no address) connects to WhatsApp's real backend (handshake +\n")
	fmt.Print("  certificate verification; no login). With -l or a host+port it peers two\n")
	fmt.Print("  noisecat instances over the WhatsApp wire protocol (e.g. -l -e /bin/sh).\n")
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
