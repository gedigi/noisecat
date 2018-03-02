package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"reflect"

	"github.com/gedigi/noise"
)

// -- Help/Usage
func noisesocatUsage() {
	showBanner()
	fmt.Printf("\nUsage: %s [options] [address] [port]\n\n", os.Args[0])
	fmt.Println("Options:")
	flag.PrintDefaults()
	listSupportedProtocols()
}

func showBanner() {
	fmt.Println()
	fmt.Printf("noisesocat %s - the noise swiss army knife\n", version)
	fmt.Println(" (c) Gerardo Di Giacomo 2018")
}

func listSupportedProtocols() {
	fmt.Print("\nProtocol name format: Noise_PT_DH_CP_HS\n\n")
	fmt.Print("Where:\n  PT: Handshake pattern\n  DH: Diffie-Hellman handshake function\n")
	fmt.Print("  CP: Cipher function\n  HS: Hash function\n\n")
	fmt.Print("  e.g. Noise_NN_25519_AESGCM_SHA256\n\n")

	fmt.Print("Available DH functions:\n")
	listDetails(protoInfo{DHFuncs: dhFuncs}, "DHFuncs")

	fmt.Print("Available Cipher functions:\n")
	listDetails(protoInfo{CipherFuncs: cipherFuncs}, "CipherFuncs")

	fmt.Print("Available Hash functions:\n")
	listDetails(protoInfo{HashFuncs: hashFuncs}, "HashFuncs")
}

func listDetails(p protoInfo, field string) {
	object := reflect.ValueOf(p)
	objectMap := reflect.Indirect(object).FieldByName(field)
	fmt.Print(" ")
	for i, v := range objectMap.MapKeys() {
		fmt.Printf(" %s", v)
		if (i+1)%5 == 0 || i == objectMap.Len()-1 {
			fmt.Print("\n ")
		} else if i < objectMap.Len()-1 {
			fmt.Print(",")
		}
	}
	fmt.Println()
}

// -- Logging

var l verbose

type verbose bool

func (l verbose) verb(format string, v ...interface{}) {
	if l == true {
		log.Printf(format, v...)
	}
}

func (l verbose) fatalf(format string, v ...interface{}) {
	if l == true {
		log.Printf(format, v...)
	}
	os.Exit(1)
}

// -- Progress struct
type progress struct {
	bytes int64
	dir   string
}

// -- Key Generator
func keyGenerator() (noise.DHKey, error) {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashBLAKE2b)
	keypair, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		return noise.DHKey{}, err
	}
	return keypair, nil
}
