package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"reflect"
	"strings"

	"github.com/gedigi/noise"
)

func showBanner() {
	fmt.Println("noisecat - the noise pipes swiss army knife")
	fmt.Println(" (c) Gerardo Di Giacomo 2018")
}

func noisecatUsage() {
	showBanner()
	fmt.Printf("\nUsage: %s [options] [address] [port]\n\n", os.Args[0])
	fmt.Println("Options:")
	flag.PrintDefaults()
	listSupportedProtocols()
}

func listSupportedProtocols() {
	fmt.Print("\nProtocol name format: Noise_PT_DH_CP_HS\n\n")
	fmt.Print(" e.g. Noise_NN_25519_AESGCM_SHA256\n\n")
	fmt.Print("Where:\n- PT: pattern\n- DH: Diffie-Helman handshake function\n")
	fmt.Print("- CP: Cipher function\n- HS: Hash function\n\n")

	fmt.Print("Available handshake patterns:\n")
	listDetails(protoInfo{HandshakePatterns: handshakePatterns}, "HandshakePatterns")

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
	for i, v := range objectMap.MapKeys() {
		fmt.Printf(" %s", v)
		if (i+1)%5 == 0 || i == objectMap.Len()-1 {
			fmt.Println()
		} else if i < objectMap.Len()-1 {
			fmt.Print(",")
		}
	}
	fmt.Println()
}

func executeCmd(command string, conn *noise.Conn) {
	var cmd *exec.Cmd

	cmdParse := strings.Split(command, " ")
	cmdName := cmdParse[0]
	var cmdArgs []string
	if len(cmdParse[1:]) > 0 {
		cmdArgs = cmdParse[1:]
	}
	cmd = exec.Command(cmdName, cmdArgs...)
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn
	cmd.Run()
}

func handleIO(conn *noise.Conn) {
	c := make(chan int64)
	var n int64
	var err error

	copy := func(reader io.ReadCloser, writer io.WriteCloser) {
		defer func() {
			reader.Close()
			writer.Close()
		}()

		if n, err = io.Copy(writer, reader); err != nil {
			fatalf("%s", err)
		}
		c <- n
	}

	go copy(conn, os.Stdout)
	go copy(os.Stdin, conn)

	var s int64
	s = <-c
	verb("SNT:%d", s)
	s = <-c
	verb("RCV:%d", s)
}

// Logging
func verb(format string, v ...interface{}) {
	if config.verbose == true {
		log.Printf(format, v...)
	}
}

func fatalf(format string, v ...interface{}) {
	log.Fatalf("ERROR: "+format, v...)
}
