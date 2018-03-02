package main

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/gedigi/noise"
)

func TestClientServer(t *testing.T) {
	var ncClient, ncServer noisesocat

	tmpFile, _ := ioutil.TempFile("/tmp", "noisesocat_")
	tmpFileName := tmpFile.Name()
	tmpFile.Close()
	os.Remove(tmpFileName)
	cmd := "touch " + tmpFileName

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA512)

	ncClient.config = &Configuration{
		srcPort: "0",
		dstHost: "127.0.0.1",
		dstPort: "12345",
		verbose: true,
		listen:  false,
		noiseConfig: &noise.Config{
			Pattern:     noise.HandshakeNN,
			CipherSuite: cs,
			Random:      rand.Reader,
			Initiator:   true,
		},
	}
	ncServer.config = &Configuration{
		srcPort:    "12345",
		srcHost:    "127.0.0.1",
		verbose:    true,
		listen:     true,
		executeCmd: cmd,
		noiseConfig: &noise.Config{
			Pattern:     noise.HandshakeNN,
			CipherSuite: cs,
			Random:      rand.Reader,
			Initiator:   false,
		},
	}

	go ncServer.startServer()
	time.Sleep(2 * time.Second)
	go ncClient.startClient()
	time.Sleep(2 * time.Second)

	_, err := os.Stat(tmpFileName)
	if os.IsNotExist(err) {
		t.Error(err)
	} else {
		os.Remove(tmpFileName)
	}

}
