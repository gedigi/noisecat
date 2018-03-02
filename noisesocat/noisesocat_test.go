package main

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/gedigi/noise"
	"github.com/gedigi/noisesocket"
)

func TestClientServer(t *testing.T) {
	var ncClient, ncServer noisesocat

	tmpFile, _ := ioutil.TempFile("/tmp", "noisesocat_")
	tmpFileName := tmpFile.Name()
	tmpFile.Close()
	os.Remove(tmpFileName)
	cmd := "touch " + tmpFileName

	ncClient.config = &Configuration{
		srcPort: "0",
		dstHost: "127.0.0.1",
		dstPort: "12345",
		verbose: true,
		listen:  false,
		noiseConfig: &noisesocket.ConnectionConfig{
			IsClient:   true,
			DHFunc:     noise.DH25519,
			CipherFunc: noise.CipherAESGCM,
			HashFunc:   noise.HashSHA256,
		},
	}
	ncServer.config = &Configuration{
		srcPort:    "12345",
		srcHost:    "127.0.0.1",
		verbose:    true,
		listen:     true,
		executeCmd: cmd,
		noiseConfig: &noisesocket.ConnectionConfig{
			IsClient: false,
			DHFunc:   noise.DH25519,
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
