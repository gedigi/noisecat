package noisecat

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/gedigi/noise"
)

func TestClientServer(t *testing.T) {
	var ncClient, ncServer Noisecat

	tmpFile, _ := ioutil.TempFile("/tmp", "noisecat_")
	tmpFileName := tmpFile.Name()
	tmpFile.Close()
	os.Remove(tmpFileName)
	cmd := "touch " + tmpFileName

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA512)

	ncClient.Config = &Configuration{
		SrcPort: "0",
		DstHost: "127.0.0.1",
		DstPort: "12345",
		Verbose: true,
		Listen:  false,
		NoiseConfig: &noise.Config{
			Pattern:     noise.HandshakeNN,
			CipherSuite: cs,
			Random:      rand.Reader,
			Initiator:   true,
		},
	}
	ncServer.Config = &Configuration{
		SrcPort:    "12345",
		SrcHost:    "127.0.0.1",
		Verbose:    true,
		Listen:     true,
		ExecuteCmd: cmd,
		NoiseConfig: &noise.Config{
			Pattern:     noise.HandshakeNN,
			CipherSuite: cs,
			Random:      rand.Reader,
			Initiator:   false,
		},
	}

	go ncServer.StartServer()
	time.Sleep(2 * time.Second)
	go ncClient.StartClient()
	time.Sleep(2 * time.Second)

	_, err := os.Stat(tmpFileName)
	if os.IsNotExist(err) {
		t.Error(err)
	} else {
		os.Remove(tmpFileName)
	}

}
