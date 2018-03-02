package noisesocat

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/gedigi/noisesocket"
)

func TestClientServer(t *testing.T) {
	var ncClient, ncServer Noisesocat

	tmpFile, _ := ioutil.TempFile("/tmp", "noisesocat_")
	tmpFileName := tmpFile.Name()
	tmpFile.Close()
	os.Remove(tmpFileName)
	cmd := "touch " + tmpFileName

	clientKey, _ := keyGenerator()
	serverKey, _ := keyGenerator()

	ncClient.Config = &Configuration{
		SrcPort: "0",
		DstHost: "127.0.0.1",
		DstPort: "12345",
		Verbose: true,
		Listen:  false,
		NoiseConfig: &noisesocket.ConnectionConfig{
			IsClient:   true,
			DHFunc:     noisesocket.NOISE_DH_CURVE25519,
			CipherFunc: noisesocket.NOISE_CIPHER_AESGCM,
			HashFunc:   noisesocket.NOISE_HASH_SHA512,
			StaticKey:  clientKey,
		},
	}
	ncServer.Config = &Configuration{
		SrcPort:    "12345",
		SrcHost:    "127.0.0.1",
		Verbose:    true,
		Listen:     true,
		ExecuteCmd: cmd,
		NoiseConfig: &noisesocket.ConnectionConfig{
			IsClient:  false,
			DHFunc:    noisesocket.NOISE_DH_CURVE25519,
			StaticKey: serverKey,
		},
	}
	ncClient.L, ncServer.L = true, true

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
