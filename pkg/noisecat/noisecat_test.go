package noisecat

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/gedigi/noise"
	"github.com/gedigi/noisesocket"
)

func TestClientServerNoise(t *testing.T) {
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
	}
	ncClient.NoiseConfig = &NoiseConfig{
		Pattern:     noise.HandshakeNN,
		CipherSuite: cs,
		Random:      rand.Reader,
		Initiator:   true,
	}
	ncServer.Config = &Configuration{
		SrcPort:    "12345",
		SrcHost:    "127.0.0.1",
		Verbose:    true,
		Listen:     true,
		ExecuteCmd: cmd,
	}
	ncServer.NoiseConfig = &NoiseConfig{
		Pattern:     noise.HandshakeNN,
		CipherSuite: cs,
		Random:      rand.Reader,
		Initiator:   false,
	}

	ncClient.Log, ncServer.Log = true, true

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

func TestClientServerNoisesocket(t *testing.T) {
	var ncClient, ncServer Noisecat

	tmpFile, _ := ioutil.TempFile("/tmp", "noisesocat_")
	tmpFileName := tmpFile.Name()
	tmpFile.Close()
	os.Remove(tmpFileName)
	cmd := "touch " + tmpFileName

	cs := noise.NewCipherSuite(
		DHByteObj[NOISE_DH_CURVE25519],
		CipherByteObj[NOISE_CIPHER_CHACHAPOLY],
		HashByteObj[NOISE_HASH_BLAKE2b],
	)

	clientKey, _ := cs.GenerateKeypair(rand.Reader)
	serverKey, _ := cs.GenerateKeypair(rand.Reader)

	ncClient.Config = &Configuration{
		SrcPort: "0",
		DstHost: "127.0.0.1",
		DstPort: "12345",
		Verbose: true,
		Listen:  false,
	}
	ncClient.NoiseConfig = &NoisesocketConfig{
		IsClient:      true,
		DHFunc:        NOISE_DH_CURVE25519,
		CipherFunc:    NOISE_CIPHER_CHACHAPOLY,
		HashFunc:      NOISE_HASH_BLAKE2b,
		StaticKeypair: clientKey,
	}
	ncServer.Config = &Configuration{
		SrcPort:    "12345",
		SrcHost:    "127.0.0.1",
		Verbose:    true,
		Listen:     true,
		ExecuteCmd: cmd,
	}
	ncServer.NoiseConfig = &NoisesocketConfig{
		IsClient:      false,
		DHFunc:        noisesocket.NOISE_DH_CURVE25519,
		StaticKeypair: serverKey,
	}

	ncClient.Log, ncServer.Log = true, true

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
