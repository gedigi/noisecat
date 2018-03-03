package noisesocat

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/gedigi/noisecat/pkg/common"

	"github.com/gedigi/noise"
	"github.com/gedigi/noisesocket"
)

func TestClientServer(t *testing.T) {
	var ncClient, ncServer Noisesocat

	tmpFile, _ := ioutil.TempFile("/tmp", "noisesocat_")
	tmpFileName := tmpFile.Name()
	tmpFile.Close()
	os.Remove(tmpFileName)
	cmd := "touch " + tmpFileName

	cs := noise.NewCipherSuite(
		common.DHByteObj[common.NOISE_DH_CURVE25519],
		common.CipherByteObj[common.NOISE_CIPHER_CHACHAPOLY],
		common.HashByteObj[common.NOISE_HASH_BLAKE2b],
	)

	clientKey, _ := cs.GenerateKeypair(rand.Reader)
	serverKey, _ := cs.GenerateKeypair(rand.Reader)

	ncClient.Config = &common.Configuration{
		SrcPort: "0",
		DstHost: "127.0.0.1",
		DstPort: "12345",
		Verbose: true,
		Listen:  false,
	}
	ncClient.NoiseConfig = &noisesocket.ConnectionConfig{
		IsClient:      true,
		DHFunc:        common.NOISE_DH_CURVE25519,
		CipherFunc:    common.NOISE_CIPHER_CHACHAPOLY,
		HashFunc:      common.NOISE_HASH_BLAKE2b,
		StaticKeypair: clientKey,
	}
	ncServer.Config = &common.Configuration{
		SrcPort:    "12345",
		SrcHost:    "127.0.0.1",
		Verbose:    true,
		Listen:     true,
		ExecuteCmd: cmd,
	}
	ncServer.NoiseConfig = &noisesocket.ConnectionConfig{
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
