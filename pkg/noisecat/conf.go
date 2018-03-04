package noisecat

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/ioutil"

	"github.com/gedigi/noise"
)

// Configuration parameters
type Configuration struct {
	SrcPort string
	SrcHost string
	DstPort string
	DstHost string

	ExecuteCmd string
	Proxy      string
	Listen     bool
	Verbose    bool
	Daemon     bool
	Keygen     bool

	Protocol   string
	Pattern    byte
	DHFunc     byte
	CipherFunc byte
	HashFunc   byte

	PSK     string
	RStatic string
	LStatic string

	Framework string
}

// NoiseInterface intrfaces with noise or noisesocket configurations
type NoiseInterface interface {
	GetLocalStaticPublic() []byte
}

// ParseConfig parses a configuration struct for setup and correctness
func (config *Configuration) ParseConfig() (interface{}, error) {
	var err error

	if config.Daemon {
		if !config.Listen {
			return nil, errors.New("-k requires -l")
		}
		if config.Proxy == "" && config.ExecuteCmd == "" {
			return nil, errors.New("-k requires -proxy or -e")
		}
	}
	if config.Proxy != "" && !config.Listen {
		return nil, errors.New("Client mode doesn't support -proxy")
	}

	var noiseConf interface{}
	if config.Framework == "noise" {
		noiseConf, err = config.parseNoise()
		if err != nil {
			return nil, err
		}
	} else {
		noiseConf, err = config.parseNoisesocket()
		if err != nil {
			return nil, err
		}
	}
	return noiseConf, nil
}

func (config *Configuration) checkLocalKeypair(cs noise.CipherSuite) (noise.DHKey, error) {
	var keypair noise.DHKey
	if config.LStatic != "" {
		k, err := ioutil.ReadFile(config.LStatic)
		if err != nil {
			return noise.DHKey{}, errors.New("Can't read keyfile")
		}
		json.Unmarshal(k, &keypair)
		if keypair.Public == nil {
			return noise.DHKey{}, errors.New("Can't load keypair")
		}
		return keypair, nil
	}
	keypair, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		return noise.DHKey{}, errors.New("Can't generate keys")
	}
	return keypair, nil
}
