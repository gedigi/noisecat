package noisecat

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/ioutil"

	"github.com/flynn/noise"
)

// Config parameters
type Config struct {
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
}

// NoiseInterface intrfaces with noise configurations
type NoiseInterface interface {
	GetLocalStaticPublic() []byte
}

// ParseConfig parses a configuration struct for setup and correctness
func (config *Config) ParseConfig() (*noise.Config, error) {

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

	return config.parseNoise()
}

func (config *Config) checkLocalKeypair(cs noise.CipherSuite) (noise.DHKey, error) {
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
	return cs.GenerateKeypair(rand.Reader)
}
