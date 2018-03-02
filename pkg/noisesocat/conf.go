package noisesocat

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"github.com/gedigi/noisesocket"
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

	PSK     string
	RStatic string
	LStatic string

	DHFunc     string
	CipherFunc string
	HashFunc   string

	NoiseConfig *noisesocket.ConnectionConfig
}

// ParseConfig parses a configuration struct for setup and correctness
func (config *Configuration) ParseConfig() error {
	var err error

	config.NoiseConfig = new(noisesocket.ConnectionConfig)

	config.NoiseConfig.DHFunc, config.NoiseConfig.CipherFunc, config.NoiseConfig.HashFunc, err =
		protocolInfo.parseProtocol("Noise_XX_" + config.DHFunc + "_" + config.CipherFunc + "_" + config.HashFunc)
	if err != nil {
		return err
	}

	// Skip all the checks if I only have to generate a keypair
	if config.Keygen {
		return nil
	}

	if config.Daemon {
		if !config.Listen {
			return errors.New("-k requires -l")
		}
		if config.Proxy == "" && config.ExecuteCmd == "" {
			return errors.New("-k requires -proxy or -e")
		}
	}
	if config.Proxy != "" && !config.Listen {
		return errors.New("Client mode doesn't support -proxy")
	}

	checkLocalStatic := func() error {
		if config.LStatic != "" {
			if _, err := os.Stat(config.LStatic); os.IsNotExist(err) {
				return errors.New("File doesn't exist")
			}
			k, err := ioutil.ReadFile(config.LStatic)
			if err != nil {
				return errors.New("Can't read keyfile")
			}
			json.Unmarshal(k, &config.NoiseConfig.StaticKey)
		} else {
			config.NoiseConfig.StaticKey, err = keyGenerator()
			if err != nil {
				return errors.New("Can't generate keys")
			}
		}
		return nil
	}
	checkLocalStatic()

	return nil
}
