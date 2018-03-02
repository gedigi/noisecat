package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"github.com/gedigi/noisesocket"
)

// Configuration parameters
type Configuration struct {
	srcPort string
	srcHost string
	dstPort string
	dstHost string

	executeCmd string
	proxy      string
	listen     bool
	verbose    bool
	daemon     bool
	keygen     bool

	psk     string
	rStatic string
	lStatic string

	dhFunc     string
	cipherFunc string
	hashFunc   string

	noiseConfig *noisesocket.ConnectionConfig
}

func (config *Configuration) parseConfig() error {
	var err error

	config.noiseConfig = &noisesocket.ConnectionConfig{}

	// Skip all the checks if I only have to generate a keypair
	if config.keygen {
		return nil
	}

	if config.daemon {
		if !config.listen {
			return errors.New("-k requires -l")
		}
		if config.proxy == "" && config.executeCmd == "" {
			return errors.New("-k requires -proxy or -e")
		}
	}
	if config.proxy != "" && !config.listen {
		return errors.New("Client mode doesn't support -proxy")
	}

	checkLocalStatic := func() error {
		if config.lStatic != "" {
			if _, err := os.Stat(config.lStatic); os.IsNotExist(err) {
				return errors.New("File doesn't exist")
			}
			k, err := ioutil.ReadFile(config.lStatic)
			if err != nil {
				return errors.New("Can't read keyfile")
			}
			json.Unmarshal(k, &config.noiseConfig.StaticKey)
		} else {
			config.noiseConfig.StaticKey, err = keyGenerator()
			if err != nil {
				return errors.New("Can't generate keys")
			}
		}
		return nil
	}
	checkLocalStatic()

	return nil
}
