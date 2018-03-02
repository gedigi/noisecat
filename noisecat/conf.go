package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"

	"github.com/gedigi/noise"
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

	protocol string
	pattern  noise.HandshakePattern
	dh       noise.DHFunc
	cipher   noise.CipherFunc
	hash     noise.HashFunc

	psk     string
	rStatic string
	lStatic string

	noiseConfig *noise.Config
}

func (config *Configuration) parseConfig() error {
	var err error

	config.noiseConfig = &noise.Config{}

	config.pattern, config.dh, config.cipher, config.hash, err = protocolInfo.parseProtocol(config.protocol)
	if err != nil {
		return err
	}

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

	cs := noise.NewCipherSuite(config.dh, config.cipher, config.hash)
	config.noiseConfig = &noise.Config{
		CipherSuite: cs,
		Random:      rand.Reader,
		Pattern:     config.pattern,
		Initiator:   !config.listen,
	}

	if config.psk != "" {
		h := sha256.New()
		h.Write([]byte(config.psk))
		config.noiseConfig.PresharedKey = h.Sum(nil)
	}

	checkLocalKeypair := func() error {
		if config.lStatic != "" {
			k, err := ioutil.ReadFile(config.lStatic)
			if err != nil {
				return errors.New("Can't read keyfile")
			}
			json.Unmarshal(k, &config.noiseConfig.StaticKeypair)
		} else {
			config.noiseConfig.StaticKeypair, err = cs.GenerateKeypair(rand.Reader)
			if err != nil {
				return errors.New("Can't generate keys")
			}
		}
		return nil
	}

	checkRemoteStatic := func() error {
		if config.rStatic == "" {
			return errors.New("You need to provide the remote peer static key (-rstatic)")
		}
		decodedRStatic, err := base64.StdEncoding.DecodeString(config.rStatic)
		if err != nil {
			return errors.New("Invalid remote static key")
		}
		if len(decodedRStatic) != 32 {
			return errors.New("Remote static key needs to be 32 bytes")
		}
		config.noiseConfig.PeerStatic = decodedRStatic
		return nil
	}

	if config.noiseConfig.Initiator {
		switch config.noiseConfig.Pattern.Name[0] {
		case 'X', 'I', 'K':
			if err = checkLocalKeypair(); err != nil {
				return err
			}
		}
		switch config.noiseConfig.Pattern.Name[1] {
		case 'K':
			if err = checkRemoteStatic(); err != nil {
				return err
			}
		}
	} else {
		switch config.noiseConfig.Pattern.Name[0] {
		case 'K':
			if err = checkRemoteStatic(); err != nil {
				return err
			}
		}
		switch config.noiseConfig.Pattern.Name[1] {
		case 'X', 'K':
			if err = checkLocalKeypair(); err != nil {
				return err
			}
		}
	}
	return nil
}
