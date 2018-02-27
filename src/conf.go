package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"

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

	protocol string
	pattern  noise.HandshakePattern
	dh       noise.DHFunc
	cipher   noise.CipherFunc
	hash     noise.HashFunc

	psk     string
	rStatic string

	noiseConfig *noise.Config
}

func (config *Configuration) parseConfig() error {
	var err error

	config.pattern, config.dh, config.cipher, config.hash, err = protocolInfo.parseProtocol(config.protocol)
	if err != nil {
		return err
	}

	if config.psk != "" {
		if len(config.psk) > 32 {
			return errors.New("Pre-shared key can be 32 bytes maximum")
		} else if len(config.psk) < 32 {
			config.psk += strings.Repeat("\x00", 32-len(config.psk))
		}
	}

	if config.rStatic != "" {
		if len(config.rStatic) != 64 {
			return errors.New("Remote static key needs to be 32 bytes")
		}
		rStatic, err := hex.DecodeString(config.rStatic)
		if err != nil {
			return errors.New("Invalid remote static key")
		}
		config.rStatic = string(rStatic)
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
	return nil
}

func (config *Configuration) parseNoiseConfig() error {
	var err error

	cs := noise.NewCipherSuite(config.dh, config.cipher, config.hash)
	config.noiseConfig = &noise.Config{
		CipherSuite: cs,
		Random:      rand.Reader,
		Pattern:     config.pattern,
		Initiator:   !config.listen,
	}

	if config.psk != "" {
		config.noiseConfig.PresharedKey = []byte(config.psk)
	}
	if config.noiseConfig.Initiator {
		switch config.noiseConfig.Pattern.Name[0] {
		case 'X', 'I', 'K':
			config.noiseConfig.StaticKeypair, err = cs.GenerateKeypair(rand.Reader)
			if err != nil {
				return errors.New("Can't generate keys")
			}
		}
		switch config.noiseConfig.Pattern.Name[1] {
		case 'K':
			if config.rStatic == "" {
				return errors.New("You need to provide the remote peer static key (-rstatic)")
			}
			config.noiseConfig.PeerStatic = []byte(config.rStatic)
		}
	} else {
		switch config.noiseConfig.Pattern.Name[0] {
		case 'K':
			if config.rStatic == "" {
				return errors.New("You need to provide the remote peer static key (-rstatic)")
			}
			config.noiseConfig.PeerStatic = []byte(config.rStatic)
		}
		switch config.noiseConfig.Pattern.Name[1] {
		case 'X', 'K':
			config.noiseConfig.StaticKeypair, err = cs.GenerateKeypair(rand.Reader)
			if err != nil {
				return errors.New("Can't generate keys")
			}
		}
	}
	return nil
}
