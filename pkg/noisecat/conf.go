package noisecat

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

	Protocol string
	Pattern  noise.HandshakePattern
	DH       noise.DHFunc
	Cipher   noise.CipherFunc
	Hash     noise.HashFunc

	PSK     string
	RStatic string
	LStatic string

	NoiseConfig *noise.Config
}

// ParseConfig parses a configuration struct for setup and correctness
func (config *Configuration) ParseConfig() error {
	var err error

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

	config.NoiseConfig = new(noise.Config)

	config.Pattern, config.DH, config.Cipher, config.Hash, err = protocolInfo.parseProtocol(config.Protocol)
	if err != nil {
		return err
	}
	cs := noise.NewCipherSuite(config.DH, config.Cipher, config.Hash)
	config.NoiseConfig = &noise.Config{
		CipherSuite: cs,
		Random:      rand.Reader,
		Pattern:     config.Pattern,
		Initiator:   !config.Listen,
	}

	if config.PSK != "" {
		h := sha256.New()
		h.Write([]byte(config.PSK))
		config.NoiseConfig.PresharedKey = h.Sum(nil)
	}

	checkLocalKeypair := func() error {
		if config.LStatic != "" {
			k, err := ioutil.ReadFile(config.LStatic)
			if err != nil {
				return errors.New("Can't read keyfile")
			}
			json.Unmarshal(k, &config.NoiseConfig.StaticKeypair)
		} else {
			config.NoiseConfig.StaticKeypair, err = cs.GenerateKeypair(rand.Reader)
			if err != nil {
				return errors.New("Can't generate keys")
			}
		}
		return nil
	}

	checkRemoteStatic := func() error {
		if config.RStatic == "" {
			return errors.New("You need to provide the remote peer static key (-rstatic)")
		}
		decodedRStatic, err := base64.StdEncoding.DecodeString(config.RStatic)
		if err != nil {
			return errors.New("Invalid remote static key")
		}
		if len(decodedRStatic) != 32 {
			return errors.New("Remote static key needs to be 32 bytes")
		}
		config.NoiseConfig.PeerStatic = decodedRStatic
		return nil
	}

	if config.NoiseConfig.Initiator {
		switch config.NoiseConfig.Pattern.Name[0] {
		case 'X', 'I', 'K':
			if err = checkLocalKeypair(); err != nil {
				return err
			}
		}
		switch config.NoiseConfig.Pattern.Name[1] {
		case 'K':
			if err = checkRemoteStatic(); err != nil {
				return err
			}
		}
	} else {
		switch config.NoiseConfig.Pattern.Name[0] {
		case 'K':
			if err = checkRemoteStatic(); err != nil {
				return err
			}
		}
		switch config.NoiseConfig.Pattern.Name[1] {
		case 'X', 'K':
			if err = checkLocalKeypair(); err != nil {
				return err
			}
		}
	}
	return nil
}
