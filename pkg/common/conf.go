package common

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"regexp"

	"github.com/gedigi/noise"
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

// ParseConfig parses a configuration struct for setup and correctness
func (config *Configuration) ParseConfig() (interface{}, error) {
	var err error

	// Skip all the checks if I only have to generate a keypair
	if config.Keygen {
		return nil, nil
	}

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

func (config *Configuration) parseNoisesocket() (*noisesocket.ConnectionConfig, error) {
	_, dh, cipher, hash, err := parseProtocolName(config.Protocol)
	if err != nil {
		return nil, err
	}
	cs := noise.NewCipherSuite(DHByteObj[dh], CipherByteObj[cipher], HashByteObj[hash])
	noiseConf := &noisesocket.ConnectionConfig{
		IsClient:   !config.Listen,
		DHFunc:     dh,
		CipherFunc: cipher,
		HashFunc:   hash,
	}
	noiseConf.StaticKeypair, err = config.checkLocalKeypair(cs)
	if err != nil {
		return nil, err
	}
	return noiseConf, nil
}

func (config *Configuration) parseNoise() (*noise.Config, error) {
	pattern, dh, cipher, hash, err := parseProtocolName(config.Protocol)
	if err != nil {
		return nil, err
	}
	cs := noise.NewCipherSuite(DHByteObj[dh], CipherByteObj[cipher], HashByteObj[hash])
	noiseConf := &noise.Config{
		CipherSuite: cs,
		Random:      rand.Reader,
		Pattern:     PatternByteObj[pattern],
		Initiator:   !config.Listen,
	}

	if config.PSK != "" {
		h := sha256.New()
		h.Write([]byte(config.PSK))
		noiseConf.PresharedKey = h.Sum(nil)
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
		noiseConf.PeerStatic = decodedRStatic
		return nil
	}

	if noiseConf.Initiator {
		switch noiseConf.Pattern.Name[0] {
		case 'X', 'I', 'K':
			noiseConf.StaticKeypair, err = config.checkLocalKeypair(cs)
			if err != nil {
				return nil, err
			}
		}
		switch noiseConf.Pattern.Name[1] {
		case 'K':
			if err = checkRemoteStatic(); err != nil {
				return nil, err
			}
		}
	} else {
		switch noiseConf.Pattern.Name[0] {
		case 'K':
			if err = checkRemoteStatic(); err != nil {
				return nil, err
			}
		}
		switch noiseConf.Pattern.Name[1] {
		case 'X', 'K':
			noiseConf.StaticKeypair, err = config.checkLocalKeypair(cs)
			if err != nil {
				return nil, err
			}
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
		return keypair, nil
	}
	keypair, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		return noise.DHKey{}, errors.New("Can't generate keys")
	}
	return keypair, nil
}

func parseProtocolName(protoName string) (byte, byte, byte, byte, error) {
	var hs, dh, cipher, hash byte
	var err error
	var ok bool
	regEx := regexp.MustCompile(`Noise_(\w{2})_(\w+)_(\w+)_(\w+)`)
	results := regEx.FindStringSubmatch(protoName)
	if len(results) == 5 {
		if hs, ok = PatternStrByte[results[1]]; ok == false {
			err = errors.New("Invalid handshake pattern")
			goto exit
		}
		if dh, ok = DHStrByte[results[2]]; ok == false {
			err = errors.New("Invalid DH function")
			goto exit
		}
		if cipher, ok = CipherStrByte[results[3]]; ok == false {
			err = errors.New("Invalid cipher function")
			goto exit
		}
		if hash, ok = HashStrByte[results[4]]; ok == false {
			err = errors.New("Invalid hash function")
			goto exit
		}
		err = nil
	} else {
		err = errors.New("Invalid protocol name")
	}
exit:
	return hs, dh, cipher, hash, err
}
