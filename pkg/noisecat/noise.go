package noisecat

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/gedigi/noise"
)

// NoiseConfig is a noise configuration variable
type NoiseConfig noise.Config

// GetLocalStaticPublic returns the noise local static key forn
func (n *NoiseConfig) GetLocalStaticPublic() []byte {
	return n.StaticKeypair.Public
}

func (config *Configuration) parseNoise() (*noise.Config, error) {
	var err error
	config.Pattern, config.DHFunc, config.CipherFunc, config.HashFunc, err = parseProtocolName(config.Protocol)
	if err != nil {
		return nil, err
	}
	cs := noise.NewCipherSuite(
		DHByteObj[config.DHFunc],
		CipherByteObj[config.CipherFunc],
		HashByteObj[config.HashFunc],
	)
	noiseConf := &noise.Config{
		CipherSuite: cs,
		Random:      rand.Reader,
		Pattern:     PatternByteObj[config.Pattern],
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
