package noisecat

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/flynn/noise"
)

func (config *Config) parseNoise() (*noise.Config, error) {
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
		psk, err := base64.StdEncoding.DecodeString(config.PSK)
		if err != nil {
			return nil, errors.New("invalid PSK: must be base64-encoded")
		}
		if len(psk) != 32 {
			return nil, errors.New("PSK must decode to 32 bytes")
		}
		noiseConf.PresharedKey = psk
	}

	checkRemoteStatic := func() error {
		if config.RStatic == "" {
			return errors.New("remote peer static key required (-rstatic)")
		}
		decodedRStatic, err := base64.StdEncoding.DecodeString(config.RStatic)
		if err != nil {
			return fmt.Errorf("invalid remote static key: %w", err)
		}
		if len(decodedRStatic) != 32 {
			return errors.New("remote static key must be 32 bytes")
		}
		noiseConf.PeerStatic = decodedRStatic
		return nil
	}

	// Each Noise pattern's two-letter name encodes which side contributes a static key:
	// Name[0] = initiator's role, Name[1] = responder's role. 'N' = no static,
	// 'K' = known beforehand (remote static expected), 'X' = transmitted in handshake,
	// 'I' = transmitted immediately.
	patternName := noiseConf.Pattern.Name
	if len(patternName) < 2 {
		return nil, fmt.Errorf("unsupported pattern: %s", patternName)
	}
	if noiseConf.Initiator {
		switch patternName[0] {
		case 'X', 'I', 'K':
			if noiseConf.StaticKeypair, err = config.checkLocalKeypair(cs); err != nil {
				return nil, err
			}
		}
		if patternName[1] == 'K' {
			if err = checkRemoteStatic(); err != nil {
				return nil, err
			}
		}
	} else {
		if patternName[0] == 'K' {
			if err = checkRemoteStatic(); err != nil {
				return nil, err
			}
		}
		switch patternName[1] {
		case 'X', 'K':
			if noiseConf.StaticKeypair, err = config.checkLocalKeypair(cs); err != nil {
				return nil, err
			}
		}
	}
	return noiseConf, nil
}
