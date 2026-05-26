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
	config.Pattern, config.DHFunc, config.CipherFunc, config.HashFunc, config.PSKPlacement, err = parseProtocolName(config.Protocol)
	if err != nil {
		return nil, err
	}
	// secp256k1 is implemented by the BOLT-8 transport directly and is not
	// a flynn/noise DH function. Skip the usual noise.CipherSuite assembly
	// and return a minimally-populated Config carrying only the keys —
	// pkg/transport/bolt8 reads cfg.StaticKeypair and cfg.PeerStatic from it.
	if config.DHFunc == NOISE_DH_SECP256K1 {
		noiseConf := &noise.Config{
			Random:    rand.Reader,
			Initiator: !config.Listen,
		}
		// Local static (32-byte secp256k1 private key) is mandatory for
		// every BOLT-8 endpoint.
		kp, err := loadSecp256k1Keypair(config.LStatic)
		if err != nil {
			return nil, err
		}
		noiseConf.StaticKeypair = kp
		// Remote static (33-byte compressed) is mandatory for the initiator
		// because XK has the responder static as a pre-message.
		if !config.Listen {
			if config.RStatic == "" {
				return nil, errors.New("BOLT-8 initiator requires -rstatic (33-byte compressed secp256k1 pubkey)")
			}
			rs, err := base64.StdEncoding.DecodeString(config.RStatic)
			if err != nil {
				return nil, fmt.Errorf("invalid -rstatic: %w", err)
			}
			if len(rs) != 33 {
				return nil, errors.New("-rstatic for secp256k1 must decode to 33 bytes (compressed)")
			}
			noiseConf.PeerStatic = rs
		}
		// Auto-select the bolt8 transport if the user has not picked one
		// explicitly. raw / noisesocket cannot speak BOLT-8 framing.
		if config.Transport == "" || config.Transport == "raw" {
			config.Transport = "bolt8"
		}
		return noiseConf, nil
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
		if config.PSKPlacement == noPSK {
			return nil, errors.New("-psk set but protocol has no psk modifier — use e.g. Noise_NKpsk2_25519_AESGCM_SHA256")
		}
		psk, err := base64.StdEncoding.DecodeString(config.PSK)
		if err != nil {
			return nil, errors.New("invalid PSK: must be base64-encoded")
		}
		if len(psk) != 32 {
			return nil, errors.New("PSK must decode to 32 bytes")
		}
		noiseConf.PresharedKey = psk
		noiseConf.PresharedKeyPlacement = int(config.PSKPlacement)
	} else if config.PSKPlacement != noPSK {
		return nil, fmt.Errorf("protocol %s has a psk modifier but -psk was not provided", config.Protocol)
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
