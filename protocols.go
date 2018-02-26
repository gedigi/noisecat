package main

import (
	"errors"
	"reflect"
	"regexp"

	"github.com/gedigi/noise"
)

type protoInfo struct {
	HandshakePatterns map[string]noise.HandshakePattern
	DHFuncs           map[string]noise.DHFunc
	CipherFuncs       map[string]noise.CipherFunc
	HashFuncs         map[string]noise.HashFunc
}

// -- Hash functions
var hashFuncs = map[string]noise.HashFunc{
	"SHA256":  noise.HashSHA256,
	"SHA512":  noise.HashSHA512,
	"BLAKE2b": noise.HashBLAKE2b,
	"BLAKE2s": noise.HashBLAKE2s,
}

// -- Protocol parsing
func (p *protoInfo) parseProtocol(protoName string) (noise.HandshakePattern, noise.DHFunc, noise.CipherFunc, noise.HashFunc, error) {
	var hs noise.HandshakePattern
	var dh noise.DHFunc
	var cipher noise.CipherFunc
	var hash noise.HashFunc
	var err error
	var ok bool
	regEx := regexp.MustCompile(`Noise_(\w{2})_(\w+)_(\w+)_(\w+)`)
	results := regEx.FindStringSubmatch(protoName)
	if len(results) == 5 {
		if hs, ok = p.getConfig("HandshakePatterns", results[1]).(noise.HandshakePattern); ok == false {
			err = errors.New("Invalid handshake pattern")
			goto exit
		}
		if dh, ok = p.getConfig("DHFuncs", results[2]).(noise.DHFunc); ok == false {
			err = errors.New("Invalid DH function")
			goto exit
		}
		if cipher, ok = p.getConfig("CipherFuncs", results[3]).(noise.CipherFunc); ok == false {
			err = errors.New("Invalid cipher function")
			goto exit
		}
		if hash, ok = p.getConfig("HashFuncs", results[4]).(noise.HashFunc); ok == false {
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

func (p *protoInfo) getConfig(field string, search string) interface{} {
	object := reflect.ValueOf(p)
	objectMap := reflect.Indirect(object).FieldByName(field)
	result := objectMap.MapIndex(reflect.ValueOf(search))
	if result.IsValid() == true {
		return result.Interface()
	}
	return nil
}

var protocolInfo = protoInfo{
	HandshakePatterns: handshakePatterns,
	DHFuncs:           dhFuncs,
	CipherFuncs:       cipherFuncs,
	HashFuncs:         hashFuncs,
}

// -- Handshake patterns
var handshakePatterns = map[string]noise.HandshakePattern{
	"NN": noise.HandshakeNN,
	// "KN": noise.HandshakeKN,
	"NK": noise.HandshakeNK,
	// "KK": noise.HandshakeKK,
	"NX": noise.HandshakeNX,
	// "KX": noise.HandshakeKX,
	"XN": noise.HandshakeXN,
	"IN": noise.HandshakeIN,
	"XK": noise.HandshakeXK,
	"IK": noise.HandshakeIK,
	"XX": noise.HandshakeXX,
	"IX": noise.HandshakeIX,
}

// -- DH functions
var dhFuncs = map[string]noise.DHFunc{
	"25519": noise.DH25519,
}

// -- Cipher functions
var cipherFuncs = map[string]noise.CipherFunc{
	"AESGCM":     noise.CipherAESGCM,
	"ChaChaPoly": noise.CipherChaChaPoly,
}
