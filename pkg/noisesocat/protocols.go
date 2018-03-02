package noisesocat

import (
	"errors"
	"regexp"

	"github.com/gedigi/noisesocket"
)

// ProtoInfo defines the struct with protocol options
type ProtoInfo struct {
	HandshakePatterns map[string]byte
	DHFuncs           map[string]byte
	CipherFuncs       map[string]byte
	HashFuncs         map[string]byte
}

// -- Protocol parsing
func (p *ProtoInfo) parseProtocol(protoName string) (byte, byte, byte, error) {
	var dh, cipher, hash byte
	var err error
	var ok bool
	regEx := regexp.MustCompile(`Noise_XX_(\w+)_(\w+)_(\w+)`)
	results := regEx.FindStringSubmatch(protoName)
	if len(results) == 4 {
		if dh, ok = p.DHFuncs[results[1]]; ok == false {
			err = errors.New("Invalid DH function")
			goto exit
		}
		if cipher, ok = p.CipherFuncs[results[2]]; ok == false {
			err = errors.New("Invalid cipher function")
			goto exit
		}
		if hash, ok = p.HashFuncs[results[3]]; ok == false {
			err = errors.New("Invalid hash function")
			goto exit
		}
		err = nil
	} else {
		err = errors.New("Invalid protocol name")
	}
exit:
	return dh, cipher, hash, err
}

var protocolInfo = ProtoInfo{
	DHFuncs:     dhFuncs,
	CipherFuncs: cipherFuncs,
	HashFuncs:   hashFuncs,
}

// -- DH functions
var dhFuncs = map[string]byte{
	"25519": noisesocket.NOISE_DH_CURVE25519,
}

// -- Cipher functions
var cipherFuncs = map[string]byte{
	"ChaChaPoly": noisesocket.NOISE_CIPHER_CHACHAPOLY,
	"AESGCM":     noisesocket.NOISE_CIPHER_AESGCM,
}

// -- Hash functions
var hashFuncs = map[string]byte{
	"BLAKE2s": noisesocket.NOISE_HASH_BLAKE2s,
	"BLAKE2b": noisesocket.NOISE_HASH_BLAKE2b,
	"SHA256":  noisesocket.NOISE_HASH_SHA256,
	"SHA512":  noisesocket.NOISE_HASH_SHA512,
}
