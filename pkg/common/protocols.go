package common

import "github.com/gedigi/noise"

const (
	NOISE_DH_CURVE25519 = 1
	NOISE_DH_CURVE448   = 2

	NOISE_CIPHER_CHACHAPOLY = 1
	NOISE_CIPHER_AESGCM     = 2

	NOISE_HASH_BLAKE2s = 1
	NOISE_HASH_BLAKE2b = 2
	NOISE_HASH_SHA256  = 3
	NOISE_HASH_SHA512  = 4

	NOISE_PATTERN_NN = 4
	NOISE_PATTERN_NK = 5
	NOISE_PATTERN_NX = 6
	NOISE_PATTERN_XN = 7
	NOISE_PATTERN_XK = 8
	NOISE_PATTERN_XX = 9
	NOISE_PATTERN_KN = 10
	NOISE_PATTERN_KK = 11
	NOISE_PATTERN_KX = 12
	NOISE_PATTERN_IN = 13
	NOISE_PATTERN_IK = 14
	NOISE_PATTERN_IX = 15
)

// DH Funcs
var DHStrByte = map[string]byte{
	"25519": NOISE_DH_CURVE25519,
	// "448":   NOISE_DH_CURVE448,
}

var DHByteObj = map[byte]noise.DHFunc{
	NOISE_DH_CURVE25519: noise.DH25519,
}

// Hash Funcs
var HashStrByte = map[string]byte{
	"BLAKE2s": NOISE_HASH_BLAKE2s,
	"BLAKE2b": NOISE_HASH_BLAKE2b,
	"SHA256":  NOISE_HASH_SHA256,
	"SHA512":  NOISE_HASH_SHA512,
}

var HashByteObj = map[byte]noise.HashFunc{
	NOISE_HASH_BLAKE2s: noise.HashBLAKE2s,
	NOISE_HASH_BLAKE2b: noise.HashBLAKE2b,
	NOISE_HASH_SHA256:  noise.HashSHA256,
	NOISE_HASH_SHA512:  noise.HashSHA512,
}

// Cipher Funcs
var CipherStrByte = map[string]byte{
	"ChaChaPoly": NOISE_CIPHER_CHACHAPOLY,
	"AESGCM":     NOISE_CIPHER_AESGCM,
}

var CipherByteObj = map[byte]noise.CipherFunc{
	NOISE_CIPHER_CHACHAPOLY: noise.CipherChaChaPoly,
	NOISE_CIPHER_AESGCM:     noise.CipherAESGCM,
}

// Handshake Patterns
var PatternStrByte = map[string]byte{
	"NN": NOISE_PATTERN_NN,
	"NL": NOISE_PATTERN_NK,
	"NX": NOISE_PATTERN_NX,
	"XN": NOISE_PATTERN_XN,
	"XK": NOISE_PATTERN_XK,
	"XX": NOISE_PATTERN_XX,
	"KN": NOISE_PATTERN_KN,
	"KK": NOISE_PATTERN_KK,
	"KX": NOISE_PATTERN_KX,
	"IN": NOISE_PATTERN_IN,
	"IK": NOISE_PATTERN_IK,
	"IX": NOISE_PATTERN_IX,
}
var PatternByteObj = map[byte]noise.HandshakePattern{
	NOISE_PATTERN_NN: noise.HandshakeNN,
	NOISE_PATTERN_NK: noise.HandshakeNK,
	NOISE_PATTERN_NX: noise.HandshakeNX,
	NOISE_PATTERN_XN: noise.HandshakeXN,
	NOISE_PATTERN_XK: noise.HandshakeXK,
	NOISE_PATTERN_XX: noise.HandshakeXX,
	NOISE_PATTERN_KN: noise.HandshakeKN,
	NOISE_PATTERN_KK: noise.HandshakeKK,
	NOISE_PATTERN_KX: noise.HandshakeKX,
	NOISE_PATTERN_IN: noise.HandshakeIN,
	NOISE_PATTERN_IK: noise.HandshakeIK,
	NOISE_PATTERN_IX: noise.HandshakeIX,
}
