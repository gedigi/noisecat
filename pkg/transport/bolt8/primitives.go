// Package bolt8 implements Lightning Network's BOLT-8 transport
// (https://github.com/lightning/bolts/blob/master/08-transport.md)
// directly from primitives: secp256k1 ECDH, HKDF-SHA256, ChaCha20-Poly1305.
//
// The BOLT-8 wire format diverges from generic Noise framings (fixed-size
// acts with a 1-byte version prefix, encrypted length headers, per-direction
// rekey every 1000 messages), so we drive the protocol from the spec rather
// than through flynn/noise's HandshakeState abstraction.
package bolt8

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Protocol constants per BOLT-8 §2.1.
const (
	protocolName  = "Noise_XK_secp256k1_ChaChaPoly_SHA256"
	prologue      = "lightning"
	macSize       = chacha20poly1305.Overhead // 16
	rekeyInterval = 1000
	// MaxMessageLen is the largest plaintext body BOLT-8 will frame.
	MaxMessageLen = 65535
)

// mixHash sets h = SHA256(h || data).
func mixHash(h *[32]byte, data []byte) {
	s := sha256.New()
	s.Write(h[:])
	s.Write(data)
	copy(h[:], s.Sum(nil))
}

// hkdfExpand performs BOLT-8's HKDF call: HKDF-SHA256(salt=ck, ikm=ikm,
// info=nil), returns the first 64 bytes split into a new chaining key
// and a new derived key.
func hkdfExpand(ck [32]byte, ikm []byte) (newCK, newK [32]byte) {
	r := hkdf.New(sha256.New, ikm, ck[:], nil)
	var buf [64]byte
	_, _ = io.ReadFull(r, buf[:])
	copy(newCK[:], buf[:32])
	copy(newK[:], buf[32:])
	return newCK, newK
}

// ecdh computes BOLT-8's ECDH: SHA-256 of the compressed shared point.
// priv * pub on the secp256k1 curve, then SHA-256 the 33-byte compressed
// serialization of the resulting point.
func ecdh(priv *secp256k1.PrivateKey, pub *secp256k1.PublicKey) []byte {
	var pubJ secp256k1.JacobianPoint
	pub.AsJacobian(&pubJ)
	var sharedJ secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(&priv.Key, &pubJ, &sharedJ)
	sharedJ.ToAffine()
	compressed := compressPoint(&sharedJ.X, &sharedJ.Y)
	sum := sha256.Sum256(compressed)
	return sum[:]
}

// compressPoint serializes a (normalized) affine (x, y) field-value pair
// into the 33-byte SEC1 compressed form. Mirrors PublicKey.SerializeCompressed.
func compressPoint(x, y *secp256k1.FieldVal) []byte {
	x.Normalize()
	y.Normalize()
	out := make([]byte, 33)
	if y.IsOdd() {
		out[0] = 0x03
	} else {
		out[0] = 0x02
	}
	xb := x.Bytes()
	copy(out[1:], xb[:])
	return out
}

// nonceLE encodes BOLT-8's 96-bit nonce: 32 leading zero bits followed by
// the 64-bit little-endian counter.
func nonceLE(n uint64) [12]byte {
	var b [12]byte
	binary.LittleEndian.PutUint64(b[4:], n)
	return b
}

// encryptWithAD is BOLT-8's encryptWithAD: ChaCha20-Poly1305 with the
// little-endian-encoded counter as nonce.
func encryptWithAD(key [32]byte, n uint64, ad, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	nonce := nonceLE(n)
	return aead.Seal(nil, nonce[:], plaintext, ad), nil
}

// decryptWithAD inverts encryptWithAD; returns plaintext or an error on
// authentication failure.
func decryptWithAD(key [32]byte, n uint64, ad, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	nonce := nonceLE(n)
	return aead.Open(nil, nonce[:], ciphertext, ad)
}

// initialState computes the BOLT-8 initial (h, ck) per §2.1.
// Both peers MUST arrive at identical (h, ck) values to handshake.
func initialState(localStaticPub, remoteStaticPub []byte, isInitiator bool) (h, ck [32]byte) {
	h = sha256.Sum256([]byte(protocolName))
	ck = h
	mixHash(&h, []byte(prologue))
	if isInitiator {
		mixHash(&h, remoteStaticPub)
	} else {
		mixHash(&h, localStaticPub)
	}
	return h, ck
}

