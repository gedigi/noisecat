package whatsapp

import (
	"crypto/rand"
	"crypto/sha512"
	"strings"
	"testing"
	"time"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
)

// fixedRandom is a deterministic "random" input for XEdDSA signing in tests
// (the value only hedges the signature; verification is independent of it).
var fixedRandom = func() [64]byte {
	var r [64]byte
	for i := range r {
		r[i] = 0x42
	}
	return r
}()

// xeddsaSign is the signing counterpart of xeddsaVerify, ported from
// go.mau.fi/libsignal's ecc.sign. Used only by tests to mint cert chains.
func xeddsaSign(privateKey *[32]byte, message []byte, random [64]byte) [64]byte {
	var A edwards25519.Point
	privScalar, _ := edwards25519.NewScalar().SetBytesWithClamping(privateKey[:])
	A.ScalarBaseMult(privScalar)
	publicKey := *(*[32]byte)(A.Bytes())

	diversifier := [32]byte{0xFE}
	for i := 1; i < 32; i++ {
		diversifier[i] = 0xFF
	}

	hash := sha512.New()
	hash.Write(diversifier[:])
	hash.Write(privateKey[:])
	hash.Write(message)
	hash.Write(random[:])
	var r [64]byte
	hash.Sum(r[:0])
	rReduced, _ := edwards25519.NewScalar().SetUniformBytes(r[:])
	var R edwards25519.Point
	R.ScalarBaseMult(rReduced)
	encodedR := *(*[32]byte)(R.Bytes())

	hash.Reset()
	hash.Write(encodedR[:])
	hash.Write(publicKey[:])
	hash.Write(message)
	var hramDigest [64]byte
	hash.Sum(hramDigest[:0])
	hramReduced, _ := edwards25519.NewScalar().SetUniformBytes(hramDigest[:])
	sScalar := edwards25519.NewScalar().MultiplyAdd(hramReduced, privScalar, rReduced)
	s := *(*[32]byte)(sScalar.Bytes())

	var sig [64]byte
	copy(sig[:], encodedR[:])
	copy(sig[32:], s[:])
	sig[63] |= publicKey[31] & 0x80
	return sig
}

func newCurveKey(t *testing.T) (priv, pub [32]byte) {
	t.Helper()
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(pub[:], p)
	return priv, pub
}

func marshalDetails(serial, issuerSerial uint32, key []byte, notBefore, notAfter uint64) []byte {
	b := appendVarintField(nil, fDetailsSerial, uint64(serial))
	b = appendVarintField(b, fDetailsIssuerSerial, uint64(issuerSerial))
	b = appendBytesField(b, fDetailsKey, key)
	b = appendVarintField(b, fDetailsNotBefore, notBefore)
	b = appendVarintField(b, fDetailsNotAfter, notAfter)
	return b
}

func marshalNoiseCert(details, sig []byte) []byte {
	b := appendBytesField(nil, fNoiseCertDetails, details)
	return appendBytesField(b, fNoiseCertSignature, sig)
}

// testCA is a self-signed root + intermediate for minting test cert chains.
type testCA struct {
	rootPriv, rootPub [32]byte
	intPriv, intPub   [32]byte
}

func newTestCA(t *testing.T) *testCA {
	ca := &testCA{}
	ca.rootPriv, ca.rootPub = newCurveKey(t)
	ca.intPriv, ca.intPub = newCurveKey(t)
	return ca
}

// chain mints a CertChain whose leaf binds to leafKey, with the given
// validity window and intermediate issuerSerial (0 = valid).
func (ca *testCA) chain(leafKey []byte, notBefore, notAfter uint64, intIssuerSerial uint32) []byte {
	const intSerial = 1
	intDetails := marshalDetails(intSerial, intIssuerSerial, ca.intPub[:], notBefore, notAfter)
	intSig := xeddsaSign(&ca.rootPriv, intDetails, fixedRandom)
	leafDetails := marshalDetails(2, intSerial, leafKey, notBefore, notAfter)
	leafSig := xeddsaSign(&ca.intPriv, leafDetails, fixedRandom)
	chain := appendBytesField(nil, fCertLeaf, marshalNoiseCert(leafDetails, leafSig[:]))
	chain = appendBytesField(chain, fCertIntermediate, marshalNoiseCert(intDetails, intSig[:]))
	return chain
}

func validWindow() (uint64, uint64) {
	now := time.Now().Unix()
	return uint64(now - 3600), uint64(now + 3600)
}

func TestXEdDSASignVerify(t *testing.T) {
	priv, pub := newCurveKey(t)
	msg := []byte("the quick brown fox")
	sig := xeddsaSign(&priv, msg, fixedRandom)
	if !xeddsaVerify(pub, msg, sig) {
		t.Fatal("valid signature failed to verify")
	}
	// Tampered message.
	if xeddsaVerify(pub, append(msg, '!'), sig) {
		t.Fatal("signature verified over tampered message")
	}
	// Tampered signature.
	bad := sig
	bad[0] ^= 0x01
	if xeddsaVerify(pub, msg, bad) {
		t.Fatal("tampered signature verified")
	}
	// Wrong key.
	_, otherPub := newCurveKey(t)
	if xeddsaVerify(otherPub, msg, sig) {
		t.Fatal("signature verified under wrong key")
	}
}

func TestVerifyServerCertValid(t *testing.T) {
	ca := newTestCA(t)
	_, serverStatic := newCurveKey(t)
	nb, na := validWindow()
	chain := ca.chain(serverStatic[:], nb, na, 0)
	if err := verifyServerCert(chain, serverStatic[:], ca.rootPub); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
}

func TestVerifyServerCertFailures(t *testing.T) {
	nb, na := validWindow()
	now := time.Now().Unix()

	cases := []struct {
		name  string
		build func(t *testing.T) (chain []byte, static []byte, root [32]byte)
		want  string
	}{
		{
			name: "wrong root key",
			build: func(t *testing.T) ([]byte, []byte, [32]byte) {
				ca := newTestCA(t)
				_, s := newCurveKey(t)
				_, otherRoot := newCurveKey(t)
				return ca.chain(s[:], nb, na, 0), s[:], otherRoot
			},
			want: "intermediate cert signature",
		},
		{
			name: "expired",
			build: func(t *testing.T) ([]byte, []byte, [32]byte) {
				ca := newTestCA(t)
				_, s := newCurveKey(t)
				return ca.chain(s[:], uint64(now-7200), uint64(now-3600), 0), s[:], ca.rootPub
			},
			want: "expired",
		},
		{
			name: "not yet valid",
			build: func(t *testing.T) ([]byte, []byte, [32]byte) {
				ca := newTestCA(t)
				_, s := newCurveKey(t)
				return ca.chain(s[:], uint64(now+3600), uint64(now+7200), 0), s[:], ca.rootPub
			},
			want: "not valid yet",
		},
		{
			name: "leaf key mismatch",
			build: func(t *testing.T) ([]byte, []byte, [32]byte) {
				ca := newTestCA(t)
				_, leafKey := newCurveKey(t)
				_, otherStatic := newCurveKey(t)
				return ca.chain(leafKey[:], nb, na, 0), otherStatic[:], ca.rootPub
			},
			want: "doesn't match",
		},
		{
			name: "bad intermediate issuer serial",
			build: func(t *testing.T) ([]byte, []byte, [32]byte) {
				ca := newTestCA(t)
				_, s := newCurveKey(t)
				return ca.chain(s[:], nb, na, 5), s[:], ca.rootPub
			},
			want: "issuer serial",
		},
		{
			name: "tampered leaf signature",
			build: func(t *testing.T) ([]byte, []byte, [32]byte) {
				ca := newTestCA(t)
				_, s := newCurveKey(t)
				chain := ca.chain(s[:], nb, na, 0)
				chain[len(chain)-1] ^= 0x80 // flip a bit in the trailing leaf signature
				return chain, s[:], ca.rootPub
			},
			want: "signature",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain, static, root := tc.build(t)
			err := verifyServerCert(chain, static, root)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}
