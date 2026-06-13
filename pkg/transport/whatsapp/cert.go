package whatsapp

import (
	"crypto/ed25519"
	"crypto/hmac"
	"errors"
	"fmt"
	"time"

	"filippo.io/edwards25519/field"
)

// WACertPubKey is WhatsApp's pinned Noise-certificate root public key (a
// 32-byte Curve25519/Montgomery key), copied verbatim from whatsmeow's
// handshake.go. It is the trust anchor for the server certificate chain.
var WACertPubKey = [32]byte{
	0x14, 0x23, 0x75, 0x57, 0x4d, 0x0a, 0x58, 0x71, 0x66, 0xaa, 0xe7, 0x1e, 0xbe, 0x51, 0x64, 0x37,
	0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69, 0x5c, 0x6c, 0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b,
}

// waCertIssuerSerial is the serial the intermediate certificate must name as
// its issuer (i.e. the root is serial 0).
const waCertIssuerSerial = 0

// CertChain protobuf field numbers (whatsmeow waCert).
const (
	fCertLeaf         = 1
	fCertIntermediate = 2

	fNoiseCertDetails   = 1
	fNoiseCertSignature = 2

	fDetailsSerial       = 1
	fDetailsIssuerSerial = 2
	fDetailsKey          = 3
	fDetailsNotBefore    = 4
	fDetailsNotAfter     = 5
)

// certDetails is the decoded CertChain.NoiseCertificate.Details.
type certDetails struct {
	serial       uint32
	issuerSerial uint32
	key          []byte
	notBefore    uint64
	notAfter     uint64
}

func parseDetails(b []byte) (certDetails, error) {
	var d certDetails
	fields, err := pbParse(b)
	if err != nil {
		return d, err
	}
	for _, f := range fields {
		switch f.num {
		case fDetailsSerial:
			d.serial = uint32(f.val)
		case fDetailsIssuerSerial:
			d.issuerSerial = uint32(f.val)
		case fDetailsKey:
			d.key = f.data
		case fDetailsNotBefore:
			d.notBefore = f.val
		case fDetailsNotAfter:
			d.notAfter = f.val
		}
	}
	return d, nil
}

// noiseCert is the raw details + signature of one certificate.
type noiseCert struct {
	details   []byte // raw serialized Details (the signed message)
	signature []byte
}

func parseNoiseCert(b []byte) (noiseCert, error) {
	fields, err := pbParse(b)
	if err != nil {
		return noiseCert{}, err
	}
	return noiseCert{
		details:   nestedBytes(fields, fNoiseCertDetails),
		signature: nestedBytes(fields, fNoiseCertSignature),
	}, nil
}

// verifyServerCert checks the decrypted ServerHello payload (a CertChain)
// against the pinned root key, mirroring whatsmeow's verifyServerCert. The
// root key is a parameter so tests can inject their own anchor.
//
// Chain: root (rootKey) signs intermediate.details; intermediate.key signs
// leaf.details; leaf.key must equal the server static key decrypted during
// the Noise handshake (staticDecrypted).
func verifyServerCert(certDecrypted, staticDecrypted []byte, rootKey [32]byte) error {
	top, err := pbParse(certDecrypted)
	if err != nil {
		return fmt.Errorf("unmarshal cert chain: %w", err)
	}
	leafBytes := nestedBytes(top, fCertLeaf)
	intBytes := nestedBytes(top, fCertIntermediate)
	if leafBytes == nil || intBytes == nil {
		return errors.New("missing leaf or intermediate certificate")
	}
	leaf, err := parseNoiseCert(leafBytes)
	if err != nil {
		return err
	}
	intermediate, err := parseNoiseCert(intBytes)
	if err != nil {
		return err
	}
	if leaf.details == nil || leaf.signature == nil || intermediate.details == nil || intermediate.signature == nil {
		return errors.New("missing parts of noise certificate")
	}
	if len(intermediate.signature) != 64 {
		return fmt.Errorf("unexpected intermediate signature length %d (expected 64)", len(intermediate.signature))
	}
	if len(leaf.signature) != 64 {
		return fmt.Errorf("unexpected leaf signature length %d (expected 64)", len(leaf.signature))
	}

	// Root verifies the intermediate.
	if !xeddsaVerify(rootKey, intermediate.details, [64]byte(intermediate.signature)) {
		return errors.New("failed to verify intermediate cert signature")
	}
	intDetails, err := parseDetails(intermediate.details)
	if err != nil {
		return err
	}
	if intDetails.issuerSerial != waCertIssuerSerial {
		return fmt.Errorf("unexpected intermediate issuer serial %d (expected %d)", intDetails.issuerSerial, waCertIssuerSerial)
	}
	if len(intDetails.key) != 32 {
		return fmt.Errorf("unexpected intermediate key length %d (expected 32)", len(intDetails.key))
	}

	// Intermediate verifies the leaf.
	if !xeddsaVerify([32]byte(intDetails.key), leaf.details, [64]byte(leaf.signature)) {
		return errors.New("failed to verify leaf cert signature")
	}
	if err := checkCertValidity(intDetails); err != nil {
		return fmt.Errorf("intermediate cert %w", err)
	}
	leafDetails, err := parseDetails(leaf.details)
	if err != nil {
		return err
	}
	if leafDetails.issuerSerial != intDetails.serial {
		return fmt.Errorf("unexpected leaf issuer serial %d (expected %d)", leafDetails.issuerSerial, intDetails.serial)
	}
	// Bind the verified chain to the party we actually completed the
	// handshake with: the leaf key must equal the server static key.
	if !hmac.Equal(leafDetails.key, staticDecrypted) {
		return errors.New("cert key doesn't match decrypted server static")
	}
	if err := checkCertValidity(leafDetails); err != nil {
		return fmt.Errorf("leaf cert %w", err)
	}
	return nil
}

// checkCertValidity enforces the notBefore/notAfter window (unix seconds).
func checkCertValidity(d certDetails) error {
	now := time.Now()
	notBefore := time.Unix(int64(d.notBefore), 0)
	notAfter := time.Unix(int64(d.notAfter), 0)
	if now.Before(notBefore) {
		return fmt.Errorf("not valid yet (now %s is before %s)", now, notBefore)
	}
	if now.After(notAfter) {
		return fmt.Errorf("expired (now %s is after %s)", now, notAfter)
	}
	return nil
}

// xeddsaVerify verifies an XEdDSA (Curve25519) signature, ported from
// go.mau.fi/libsignal's ecc.verify. montPub is a 32-byte Montgomery public
// key; the curve point is converted to its Edwards form and verified with
// standard ed25519, moving the sign bit out of the signature.
func xeddsaVerify(montPub [32]byte, message []byte, signature [64]byte) bool {
	pub := montPub
	pub[31] &= 0x7F

	// ed_y = (mont_x - 1) / (mont_x + 1)
	var edY, one, montX, montXMinusOne, montXPlusOne field.Element
	if _, err := montX.SetBytes(pub[:]); err != nil {
		return false
	}
	one.One()
	montXMinusOne.Subtract(&montX, &one)
	montXPlusOne.Add(&montX, &one)
	montXPlusOne.Invert(&montXPlusOne)
	edY.Multiply(&montXMinusOne, &montXPlusOne)

	var aEd [32]byte
	copy(aEd[:], edY.Bytes())

	// Move the sign bit from the signature into the public key.
	sig := signature
	aEd[31] |= sig[63] & 0x80
	sig[63] &= 0x7F

	return ed25519.Verify(aEd[:], message, sig[:])
}
