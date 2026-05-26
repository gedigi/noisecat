package noisecat

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ValidateStaticKey checks that the supplied base64-encoded public key
// is well-formed for the given Noise DH function. For Curve25519 it
// only verifies the length (32 bytes); for secp256k1 it also parses
// the bytes as a compressed point on the curve so a typo or off-curve
// value is caught before any handshake is attempted.
//
// dhFunc is one of the NOISE_DH_* constants from pkg/noisecat/protocols.go
// (e.g. NOISE_DH_CURVE25519, NOISE_DH_SECP256K1).
//
// Returns nil on success, or an error describing the problem.
func ValidateStaticKey(b64 string, dhFunc byte) error {
	if b64 == "" {
		return errors.New("empty key")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("not valid base64: %w", err)
	}
	switch dhFunc {
	case NOISE_DH_CURVE25519:
		if len(raw) != 32 {
			return fmt.Errorf("curve25519 public key must be 32 bytes, got %d", len(raw))
		}
		return nil
	case NOISE_DH_SECP256K1:
		if len(raw) != 33 {
			return fmt.Errorf("secp256k1 compressed public key must be 33 bytes, got %d", len(raw))
		}
		if _, err := secp256k1.ParsePubKey(raw); err != nil {
			return fmt.Errorf("not a valid secp256k1 point: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported DH function %d", dhFunc)
	}
}

// ValidateStaticKeyForProtocol is a convenience wrapper that parses the
// Noise protocol name to determine the DH function before validating.
// Useful for CLI tools that already have a -proto string in hand.
func ValidateStaticKeyForProtocol(b64, protoName string) error {
	_, dhFunc, _, _, _, err := parseProtocolName(protoName)
	if err != nil {
		return fmt.Errorf("can't determine DH function from protocol %q: %w", protoName, err)
	}
	return ValidateStaticKey(b64, dhFunc)
}
