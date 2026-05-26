package noisecat

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestValidateStaticKey(t *testing.T) {
	// 32-byte zero key for Curve25519 — valid by length even though it's a
	// degenerate value. ValidateStaticKey checks shape only; semantic
	// rejection of weak keys is out of scope.
	zero25519 := base64.StdEncoding.EncodeToString(make([]byte, 32))

	// Build a real secp256k1 compressed public key.
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	realSecp := base64.StdEncoding.EncodeToString(priv.PubKey().SerializeCompressed())

	// Build a 33-byte buffer that LOOKS like a compressed key (right
	// version byte, right length) but with random x coordinate that does
	// not correspond to a curve point. dcrd's ParsePubKey rejects it.
	notOnCurve := make([]byte, 33)
	notOnCurve[0] = 0x02
	if _, err := rand.Read(notOnCurve[1:]); err != nil {
		t.Fatal(err)
	}
	notOnCurveB64 := base64.StdEncoding.EncodeToString(notOnCurve)

	cases := []struct {
		name      string
		b64       string
		dhFunc    byte
		wantErr   string // substring; empty = expect success
	}{
		{name: "empty input", b64: "", dhFunc: NOISE_DH_CURVE25519, wantErr: "empty"},
		{name: "not base64", b64: "!!!", dhFunc: NOISE_DH_CURVE25519, wantErr: "base64"},
		{name: "25519 ok", b64: zero25519, dhFunc: NOISE_DH_CURVE25519},
		{
			name:    "25519 wrong length",
			b64:     base64.StdEncoding.EncodeToString([]byte("too-short")),
			dhFunc:  NOISE_DH_CURVE25519,
			wantErr: "32 bytes",
		},
		{name: "secp256k1 ok", b64: realSecp, dhFunc: NOISE_DH_SECP256K1},
		{
			name:    "secp256k1 wrong length",
			b64:     zero25519, // 32 bytes — too short for secp256k1
			dhFunc:  NOISE_DH_SECP256K1,
			wantErr: "33 bytes",
		},
		{
			name:    "secp256k1 off curve",
			b64:     notOnCurveB64,
			dhFunc:  NOISE_DH_SECP256K1,
			// Either "not a valid secp256k1 point" or a deeper error from dcrd —
			// match the wrapping prefix.
			wantErr: "secp256k1",
		},
		{
			name:    "unknown DH function",
			b64:     zero25519,
			dhFunc:  99,
			wantErr: "unsupported DH function",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateStaticKey(tc.b64, tc.dhFunc)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateStaticKeyForProtocol(t *testing.T) {
	priv, _ := secp256k1.GeneratePrivateKey()
	secp := base64.StdEncoding.EncodeToString(priv.PubKey().SerializeCompressed())
	cv25519 := base64.StdEncoding.EncodeToString(make([]byte, 32))

	if err := ValidateStaticKeyForProtocol(cv25519, "Noise_XX_25519_AESGCM_SHA256"); err != nil {
		t.Fatalf("25519 protocol + 32-byte key: %v", err)
	}
	if err := ValidateStaticKeyForProtocol(secp, "Noise_XK_secp256k1_ChaChaPoly_SHA256"); err != nil {
		t.Fatalf("secp256k1 protocol + 33-byte key: %v", err)
	}
	// Mismatch: secp256k1 key against a curve25519 protocol.
	if err := ValidateStaticKeyForProtocol(secp, "Noise_XX_25519_AESGCM_SHA256"); err == nil {
		t.Fatal("expected size mismatch error")
	}
	// Invalid protocol name.
	if err := ValidateStaticKeyForProtocol(cv25519, "garbage"); err == nil {
		t.Fatal("expected protocol-parse error")
	}
}
