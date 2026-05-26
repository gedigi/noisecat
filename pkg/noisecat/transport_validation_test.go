package noisecat

import (
	"strings"
	"testing"
)

// TestResolveTransportRejectsMismatchedDH ensures the CLI surfaces a
// clear error when the user combines a transport with an incompatible
// DH function. Three combinations are illegal:
//
//   - transport=bolt8 with a Curve25519 protocol (bolt8 only speaks
//     secp256k1).
//   - transport=raw with a secp256k1 protocol (raw uses flynn/noise,
//     which has no secp256k1 DH function).
//   - transport=noisesocket with a secp256k1 protocol (same reason).
func TestResolveTransportRejectsMismatchedDH(t *testing.T) {
	cases := []struct {
		name      string
		transport string
		dhFunc    byte
		wantErr   string
	}{
		{
			name:      "bolt8 + curve25519",
			transport: "bolt8",
			dhFunc:    NOISE_DH_CURVE25519,
			wantErr:   "bolt8 only supports secp256k1",
		},
		{
			name:      "raw + secp256k1",
			transport: "raw",
			dhFunc:    NOISE_DH_SECP256K1,
			wantErr:   "raw cannot speak secp256k1",
		},
		{
			name:      "noisesocket + secp256k1",
			transport: "noisesocket",
			dhFunc:    NOISE_DH_SECP256K1,
			wantErr:   "noisesocket cannot speak secp256k1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Transport: tc.transport, DHFunc: tc.dhFunc}
			_, err := resolveTransport(cfg)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestResolveTransportAcceptsValidCombos covers the happy path: each
// transport accepts at least one DH function.
func TestResolveTransportAcceptsValidCombos(t *testing.T) {
	cases := []struct {
		transport string
		dhFunc    byte
	}{
		{transport: "", dhFunc: NOISE_DH_CURVE25519},            // default → raw
		{transport: "raw", dhFunc: NOISE_DH_CURVE25519},
		{transport: "noisesocket", dhFunc: NOISE_DH_CURVE25519},
		{transport: "bolt8", dhFunc: NOISE_DH_SECP256K1},
	}
	for _, tc := range cases {
		t.Run(tc.transport+"+"+strconvDH(tc.dhFunc), func(t *testing.T) {
			cfg := &Config{Transport: tc.transport, DHFunc: tc.dhFunc}
			if _, err := resolveTransport(cfg); err != nil {
				t.Fatalf("unexpected error for %s + %d: %v", tc.transport, tc.dhFunc, err)
			}
		})
	}
}

func strconvDH(b byte) string {
	switch b {
	case NOISE_DH_CURVE25519:
		return "25519"
	case NOISE_DH_SECP256K1:
		return "secp256k1"
	default:
		return "?"
	}
}
