package noisecat

import (
	"strings"
	"testing"
)

func TestParseProtocolName(t *testing.T) {
	cases := []struct {
		name       string
		proto      string
		wantErr    bool
		errSubstr  string
		wantHsByte byte
	}{
		{
			name:       "valid NN/25519/AESGCM/SHA256",
			proto:      "Noise_NN_25519_AESGCM_SHA256",
			wantHsByte: NOISE_PATTERN_NN,
		},
		{
			name:       "valid NK (regression for NL→NK typo)",
			proto:      "Noise_NK_25519_ChaChaPoly_BLAKE2b",
			wantHsByte: NOISE_PATTERN_NK,
		},
		{
			name:       "valid XX",
			proto:      "Noise_XX_25519_AESGCM_SHA512",
			wantHsByte: NOISE_PATTERN_XX,
		},
		{
			name:      "NL no longer valid (used to shadow NK)",
			proto:     "Noise_NL_25519_AESGCM_SHA256",
			wantErr:   true,
			errSubstr: "handshake pattern NL",
		},
		{
			name:      "unknown DH function",
			proto:     "Noise_NN_448_AESGCM_SHA256",
			wantErr:   true,
			errSubstr: "DH function 448",
		},
		{
			name:      "garbage",
			proto:     "not-a-noise-protocol",
			wantErr:   true,
			errSubstr: "invalid protocol name",
		},
		{
			name:      "all four components invalid → all reported",
			proto:     "Noise_ZZ_999_FOO_BAR",
			wantErr:   true,
			errSubstr: "handshake pattern ZZ",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hs, _, _, _, _, err := parseProtocolName(tc.proto)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (hs=%d)", hs)
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if hs != tc.wantHsByte {
				t.Fatalf("hs byte = %d, want %d", hs, tc.wantHsByte)
			}
		})
	}
}

func TestParseProtocolNameJoinsAllErrors(t *testing.T) {
	_, _, _, _, _, err := parseProtocolName("Noise_ZZ_999_FOO_BAR")
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"ZZ", "999", "FOO", "BAR"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q (expected all four components reported)", err.Error(), want)
		}
	}
}
