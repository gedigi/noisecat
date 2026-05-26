package noisecat

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
)

// rstatic returns a base64-encoded 32-byte placeholder static key.
func rstatic() string { return base64.StdEncoding.EncodeToString(make([]byte, 32)) }

func TestParseNoiseRequiresRemoteStaticForKResponderPattern(t *testing.T) {
	// Initiator side of an NK handshake needs the responder's static key.
	cfg := &Config{Protocol: "Noise_NK_25519_AESGCM_SHA256"}
	if _, err := cfg.ParseConfig(); err == nil || !strings.Contains(err.Error(), "rstatic") {
		t.Fatalf("expected error mentioning rstatic, got %v", err)
	}
	cfg.RStatic = rstatic()
	if _, err := cfg.ParseConfig(); err != nil {
		t.Fatalf("with rstatic set: unexpected error %v", err)
	}
}

func TestParseNoiseGeneratesLocalKeypairForXInitiator(t *testing.T) {
	cfg := &Config{Protocol: "Noise_XX_25519_AESGCM_SHA256"}
	noiseCfg, err := cfg.ParseConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(noiseCfg.StaticKeypair.Public) != 32 || len(noiseCfg.StaticKeypair.Private) != 32 {
		t.Fatal("expected XX initiator to generate a 32-byte keypair")
	}
}

func TestParseNoiseResponderXXGeneratesLocalKeypair(t *testing.T) {
	cfg := &Config{Protocol: "Noise_XX_25519_AESGCM_SHA256", Listen: true}
	noiseCfg, err := cfg.ParseConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(noiseCfg.StaticKeypair.Public) != 32 {
		t.Fatal("expected XX responder to generate a keypair")
	}
}

func TestParseNoiseKResponderRequiresRemoteStatic(t *testing.T) {
	// KK responder needs the initiator's static key.
	cfg := &Config{Protocol: "Noise_KK_25519_AESGCM_SHA256", Listen: true}
	if _, err := cfg.ParseConfig(); err == nil || !strings.Contains(err.Error(), "rstatic") {
		t.Fatalf("expected error mentioning rstatic, got %v", err)
	}
	cfg.RStatic = rstatic()
	if _, err := cfg.ParseConfig(); err != nil {
		t.Fatalf("with rstatic: unexpected error %v", err)
	}
}

func TestParseNoiseRStaticInvalidBase64(t *testing.T) {
	cfg := &Config{Protocol: "Noise_NK_25519_AESGCM_SHA256", RStatic: "!!!"}
	_, err := cfg.ParseConfig()
	if err == nil || !strings.Contains(err.Error(), "remote static key") {
		t.Fatalf("expected remote static key error, got %v", err)
	}
}

func TestParseNoiseRStaticWrongLength(t *testing.T) {
	cfg := &Config{
		Protocol: "Noise_NK_25519_AESGCM_SHA256",
		RStatic:  base64.StdEncoding.EncodeToString([]byte("too-short")),
	}
	_, err := cfg.ParseConfig()
	if err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("expected '32 bytes' error, got %v", err)
	}
}

func TestParseNoiseSetsPSKFrom32Bytes(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i)
	}
	// Use a psk-modified protocol so the PSK is honored. NNpsk0
	// prepends the PSK token to the first handshake message.
	cfg := &Config{
		Protocol: "Noise_NNpsk0_25519_AESGCM_SHA256",
		PSK:      base64.StdEncoding.EncodeToString(psk),
	}
	noiseCfg, err := cfg.ParseConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(noiseCfg.PresharedKey) != 32 || noiseCfg.PresharedKey[31] != 31 {
		t.Fatalf("PresharedKey not propagated: %v", noiseCfg.PresharedKey)
	}
	if noiseCfg.PresharedKeyPlacement != 0 {
		t.Fatalf("PresharedKeyPlacement = %d, want 0", noiseCfg.PresharedKeyPlacement)
	}
}

// TestPSKProtocolNameParses asserts the new regex accepts every valid
// psk modifier (0..3) on a base pattern and rejects garbage.
func TestPSKProtocolNameParses(t *testing.T) {
	good := []struct {
		proto string
		want  int8
	}{
		{"Noise_NNpsk0_25519_AESGCM_SHA256", 0},
		{"Noise_NKpsk2_25519_ChaChaPoly_SHA256", 2},
		{"Noise_XXpsk3_25519_AESGCM_BLAKE2s", 3},
		{"Noise_IKpsk1_25519_AESGCM_SHA256", 1},
		{"Noise_NN_25519_AESGCM_SHA256", noPSK},
	}
	for _, tc := range good {
		_, _, _, _, psk, err := parseProtocolName(tc.proto)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", tc.proto, err)
			continue
		}
		if psk != tc.want {
			t.Errorf("%s: psk = %d, want %d", tc.proto, psk, tc.want)
		}
	}
	// psk4 is out of spec; the regex should reject it as an invalid name.
	if _, _, _, _, _, err := parseProtocolName("Noise_NNpsk4_25519_AESGCM_SHA256"); err == nil {
		t.Error("Noise_NNpsk4_... should not parse")
	}
}

// TestPSKRoundTrip parametrizes a full client/server ParseConfig round
// trip across every psk placement (0, 1, 2, 3). At each placement the
// derived noise.Config must agree on both the PSK bytes and the
// PresharedKeyPlacement value — that's what tells flynn/noise where to
// insert the MixKeyAndHash(psk) token in the handshake.
//
// Each PSK placement is valid for the NN pattern; the spec allows
// applying psk0..psk3 to any non-trivial pattern.
func TestPSKRoundTrip(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i)
	}
	pskB64 := base64.StdEncoding.EncodeToString(psk)

	for placement := 0; placement <= 3; placement++ {
		t.Run("psk"+strconv.Itoa(placement), func(t *testing.T) {
			proto := "Noise_NNpsk" + strconv.Itoa(placement) + "_25519_AESGCM_SHA256"
			clientNC, err := (&Config{Protocol: proto, PSK: pskB64}).ParseConfig()
			if err != nil {
				t.Fatalf("client ParseConfig: %v", err)
			}
			serverNC, err := (&Config{Protocol: proto, Listen: true, PSK: pskB64}).ParseConfig()
			if err != nil {
				t.Fatalf("server ParseConfig: %v", err)
			}
			if !bytesEqual32(clientNC.PresharedKey, serverNC.PresharedKey) {
				t.Fatal("PSK bytes differ across peers")
			}
			if clientNC.PresharedKeyPlacement != serverNC.PresharedKeyPlacement {
				t.Fatalf("PresharedKeyPlacement differs across peers: client=%d server=%d",
					clientNC.PresharedKeyPlacement, serverNC.PresharedKeyPlacement)
			}
			if clientNC.PresharedKeyPlacement != placement {
				t.Fatalf("PresharedKeyPlacement = %d, want %d",
					clientNC.PresharedKeyPlacement, placement)
			}
		})
	}
}

func bytesEqual32(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
