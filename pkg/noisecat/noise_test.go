package noisecat

import (
	"encoding/base64"
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
	cfg := &Config{
		Protocol: "Noise_NN_25519_AESGCM_SHA256",
		PSK:      base64.StdEncoding.EncodeToString(psk),
	}
	noiseCfg, err := cfg.ParseConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(noiseCfg.PresharedKey) != 32 || noiseCfg.PresharedKey[31] != 31 {
		t.Fatalf("PresharedKey not propagated: %v", noiseCfg.PresharedKey)
	}
}
