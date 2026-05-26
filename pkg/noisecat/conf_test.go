package noisecat

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/flynn/noise"
)

func TestParseConfigValidation(t *testing.T) {
	validProto := "Noise_NN_25519_AESGCM_SHA256"
	cases := []struct {
		name      string
		cfg       Config
		wantErr   string // substring; empty means success
	}{
		{
			name: "client mode ok",
			cfg:  Config{Protocol: validProto, DstHost: "h", DstPort: "1"},
		},
		{
			name: "server mode ok",
			cfg:  Config{Protocol: validProto, Listen: true, SrcPort: "1"},
		},
		{
			name:    "-k without -l",
			cfg:     Config{Protocol: validProto, Daemon: true, ExecuteCmd: "/bin/sh"},
			wantErr: "-k requires -l",
		},
		{
			name:    "-k without -e or -proxy",
			cfg:     Config{Protocol: validProto, Daemon: true, Listen: true},
			wantErr: "requires -proxy or -e",
		},
		{
			name:    "-proxy in client mode",
			cfg:     Config{Protocol: validProto, Proxy: "1.2.3.4:5"},
			wantErr: "client mode",
		},
		{
			name:    "-proxy and -e together",
			cfg:     Config{Protocol: validProto, Listen: true, Daemon: true, Proxy: "1.2.3.4:5", ExecuteCmd: "/bin/sh"},
			wantErr: "mutually exclusive",
		},
		{
			name:    "-proxy bad format",
			cfg:     Config{Protocol: validProto, Listen: true, Daemon: true, Proxy: "not-a-host-port"},
			wantErr: "host:port",
		},
		{
			name:    "invalid source port",
			cfg:     Config{Protocol: validProto, Listen: true, SrcPort: "99999"},
			wantErr: "source port",
		},
		{
			name:    "PSK wrong length",
			cfg:     Config{Protocol: "Noise_NNpsk0_25519_AESGCM_SHA256", Listen: true, PSK: base64.StdEncoding.EncodeToString([]byte("short"))},
			wantErr: "32 bytes",
		},
		{
			name:    "PSK not base64",
			cfg:     Config{Protocol: "Noise_NNpsk0_25519_AESGCM_SHA256", Listen: true, PSK: "!!!not-base64!!!"},
			wantErr: "base64",
		},
		{
			name: "PSK 32 bytes ok",
			cfg:  Config{Protocol: "Noise_NNpsk0_25519_AESGCM_SHA256", Listen: true, PSK: base64.StdEncoding.EncodeToString(make([]byte, 32))},
		},
		{
			name:    "PSK without modifier rejected",
			cfg:     Config{Protocol: validProto, Listen: true, PSK: base64.StdEncoding.EncodeToString(make([]byte, 32))},
			wantErr: "psk modifier",
		},
		{
			name:    "PSK modifier without -psk rejected",
			cfg:     Config{Protocol: "Noise_NNpsk0_25519_AESGCM_SHA256", Listen: true},
			wantErr: "psk modifier but -psk",
		},
		{
			name:    "invalid protocol name",
			cfg:     Config{Protocol: "not-a-protocol", Listen: true},
			wantErr: "invalid protocol",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			_, err := cfg.ParseConfig()
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

func TestCheckLocalKeypairLoadsFromFile(t *testing.T) {
	dir := t.TempDir()
	keyfile := filepath.Join(dir, "static.json")

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	kp, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(kp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyfile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{LStatic: keyfile}
	loaded, err := cfg.checkLocalKeypair(cs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(loaded.Public) != string(kp.Public) || string(loaded.Private) != string(kp.Private) {
		t.Fatal("loaded keypair does not match written keypair")
	}
}

func TestCheckLocalKeypairRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	keyfile := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(keyfile, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	cfg := &Config{LStatic: keyfile}
	if _, err := cfg.checkLocalKeypair(cs); err == nil {
		t.Fatal("expected error for malformed key file, got nil")
	}
}

func TestCheckLocalKeypairRejectsShortKeys(t *testing.T) {
	dir := t.TempDir()
	keyfile := filepath.Join(dir, "short.json")
	short := noise.DHKey{Public: []byte("short"), Private: []byte("short")}
	data, err := json.Marshal(short)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyfile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	cfg := &Config{LStatic: keyfile}
	if _, err := cfg.checkLocalKeypair(cs); err == nil {
		t.Fatal("expected error for short keys, got nil")
	}
}

func TestGenerateKeypairRoundTrip(t *testing.T) {
	cfg := Config{Protocol: "Noise_XX_25519_AESGCM_SHA256", Keygen: true}
	if _, err := cfg.ParseConfig(); err != nil {
		t.Fatalf("ParseConfig in keygen mode: %v", err)
	}
	out, err := GenerateKeypair(cfg.DHFunc, cfg.CipherFunc, cfg.HashFunc)
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	var kp noise.DHKey
	if err := json.Unmarshal(out, &kp); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(kp.Public) != 32 || len(kp.Private) != 32 {
		t.Fatalf("expected 32-byte keys, got pub=%d priv=%d", len(kp.Public), len(kp.Private))
	}
}
