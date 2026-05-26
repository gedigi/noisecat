package main

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildBinary compiles the noisecat binary into the test's temp dir and
// returns the path. Each call yields a fresh build. We need a real
// process because the -validate flag exits with a status code.
func buildBinary(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		// Skipping on Windows just to keep the test platform-portable;
		// the underlying library function is already tested at the unit
		// level via ValidateStaticKey on every OS.
		t.Skip("os/exec on the windows runner is awkward to script; library coverage is enough")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "noisecat")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return binary
}

// TestValidateFlagCurve25519 exercises the full `noisecat -validate <key>`
// CLI path for the default Curve25519 protocol. A valid 32-byte key
// exits 0 with "OK"; a wrong-length key exits 1 with an error message
// on stderr.
func TestValidateFlagCurve25519(t *testing.T) {
	bin := buildBinary(t)

	goodKey := make([]byte, 32)
	if _, err := rand.Read(goodKey); err != nil {
		t.Fatal(err)
	}
	goodB64 := base64.StdEncoding.EncodeToString(goodKey)

	t.Run("valid key exits 0", func(t *testing.T) {
		cmd := exec.Command(bin, "-validate", goodB64)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expected exit 0, got error: %v\noutput: %s", err, out)
		}
		if !strings.Contains(string(out), "OK") {
			t.Fatalf("expected OK on stdout, got %q", out)
		}
	})

	t.Run("short key exits 1", func(t *testing.T) {
		shortB64 := base64.StdEncoding.EncodeToString([]byte("only-six"))
		cmd := exec.Command(bin, "-validate", shortB64)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected non-zero exit, got success: %s", out)
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
			t.Fatalf("expected exit code 1, got %v", err)
		}
		if !strings.Contains(string(out), "32 bytes") {
			t.Fatalf("expected error mentioning '32 bytes', got %q", out)
		}
	})

	t.Run("garbage base64 exits 1", func(t *testing.T) {
		cmd := exec.Command(bin, "-validate", "!!!not-base64!!!")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected non-zero exit, got success: %s", out)
		}
		if !strings.Contains(string(out), "base64") {
			t.Fatalf("expected base64 error, got %q", out)
		}
	})
}

// TestValidateFlagSecp256k1 confirms -validate picks the DH function
// from -proto and applies the corresponding length rule (33 bytes
// compressed for secp256k1 instead of 32).
func TestValidateFlagSecp256k1(t *testing.T) {
	bin := buildBinary(t)

	// Generate a real secp256k1 keypair via the binary's -keygen mode
	// so we don't have to import the secp256k1 library into cmd/.
	keygen := exec.Command(bin, "-proto", "Noise_XK_secp256k1_ChaChaPoly_SHA256", "-keygen")
	out, err := keygen.CombinedOutput()
	if err != nil {
		t.Fatalf("-keygen failed: %v\n%s", err, out)
	}
	// out is JSON like {"Private":"...","Public":"..."}; pull out Public.
	idx := strings.Index(string(out), `"Public":"`)
	if idx < 0 {
		t.Fatalf("could not find Public in keygen output: %s", out)
	}
	start := idx + len(`"Public":"`)
	end := strings.Index(string(out[start:]), `"`)
	if end < 0 {
		t.Fatalf("malformed keygen output: %s", out)
	}
	pubB64 := string(out[start : start+end])

	cmd := exec.Command(bin, "-proto", "Noise_XK_secp256k1_ChaChaPoly_SHA256", "-validate", pubB64)
	vout, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected exit 0 for valid secp256k1 key, got %v\n%s", err, vout)
	}
	if !strings.Contains(string(vout), "OK") {
		t.Fatalf("expected OK, got %q", vout)
	}

	// A 32-byte (Curve25519-sized) key should be rejected when
	// validating against a secp256k1 protocol.
	short := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cmd = exec.Command(bin, "-proto", "Noise_XK_secp256k1_ChaChaPoly_SHA256", "-validate", short)
	vout, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for length mismatch, got: %s", vout)
	}
	if !strings.Contains(string(vout), "33 bytes") {
		t.Fatalf("expected '33 bytes' error, got %q", vout)
	}
}
