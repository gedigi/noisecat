package noisecat

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/flynn/noise"
)

// secp256k1KeyFile is the JSON layout for a BOLT-8 / secp256k1 static key
// stored on disk. It mirrors the noise.DHKey JSON used elsewhere
// (Private/Public base64), but Public is 33 bytes compressed and Private
// is 32 bytes raw.
type secp256k1KeyFile struct {
	Private []byte `json:"Private"`
	Public  []byte `json:"Public"`
}

// loadSecp256k1Keypair returns a noise.DHKey carrying the 32-byte
// secp256k1 private key and the 33-byte compressed public key. If path
// is empty, a fresh keypair is generated. The same JSON layout (Private
// + Public, base64-encoded by encoding/json's []byte handling) is used
// as for Curve25519 — the only difference is that Public is 33 bytes.
func loadSecp256k1Keypair(path string) (noise.DHKey, error) {
	if path == "" {
		priv, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			return noise.DHKey{}, fmt.Errorf("generate secp256k1 keypair: %w", err)
		}
		return noise.DHKey{
			Private: priv.Serialize(),
			Public:  priv.PubKey().SerializeCompressed(),
		}, nil
	}
	if err := warnIfWorldReadable(path); err != nil {
		return noise.DHKey{}, err
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is the user-supplied -lstatic value
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("can't read keyfile %q: %w", path, err)
	}
	var kf secp256k1KeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return noise.DHKey{}, fmt.Errorf("can't parse keyfile %q: %w", path, err)
	}
	if len(kf.Private) != 32 {
		return noise.DHKey{}, fmt.Errorf("keyfile %q: secp256k1 private key must be 32 bytes (got %d)", path, len(kf.Private))
	}
	if len(kf.Public) != 33 {
		return noise.DHKey{}, fmt.Errorf("keyfile %q: secp256k1 public key must be 33 bytes compressed (got %d)", path, len(kf.Public))
	}
	return noise.DHKey{Private: kf.Private, Public: kf.Public}, nil
}

// GenerateSecp256k1Keypair returns a JSON-encoded keypair suitable for
// writing to a -lstatic file when the user runs -keygen with a
// secp256k1 protocol. The format matches loadSecp256k1Keypair's
// expectations.
func GenerateSecp256k1Keypair() ([]byte, error) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return json.Marshal(secp256k1KeyFile{
		Private: priv.Serialize(),
		Public:  priv.PubKey().SerializeCompressed(),
	})
}

// suppress unused import warnings if no test exercises every helper.
var (
	_ = base64.StdEncoding
	_ = rand.Reader
	_ = errors.New
)
