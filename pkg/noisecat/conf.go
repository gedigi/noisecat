package noisecat

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"

	"github.com/flynn/noise"
)

// Config parameters
type Config struct {
	SrcPort string
	SrcHost string
	DstPort string
	DstHost string

	ExecuteCmd string
	Proxy      string
	Listen     bool
	Verbose    bool
	Daemon     bool
	Keygen     bool

	Protocol   string
	Pattern    byte
	DHFunc     byte
	CipherFunc byte
	HashFunc   byte

	PSK     string
	RStatic string
	LStatic string
}

// NoiseInterface interfaces with noise configurations
type NoiseInterface interface {
	GetLocalStaticPublic() []byte
}

// ParseConfig validates the user-facing flag combinations and produces a
// noise.Config ready to be handed to the underlying noisenet package.
func (config *Config) ParseConfig() (*noise.Config, error) {
	if config.Keygen {
		// Only the protocol matters for keygen; parse it and short-circuit.
		var err error
		config.Pattern, config.DHFunc, config.CipherFunc, config.HashFunc, err = parseProtocolName(config.Protocol)
		return nil, err
	}

	if config.Daemon {
		if !config.Listen {
			return nil, errors.New("-k requires -l")
		}
		if config.Proxy == "" && config.ExecuteCmd == "" {
			return nil, errors.New("-k requires -proxy or -e")
		}
	}
	if config.Proxy != "" && !config.Listen {
		return nil, errors.New("client mode does not support -proxy")
	}
	if config.Proxy != "" && config.ExecuteCmd != "" {
		return nil, errors.New("-proxy and -e are mutually exclusive")
	}
	if config.Proxy != "" {
		if _, _, err := net.SplitHostPort(config.Proxy); err != nil {
			return nil, fmt.Errorf("-proxy must be host:port: %w", err)
		}
	}
	if config.SrcPort != "" {
		if p, err := strconv.Atoi(config.SrcPort); err != nil || p < 0 || p > 65535 {
			return nil, fmt.Errorf("invalid -p source port %q", config.SrcPort)
		}
	}
	if config.Listen && !config.Daemon && config.SrcPort == "0" {
		// Listening on an ephemeral port is legal but almost never useful: warn.
		// We can't log here directly without verbose state; the caller may show it.
	}

	return config.parseNoise()
}

func (config *Config) checkLocalKeypair(cs noise.CipherSuite) (noise.DHKey, error) {
	if config.LStatic == "" {
		return cs.GenerateKeypair(rand.Reader)
	}
	if err := warnIfWorldReadable(config.LStatic); err != nil {
		return noise.DHKey{}, err
	}
	data, err := os.ReadFile(config.LStatic)
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("can't read keyfile %q: %w", config.LStatic, err)
	}
	var keypair noise.DHKey
	if err := json.Unmarshal(data, &keypair); err != nil {
		return noise.DHKey{}, fmt.Errorf("can't parse keyfile %q: %w", config.LStatic, err)
	}
	if len(keypair.Public) != 32 || len(keypair.Private) != 32 {
		return noise.DHKey{}, fmt.Errorf("keyfile %q: expected 32-byte public and private keys", config.LStatic)
	}
	return keypair, nil
}

// warnIfWorldReadable prints a warning to stderr if a key file is readable
// by group or other on POSIX systems. It does not refuse to proceed.
func warnIfWorldReadable(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("can't stat keyfile %q: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "noisecat: warning: keyfile %q is accessible by other users (mode %o); chmod 600 recommended\n", path, info.Mode().Perm())
	}
	return nil
}
