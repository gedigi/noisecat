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
	"strings"

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
	// PSKPlacement is the psk-modifier index parsed out of the protocol
	// name (e.g. "psk2" in Noise_NKpsk2_...). noPSK means no modifier;
	// 0..3 are valid placements per the Noise spec. When set, parseNoise
	// propagates the value into noise.Config.PresharedKeyPlacement so
	// flynn/noise inserts the MixKeyAndHash(psk) token at the right
	// position in the handshake.
	PSKPlacement int8

	PSK     string
	RStatic string
	LStatic string

	// Transport selects the wire-framing layer: "raw" (default),
	// "noisesocket", or — once implemented — "bolt8".
	Transport string
	// Prologue is the application-prologue byte sequence mixed into the
	// handshake hash. NoiseSocket prepends its spec-mandated prefix.
	Prologue string
	// NegotiationData is the NoiseSocket-only negotiation_data field sent
	// with the initiator's first handshake message.
	NegotiationData string
	// Validate, when non-empty, causes the CLI to run ValidateStaticKey
	// against this base64 string and exit. Useful for sanity-checking a
	// -rstatic value before opening a real connection.
	Validate string

	// IPv4Only / IPv6Only restrict address resolution to one family,
	// mapping to the -4 / -6 flags. They are mutually exclusive; when
	// both are false the network is the family-agnostic "tcp".
	IPv4Only bool
	IPv6Only bool

	// TimeoutSeconds is the -w value: the maximum time (in seconds) a
	// dial+handshake may take, and the idle timeout applied to an
	// established connection's data phase. Zero means no timeout.
	TimeoutSeconds int

	// NoiseSocket negotiation (noisesocket transport only). Negotiation
	// activates when NSFallback (client) or NSSupport (server) is set.
	//
	// NSFallback is the initiator's comma-separated list of protocols it
	// will accept if the responder asks it to retry or switch.
	NSFallback string
	// NSSupport is the responder's comma-separated list of supported
	// protocols, in preference order.
	NSSupport string
	// NSPolicy is the responder's action when the proposed protocol is
	// unsupported: "reject" (default), "retry", or "switch".
	NSPolicy string
}

// splitList splits a comma-separated flag value into a trimmed,
// empty-free slice. Returns nil for an empty string.
func splitList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// negotiationEnabled reports whether the NoiseSocket negotiation layer is
// active for this config (client proposes fallbacks, or server advertises
// supported protocols).
func (config *Config) negotiationEnabled() bool {
	if config.Listen {
		return config.NSSupport != ""
	}
	return config.NSFallback != ""
}

// buildNoiseConfigForProtocol is the factory the noisesocket negotiation
// layer uses to materialize a noise.Config for a retry/switch target.
func (config *Config) buildNoiseConfigForProtocol(protocol string, initiator bool) (*noise.Config, error) {
	return config.buildNoise25519Config(protocol, initiator)
}

// network returns the net package network string for the selected
// address family: "tcp4" with -4, "tcp6" with -6, or "tcp" otherwise.
func (config *Config) network() string {
	switch {
	case config.IPv4Only:
		return "tcp4"
	case config.IPv6Only:
		return "tcp6"
	default:
		return "tcp"
	}
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
		config.Pattern, config.DHFunc, config.CipherFunc, config.HashFunc, config.PSKPlacement, err = parseProtocolName(config.Protocol)
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
	if config.IPv4Only && config.IPv6Only {
		return nil, errors.New("-4 and -6 are mutually exclusive")
	}
	if config.TimeoutSeconds < 0 {
		return nil, fmt.Errorf("invalid -w timeout %d: must be >= 0", config.TimeoutSeconds)
	}
	if err := config.validateNegotiation(); err != nil {
		return nil, err
	}
	if config.Transport == "whatsapp" {
		// WhatsApp speaks a fixed protocol; default -proto to it (so a
		// static keypair is provisioned for either role) unless the user
		// picked a non-default one. The transport runs its own XX state
		// machine, so any other protocol would be silently ignored —
		// reject it instead of misleading the user.
		switch config.Protocol {
		case "", "Noise_NN_25519_AESGCM_SHA256", "Noise_XX_25519_AESGCM_SHA256":
			config.Protocol = "Noise_XX_25519_AESGCM_SHA256"
		default:
			return nil, fmt.Errorf("-transport whatsapp only supports Noise_XX_25519_AESGCM_SHA256, not %q", config.Protocol)
		}
	}

	return config.parseNoise()
}

// validateNegotiation checks the NoiseSocket negotiation flag combinations.
func (config *Config) validateNegotiation() error {
	anyNeg := config.NSFallback != "" || config.NSSupport != "" || config.NSPolicy != ""
	if !anyNeg {
		return nil
	}
	if config.Transport != "noisesocket" {
		return errors.New("-ns-fallback/-ns-support/-ns-policy require -transport noisesocket")
	}
	if config.Listen {
		if config.NSFallback != "" {
			return errors.New("-ns-fallback is a client option; the listener uses -ns-support")
		}
	} else {
		if config.NSSupport != "" {
			return errors.New("-ns-support is a listener option; the client uses -ns-fallback")
		}
		if config.NSPolicy != "" {
			return errors.New("-ns-policy is a listener option")
		}
	}
	switch config.NSPolicy {
	case "", "reject", "retry", "switch":
	default:
		return fmt.Errorf("invalid -ns-policy %q: must be reject, retry, or switch", config.NSPolicy)
	}
	return nil
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
