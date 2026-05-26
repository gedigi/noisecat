// Package transport defines the pluggable transport interface noisecat uses
// to layer different framings on top of the Noise Protocol Framework. The
// noise cryptography itself is identical across implementations (provided by
// flynn/noise); each transport differs only in how messages are framed on
// the wire, what prologue is mixed into the handshake hash, and any extras
// like re-keying or negotiation data.
//
// The package ships three concrete transports:
//
//   - "raw"         (sub-package raw)         — noisecat's historical framing:
//     a 2-byte big-endian length prefix on every Noise message, no
//     negotiation, no padding, no prologue. Default; preserves backwards
//     compatibility with older noisecat releases.
//   - "noisesocket" (sub-package noisesocket) — the NoiseSocket spec:
//     handshake messages carry an optional negotiation_data field;
//     encrypted payloads contain an inner body_len plus arbitrary padding;
//     the handshake hash is initialised with "NoiseSocketInit1" plus the
//     initial negotiation_data.
//   - "bolt8"       (sub-package bolt8)       — Lightning Network's BOLT-8:
//     secp256k1 DH, fixed-size handshake acts (50/50/66 bytes) with a
//     1-byte version prefix and no length field, encrypted 2-byte length
//     headers + AEAD-tagged payloads, rekey every 1000 messages,
//     prologue "lightning".
package transport

import (
	"net"

	"github.com/flynn/noise"
)

// Transport is the contract every wire-protocol implementation honors.
// Implementations are stateless; per-connection state lives on the returned
// net.Conn / net.Listener values.
type Transport interface {
	// Name returns the human-readable identifier (e.g. "raw", "noisesocket",
	// "bolt8"). Matches what the noisecat -transport flag accepts.
	Name() string

	// Dial opens a Noise-secured connection to addr. localAddr may be empty
	// (use system default) or "host:port" / "[host]:port" for IPv6.
	Dial(network, addr, localAddr string, cfg *noise.Config, opts Options) (net.Conn, error)

	// Listen creates a transport-specific listener bound to laddr. The
	// listener's Accept returns net.Conn values that perform the handshake
	// on first Read/Write.
	Listen(network, laddr string, cfg *noise.Config, opts Options) (net.Listener, error)
}

// Options carries transport-specific knobs that don't belong on noise.Config.
// All fields are optional; transports ignore options they don't recognize.
type Options struct {
	// Prologue is mixed into the handshake hash. Different transports use
	// it differently:
	//   - raw         passes it through unchanged (default: empty)
	//   - noisesocket prepends "NoiseSocketInit1" + neg_data_len + neg_data
	//     to whatever is here (per spec)
	//   - bolt8       defaults this to "lightning" if empty
	Prologue []byte

	// NegotiationData is the variable-length blob NoiseSocket sends with
	// each handshake message. Ignored by transports that don't have a
	// notion of negotiation (raw, bolt8).
	NegotiationData []byte
}
