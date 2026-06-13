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
	"time"

	"github.com/flynn/noise"
)

// Transport is the contract every wire-protocol implementation honors.
// Implementations are stateless; per-connection state lives on the returned
// net.Conn / net.Listener values.
//
// Per-transport semantics — particularly the handling of Options.Prologue —
// vary by implementation; see the field-level docstrings on Options for the
// specific rules each transport applies.
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

	// DialTimeout bounds how long a Dial may take to establish the TCP
	// connection and complete the Noise handshake. Zero means no limit.
	// Honored by every transport's Dial; ignored by Listen. Maps to the
	// noisecat -w flag.
	DialTimeout time.Duration

	// Negotiation, when non-nil, activates the noisesocket transport's
	// Reject/Retry/Switch negotiation layer (noisecat v1 convention).
	// Other transports ignore it. When nil, noisesocket keeps its
	// spec-compliant, Accept-only behavior. See the Negotiation docs.
	Negotiation *Negotiation
}

// NegotiationPolicy is the responder's action when the initiator proposes
// a protocol the responder does not support.
type NegotiationPolicy string

const (
	// PolicyReject closes the connection with a reason.
	PolicyReject NegotiationPolicy = "reject"
	// PolicyRetry asks the initiator to retry with a supported protocol.
	PolicyRetry NegotiationPolicy = "retry"
	// PolicySwitch inverts roles: the responder becomes the initiator of
	// its preferred protocol.
	PolicySwitch NegotiationPolicy = "switch"
)

// Negotiation carries the data the noisesocket transport needs to run the
// noisecat v1 negotiation layer. The BuildConfig factory keeps Noise
// protocol/key parsing in the caller (pkg/noisecat) so the transport stays
// a pure framing layer.
//
// Fields are split by role; a Dial uses the initiator fields, a Listen's
// accepted conns use the responder fields. BuildConfig and AppData are
// shared.
type Negotiation struct {
	// BuildConfig returns a ready noise.Config for the named protocol in
	// the requested role (initiator or responder), with the key material
	// the pattern requires already loaded. It is called once per handshake
	// attempt (a retry or switch triggers another call). Returns an error
	// if the protocol is unknown or required keys are missing.
	BuildConfig func(protocol string, initiator bool) (*noise.Config, error)

	// AppData is the user's opaque negotiation payload (-negotiation),
	// carried base64-encoded in the initiator's proposal as data=.
	AppData []byte

	// Initiator-side fields.

	// Proposed is the protocol name the initiator advertises first.
	Proposed string
	// Fallback lists additional protocols the initiator will accept if the
	// responder asks it to retry or switch. The proposed protocol is always
	// implicitly allowed.
	Fallback []string

	// Responder-side fields.

	// Supported lists the protocols the responder accepts, in preference
	// order (the first is used as the retry/switch target).
	Supported []string
	// Policy is the action taken when the proposed protocol is unsupported.
	Policy NegotiationPolicy
}
