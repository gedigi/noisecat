package noisesocket

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// maxNegAttempts bounds the retry/switch chain so a misbehaving (or
// malicious) peer cannot drive an unbounded negotiation loop. Counts the
// total number of handshake attempts, including the first.
const maxNegAttempts = 4

// negVersion is the value of the ns= field for this revision of the
// noisecat negotiation convention.
const negVersion = "1"

// negMsg is a parsed noisecat v1 negotiation_data payload. It is either an
// initiator proposal (Action == "", Proto set) or a responder response
// (Action set).
type negMsg struct {
	Action string // "" (proposal), "reject", "retry", "switch"
	Proto  string // proposed / target protocol name
	Reason string // reject reason
	Data   []byte // decoded application payload (proposals only)
}

const (
	actReject = "reject"
	actRetry  = "retry"
	actSwitch = "switch"
)

// encodeProposal builds the initiator's first-frame negotiation_data:
//
//	ns=1;proto=<name>;data=<base64(appData)>
//
// The data field is omitted when appData is empty.
func encodeProposal(proto string, appData []byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "ns=%s;proto=%s", negVersion, proto)
	if len(appData) > 0 {
		b.WriteString(";data=")
		b.WriteString(base64.StdEncoding.EncodeToString(appData))
	}
	return []byte(b.String())
}

// encodeResponse builds a responder action negotiation_data. proto is used
// for retry/switch; reason is used for reject.
func encodeResponse(action, proto, reason string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "ns=%s;action=%s", negVersion, action)
	if proto != "" {
		b.WriteString(";proto=")
		b.WriteString(proto)
	}
	if reason != "" {
		b.WriteString(";reason=")
		b.WriteString(reason)
	}
	return []byte(b.String())
}

// parseNeg parses a noisecat v1 negotiation_data payload. It rejects
// payloads with a missing/unknown version or an unknown action.
func parseNeg(raw []byte) (negMsg, error) {
	var m negMsg
	if len(raw) == 0 {
		return m, errors.New("noisesocket: empty negotiation_data")
	}
	seenVersion := false
	for _, field := range strings.Split(string(raw), ";") {
		if field == "" {
			continue
		}
		k, v, ok := strings.Cut(field, "=")
		if !ok {
			return m, fmt.Errorf("noisesocket: malformed negotiation field %q", field)
		}
		switch k {
		case "ns":
			if v != negVersion {
				return m, fmt.Errorf("noisesocket: unsupported negotiation version %q", v)
			}
			seenVersion = true
		case "action":
			switch v {
			case actReject, actRetry, actSwitch:
				m.Action = v
			default:
				return m, fmt.Errorf("noisesocket: unknown negotiation action %q", v)
			}
		case "proto":
			m.Proto = v
		case "reason":
			m.Reason = v
		case "data":
			d, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return m, fmt.Errorf("noisesocket: invalid data field: %w", err)
			}
			m.Data = d
		default:
			// Unknown keys are ignored for forward-compatibility.
		}
	}
	if !seenVersion {
		return m, errors.New("noisesocket: negotiation_data missing ns= version")
	}
	if m.Action == "" && m.Proto == "" {
		return m, errors.New("noisesocket: proposal missing proto=")
	}
	if (m.Action == actRetry || m.Action == actSwitch) && m.Proto == "" {
		return m, fmt.Errorf("noisesocket: %s action missing proto=", m.Action)
	}
	return m, nil
}

// allowedProtocol reports whether name is the proposed protocol or one of
// the initiator's declared fallbacks.
func allowedProtocol(name, proposed string, fallback []string) bool {
	return name == proposed || slices.Contains(fallback, name)
}

// supports reports whether name is in the responder's supported list.
func supports(name string, supported []string) bool {
	return slices.Contains(supported, name)
}
