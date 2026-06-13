package noisesocket

import (
	"errors"
	"fmt"

	"github.com/flynn/noise"
	"github.com/gedigi/noisecat/pkg/transport"
)

// handshakeNegotiated runs the noisecat v1 negotiation layer in place of
// the legacy Accept-only handshake. Called from Handshake (which holds
// handshakeMu) when c.neg != nil.
func (c *Conn) handshakeNegotiated() error {
	if c.isClient {
		return c.negotiateInitiator()
	}
	return c.negotiateResponder()
}

// newHS builds a HandshakeState from cfg with the given prologue, without
// mutating the caller's cfg.
func newHS(cfg *noise.Config, prologue []byte) (*noise.HandshakeState, error) {
	cc := *cfg
	cc.Prologue = prologue
	hs, err := noise.NewHandshakeState(cc)
	if err != nil {
		return nil, fmt.Errorf("noisesocket: NewHandshakeState: %w", err)
	}
	return hs, nil
}

// frameBytes encodes a handshake frame (neg_len||neg||msg_len||msg) — the
// exact wire bytes — so both peers can record an identical transcript for
// prologue chaining.
func frameBytes(neg, msg []byte) []byte {
	buf := make([]byte, 0, 4+len(neg)+len(msg))
	buf = putUint16(buf, len(neg))
	buf = append(buf, neg...)
	buf = putUint16(buf, len(msg))
	buf = append(buf, msg...)
	return buf
}

// writeFrameAndRecord writes a handshake frame and returns its exact wire
// bytes (for transcript recording).
func (c *Conn) writeFrameAndRecord(neg, msg []byte) ([]byte, error) {
	if len(neg) > MaxMessageLen {
		return nil, errors.New("noisesocket: negotiation_data exceeds 16-bit length")
	}
	if len(msg) > MaxMessageLen {
		return nil, errors.New("noisesocket: noise_message exceeds 16-bit length")
	}
	fb := frameBytes(neg, msg)
	if _, err := c.conn.Write(fb); err != nil {
		return nil, err
	}
	return fb, nil
}

// prologueWith builds the chained prologue for an attempt: the standard
// NoiseSocket formula over initNeg, followed by the transcript of all
// frames exchanged in prior (dead) attempts.
func (c *Conn) prologueWith(initNeg, transcript []byte) []byte {
	p := buildPrologue(initNeg, c.appPrologue)
	return append(p, transcript...)
}

// driveFrom runs the remaining Noise handshake messages starting at
// startIndex. All frames it writes carry empty negotiation_data (the
// neg-carrying first frames are handled by the caller). If pending is
// non-nil it is consumed as the inbound message at the first read turn.
func (c *Conn) driveFrom(hs *noise.HandshakeState, total int, initiator bool, startIndex int, pending []byte) error {
	c.hs = hs
	for i := startIndex; i < total; i++ {
		// The initiator writes even-indexed messages, the responder odd.
		writeTurn := (i%2 == 0) == initiator
		if writeTurn {
			msg, cs1, cs2, err := hs.WriteMessage(nil, nil)
			if err != nil {
				return fmt.Errorf("noisesocket: WriteMessage: %w", err)
			}
			if _, err := c.writeFrameAndRecord(nil, msg); err != nil {
				return err
			}
			if cs1 != nil {
				c.assignCipherStates(cs1, cs2)
			}
		} else {
			var in []byte
			if pending != nil {
				in, pending = pending, nil
			} else {
				_, m, err := readHandshakeFrame(c.conn)
				if err != nil {
					return err
				}
				in = m
			}
			_, cs1, cs2, err := hs.ReadMessage(nil, in)
			if err != nil {
				return fmt.Errorf("noisesocket: ReadMessage: %w", err)
			}
			if cs1 != nil {
				c.assignCipherStates(cs1, cs2)
			}
		}
	}
	c.handshakeDone = true
	return nil
}

// negotiateInitiator drives the initiator side of the negotiation: propose
// a protocol, then react to the responder's Accept / Reject / Retry /
// Switch response.
func (c *Conn) negotiateInitiator() error {
	proto := c.neg.Proposed
	var transcript []byte

	for attempt := 0; attempt < maxNegAttempts; attempt++ {
		cfg, err := c.neg.BuildConfig(proto, true)
		if err != nil {
			return fmt.Errorf("noisesocket: build config for %q: %w", proto, err)
		}
		initNeg := encodeProposal(proto, c.neg.AppData)
		hs, err := newHS(cfg, c.prologueWith(initNeg, transcript))
		if err != nil {
			return err
		}

		msg1, cs1, _, err := hs.WriteMessage(nil, nil)
		if err != nil {
			return fmt.Errorf("noisesocket: WriteMessage: %w", err)
		}
		if cs1 != nil {
			return errors.New("noisesocket: negotiation unsupported for single-message patterns")
		}
		sentFrame, err := c.writeFrameAndRecord(initNeg, msg1)
		if err != nil {
			return err
		}

		rneg, rmsg, err := readHandshakeFrame(c.conn)
		if err != nil {
			return err
		}

		// Empty negotiation_data => Accept; rmsg is handshake message 1.
		if len(rneg) == 0 {
			return c.driveFrom(hs, len(cfg.Pattern.Messages), true, 1, rmsg)
		}

		resp, err := parseNeg(rneg)
		if err != nil {
			return err
		}
		switch resp.Action {
		case actReject:
			return fmt.Errorf("noisesocket: peer rejected negotiation: %s", resp.Reason)

		case actRetry:
			if !allowedProtocol(resp.Proto, c.neg.Proposed, c.neg.Fallback) {
				return fmt.Errorf("noisesocket: responder asked to retry with disallowed protocol %q", resp.Proto)
			}
			transcript = append(transcript, sentFrame...)
			transcript = append(transcript, frameBytes(rneg, rmsg)...)
			proto = resp.Proto

		case actSwitch:
			if !allowedProtocol(resp.Proto, c.neg.Proposed, c.neg.Fallback) {
				return fmt.Errorf("noisesocket: responder asked to switch to disallowed protocol %q", resp.Proto)
			}
			// The switch frame's noise_message is the new handshake's
			// message 0 (active), so only our dead proposal joins the
			// transcript. We become the responder of resp.Proto.
			transcript = append(transcript, sentFrame...)
			scfg, err := c.neg.BuildConfig(resp.Proto, false)
			if err != nil {
				return fmt.Errorf("noisesocket: build config for %q: %w", resp.Proto, err)
			}
			hs2, err := newHS(scfg, c.prologueWith(rneg, transcript))
			if err != nil {
				return err
			}
			return c.driveFrom(hs2, len(scfg.Pattern.Messages), false, 0, rmsg)

		default:
			return fmt.Errorf("noisesocket: unexpected action %q in response", resp.Action)
		}
	}
	return errors.New("noisesocket: negotiation exceeded maximum attempts")
}

// negotiateResponder drives the responder side: read the initiator's
// proposal and Accept it, or apply the configured policy
// (Reject / Retry / Switch) when the proposed protocol is unsupported.
func (c *Conn) negotiateResponder() error {
	var transcript []byte

	for attempt := 0; attempt < maxNegAttempts; attempt++ {
		ineg, imsg, err := readHandshakeFrame(c.conn)
		if err != nil {
			return err
		}
		recvFrame := frameBytes(ineg, imsg)
		prop, err := parseNeg(ineg)
		if err != nil {
			return err
		}
		if prop.Action != "" {
			return fmt.Errorf("noisesocket: initiator sent unexpected action %q", prop.Action)
		}
		proto := prop.Proto

		if supports(proto, c.neg.Supported) {
			cfg, err := c.neg.BuildConfig(proto, false)
			if err != nil {
				return fmt.Errorf("noisesocket: build config for %q: %w", proto, err)
			}
			hs, err := newHS(cfg, c.prologueWith(ineg, transcript))
			if err != nil {
				return err
			}
			return c.driveFrom(hs, len(cfg.Pattern.Messages), false, 0, imsg)
		}

		policy := c.neg.Policy
		if policy == "" {
			policy = transport.PolicyReject
		}
		switch policy {
		case transport.PolicyReject:
			reason := fmt.Sprintf("protocol %q not supported", proto)
			if _, err := c.writeFrameAndRecord(encodeResponse(actReject, "", reason), nil); err != nil {
				return err
			}
			return fmt.Errorf("noisesocket: rejected initiator: %s", reason)

		case transport.PolicyRetry:
			target := c.neg.Supported[0]
			sentFrame, err := c.writeFrameAndRecord(encodeResponse(actRetry, target, ""), nil)
			if err != nil {
				return err
			}
			transcript = append(transcript, recvFrame...)
			transcript = append(transcript, sentFrame...)

		case transport.PolicySwitch:
			target := c.neg.Supported[0]
			cfg, err := c.neg.BuildConfig(target, true)
			if err != nil {
				return fmt.Errorf("noisesocket: build config for %q: %w", target, err)
			}
			switchNeg := encodeResponse(actSwitch, target, "")
			// The dead proposal joins the transcript; our switch frame is
			// the new handshake's message 0 (active), so it does not.
			transcript = append(transcript, recvFrame...)
			hs, err := newHS(cfg, c.prologueWith(switchNeg, transcript))
			if err != nil {
				return err
			}
			msg0, cs1, _, err := hs.WriteMessage(nil, nil)
			if err != nil {
				return fmt.Errorf("noisesocket: WriteMessage: %w", err)
			}
			if cs1 != nil {
				return errors.New("noisesocket: switch unsupported for single-message patterns")
			}
			if _, err := c.writeFrameAndRecord(switchNeg, msg0); err != nil {
				return err
			}
			return c.driveFrom(hs, len(cfg.Pattern.Messages), true, 1, nil)

		default:
			return fmt.Errorf("noisesocket: unknown negotiation policy %q", policy)
		}
	}
	return errors.New("noisesocket: negotiation exceeded maximum attempts")
}
