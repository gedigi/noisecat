package whatsapp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// This file contains a minimal hand-rolled protobuf codec covering just the
// messages WhatsApp's Noise handshake uses (HandshakeMessage and, in cert.go,
// CertChain). Pulling in google.golang.org/protobuf + generated code would be
// far more weight than these few fixed-shape messages warrant.

// HandshakeMessage / Hello / Finish field numbers (verified against
// whatsmeow's waWa6 proto). Wire type is LEN (2) for every field below.
const (
	fHMClientHello  = 2 // HandshakeMessage.clientHello
	fHMServerHello  = 3 // HandshakeMessage.serverHello
	fHMClientFinish = 4 // HandshakeMessage.clientFinish

	fHelloEphemeral = 1 // {Client,Server}Hello.ephemeral
	fHelloStatic    = 2 // {Client,Server}Hello.static
	fHelloPayload   = 3 // {Client,Server}Hello.payload

	fFinishStatic  = 1 // ClientFinish.static
	fFinishPayload = 2 // ClientFinish.payload
)

// appendVarint appends v as a base-128 varint.
func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// appendBytesField appends a length-delimited (wire type 2) field.
func appendBytesField(b []byte, field int, val []byte) []byte {
	b = appendVarint(b, uint64(field)<<3|2)
	b = appendVarint(b, uint64(len(val)))
	return append(b, val...)
}

// appendVarintField appends a varint (wire type 0) field.
func appendVarintField(b []byte, field int, v uint64) []byte {
	b = appendVarint(b, uint64(field)<<3)
	return appendVarint(b, v)
}

// pbField is one decoded protobuf field.
type pbField struct {
	num  int
	wire int
	data []byte // populated for wire type 2 (LEN)
	val  uint64 // populated for wire type 0 (VARINT)
}

// maxPbFields caps how many fields pbParse will decode from one message. The
// handshake messages this codec handles have a handful of fields each; the
// cap stops a malicious peer from turning a large frame into a huge []pbField
// allocation before any authentication has happened.
const maxPbFields = 64

// pbParse decodes a flat list of protobuf fields. Nested messages are
// returned as raw bytes (re-parse with pbParse). Group wire types (3/4) are
// rejected; 32/64-bit fixed fields are skipped.
func pbParse(b []byte) ([]pbField, error) {
	var out []pbField
	for i := 0; i < len(b); {
		if len(out) >= maxPbFields {
			return nil, errors.New("whatsapp: too many protobuf fields")
		}
		tag, n := binary.Uvarint(b[i:])
		if n <= 0 {
			return nil, errors.New("whatsapp: malformed protobuf tag")
		}
		i += n
		field := int(tag >> 3)
		wire := int(tag & 7)
		switch wire {
		case 0: // varint
			v, n := binary.Uvarint(b[i:])
			if n <= 0 {
				return nil, errors.New("whatsapp: malformed protobuf varint")
			}
			i += n
			out = append(out, pbField{num: field, wire: 0, val: v})
		case 2: // length-delimited
			l, n := binary.Uvarint(b[i:])
			if n <= 0 {
				return nil, errors.New("whatsapp: malformed protobuf length")
			}
			i += n
			if l > uint64(len(b)-i) {
				return nil, errors.New("whatsapp: protobuf length exceeds buffer")
			}
			out = append(out, pbField{num: field, wire: 2, data: b[i : i+int(l)]})
			i += int(l)
		case 5: // 32-bit
			if len(b)-i < 4 {
				return nil, errors.New("whatsapp: truncated 32-bit field")
			}
			i += 4
		case 1: // 64-bit
			if len(b)-i < 8 {
				return nil, errors.New("whatsapp: truncated 64-bit field")
			}
			i += 8
		default:
			return nil, fmt.Errorf("whatsapp: unsupported protobuf wire type %d", wire)
		}
	}
	return out, nil
}

// nestedBytes returns the data of the first LEN field with the given number.
func nestedBytes(fields []pbField, num int) []byte {
	for _, f := range fields {
		if f.num == num && f.wire == 2 {
			return f.data
		}
	}
	return nil
}

// marshalClientHello builds HandshakeMessage{clientHello{ephemeral}}.
func marshalClientHello(ephemeral []byte) []byte {
	inner := appendBytesField(nil, fHelloEphemeral, ephemeral)
	return appendBytesField(nil, fHMClientHello, inner)
}

// marshalClientFinish builds HandshakeMessage{clientFinish{static, payload}}.
func marshalClientFinish(static, payload []byte) []byte {
	inner := appendBytesField(nil, fFinishStatic, static)
	inner = appendBytesField(inner, fFinishPayload, payload)
	return appendBytesField(nil, fHMClientFinish, inner)
}

// marshalServerHello builds HandshakeMessage{serverHello{ephemeral,static,payload}}
// (sent by the responder side of a peer-to-peer handshake).
func marshalServerHello(ephemeral, static, payload []byte) []byte {
	inner := appendBytesField(nil, fHelloEphemeral, ephemeral)
	inner = appendBytesField(inner, fHelloStatic, static)
	inner = appendBytesField(inner, fHelloPayload, payload)
	return appendBytesField(nil, fHMServerHello, inner)
}

// unmarshalClientHello extracts the ephemeral from a ClientHello message.
func unmarshalClientHello(b []byte) ([]byte, error) {
	top, err := pbParse(b)
	if err != nil {
		return nil, err
	}
	ch := nestedBytes(top, fHMClientHello)
	if ch == nil {
		return nil, errors.New("whatsapp: handshake message has no clientHello")
	}
	fields, err := pbParse(ch)
	if err != nil {
		return nil, err
	}
	eph := nestedBytes(fields, fHelloEphemeral)
	if len(eph) != 32 {
		return nil, errors.New("whatsapp: clientHello ephemeral is not 32 bytes")
	}
	return eph, nil
}

// unmarshalClientFinish extracts static+payload from a ClientFinish message.
func unmarshalClientFinish(b []byte) (static, payload []byte, err error) {
	top, err := pbParse(b)
	if err != nil {
		return nil, nil, err
	}
	cf := nestedBytes(top, fHMClientFinish)
	if cf == nil {
		return nil, nil, errors.New("whatsapp: handshake message has no clientFinish")
	}
	fields, err := pbParse(cf)
	if err != nil {
		return nil, nil, err
	}
	static = nestedBytes(fields, fFinishStatic)
	payload = nestedBytes(fields, fFinishPayload)
	if static == nil {
		return nil, nil, errors.New("whatsapp: clientFinish missing static")
	}
	return static, payload, nil
}

// serverHello holds the three fields of HandshakeMessage.serverHello.
type serverHello struct {
	ephemeral []byte
	static    []byte
	payload   []byte
}

// unmarshalServerHello extracts the serverHello from a HandshakeMessage.
func unmarshalServerHello(b []byte) (*serverHello, error) {
	top, err := pbParse(b)
	if err != nil {
		return nil, err
	}
	shBytes := nestedBytes(top, fHMServerHello)
	if shBytes == nil {
		return nil, errors.New("whatsapp: handshake response has no serverHello")
	}
	fields, err := pbParse(shBytes)
	if err != nil {
		return nil, err
	}
	sh := &serverHello{
		ephemeral: nestedBytes(fields, fHelloEphemeral),
		static:    nestedBytes(fields, fHelloStatic),
		payload:   nestedBytes(fields, fHelloPayload),
	}
	if len(sh.ephemeral) != 32 || sh.static == nil || sh.payload == nil {
		return nil, errors.New("whatsapp: serverHello missing ephemeral/static/payload")
	}
	return sh, nil
}
