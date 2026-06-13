package whatsapp

import (
	"bytes"
	"testing"
)

func TestClientHelloRoundTrip(t *testing.T) {
	eph := bytes.Repeat([]byte{0xAB}, 32)
	got, err := unmarshalClientHello(marshalClientHello(eph))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, eph) {
		t.Fatalf("ephemeral round-trip mismatch: %x", got)
	}
}

func TestServerHelloRoundTrip(t *testing.T) {
	eph := bytes.Repeat([]byte{0x01}, 32)
	static := bytes.Repeat([]byte{0x02}, 48)
	payload := bytes.Repeat([]byte{0x03}, 100)
	sh, err := unmarshalServerHello(marshalServerHello(eph, static, payload))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sh.ephemeral, eph) || !bytes.Equal(sh.static, static) || !bytes.Equal(sh.payload, payload) {
		t.Fatal("serverHello round-trip mismatch")
	}
}

func TestServerHelloRejectsShortEphemeral(t *testing.T) {
	bad := marshalServerHello(bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 48), []byte{3})
	if _, err := unmarshalServerHello(bad); err == nil {
		t.Fatal("expected error for 16-byte ephemeral")
	}
}

func TestClientFinishRoundTrip(t *testing.T) {
	static := bytes.Repeat([]byte{0x07}, 48)
	payload := bytes.Repeat([]byte{0x08}, 16)
	s, p, err := unmarshalClientFinish(marshalClientFinish(static, payload))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s, static) || !bytes.Equal(p, payload) {
		t.Fatal("clientFinish round-trip mismatch")
	}
}

func TestPbParseRejectsTruncatedLength(t *testing.T) {
	// tag for field 1 LEN (0x0A) + length 5 but no data
	if _, err := pbParse([]byte{0x0A, 0x05}); err == nil {
		t.Fatal("expected error for length exceeding buffer")
	}
}

func TestPbVarintRoundTrip(t *testing.T) {
	for _, v := range []uint64{0, 1, 127, 128, 300, 16384, 1 << 32} {
		enc := appendVarintField(nil, 1, v)
		fields, err := pbParse(enc)
		if err != nil {
			t.Fatal(err)
		}
		if len(fields) != 1 || fields[0].num != 1 || fields[0].val != v {
			t.Fatalf("varint %d round-trip failed: %+v", v, fields)
		}
	}
}
