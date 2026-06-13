package whatsapp

import (
	"bytes"
	"io"
	"testing"
)

// memRWC is a simple in-memory ReadWriteCloser (writes append, reads consume).
type memRWC struct{ buf bytes.Buffer }

func (m *memRWC) Read(p []byte) (int, error)  { return m.buf.Read(p) }
func (m *memRWC) Write(p []byte) (int, error) { return m.buf.Write(p) }
func (m *memRWC) Close() error                { return nil }

// oneByteRWC reads at most one byte per Read, to exercise reassembly.
type oneByteRWC struct {
	data []byte
	pos  int
}

func (c *oneByteRWC) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	p[0] = c.data[c.pos]
	c.pos++
	return 1, nil
}
func (c *oneByteRWC) Write(p []byte) (int, error) { c.data = append(c.data, p...); return len(p), nil }
func (c *oneByteRWC) Close() error                { return nil }

func TestFramingRoundTrip(t *testing.T) {
	rwc := &memRWC{}
	client := newClientFramedConn(rwc)
	f1 := []byte("first-frame-payload")
	f2 := bytes.Repeat([]byte{0x5A}, 500)
	if err := client.writeFrame(f1); err != nil {
		t.Fatal(err)
	}
	if err := client.writeFrame(f2); err != nil {
		t.Fatal(err)
	}

	server := &framedConn{rw: rwc, readHeader: true}
	got1, err := server.readFrame()
	if err != nil {
		t.Fatal(err)
	}
	got2, err := server.readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got1, f1) || !bytes.Equal(got2, f2) {
		t.Fatal("frame round-trip mismatch")
	}
}

func TestFramingFirstFrameCarriesWAHeader(t *testing.T) {
	rwc := &memRWC{}
	newClientFramedConn(rwc).writeFrame([]byte("x"))
	if !bytes.HasPrefix(rwc.buf.Bytes(), waConnHeader) {
		t.Fatalf("first frame should start with WA header, got %x", rwc.buf.Bytes()[:4])
	}
}

func TestFramingReassemblyOneByteAtATime(t *testing.T) {
	// Produce the wire bytes with a client framer.
	src := &memRWC{}
	client := newClientFramedConn(src)
	payload := bytes.Repeat([]byte{0xC3}, 1000)
	if err := client.writeFrame(payload); err != nil {
		t.Fatal(err)
	}
	// Replay them one byte per Read.
	server := &framedConn{rw: &oneByteRWC{data: src.buf.Bytes()}, readHeader: true}
	got, err := server.readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("reassembled frame mismatch")
	}
}

func TestFramingMissingHeader(t *testing.T) {
	// Stream that does not begin with the WA header.
	rwc := &memRWC{}
	rwc.buf.Write([]byte{0x00, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x00})
	server := &framedConn{rw: rwc, readHeader: true}
	if _, err := server.readFrame(); err == nil {
		t.Fatal("expected missing-WA-header error")
	}
}
