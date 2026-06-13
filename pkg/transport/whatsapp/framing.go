package whatsapp

import (
	"errors"
	"fmt"
	"io"
)

// maxFrameLen is the largest payload a single frame can carry: the length
// prefix is 3 bytes, so 2^24-1.
const maxFrameLen = 1<<24 - 1

// framedConn layers WhatsApp's wire framing over a byte stream: an optional
// one-time 4-byte WA header followed by, for every frame, a 3-byte
// big-endian length prefix and the payload. Reads use io.ReadFull, so a
// frame that spans multiple underlying reads (e.g. websocket messages) is
// reassembled transparently.
type framedConn struct {
	rw          io.ReadWriteCloser
	writeHeader bool // prepend the WA header to the first frame written
	readHeader  bool // expect+consume the WA header before the first frame read
}

// newClientFramedConn frames as the WhatsApp client: it sends the WA header
// once and never expects one inbound (server frames carry no header).
func newClientFramedConn(rw io.ReadWriteCloser) *framedConn {
	return &framedConn{rw: rw, writeHeader: true}
}

// writeFrame writes one whole frame as a single underlying Write (so over a
// websocket it becomes exactly one binary message).
func (f *framedConn) writeFrame(payload []byte) error {
	if len(payload) > maxFrameLen {
		return fmt.Errorf("whatsapp: frame too large (%d > %d)", len(payload), maxFrameLen)
	}
	buf := make([]byte, 0, 4+3+len(payload))
	if f.writeHeader {
		buf = append(buf, waConnHeader...)
		f.writeHeader = false
	}
	n := len(payload)
	buf = append(buf, byte(n>>16), byte(n>>8), byte(n))
	buf = append(buf, payload...)
	_, err := f.rw.Write(buf)
	return err
}

// readFrame reads one whole frame.
func (f *framedConn) readFrame() ([]byte, error) {
	if f.readHeader {
		hdr := make([]byte, len(waConnHeader))
		if _, err := io.ReadFull(f.rw, hdr); err != nil {
			return nil, err
		}
		if hdr[0] != 'W' || hdr[1] != 'A' {
			return nil, errors.New("whatsapp: missing WA connection header")
		}
		f.readHeader = false
	}
	var lp [3]byte
	if _, err := io.ReadFull(f.rw, lp[:]); err != nil {
		return nil, err
	}
	n := int(lp[0])<<16 | int(lp[1])<<8 | int(lp[2])
	if n > maxFrameLen {
		return nil, fmt.Errorf("whatsapp: frame length %d exceeds max", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(f.rw, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
