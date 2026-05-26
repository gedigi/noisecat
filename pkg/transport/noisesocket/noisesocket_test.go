package noisesocket

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/gedigi/noisecat/pkg/transport"
)

func nnCfg(initiator bool) *noise.Config {
	return &noise.Config{
		Pattern:     noise.HandshakeNN,
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
		Random:      rand.Reader,
		Initiator:   initiator,
	}
}

// TestRoundTripEmptyNegotiation: noisecat ↔ noisecat over NoiseSocket
// with neither side supplying negotiation data — the prologue is
// "NoiseSocketInit1" + 0x0000.
func TestRoundTripEmptyNegotiation(t *testing.T) {
	tp := New()
	l, err := tp.Listen("tcp", "127.0.0.1:0", nnCfg(false), transport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	addr := l.Addr().(*net.TCPAddr)
	c, err := tp.Dial("tcp", "127.0.0.1:"+strconv.Itoa(addr.Port), "", nnCfg(true), transport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	want := []byte("noisesocket-round-trip-empty")
	if _, err := c.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}

	c.Close()
	l.Close()
	wg.Wait()
}

// TestRoundTripWithNegotiation drives the spec's prologue formula:
// "NoiseSocketInit1" || neg_data_len || neg_data is mixed into both
// peers' handshake hashes. A mismatch (different neg_data on responder
// vs initiator) MUST fail the handshake.
func TestRoundTripWithNegotiation(t *testing.T) {
	const negStr = "noisecat-test-negotiation"
	negData := []byte(negStr)

	tp := New()
	l, err := tp.Listen("tcp", "127.0.0.1:0", nnCfg(false), transport.Options{NegotiationData: negData})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	addr := l.Addr().(*net.TCPAddr)
	c, err := tp.Dial("tcp", "127.0.0.1:"+strconv.Itoa(addr.Port), "", nnCfg(true), transport.Options{NegotiationData: negData})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	want := []byte("with-negotiation")
	if _, err := c.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}

	c.Close()
	l.Close()
	wg.Wait()
}

// TestNegotiationMismatchFails ensures that if responder and initiator
// disagree on the initial negotiation data, the handshake aborts — the
// prologues won't match and Decrypt will fail. Catches downgrade attacks.
func TestNegotiationMismatchFails(t *testing.T) {
	tp := New()
	// Server expects "right".
	l, err := tp.Listen("tcp", "127.0.0.1:0", nnCfg(false), transport.Options{NegotiationData: []byte("right")})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Trigger handshake by attempting a read; expect failure.
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
	}()

	addr := l.Addr().(*net.TCPAddr)
	// Client sends "wrong".
	c, err := tp.Dial("tcp", "127.0.0.1:"+strconv.Itoa(addr.Port), "", nnCfg(true), transport.Options{NegotiationData: []byte("wrong")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := c.Write([]byte("payload")); err == nil {
		// Server-side handshake should reject the mismatched negData and
		// close the conn. Even if the initial write succeeds (it's the
		// initiator's first message, before the responder validates),
		// the subsequent read MUST fail.
		buf := make([]byte, 1)
		if _, err := c.Read(buf); err == nil {
			t.Fatal("expected handshake to fail on negotiation_data mismatch")
		}
	}
}

// TestPrologueFormula sanity-checks buildPrologue against the spec's
// hex layout: magic || 2-byte BE length || data.
func TestPrologueFormula(t *testing.T) {
	tests := []struct {
		name     string
		negData  []byte
		appExt   []byte
		expected []byte
	}{
		{
			name:     "empty",
			expected: append([]byte("NoiseSocketInit1"), 0x00, 0x00),
		},
		{
			name:    "negotiation only",
			negData: []byte("hi"),
			expected: append(append([]byte("NoiseSocketInit1"), 0x00, 0x02), []byte("hi")...),
		},
		{
			name:    "negotiation + app prologue",
			negData: []byte("ab"),
			appExt:  []byte("x"),
			expected: append(append(append([]byte("NoiseSocketInit1"), 0x00, 0x02), []byte("ab")...), 'x'),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildPrologue(tc.negData, tc.appExt)
			if !bytes.Equal(got, tc.expected) {
				t.Fatalf("got %x want %x", got, tc.expected)
			}
		})
	}
}
