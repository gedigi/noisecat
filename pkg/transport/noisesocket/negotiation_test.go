package noisesocket

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/gedigi/noisecat/pkg/transport"
)

// testFactory returns a BuildConfig that understands the short protocol
// identifiers "NN" and "XX" over 25519/AESGCM/SHA256. XX needs a local
// static keypair (transmitted in-handshake, so no prearranged remote
// static is required), which makes it usable in either role and across a
// role-inverting switch.
func testFactory() func(string, bool) (*noise.Config, error) {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	return func(proto string, initiator bool) (*noise.Config, error) {
		c := &noise.Config{CipherSuite: cs, Random: rand.Reader, Initiator: initiator}
		switch proto {
		case "NN":
			c.Pattern = noise.HandshakeNN
		case "XX":
			c.Pattern = noise.HandshakeXX
			kp, err := cs.GenerateKeypair(rand.Reader)
			if err != nil {
				return nil, err
			}
			c.StaticKeypair = kp
		default:
			return nil, fmt.Errorf("testFactory: unknown protocol %q", proto)
		}
		return c, nil
	}
}

// runNeg wires a client and server over net.Pipe with the given
// negotiation configs, runs both handshakes concurrently, and (on success)
// round-trips a payload client->server->client. It returns the first
// handshake error seen, or nil if everything succeeded.
func runNeg(t *testing.T, clientNeg, serverNeg *transport.Negotiation) (clientErr, serverErr error) {
	t.Helper()
	cp, sp := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	_ = cp.SetDeadline(deadline)
	_ = sp.SetDeadline(deadline)

	client := ClientWithNegotiation(cp, clientNeg, nil)
	server := ServerWithNegotiation(sp, serverNeg, nil)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer func() { _ = server.Close() }()
		if err := server.Handshake(); err != nil {
			serverErr = err
			return
		}
		// Echo one message.
		buf := make([]byte, 64)
		n, err := server.Read(buf)
		if err != nil {
			serverErr = err
			return
		}
		if _, err := server.Write(buf[:n]); err != nil {
			serverErr = err
		}
	}()

	go func() {
		defer wg.Done()
		defer func() { _ = client.Close() }()
		if err := client.Handshake(); err != nil {
			clientErr = err
			return
		}
		msg := []byte("negotiated-hello")
		if _, err := client.Write(msg); err != nil {
			clientErr = err
			return
		}
		buf := make([]byte, 64)
		n, err := client.Read(buf)
		if err != nil {
			clientErr = err
			return
		}
		if !bytes.Equal(buf[:n], msg) {
			clientErr = fmt.Errorf("round-trip mismatch: got %q want %q", buf[:n], msg)
		}
	}()

	wg.Wait()
	return clientErr, serverErr
}

func TestNegotiateAccept(t *testing.T) {
	f := testFactory()
	clientNeg := &transport.Negotiation{BuildConfig: f, Proposed: "NN"}
	serverNeg := &transport.Negotiation{BuildConfig: f, Supported: []string{"NN", "XX"}}
	if ce, se := runNeg(t, clientNeg, serverNeg); ce != nil || se != nil {
		t.Fatalf("accept failed: client=%v server=%v", ce, se)
	}
}

func TestNegotiateReject(t *testing.T) {
	f := testFactory()
	clientNeg := &transport.Negotiation{BuildConfig: f, Proposed: "NN"}
	serverNeg := &transport.Negotiation{BuildConfig: f, Supported: []string{"XX"}, Policy: transport.PolicyReject}
	ce, se := runNeg(t, clientNeg, serverNeg)
	if ce == nil {
		t.Fatal("expected client error on reject, got nil")
	}
	if !strings.Contains(ce.Error(), "reject") {
		t.Fatalf("client error %q should mention reject", ce.Error())
	}
	if se == nil || !strings.Contains(se.Error(), "reject") {
		t.Fatalf("server error %q should mention reject", se)
	}
}

func TestNegotiateRetry(t *testing.T) {
	f := testFactory()
	clientNeg := &transport.Negotiation{BuildConfig: f, Proposed: "NN", Fallback: []string{"XX"}}
	serverNeg := &transport.Negotiation{BuildConfig: f, Supported: []string{"XX"}, Policy: transport.PolicyRetry}
	if ce, se := runNeg(t, clientNeg, serverNeg); ce != nil || se != nil {
		t.Fatalf("retry failed: client=%v server=%v", ce, se)
	}
}

func TestNegotiateRetryDisallowed(t *testing.T) {
	f := testFactory()
	// Client proposes NN with no fallback; responder asks to retry with XX.
	clientNeg := &transport.Negotiation{BuildConfig: f, Proposed: "NN"}
	serverNeg := &transport.Negotiation{BuildConfig: f, Supported: []string{"XX"}, Policy: transport.PolicyRetry}
	ce, _ := runNeg(t, clientNeg, serverNeg)
	if ce == nil || !strings.Contains(ce.Error(), "disallowed") {
		t.Fatalf("expected disallowed-protocol error, got %v", ce)
	}
}

func TestNegotiateSwitch(t *testing.T) {
	f := testFactory()
	clientNeg := &transport.Negotiation{BuildConfig: f, Proposed: "NN", Fallback: []string{"XX"}}
	serverNeg := &transport.Negotiation{BuildConfig: f, Supported: []string{"XX"}, Policy: transport.PolicySwitch}
	if ce, se := runNeg(t, clientNeg, serverNeg); ce != nil || se != nil {
		t.Fatalf("switch failed: client=%v server=%v", ce, se)
	}
}

// TestNegotiateDefaultPolicyRejects verifies that an empty policy defaults
// to reject.
func TestNegotiateDefaultPolicyRejects(t *testing.T) {
	f := testFactory()
	clientNeg := &transport.Negotiation{BuildConfig: f, Proposed: "NN"}
	serverNeg := &transport.Negotiation{BuildConfig: f, Supported: []string{"XX"}} // no Policy
	ce, _ := runNeg(t, clientNeg, serverNeg)
	if ce == nil || !strings.Contains(ce.Error(), "reject") {
		t.Fatalf("expected default-reject, got %v", ce)
	}
}

// TestPrologueChainBinding checks the downgrade-binding property: the
// prologue an attempt uses depends on the prior-attempt transcript, so two
// sides that recorded different transcripts derive different prologues
// (and their handshake AEAD would fail).
func TestPrologueChainBinding(t *testing.T) {
	c := &Conn{} // appPrologue nil
	initNeg := []byte("ns=1;proto=XX")
	transcriptA := []byte("frame-bytes-A")
	transcriptB := []byte("frame-bytes-B")

	p0 := c.prologueWith(initNeg, nil)
	pA := c.prologueWith(initNeg, transcriptA)
	pB := c.prologueWith(initNeg, transcriptB)

	if bytes.Equal(pA, pB) {
		t.Fatal("different transcripts must yield different prologues")
	}
	if !bytes.HasPrefix(pA, p0) {
		t.Fatal("chained prologue must start with the base prologue")
	}
	// Determinism: same inputs => identical prologue.
	if !bytes.Equal(pA, c.prologueWith(initNeg, transcriptA)) {
		t.Fatal("prologue derivation must be deterministic")
	}
}

// TestNegotiationTamperFails interposes a byte-flipping man-in-the-middle
// on the server->client direction and asserts the client handshake fails,
// demonstrating that frame tampering is detected.
func TestNegotiationTamperFails(t *testing.T) {
	f := testFactory()
	clientNeg := &transport.Negotiation{BuildConfig: f, Proposed: "NN", Fallback: []string{"XX"}}
	serverNeg := &transport.Negotiation{BuildConfig: f, Supported: []string{"XX"}, Policy: transport.PolicyRetry}

	// client <-> mitm <-> server. The mitm flips one byte in the very
	// first server->client frame (the retry response), corrupting the
	// transcript the client records.
	clientSide, mitmC := net.Pipe()
	mitmS, serverSide := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	for _, c := range []net.Conn{clientSide, mitmC, mitmS, serverSide} {
		_ = c.SetDeadline(deadline)
	}

	// client->server: passthrough.
	go func() { _, _ = copyBytes(mitmS, mitmC, nil) }()
	// server->client: flip the first byte of the first frame's payload
	// region (offset 2 skips the neg_len header), then passthrough.
	go func() {
		flip := func(b []byte) {
			if len(b) > 2 {
				b[2] ^= 0xFF
			}
		}
		_, _ = copyBytes(mitmC, mitmS, flip)
	}()

	client := ClientWithNegotiation(clientSide, clientNeg, nil)
	server := ServerWithNegotiation(serverSide, serverNeg, nil)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = server.Close() }()
		_ = server.Handshake()
	}()

	err := client.Handshake()
	_ = client.Close()
	wg.Wait()
	if err == nil {
		t.Fatal("expected client handshake to fail under tampering, got nil")
	}
}

// copyBytes copies from src to dst, optionally applying mutate to the
// first chunk read. Used by the MITM test. It stops on any error.
func copyBytes(dst net.Conn, src net.Conn, mutate func([]byte)) (int64, error) {
	buf := make([]byte, 4096)
	var total int64
	first := true
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if first && mutate != nil {
				mutate(buf[:n])
				first = false
			}
			w, werr := dst.Write(buf[:n])
			total += int64(w)
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			return total, err
		}
	}
}
