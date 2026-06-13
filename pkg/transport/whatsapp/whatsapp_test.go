package whatsapp

import (
	"bytes"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/gedigi/noisecat/pkg/transport"
)

func TestName(t *testing.T) {
	if New().Name() != "whatsapp" {
		t.Fatalf("unexpected name %q", New().Name())
	}
}

// TestPeerToPeerOverTCP exercises the full peer-to-peer path (Listen +
// responder handshake, Dial + initiator handshake, encrypted transport)
// over a real loopback TCP socket — the same path a bind shell uses.
func TestPeerToPeerOverTCP(t *testing.T) {
	tp := New()
	l, err := tp.Listen("tcp", "127.0.0.1:0", nil, transport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.Copy(c, c) // echo
	}()

	conn, err := tp.Dial("tcp", l.Addr().String(), "", nil, transport.Options{DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("p2p dial failed: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	msg := []byte("bind-shell-over-whatsapp-transport")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: got %q want %q", got, msg)
	}

	// Both sides should have learned each other's static key.
	wc := conn.(*Conn)
	if len(wc.PeerStaticKey()) != 32 {
		t.Fatalf("expected 32-byte peer static key, got %d", len(wc.PeerStaticKey()))
	}
}

// TestListenSurvivesJunkPeer confirms a non-noisecat peer fails on its own
// (the deferred handshake errors on first read) without affecting the
// listener: a later valid peer still completes.
func TestListenSurvivesJunkPeer(t *testing.T) {
	tp := New()
	l, err := tp.Listen("tcp", "127.0.0.1:0", nil, transport.Options{DialTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	// Junk peer: connect and send garbage.
	junk, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = junk.Write([]byte("not a whatsapp handshake at all"))

	jc, err := l.Accept()
	if err != nil {
		t.Fatalf("accept junk: %v", err)
	}
	_ = jc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := jc.Read(make([]byte, 16)); err == nil {
		t.Fatal("expected junk peer handshake to fail on first read")
	}
	_ = jc.Close()
	_ = junk.Close()

	// A valid peer still works on the same listener.
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.Copy(c, c)
	}()
	good, err := tp.Dial("tcp", l.Addr().String(), "", nil, transport.Options{DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("valid peer dial failed: %v", err)
	}
	defer func() { _ = good.Close() }()
	_ = good.SetDeadline(time.Now().Add(5 * time.Second))
	msg := []byte("ping")
	if _, err := good.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(good, got); err != nil {
		t.Fatalf("valid peer echo failed: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("valid peer echo mismatch")
	}
}

// TestLiveWhatsAppHandshake performs the real Noise handshake against
// WhatsApp's production backend and verifies the pinned certificate chain.
// It is gated behind NOISECAT_WA_LIVE=1 because it needs network access to
// a third-party service; CI never runs it.
func TestLiveWhatsAppHandshake(t *testing.T) {
	if os.Getenv("NOISECAT_WA_LIVE") != "1" {
		t.Skip("set NOISECAT_WA_LIVE=1 to run the live WhatsApp handshake test")
	}
	conn, err := New().Dial("tcp", "", "", nil, transport.Options{DialTimeout: 15 * time.Second})
	if err != nil {
		t.Fatalf("live WhatsApp handshake failed: %v", err)
	}
	defer func() { _ = conn.Close() }()
	wc, ok := conn.(*Conn)
	if !ok {
		t.Fatalf("unexpected conn type %T", conn)
	}
	if len(wc.PeerStaticKey()) != 32 {
		t.Fatalf("expected 32-byte server static key, got %d", len(wc.PeerStaticKey()))
	}
	t.Logf("WhatsApp handshake complete; certificate verified against pinned root; server static=%x", wc.PeerStaticKey())
}
