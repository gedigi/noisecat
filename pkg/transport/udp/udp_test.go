package udp

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
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

func TestName(t *testing.T) {
	if New().Name() != "udp" {
		t.Fatalf("unexpected name %q", New().Name())
	}
}

// dialEcho starts a UDP/KCP listener with an echo handler and dials it,
// returning the client connection.
func dialEcho(t *testing.T) (net.Conn, func()) {
	t.Helper()
	tp := New()
	l, err := tp.Listen("udp", "127.0.0.1:0", nnCfg(false), transport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = io.Copy(c, c)
	}()

	conn, err := tp.Dial("udp", l.Addr().String(), "", nnCfg(true), transport.Options{DialTimeout: 5 * time.Second})
	if err != nil {
		_ = l.Close()
		t.Fatalf("dial: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn, func() { _ = conn.Close(); _ = l.Close() }
}

func TestUDPRoundTrip(t *testing.T) {
	conn, cleanup := dialEcho(t)
	defer cleanup()

	msg := []byte("noise-over-reliable-udp")
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
}

// TestUDPBulkTransfer pushes 256 KiB through the KCP+Noise stream to exercise
// reliable reassembly across many datagrams. The write and read run
// concurrently to avoid an echo deadlock on the single connection.
func TestUDPBulkTransfer(t *testing.T) {
	conn, cleanup := dialEcho(t)
	defer cleanup()

	payload := make([]byte, 256*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		writeErr <- err
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read bulk echo: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("bulk transfer corrupted over UDP")
	}
}
