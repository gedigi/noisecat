package raw

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
)

func newTestConfig(initiator bool) *noise.Config {
	return &noise.Config{
		Pattern:     noise.HandshakeNN,
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
		Random:      rand.Reader,
		Initiator:   initiator,
	}
}

func TestListenNilConfig(t *testing.T) {
	if _, err := Listen("tcp", "127.0.0.1:0", nil); err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestListenAndDialRoundTrip(t *testing.T) {
	l, err := Listen("tcp", "127.0.0.1:0", newTestConfig(false))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	addr := l.Addr().(*net.TCPAddr)
	conn, err := Dial("tcp", "127.0.0.1:"+strconv.Itoa(addr.Port), "", newTestConfig(true))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	want := []byte("hello noise")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	conn.Close()
	l.Close()
	wg.Wait()
}

// TestLargeWriteFragmentation is a regression test: a single Write larger
// than one Noise message (> MaxMsgLen) must fragment so that each
// fragment + its 16-byte AEAD tag still fits the 2-byte length frame.
// Previously the fragment was capped at MaxMsgLen, making the ciphertext
// 16 bytes too big and erroring on any write > ~64 KiB.
func TestLargeWriteFragmentation(t *testing.T) {
	l, err := Listen("tcp", "127.0.0.1:0", newTestConfig(false))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Server reads the whole stream until the client closes (EOF), then
	// reports what it received — no echo, so there's no reverse-path flow
	// control to confuse the fragmentation check.
	got := make(chan []byte, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		data, _ := io.ReadAll(conn)
		got <- data
	}()

	addr := l.Addr().(*net.TCPAddr)
	conn, err := Dial("tcp", "127.0.0.1:"+strconv.Itoa(addr.Port), "", newTestConfig(true))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	// 200 KiB spans multiple Noise messages.
	want := make([]byte, 200*1024)
	for i := range want {
		want[i] = byte(i)
	}
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.Close() // flush + EOF so the server's ReadAll returns

	received := <-got
	if !bytes.Equal(received, want) {
		t.Fatalf("large payload corrupted across fragmentation: got %d bytes, want %d", len(received), len(want))
	}
}

// TestDialIPv6SourceAddr exercises the H4 regression: callers pass IPv6
// addresses wrapped with net.JoinHostPort (e.g. "[::1]:0"); the old
// strings.Split(":") rejected them.
func TestDialIPv6SourceAddr(t *testing.T) {
	// Skip if the platform doesn't have IPv6 loopback (rare on dev machines but
	// possible on minimal Linux installs).
	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	probe.Close()

	l, err := Listen("tcp6", "[::1]:0", newTestConfig(false))
	if err != nil {
		t.Fatalf("listen v6: %v", err)
	}
	defer l.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	addr := l.Addr().(*net.TCPAddr)
	dst := net.JoinHostPort("::1", strconv.Itoa(addr.Port))
	src := net.JoinHostPort("::1", "0")
	conn, err := Dial("tcp6", dst, src, newTestConfig(true))
	if err != nil {
		t.Fatalf("dial v6 with v6 source: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	want := []byte("v6")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	conn.Close()
	l.Close()
	wg.Wait()
}

func TestDialInvalidSourceAddr(t *testing.T) {
	_, err := Dial("tcp", "127.0.0.1:1", "not-a-valid-source", newTestConfig(true))
	if err == nil {
		t.Fatal("expected error for malformed source address")
	}
}
