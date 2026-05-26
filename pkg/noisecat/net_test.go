package noisecat

import (
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/gedigi/noisecat/pkg/transport/raw"
)

// freePort returns a TCP port that was free at the moment of probing.
// Useful for tests that must bind a specific port (e.g. for the listening
// server) before any client can connect.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	return port
}

func nnNoiseConfig(initiator bool) *noise.Config {
	return &noise.Config{
		Pattern:     noise.HandshakeNN,
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
		Random:      rand.Reader,
		Initiator:   initiator,
	}
}

// TestStartServerProxiesSingleConnection drives StartServer (non-daemon) with
// a backing echo server. A Noise client connects, sends bytes, and reads
// the same bytes echoed back via the proxy.
func TestStartServerProxiesSingleConnection(t *testing.T) {
	// Backing echo server on its own port.
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	port := freePort(t)
	nc := Noisecat{
		Config: &Config{
			SrcHost: "127.0.0.1",
			SrcPort: port,
			Listen:  true,
			Proxy:   backend.Addr().String(),
		},
		NoiseConfig: nnNoiseConfig(false),
		Log:         Verbose(false),
	}

	serverDone := make(chan struct{})
	go func() {
		nc.StartServer()
		close(serverDone)
	}()

	// Give the server a moment to bind. Cheap retry loop is more reliable than sleep.
	clientConn := waitDial(t, "127.0.0.1:"+port, 2*time.Second)
	defer clientConn.Close()

	want := []byte("single-conn-payload")
	if _, err := clientConn.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(clientConn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q want %q", got, want)
	}

	clientConn.Close()
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("StartServer did not return after client disconnect")
	}
}

// waitDial repeatedly tries to connect (raw TCP, not Noise) for up to d,
// returning the first successful connection. It returns a Noise-wrapped
// client connection that has not yet completed the handshake — callers
// can close it without doing the full Noise exchange.
func waitDial(t *testing.T, addr string, d time.Duration) net.Conn {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		c, err := raw.Dial("tcp", addr, "", nnNoiseConfig(true))
		if err == nil {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("could not connect to %s within %s: %v", addr, d, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type mismatch struct{ got, want string }

func (m *mismatch) Error() string {
	return "got " + m.got + " want " + m.want
}
