package noisecat

import (
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/gedigi/noisecat/pkg/noisenet"
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

// TestStartServerDaemonHandlesConcurrentClients is the C1 regression test:
// in -k daemon mode, multiple concurrent clients each see their own
// proxy conversation.
func TestStartServerDaemonHandlesConcurrentClients(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	// Accept and echo each incoming backend connection.
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	port := freePort(t)
	nc := Noisecat{
		Config: &Config{
			SrcHost: "127.0.0.1",
			SrcPort: port,
			Listen:  true,
			Daemon:  true,
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
	defer func() {
		// Trigger graceful shutdown for cleanup.
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		select {
		case <-serverDone:
		case <-time.After(3 * time.Second):
		}
	}()

	const numClients = 4
	var wg sync.WaitGroup
	errs := make(chan error, numClients)
	wg.Add(numClients)

	// First client establishes the bind worked; subsequent ones reuse it.
	probe := waitDial(t, "127.0.0.1:"+port, 2*time.Second)
	probe.Close()

	for i := 0; i < numClients; i++ {
		go func(id int) {
			defer wg.Done()
			payload := []byte("client-" + strconv.Itoa(id))
			conn, err := noisenet.Dial("tcp", "127.0.0.1:"+port, "", nnNoiseConfig(true))
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write(payload); err != nil {
				errs <- err
				return
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				errs <- err
				return
			}
			if string(got) != string(payload) {
				errs <- &mismatch{got: string(got), want: string(payload)}
				return
			}
			errs <- nil
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("client failed: %v", err)
		}
	}
}

// TestStartServerGracefulShutdown checks that SIGTERM cleanly stops the
// accept loop in daemon mode.
func TestStartServerGracefulShutdown(t *testing.T) {
	port := freePort(t)
	nc := Noisecat{
		Config: &Config{
			SrcHost:    "127.0.0.1",
			SrcPort:    port,
			Listen:     true,
			Daemon:     true,
			ExecuteCmd: "true",
		},
		NoiseConfig: nnNoiseConfig(false),
		Log:         Verbose(false),
	}

	done := make(chan struct{})
	go func() {
		nc.StartServer()
		close(done)
	}()

	// Wait until the server has bound.
	conn := waitDial(t, "127.0.0.1:"+port, 2*time.Second)
	conn.Close()

	// Send SIGTERM to ourselves: signal.Notify in StartServer should catch it.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("kill: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shut down on SIGTERM")
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
		c, err := noisenet.Dial("tcp", addr, "", nnNoiseConfig(true))
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
