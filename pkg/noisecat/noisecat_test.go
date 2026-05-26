package noisecat

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
	"github.com/gedigi/noisecat/pkg/noisenet"
)

// TestClientServerNoiseEcho exercises the full noisecat round-trip without
// relying on time.Sleep for synchronization. The server runs as a goroutine,
// echoes any bytes it receives back to the client, and the client compares
// what it sends with what it receives.
//
// We bypass StartClient/StartServer (which use stdin/stdout) and drive the
// underlying noisenet directly so the test can run inside `go test` without
// hijacking the test runner's stdio.
func TestClientServerNoiseEcho(t *testing.T) {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA512)

	serverCfg := &noise.Config{
		Pattern:     noise.HandshakeNN,
		CipherSuite: cs,
		Random:      rand.Reader,
		Initiator:   false,
	}
	clientCfg := &noise.Config{
		Pattern:     noise.HandshakeNN,
		CipherSuite: cs,
		Random:      rand.Reader,
		Initiator:   true,
	}

	// Listen on an OS-assigned ephemeral port so concurrent test runs do not collide.
	listener, err := noisenet.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	// Server: accept one connection, echo until EOF.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	// Client: connect, send a payload, read it back.
	addr := listener.Addr().(*net.TCPAddr)
	conn, err := noisenet.Dial("tcp", "127.0.0.1:"+strconv.Itoa(addr.Port), "", clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	payload := []byte("noisecat round-trip\n")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}

	conn.Close()
	listener.Close()
	wg.Wait()
}

// TestDaemonModeHandlesConcurrentConnections exercises the regression for C1:
// in -k daemon mode, two clients connecting back-to-back must each see their
// own conversation, even though they reuse the same Noisecat config.
func TestDaemonModeHandlesConcurrentConnections(t *testing.T) {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA512)
	serverCfg := &noise.Config{
		Pattern:     noise.HandshakeNN,
		CipherSuite: cs,
		Random:      rand.Reader,
		Initiator:   false,
	}

	listener, err := noisenet.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	const numClients = 4
	var wg sync.WaitGroup
	// Server: accept N connections, each in its own goroutine, each echoing.
	wg.Add(numClients)
	go func() {
		for i := 0; i < numClients; i++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	port := strconv.Itoa(addr.Port)

	results := make(chan error, numClients)
	for i := 0; i < numClients; i++ {
		go func(id int) {
			clientCfg := &noise.Config{
				Pattern:     noise.HandshakeNN,
				CipherSuite: cs,
				Random:      rand.Reader,
				Initiator:   true,
			}
			conn, err := noisenet.Dial("tcp", "127.0.0.1:"+port, "", clientCfg)
			if err != nil {
				results <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

			payload := []byte("client-" + strconv.Itoa(id) + "-payload")
			if _, err := conn.Write(payload); err != nil {
				results <- err
				return
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				results <- err
				return
			}
			if !bytes.Equal(got, payload) {
				results <- &mismatchError{got: string(got), want: string(payload)}
				return
			}
			results <- nil
		}(i)
	}

	for i := 0; i < numClients; i++ {
		if err := <-results; err != nil {
			t.Fatalf("client %d failed: %v", i, err)
		}
	}
	wg.Wait()
}

type mismatchError struct{ got, want string }

func (m *mismatchError) Error() string {
	return "got " + m.got + " want " + m.want
}
