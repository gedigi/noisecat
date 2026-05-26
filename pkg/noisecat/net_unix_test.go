//go:build unix

package noisecat

import (
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gedigi/noisecat/pkg/noisenet"
)

// TestStartServerDaemonHandlesConcurrentClients is the C1 regression test:
// in -k daemon mode, multiple concurrent clients each see their own
// proxy conversation. Uses SIGTERM for cleanup so it is Unix-only.
func TestStartServerDaemonHandlesConcurrentClients(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
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

	conn := waitDial(t, "127.0.0.1:"+port, 2*time.Second)
	conn.Close()

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("kill: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shut down on SIGTERM")
	}
}
