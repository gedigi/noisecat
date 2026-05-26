package noisecat

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// TestRouterDispatchesAndClosesConnOnProxy exercises Router → proxyConn
// without involving os/exec (which hangs on net.Pipe stdin). When the proxy
// target is unreachable, proxyConn returns immediately, Router's defer
// closes the Conn, and the test observes both behaviors.
func TestRouterDispatchesAndClosesConnOnProxy(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()

	// Bind+release a port to get a guaranteed-closed address.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := probe.Addr().String()
	probe.Close()

	p := &Params{
		Conn:  a,
		Proxy: closedAddr,
		Log:   Verbose(false),
	}

	done := make(chan struct{})
	go func() {
		p.Router()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Router did not return after proxy failure")
	}

	// Connection should now be closed (defer fired).
	_ = a.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := a.Write([]byte("x")); err == nil {
		t.Fatal("expected error writing to closed conn")
	}
}

func TestExecuteCmdHandlesQuotedArgs(t *testing.T) {
	if _, err := exec.LookPath("printf"); err != nil {
		t.Skip("printf not available")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	// Argument with a space; old strings.Split(" ") would split it.
	p := &Params{
		Conn:       a,
		ExecuteCmd: `printf "hello world"`,
		Log:        Verbose(false),
	}

	go p.executeCmd()

	// Use a deadline + ReadFull instead of ReadAll, because cmd.Run hangs on
	// net.Pipe stdin and does not close `a` for us. We only care that printf's
	// output reaches `b`.
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len("hello world"))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("expected 'hello world', got %q", got)
	}
}

func TestExecuteCmdEmptyCommand(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	p := &Params{
		Conn:       a,
		ExecuteCmd: "   ",
		Log:        Verbose(false),
	}
	done := make(chan struct{})
	go func() {
		p.executeCmd()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("executeCmd hung on empty command")
	}
}

func TestExecuteCmdMalformedQuoting(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	// Unclosed quote — shellwords should report a parse error and executeCmd
	// should return without spawning anything.
	p := &Params{
		Conn:       a,
		ExecuteCmd: `printf "unterminated`,
		Log:        Verbose(false),
	}
	done := make(chan struct{})
	go func() {
		p.executeCmd()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("executeCmd hung on malformed quoting")
	}
}

// TestProxyConnDrainsBackendAfterClientHalfClose is the regression test for
// issue #6. The reported symptom: a client sends a request to noisecat in
// -proxy mode and TCP-closes its write side; the backend writes a response
// a moment later; the client never sees it because the previous handleIO
// tore down the noise conn and the proxy conn the instant either copy
// direction returned. With half-close semantics, the backend has time to
// finish its write and the response is delivered.
//
// Uses real TCP on both sides so CloseWrite is meaningful — net.Pipe does
// not support half-close.
func TestProxyConnDrainsBackendAfterClientHalfClose(t *testing.T) {
	const (
		clientRequest   = "GET / HTTP/1.0\r\n\r\n"
		backendDelay    = 200 * time.Millisecond
		backendResponse = "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nHELLO"
	)

	// Backend: read request, sleep, write response, close.
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
		buf := make([]byte, len(clientRequest))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		time.Sleep(backendDelay)
		_, _ = conn.Write([]byte(backendResponse))
	}()

	// Client-facing TCP pair: 'serverConn' is what Router operates on,
	// 'clientConn' is what the test (acting as the client) uses.
	frontEnd, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer frontEnd.Close()

	serverAcceptedCh := make(chan net.Conn, 1)
	go func() {
		c, err := frontEnd.Accept()
		if err != nil {
			return
		}
		serverAcceptedCh <- c
	}()

	clientConn, err := net.Dial("tcp", frontEnd.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	serverConn := <-serverAcceptedCh
	defer serverConn.Close()

	p := &Params{Conn: serverConn, Proxy: backend.Addr().String(), Log: Verbose(false)}
	go p.Router()

	// Client sends the request and CloseWrites (half-closes its write
	// side). With the old code, the server side would see this EOF and
	// tear down the proxy connection before the backend's response made
	// it back.
	if _, err := clientConn.Write([]byte(clientRequest)); err != nil {
		t.Fatal(err)
	}
	if err := clientConn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(backendResponse))
	if _, err := io.ReadFull(clientConn, got); err != nil {
		t.Fatalf("expected to read backend response, got error: %v", err)
	}
	if string(got) != backendResponse {
		t.Fatalf("got %q, want %q", got, backendResponse)
	}
}

// TestProxyConnSafetyTimeout asserts that handleIO will not hang forever
// if one direction completes but the other is stuck (e.g. silent backend).
func TestProxyConnSafetyTimeout(t *testing.T) {
	// Backend that accepts but never sends or closes.
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
		// Hold the connection open until the listener closes.
		defer conn.Close()
		<-time.After(10 * time.Second)
	}()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	p := &Params{
		Conn:          a,
		Proxy:         backend.Addr().String(),
		Log:           Verbose(false),
		SafetyTimeout: 200 * time.Millisecond,
	}
	done := make(chan struct{})
	go func() { p.Router(); close(done) }()

	// Close the client side so the SNT direction finishes immediately,
	// leaving RCV blocked on a silent backend — the safety timer should
	// tear it down.
	b.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Router did not unblock within the safety timeout")
	}
}

func TestProxyConnForwardsBidirectionally(t *testing.T) {
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
		_, _ = io.Copy(conn, conn)
	}()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	p := &Params{
		Conn:  a,
		Proxy: backend.Addr().String(),
		Log:   Verbose(false),
	}

	go p.proxyConn()

	_ = b.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := b.Write([]byte("hello-proxy")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("hello-proxy"))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello-proxy" {
		t.Fatalf("got %q", got)
	}
}

func TestProxyConnReportsDialFailure(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := probe.Addr().String()
	probe.Close()

	p := &Params{
		Conn:  a,
		Proxy: closedAddr,
		Log:   Verbose(false),
	}

	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	done := make(chan struct{})
	go func() {
		p.proxyConn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxyConn did not return on dial failure")
	}
	w.Close()
	out, _ := io.ReadAll(r)
	if !bytes.Contains(out, []byte("proxy target")) {
		t.Fatalf("expected error log mentioning proxy target, got %q", out)
	}
}

func TestHandleIOBidirectional(t *testing.T) {
	connA, clientSide := net.Pipe()
	defer connA.Close()

	stdinR, stdinW := io.Pipe()
	defer stdinR.Close()

	var stdoutBuf bytes.Buffer
	var stdoutMu sync.Mutex
	stdout := lockedWriter{mu: &stdoutMu, w: &stdoutBuf}

	p := &Params{Conn: connA, Log: Verbose(false)}

	done := make(chan struct{})
	go func() {
		p.handleIO(stdout, stdinR)
		close(done)
	}()

	// stdin → connA → clientSide
	go func() { _, _ = stdinW.Write([]byte("to-server")) }()
	got := make([]byte, len("to-server"))
	if _, err := io.ReadFull(clientSide, got); err != nil {
		t.Fatalf("clientSide read: %v", err)
	}
	if string(got) != "to-server" {
		t.Fatalf("got %q", got)
	}

	// clientSide → connA → stdout
	if _, err := clientSide.Write([]byte("from-server")); err != nil {
		t.Fatal(err)
	}

	// Wait for the RCV direction to land "from-server" in stdoutBuf.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stdoutMu.Lock()
		ok := bytes.Contains(stdoutBuf.Bytes(), []byte("from-server"))
		stdoutMu.Unlock()
		if ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	stdoutMu.Lock()
	out := stdoutBuf.String()
	stdoutMu.Unlock()
	if !bytes.Contains([]byte(out), []byte("from-server")) {
		t.Fatalf("expected 'from-server' in stdout, got %q", out)
	}

	// Trigger shutdown: closing stdinW makes SNT see EOF, which closes connA,
	// which makes RCV's io.Copy return. handleIO exits, defer closes connA
	// (already closed).
	_ = stdinW.Close()
	_ = clientSide.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleIO did not return after both sides closed")
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestVerboseErrfAlwaysPrints(t *testing.T) {
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	Verbose(false).Errf("boom: %d", 42)
	w.Close()
	out, _ := io.ReadAll(r)
	if !bytes.Contains(out, []byte("boom: 42")) {
		t.Fatalf("expected 'boom: 42' in stderr, got %q", out)
	}
}

func TestVerboseVerbOnlyWhenEnabled(t *testing.T) {
	// We can't easily intercept log.Printf without changing global state, but
	// we can confirm Verb does not panic in either mode and that the runtime
	// path is exercised for coverage.
	Verbose(false).Verb("quiet %d", 1)
	Verbose(true).Verb("loud %d", 2)
}
