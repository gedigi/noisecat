package noisecat

import (
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/mattn/go-shellwords"
)

// defaultHandleIOSafetyTimeout bounds how long handleIO will wait for
// the second copy direction to finish after the first one has
// half-closed its write side. Prevents an unresponsive backend (or a
// peer that has half-closed but never gets around to closing its read
// side) from pinning the goroutine forever. Tests can override per
// Params via the SafetyTimeout field.
const defaultHandleIOSafetyTimeout = 30 * time.Second

// Params type defines the parameters required by the runners
type Params struct {
	Conn       net.Conn
	Proxy      string
	ExecuteCmd string
	Log        Verbose

	// SafetyTimeout overrides the default handleIO half-close safety
	// timeout. Zero means use defaultHandleIOSafetyTimeout. Only used
	// by tests; production callers leave it unset.
	SafetyTimeout time.Duration
}

// Router routes a connection based on provided parameters
func (c *Params) Router() {
	defer func() { _ = c.Conn.Close() }()

	switch {
	case c.Proxy != "":
		c.proxyConn()
	case c.ExecuteCmd != "":
		c.executeCmd()
	default:
		c.handleIO(os.Stdout, os.Stdin)
	}
}

func (c *Params) proxyConn() {
	pConn, err := net.Dial("tcp", c.Proxy)
	if err != nil {
		c.Log.Errf("can't connect to proxy target: %s", err)
		return
	}
	defer func() { _ = pConn.Close() }()
	c.handleIO(pConn, pConn)
}

func (c *Params) executeCmd() {
	args, err := shellwords.Parse(c.ExecuteCmd)
	if err != nil {
		c.Log.Errf("can't parse -e command: %s", err)
		return
	}
	if len(args) == 0 {
		c.Log.Errf("can't parse -e command: empty")
		return
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Conn, c.Conn, c.Conn
	if err := cmd.Run(); err != nil {
		c.Log.Verb("command exited with error: %s", err)
	}
}

// progress reports the byte count and termination cause of one direction
// of an io.Copy in handleIO.
type progress struct {
	Bytes int64
	Dir   string
	Err   error
}

// halfCloseWriter is the subset of net.Conn that supports TCP-style
// half-close. *net.TCPConn, *noisenet.Conn, and any conn that delegates
// to a TCPConn satisfy it.
type halfCloseWriter interface {
	CloseWrite() error
}

// signalEndOfWrite tells the destination "we won't write anything else"
// without closing the read side, so the peer's Read returns EOF while
// our Read can still drain remaining inbound data. Falls back to full
// Close for endpoints that lack CloseWrite (notably io.Pipe in tests
// and os.Stdout in chat mode, where full close is the right thing to
// do anyway).
func signalEndOfWrite(dst io.Writer) {
	if cw, ok := dst.(halfCloseWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	if closer, ok := dst.(io.Closer); ok {
		_ = closer.Close()
	}
}

func (c *Params) handleIO(w io.Writer, r io.Reader) {
	ch := make(chan progress, 2)
	var once sync.Once
	fullClose := func() {
		once.Do(func() {
			_ = c.Conn.Close()
			var wCloser io.Closer
			if closer, ok := w.(io.Closer); ok && w != c.Conn {
				wCloser = closer
				_ = closer.Close()
			}
			if closer, ok := r.(io.Closer); ok && r != c.Conn && io.Closer(closer) != wCloser {
				_ = closer.Close()
			}
		})
	}

	copyIO := func(dst io.Writer, src io.Reader, dir string) {
		n, err := io.Copy(dst, src)
		// Half-close the write side so the peer sees EOF on its Read but
		// the opposite direction's io.Copy can still drain in-flight data.
		signalEndOfWrite(dst)
		ch <- progress{Bytes: n, Dir: dir, Err: err}
	}

	go copyIO(c.Conn, r, "SNT")
	go copyIO(w, c.Conn, "RCV")

	// Wait for the first direction to finish, then start a safety timer
	// for the second. If the second direction's blocking read does not
	// return on its own (e.g. a misbehaving backend), the timer fully
	// closes everything to break the deadlock — preserving the
	// progress-without-hangs property the previous "close both" version
	// was protecting against.
	first := <-ch
	c.Log.Verb("%s: %d bytes", first.Dir, first.Bytes)
	if first.Err != nil && !errors.Is(first.Err, io.EOF) && !isClosedNet(first.Err) {
		c.Log.Verb("%s error: %s", first.Dir, first.Err)
	}

	timeout := c.SafetyTimeout
	if timeout <= 0 {
		timeout = defaultHandleIOSafetyTimeout
	}
	timer := time.AfterFunc(timeout, fullClose)
	second := <-ch
	timer.Stop()
	c.Log.Verb("%s: %d bytes", second.Dir, second.Bytes)
	if second.Err != nil && !errors.Is(second.Err, io.EOF) && !isClosedNet(second.Err) {
		c.Log.Verb("%s error: %s", second.Dir, second.Err)
	}
	fullClose()
}

func isClosedNet(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
