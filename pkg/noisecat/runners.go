package noisecat

import (
	"errors"
	"io"
	"net"
	"os"
	"os/exec"

	"github.com/mattn/go-shellwords"
)

// Params type defines the parameters required by the runners
type Params struct {
	Conn       net.Conn
	Proxy      string
	ExecuteCmd string
	Log        Verbose
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

func (c *Params) handleIO(w io.Writer, r io.Reader) {
	ch := make(chan progress, 2)

	copyIO := func(dst io.Writer, src io.Reader, dir string) {
		n, err := io.Copy(dst, src)
		// Close every endpoint so the other direction's blocking Read/Write
		// returns and handleIO can exit. Closing the noise conn is mandatory;
		// closing dst/src (when they're separate Closers, e.g. a proxy conn
		// or stdin) breaks the case where the peer is silent but the user
		// (or the backing server) closes their side.
		_ = c.Conn.Close()
		if closer, ok := dst.(io.Closer); ok && dst != c.Conn {
			_ = closer.Close()
		}
		if closer, ok := src.(io.Closer); ok && src != c.Conn {
			_ = closer.Close()
		}
		ch <- progress{Bytes: n, Dir: dir, Err: err}
	}

	go copyIO(c.Conn, r, "SNT")
	go copyIO(w, c.Conn, "RCV")

	for i := 0; i < 2; i++ {
		s := <-ch
		c.Log.Verb("%s: %d bytes", s.Dir, s.Bytes)
		if s.Err != nil && !errors.Is(s.Err, io.EOF) && !isClosedNet(s.Err) {
			c.Log.Verb("%s error: %s", s.Dir, s.Err)
		}
	}
}

func isClosedNet(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
