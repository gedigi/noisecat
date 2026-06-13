package noisecat

import (
	"net"
	"time"
)

// idleConn wraps a net.Conn and closes it after a period of inactivity.
// Every successful Read or Write pushes the deadline forward by idle, so
// the connection is torn down only when both directions have been silent
// for that long. This mirrors netcat's -w idle-timeout semantics for the
// data phase (the dial/handshake phase is bounded separately by
// transport.Options.DialTimeout).
type idleConn struct {
	net.Conn
	idle time.Duration
}

// newIdleConn wraps c so that it self-closes after idle of inactivity.
// An idle of zero returns c unchanged (no timeout).
func newIdleConn(c net.Conn, idle time.Duration) net.Conn {
	if idle <= 0 {
		return c
	}
	ic := &idleConn{Conn: c, idle: idle}
	ic.bump()
	return ic
}

// bump pushes the read+write deadline idle into the future. A failure to
// set the deadline (e.g. an already-closed conn) is ignored: the next
// Read/Write will surface the real error.
func (c *idleConn) bump() {
	_ = c.SetDeadline(time.Now().Add(c.idle))
}

func (c *idleConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.bump()
	}
	return n, err
}

func (c *idleConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.bump()
	}
	return n, err
}

// CloseWrite forwards TCP-style half-close to the wrapped conn when it
// supports it, so handleIO's signalEndOfWrite still works through the
// idle wrapper. Returns nil if the underlying conn has no CloseWrite.
func (c *idleConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
