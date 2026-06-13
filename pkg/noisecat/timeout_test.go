package noisecat

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestConfigNetwork(t *testing.T) {
	cases := []struct {
		cfg  Config
		want string
	}{
		{Config{}, "tcp"},
		{Config{IPv4Only: true}, "tcp4"},
		{Config{IPv6Only: true}, "tcp6"},
	}
	for _, tc := range cases {
		if got := tc.cfg.network(); got != tc.want {
			t.Errorf("network()=%q, want %q (cfg %+v)", got, tc.want, tc.cfg)
		}
	}
}

func TestNewIdleConnZeroIsNoop(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close(); _ = c2.Close() }()
	if got := newIdleConn(c1, 0); got != c1 {
		t.Fatalf("newIdleConn with zero idle should return the conn unchanged")
	}
}

// fakeHalfCloser records whether CloseWrite was called and satisfies the
// minimal net.Conn surface idleConn needs.
type fakeHalfCloser struct {
	net.Conn
	closeWriteCalled bool
}

func (f *fakeHalfCloser) CloseWrite() error {
	f.closeWriteCalled = true
	return nil
}

func TestIdleConnForwardsCloseWrite(t *testing.T) {
	p1, p2 := net.Pipe()
	defer func() { _ = p1.Close(); _ = p2.Close() }()
	fhc := &fakeHalfCloser{Conn: p1}
	ic := newIdleConn(fhc, time.Minute)
	cw, ok := ic.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("idleConn does not expose CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if !fhc.closeWriteCalled {
		t.Fatal("CloseWrite was not forwarded to the wrapped conn")
	}
}

func TestIdleConnCloseWriteNoUnderlyingSupport(t *testing.T) {
	p1, p2 := net.Pipe() // net.Pipe conns have no CloseWrite
	defer func() { _ = p1.Close(); _ = p2.Close() }()
	ic := newIdleConn(p1, time.Minute)
	cw := ic.(interface{ CloseWrite() error })
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite on conn without support should be nil, got %v", err)
	}
}

func TestIdleConnTimesOutIdleConnection(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	ic := newIdleConn(a, 50*time.Millisecond)

	// No activity: the read should hit the idle deadline and fail.
	buf := make([]byte, 1)
	_, err := ic.Read(buf)
	if err == nil {
		t.Fatal("expected idle timeout error, got nil")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected a timeout net.Error, got %v", err)
	}
}

func TestIdleConnActivityResetsDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	ic := newIdleConn(a, 120*time.Millisecond)

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 4)
		// Two reads spaced under the idle window; each should succeed
		// because the prior read bumps the deadline forward.
		for i := 0; i < 2; i++ {
			if _, err := ic.Read(buf); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	for i := 0; i < 2; i++ {
		time.Sleep(70 * time.Millisecond) // < idle window, so no timeout
		if _, err := b.Write([]byte("ping")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("reads should have succeeded with activity resetting the deadline, got %v", err)
	}
}
