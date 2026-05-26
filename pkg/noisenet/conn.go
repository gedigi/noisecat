// Package noisenet is a backwards-compatibility shim that re-exports the
// "raw" transport (pkg/transport/raw). New code should import the
// pkg/transport/raw package directly; this shim exists so external callers
// that imported github.com/gedigi/noisecat/pkg/noisenet keep compiling.
//
// Deprecated: use github.com/gedigi/noisecat/pkg/transport/raw instead.
package noisenet

import (
	"net"

	"github.com/flynn/noise"
	"github.com/gedigi/noisecat/pkg/transport/raw"
)

// Conn is the noise-secured connection type. Aliased to the raw transport's
// implementation so existing code that referenced *noisenet.Conn continues
// to work.
//
// Deprecated: use raw.Conn instead.
type Conn = raw.Conn

// Listener is the noise listener type.
//
// Deprecated: use raw.Listener instead.
type Listener = raw.Listener

// Server wraps an existing net.Conn into a Noise server-side connection.
//
// Deprecated: use raw.Server instead.
func Server(conn net.Conn, config *noise.Config) *Conn { return raw.Server(conn, config) }

// Client wraps an existing net.Conn into a Noise client-side connection.
//
// Deprecated: use raw.Client instead.
func Client(conn net.Conn, config *noise.Config) *Conn { return raw.Client(conn, config) }

// Listen creates a noise listener using the raw transport's framing.
//
// Deprecated: use raw.Listen instead.
func Listen(network, laddr string, config *noise.Config) (net.Listener, error) {
	return raw.Listen(network, laddr, config)
}

// Dial connects to the given address using the raw transport's framing.
//
// Deprecated: use raw.Dial instead.
func Dial(network, addr, localAddr string, config *noise.Config) (*Conn, error) {
	return raw.Dial(network, addr, localAddr, config)
}

// DialWithDialer is the dialer-aware version of Dial.
//
// Deprecated: use raw.DialWithDialer instead.
func DialWithDialer(dialer *net.Dialer, network, addr, localAddr string, config *noise.Config) (*Conn, error) {
	return raw.DialWithDialer(dialer, network, addr, localAddr, config)
}
