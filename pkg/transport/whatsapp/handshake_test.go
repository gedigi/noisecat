package whatsapp

import (
	"bytes"
	"crypto/sha256"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestNoiseInitHash(t *testing.T) {
	nh := newNoiseHandshake()
	if err := nh.start(noiseStartPattern, waConnHeader); err != nil {
		t.Fatal(err)
	}
	pattern := []byte(noiseStartPattern)
	if len(pattern) != 32 {
		t.Fatalf("noiseStartPattern must be 32 bytes, got %d", len(pattern))
	}
	// ck (salt) is the raw 32-byte pattern; h is SHA256(pattern || WA header).
	if !bytes.Equal(nh.salt, pattern) {
		t.Fatal("initial chaining key (salt) should equal the padded pattern")
	}
	want := sha256.Sum256(append(append([]byte{}, pattern...), waConnHeader...))
	if !bytes.Equal(nh.hash, want[:]) {
		t.Fatalf("initial hash mismatch:\n got %x\nwant %x", nh.hash, want)
	}
}

// runCertServer plays the responder side of the WhatsApp Noise_XX handshake
// over rwc, sending certChain as the ServerHello payload (exercising the
// real-backend code path where the client verifies a certificate), and
// returns a server-side Conn for the transport phase.
func runCertServer(rwc net.Conn, serverStatic dhKeypair, certChain []byte) (*Conn, error) {
	framed := &framedConn{rw: rwc, readHeader: true}
	hs, err := serverHandshake(framed, serverStatic, certChain)
	if err != nil {
		return nil, err
	}
	return newConn(rwc, framed, hs), nil
}

func TestWhatsAppHandshakeAndEcho(t *testing.T) {
	ca := newTestCA(t)
	serverPriv, serverPub := newCurveKey(t)
	serverStatic := dhKeypair{priv: serverPriv, pub: serverPub}
	nb, na := validWindow()
	chain := ca.chain(serverPub[:], nb, na, 0)

	cliPipe, srvPipe := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	_ = cliPipe.SetDeadline(deadline)
	_ = srvPipe.SetDeadline(deadline)

	var srvErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sconn, err := runCertServer(srvPipe, serverStatic, chain)
		if err != nil {
			srvErr = err
			return
		}
		buf := make([]byte, 256)
		n, err := sconn.Read(buf)
		if err != nil {
			srvErr = err
			return
		}
		if _, err := sconn.Write(buf[:n]); err != nil {
			srvErr = err
		}
	}()

	clientPriv, clientPub := newCurveKey(t)
	framed := newClientFramedConn(cliPipe)
	hs, err := clientHandshake(framed, dhKeypair{priv: clientPriv, pub: clientPub}, []byte{}, &ca.rootPub)
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	if !bytes.Equal(hs.peerStatic, serverPub[:]) {
		t.Fatal("client did not recover the server's static key")
	}
	cconn := newConn(cliPipe, framed, hs)

	msg := []byte("hello whatsapp noise transport")
	if _, err := cconn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(cconn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	wg.Wait()
	if srvErr != nil {
		t.Fatalf("server error: %v", srvErr)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: got %q want %q", got, msg)
	}
}

func TestWhatsAppHandshakeRejectsUntrustedCert(t *testing.T) {
	ca := newTestCA(t)
	serverPriv, serverPub := newCurveKey(t)
	serverStatic := dhKeypair{priv: serverPriv, pub: serverPub}
	nb, na := validWindow()
	chain := ca.chain(serverPub[:], nb, na, 0)

	// The client trusts a DIFFERENT root, so cert verification must fail.
	_, untrustedRoot := newCurveKey(t)

	cliPipe, srvPipe := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	_ = cliPipe.SetDeadline(deadline)
	_ = srvPipe.SetDeadline(deadline)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// The server will complete msg2 then block on msg3 (client aborts);
		// its error is expected and ignored.
		_, _ = runCertServer(srvPipe, serverStatic, chain)
	}()

	clientPriv, clientPub := newCurveKey(t)
	framed := newClientFramedConn(cliPipe)
	_, err := clientHandshake(framed, dhKeypair{priv: clientPriv, pub: clientPub}, []byte{}, &untrustedRoot)
	if err == nil {
		t.Fatal("expected handshake to fail against untrusted cert root")
	}
	_ = cliPipe.Close()
	_ = srvPipe.Close()
	wg.Wait()
}
