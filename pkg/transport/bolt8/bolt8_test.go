package bolt8

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ---- BOLT-8 Appendix A: deterministic test vectors ----

// fromHex panics on bad input — meant for hex-string constants in tests.
func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func privFromHex(t *testing.T, s string) *secp256k1.PrivateKey {
	return secp256k1.PrivKeyFromBytes(fromHex(t, s))
}

func pubFromHex(t *testing.T, s string) *secp256k1.PublicKey {
	pub, err := secp256k1.ParsePubKey(fromHex(t, s))
	if err != nil {
		t.Fatalf("parse pub %q: %v", s, err)
	}
	return pub
}

// TestActVectorsInitiator drives an initiator with the Appendix A
// fixed inputs and verifies the act 1 bytes are exactly the spec's
// expected output. We supply the responder's ephemeral via a mock so
// the initiator's act 2 read consumes the spec's exact bytes.
func TestActVectorsInitiator(t *testing.T) {
	// Spec inputs:
	rsPub := pubFromHex(t, "028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7")
	lsPriv := privFromHex(t, "1111111111111111111111111111111111111111111111111111111111111111")
	ePriv := privFromHex(t, "1212121212121212121212121212121212121212121212121212121212121212")
	expectedAct1 := fromHex(t, "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a")
	stubAct2 := fromHex(t, "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae")
	expectedAct3 := fromHex(t, "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba")

	rw := &capturingRW{toRead: stubAct2}
	ck, _, err := runInitiator(rw, lsPriv, rsPub, ePriv)
	if err != nil {
		t.Fatalf("runInitiator: %v", err)
	}
	if len(rw.written) < 50 || !bytes.Equal(rw.written[:50], expectedAct1) {
		t.Fatalf("act 1 mismatch\n got: %x\nwant: %x", rw.written[:50], expectedAct1)
	}
	if len(rw.written) < 116 || !bytes.Equal(rw.written[50:116], expectedAct3) {
		t.Fatalf("act 3 mismatch\n got: %x\nwant: %x", rw.written[50:116], expectedAct3)
	}

	// Expected derived sk/rk from the spec.
	wantSK := fromHex(t, "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9")
	wantRK := fromHex(t, "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442")
	sk, rk := hkdfExpand(ck, nil)
	if !bytes.Equal(sk[:], wantSK) {
		t.Fatalf("derived sk mismatch\n got: %x\nwant: %x", sk[:], wantSK)
	}
	if !bytes.Equal(rk[:], wantRK) {
		t.Fatalf("derived rk mismatch\n got: %x\nwant: %x", rk[:], wantRK)
	}
}

// capturingRW is a tiny io.ReadWriter that returns scripted bytes from
// Read and accumulates Writes into a buffer. Used to test handshake
// implementations against fixed wire bytes.
type capturingRW struct {
	toRead  []byte
	readOff int
	written []byte
}

func (c *capturingRW) Read(p []byte) (int, error) {
	if c.readOff >= len(c.toRead) {
		return 0, io.EOF
	}
	n := copy(p, c.toRead[c.readOff:])
	c.readOff += n
	return n, nil
}

func (c *capturingRW) Write(p []byte) (int, error) {
	c.written = append(c.written, p...)
	return len(p), nil
}

// TestRoundTripOverTCP pairs an initiator with a responder over a
// real TCP loopback, runs the BOLT-8 handshake, and exchanges a few
// messages bidirectionally.
func TestRoundTripOverTCP(t *testing.T) {
	respPriv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	initPriv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		raw, err := l.Accept()
		if err != nil {
			return
		}
		server := Server(raw, respPriv)
		defer server.Close()
		_, _ = io.Copy(server, server)
	}()

	addr := l.Addr().(*net.TCPAddr)
	raw, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(addr.Port))
	if err != nil {
		t.Fatal(err)
	}
	client := Client(raw, initPriv, respPriv.PubKey())
	defer client.Close()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	payload := []byte("bolt8-round-trip")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q want %q", got, payload)
	}
}

// TestEncryptedMessageVector validates the per-message framing against
// the spec's chaining-key + first-message hex output.
func TestEncryptedMessageVector(t *testing.T) {
	// The spec's encryption test vector starts from a known sk and
	// initial chaining key. We replicate that state inside a Conn and
	// confirm the first two encrypted frames match the spec.
	sk := *(*[32]byte)(fromHex(t, "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9"))
	ck := *(*[32]byte)(fromHex(t, "919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01"))
	wantMsg0 := fromHex(t, "cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95")
	wantMsg1 := fromHex(t, "72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1")

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	c := &Conn{conn: a, isInitiator: true, handshakeDone: true, sk: sk, rk: sk, sck: ck, rck: ck}

	var captured [2][]byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 39) // 18-byte length frame + 5-byte body + 16-byte MAC = 39
		if _, err := io.ReadFull(b, buf); err != nil {
			return
		}
		captured[0] = append([]byte(nil), buf...)
		if _, err := io.ReadFull(b, buf); err != nil {
			return
		}
		captured[1] = append([]byte(nil), buf...)
	}()

	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	a.Close()
	<-done

	if !bytes.Equal(captured[0], wantMsg0) {
		t.Fatalf("msg 0 mismatch\n got: %x\nwant: %x", captured[0], wantMsg0)
	}
	if !bytes.Equal(captured[1], wantMsg1) {
		t.Fatalf("msg 1 mismatch\n got: %x\nwant: %x", captured[1], wantMsg1)
	}
}

// TestRekey exercises the BOLT-8 rekey rule: after the send nonce
// reaches 1000, both sides rotate the cipher key. A round-trip of
// 1001 messages must still arrive intact.
func TestRekey(t *testing.T) {
	respPriv, _ := secp256k1.GeneratePrivateKey()
	initPriv, _ := secp256k1.GeneratePrivateKey()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		raw, err := l.Accept()
		if err != nil {
			return
		}
		server := Server(raw, respPriv)
		defer server.Close()
		_, _ = io.Copy(server, server)
	}()

	addr := l.Addr().(*net.TCPAddr)
	raw, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(addr.Port))
	if err != nil {
		t.Fatal(err)
	}
	client := Client(raw, initPriv, respPriv.PubKey())
	defer client.Close()

	_ = client.SetDeadline(time.Now().Add(20 * time.Second))

	// Send and verify 600 messages — enough to cross the rekey boundary
	// (the send nonce reaches 1000 after 500 messages because each
	// message uses two nonce slots: one for the length, one for the body).
	for i := 0; i < 600; i++ {
		payload := []byte("msg-" + strconv.Itoa(i))
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(client, got); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("msg %d: got %q want %q", i, got, payload)
		}
	}
}

// TestFingerprintMatches confirms both peers derive the same handshake
// hash, which is what makes the value useful for channel binding.
func TestFingerprintMatches(t *testing.T) {
	respPriv, _ := secp256k1.GeneratePrivateKey()
	initPriv, _ := secp256k1.GeneratePrivateKey()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	serverFP := make(chan [32]byte, 1)
	go func() {
		raw, err := l.Accept()
		if err != nil {
			return
		}
		s := Server(raw, respPriv)
		// Trigger handshake by reading.
		_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
		one := make([]byte, 1)
		_, _ = s.Read(one)
		serverFP <- s.Fingerprint()
		_ = s.Close()
	}()

	addr := l.Addr().(*net.TCPAddr)
	raw, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(addr.Port))
	if err != nil {
		t.Fatal(err)
	}
	c := Client(raw, initPriv, respPriv.PubKey())
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}

	clientFP := c.Fingerprint()
	server := <-serverFP

	if clientFP != server {
		t.Fatalf("fingerprint mismatch:\n client: %x\n server: %x", clientFP, server)
	}
	var zero [32]byte
	if clientFP == zero {
		t.Fatal("fingerprint is zero — handshake didn't complete?")
	}
}

// TestMACFailureClosesConn corrupts a byte in a transport-message length
// frame before the receiver reads it. The decrypt MUST fail, and the
// receiver's underlying TCP conn MUST be closed (BOLT-8 §3 termination
// rule). A subsequent Read should return an error from a closed socket,
// not just the same MAC failure with the socket still open.
func TestMACFailureClosesConn(t *testing.T) {
	respPriv, _ := secp256k1.GeneratePrivateKey()
	initPriv, _ := secp256k1.GeneratePrivateKey()

	// Set up a TCP listener for the BOLT-8 server.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Server side is wrapped in our test scaffolding so we can capture
	// the raw conn and inject corruption into the wire bytes.
	type serverResult struct {
		err  error
		read int
	}
	resultCh := make(chan serverResult, 1)
	rawConnCh := make(chan net.Conn, 1)

	go func() {
		raw, err := l.Accept()
		if err != nil {
			resultCh <- serverResult{err: err}
			return
		}
		server := Server(raw, respPriv)
		buf := make([]byte, 64)
		n, rerr := server.Read(buf)
		rawConnCh <- raw
		resultCh <- serverResult{err: rerr, read: n}
	}()

	// Tamper writer: sits between our BOLT-8 Conn and the server's
	// listening socket. Writes are passed through; the first body-frame
	// length header (the third 18-byte chunk on the wire — after the two
	// 50-byte and 66-byte handshake acts) gets its first ciphertext byte
	// XOR'd. Concretely, we just flip a bit in any post-act-3 write.

	addr := l.Addr().(*net.TCPAddr)
	rawClient, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(addr.Port))
	if err != nil {
		t.Fatal(err)
	}
	tw := &tamperingConn{Conn: rawClient}
	client := Client(tw, initPriv, respPriv.PubKey())
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))

	// Make sure the handshake completes before we arm the tamperer.
	if err := client.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	tw.armed = true

	// Send a transport message; the tampering corrupts the on-wire length
	// frame's first ciphertext byte, so the server's MAC check fails.
	if _, err := client.Write([]byte("payload-that-will-be-corrupted")); err != nil {
		t.Fatal(err)
	}

	result := <-resultCh
	if result.err == nil {
		t.Fatal("server Read returned no error after corruption")
	}
	if !strings.Contains(result.err.Error(), "decrypt") {
		t.Fatalf("expected decrypt error, got %v", result.err)
	}

	// The server-side raw conn MUST be closed by now.
	srvRaw := <-rawConnCh
	_, err = srvRaw.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("server raw conn still open after MAC failure")
	}
}

// tamperingConn wraps a net.Conn and flips the second byte of the first
// payload write that happens after `armed` is set. Hits the BOLT-8
// post-handshake length frame's ciphertext bytes (bytes 0 and 1 of an
// 18-byte length frame are encrypted plaintext-length bytes).
type tamperingConn struct {
	net.Conn
	armed     bool
	tampered  bool
}

func (t *tamperingConn) Write(p []byte) (int, error) {
	if t.armed && !t.tampered && len(p) > 1 {
		corrupted := make([]byte, len(p))
		copy(corrupted, p)
		corrupted[1] ^= 0xFF
		t.tampered = true
		return t.Conn.Write(corrupted)
	}
	return t.Conn.Write(p)
}

// TestActVectorsResponder mirrors TestActVectorsInitiator but drives a
// responder with the same spec inputs and checks the act 2 output and
// the recovered initiator static key against BOLT-8 Appendix A.
//
// Spec inputs (from "Responder Tests"):
//   ls.priv = 0x2121...21 (32 bytes of 0x21) -> public ec7f7...
//   e.priv  = 0x2222...22 (32 bytes of 0x22) -> public 466d7...
//   act 1 in:   0x00 || initiator_eph_pub (036360...) || tag (0df6...)
//   act 2 out:  0x00 || responder_eph_pub (02466d...) || tag (6e2470...)
//   act 3 in:   0x00 || encrypted initiator static (b9e3...) || final tag
//   recovered rs = 0x034f355bdcb7cc...871aa
func TestActVectorsResponder(t *testing.T) {
	lsPriv := privFromHex(t, "2121212121212121212121212121212121212121212121212121212121212121")
	ePriv := privFromHex(t, "2222222222222222222222222222222222222222222222222222222222222222")
	act1In := fromHex(t, "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a")
	expectedAct2 := fromHex(t, "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae")
	act3In := fromHex(t, "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba")
	expectedRSHex := "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"

	rw := &capturingRW{toRead: append(append([]byte{}, act1In...), act3In...)}
	ck, _, rs, err := runResponder(rw, lsPriv, ePriv)
	if err != nil {
		t.Fatalf("runResponder: %v", err)
	}
	if !bytes.Equal(rw.written, expectedAct2) {
		t.Fatalf("act 2 mismatch\n got: %x\nwant: %x", rw.written, expectedAct2)
	}
	gotRS := hex.EncodeToString(rs.SerializeCompressed())
	if gotRS != expectedRSHex {
		t.Fatalf("recovered initiator static\n got: %s\nwant: %s", gotRS, expectedRSHex)
	}
	// Derived transport keys swap on the responder side per BOLT-8 §3 step 7.
	wantInitiatorSK := fromHex(t, "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9")
	wantInitiatorRK := fromHex(t, "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442")
	// HKDF on the responder side produces (rk, sk) where rk = initiator's sk
	// and sk = initiator's rk (the spec swaps them).
	a, b := hkdfExpand(ck, nil)
	if !bytes.Equal(a[:], wantInitiatorSK) {
		t.Fatalf("first HKDF half mismatch\n got: %x\nwant: %x", a[:], wantInitiatorSK)
	}
	if !bytes.Equal(b[:], wantInitiatorRK) {
		t.Fatalf("second HKDF half mismatch\n got: %x\nwant: %x", b[:], wantInitiatorRK)
	}
}

// TestRekeyVectors checks message-500 / message-501 byte exactness
// against BOLT-8 Appendix A — these vectors straddle the rekey
// boundary (rekey fires when nonce reaches 1000, and each message
// consumes two nonce slots, so message 501 is the first one encrypted
// with the rotated key).
//
// We seed a Conn with the post-handshake keys from Appendix A and
// drive 502 writes of the literal payload "hello"; only the 500th
// and 501st are inspected.
func TestRekeyVectors(t *testing.T) {
	sk := *(*[32]byte)(fromHex(t, "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9"))
	ck := *(*[32]byte)(fromHex(t, "919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01"))
	wantMsg500 := fromHex(t, "178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8")
	wantMsg501 := fromHex(t, "1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd")

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	c := &Conn{conn: a, isInitiator: true, handshakeDone: true, sk: sk, rk: sk, sck: ck, rck: ck}

	captured := make([][]byte, 502)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 502; i++ {
			buf := make([]byte, 39) // 18-byte length frame + 5-byte body + 16-byte MAC
			if _, err := io.ReadFull(b, buf); err != nil {
				return
			}
			captured[i] = append([]byte(nil), buf...)
		}
	}()

	for i := 0; i < 502; i++ {
		if _, err := c.Write([]byte("hello")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	a.Close()
	<-done

	if !bytes.Equal(captured[500], wantMsg500) {
		t.Fatalf("msg 500 mismatch\n got: %x\nwant: %x", captured[500], wantMsg500)
	}
	if !bytes.Equal(captured[501], wantMsg501) {
		t.Fatalf("msg 501 mismatch\n got: %x\nwant: %x", captured[501], wantMsg501)
	}
}

// TestRekeyAtMessage1000 picks up where TestRekeyVectors leaves off and
// confirms the second rekey transition (at nonce 1000 after the first
// rekey, i.e. cumulative message ~1000/1001 from the start).
func TestRekeyAtMessage1000(t *testing.T) {
	sk := *(*[32]byte)(fromHex(t, "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9"))
	ck := *(*[32]byte)(fromHex(t, "919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01"))
	wantMsg1000 := fromHex(t, "4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09")
	wantMsg1001 := fromHex(t, "2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36")

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	c := &Conn{conn: a, isInitiator: true, handshakeDone: true, sk: sk, rk: sk, sck: ck, rck: ck}

	captured := make([][]byte, 1002)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1002; i++ {
			buf := make([]byte, 39)
			if _, err := io.ReadFull(b, buf); err != nil {
				return
			}
			captured[i] = append([]byte(nil), buf...)
		}
	}()

	for i := 0; i < 1002; i++ {
		if _, err := c.Write([]byte("hello")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	a.Close()
	<-done

	if !bytes.Equal(captured[1000], wantMsg1000) {
		t.Fatalf("msg 1000 mismatch\n got: %x\nwant: %x", captured[1000], wantMsg1000)
	}
	if !bytes.Equal(captured[1001], wantMsg1001) {
		t.Fatalf("msg 1001 mismatch\n got: %x\nwant: %x", captured[1001], wantMsg1001)
	}
}
