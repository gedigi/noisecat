package bolt8

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"strconv"
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
	ck, err := runInitiator(rw, lsPriv, rsPub, ePriv)
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
