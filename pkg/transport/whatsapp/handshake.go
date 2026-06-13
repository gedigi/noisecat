package whatsapp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Protocol constants, verified against whatsmeow.
const (
	// noiseStartPattern is the protocol name used to initialize the
	// handshake hash. whatsmeow hard-codes the 4 trailing NULs so the
	// string is exactly 32 bytes (Noise: h = name padded to HASHLEN).
	noiseStartPattern = "Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"

	// endpointURL / originHeader are the WhatsApp multi-device websocket.
	endpointURL  = "wss://web.whatsapp.com/ws/chat"
	originHeader = "https://web.whatsapp.com"
)

// waConnHeader is the 4-byte intro header ('W','A',magic,dictVersion). It is
// both prepended once to the first wire frame and mixed into the handshake
// hash as the Noise prologue.
var waConnHeader = []byte{'W', 'A', 6, 3}

// generateIV builds the 12-byte AEAD nonce: 8 zero bytes followed by the
// big-endian uint32 counter. Used for both handshake and transport messages.
func generateIV(count uint32) []byte {
	iv := make([]byte, 12)
	binary.BigEndian.PutUint32(iv[8:], count)
	return iv
}

// gcmPrepare wraps a 32-byte key as AES-256-GCM.
func gcmPrepare(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("whatsapp: init AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("whatsapp: init GCM: %w", err)
	}
	return gcm, nil
}

// noiseHandshake is a direct port of whatsmeow's socket.NoiseHandshake — the
// Noise_XX_25519_AESGCM_SHA256 state machine, with the AEAD additional-data
// being the running handshake hash and the per-key nonce counter reset on
// each key mix.
type noiseHandshake struct {
	hash    []byte
	salt    []byte
	key     cipher.AEAD
	counter uint32
}

func newNoiseHandshake() *noiseHandshake { return &noiseHandshake{} }

func sha256Slice(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func (nh *noiseHandshake) start(pattern string, header []byte) error {
	data := []byte(pattern)
	if len(data) == 32 {
		nh.hash = data
	} else {
		nh.hash = sha256Slice(data)
	}
	nh.salt = nh.hash
	key, err := gcmPrepare(nh.hash)
	if err != nil {
		return err
	}
	nh.key = key
	nh.authenticate(header)
	return nil
}

// authenticate is Noise MixHash: h = SHA256(h || data).
func (nh *noiseHandshake) authenticate(data []byte) {
	nh.hash = sha256Slice(append(append([]byte{}, nh.hash...), data...))
}

func (nh *noiseHandshake) postIncrementCounter() uint32 {
	c := nh.counter
	nh.counter++
	return c
}

func (nh *noiseHandshake) encrypt(plaintext []byte) []byte {
	ciphertext := nh.key.Seal(nil, generateIV(nh.postIncrementCounter()), plaintext, nh.hash)
	nh.authenticate(ciphertext)
	return ciphertext
}

func (nh *noiseHandshake) decrypt(ciphertext []byte) ([]byte, error) {
	plaintext, err := nh.key.Open(nil, generateIV(nh.postIncrementCounter()), ciphertext, nh.hash)
	if err == nil {
		nh.authenticate(ciphertext)
	}
	return plaintext, err
}

func (nh *noiseHandshake) mixSharedSecretIntoKey(priv, pub [32]byte) error {
	secret, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return fmt.Errorf("whatsapp: x25519: %w", err)
	}
	return nh.mixIntoKey(secret)
}

func (nh *noiseHandshake) mixIntoKey(data []byte) error {
	nh.counter = 0
	write, read, err := nh.extractAndExpand(nh.salt, data)
	if err != nil {
		return err
	}
	nh.salt = write
	key, err := gcmPrepare(read)
	if err != nil {
		return err
	}
	nh.key = key
	return nil
}

// finish derives the final transport keys via Noise Split:
// HKDF(ck, empty, 2) -> (write, read).
func (nh *noiseHandshake) finish() (write, read []byte, err error) {
	return nh.extractAndExpand(nh.salt, nil)
}

func (nh *noiseHandshake) extractAndExpand(salt, data []byte) (write, read []byte, err error) {
	h := hkdf.New(sha256.New, data, salt, nil)
	write = make([]byte, 32)
	read = make([]byte, 32)
	if _, err = io.ReadFull(h, write); err != nil {
		return nil, nil, fmt.Errorf("whatsapp: hkdf write key: %w", err)
	}
	if _, err = io.ReadFull(h, read); err != nil {
		return nil, nil, fmt.Errorf("whatsapp: hkdf read key: %w", err)
	}
	return write, read, nil
}

// dhKeypair is an X25519 keypair.
type dhKeypair struct {
	priv [32]byte
	pub  [32]byte
}

// generateKeypair makes a fresh X25519 ephemeral keypair.
func generateKeypair() (dhKeypair, error) {
	var kp dhKeypair
	if _, err := rand.Read(kp.priv[:]); err != nil {
		return kp, fmt.Errorf("whatsapp: read random: %w", err)
	}
	pub, err := curve25519.X25519(kp.priv[:], curve25519.Basepoint)
	if err != nil {
		return kp, fmt.Errorf("whatsapp: derive public key: %w", err)
	}
	copy(kp.pub[:], pub)
	return kp, nil
}

// handshakeResult holds the outcome of a completed WhatsApp Noise handshake.
type handshakeResult struct {
	writeKey   cipher.AEAD
	readKey    cipher.AEAD
	peerStatic []byte // the remote peer's Noise static public key (32 bytes)
}

// clientHandshake runs the initiator side of the WhatsApp Noise_XX handshake
// over rw and returns the derived transport keys. clientStatic is the
// client's long-term Noise keypair; clientPayload is the (encrypted)
// ClientFinish payload — empty is fine, the Noise key agreement completes
// regardless of its contents. When rootKey is non-nil the server's
// certificate chain is verified against it (connecting to the real WhatsApp
// backend); when nil, cert verification is skipped (peer-to-peer mode, where
// the responder is another noisecat and sends no certificate).
func clientHandshake(rw *framedConn, clientStatic dhKeypair, clientPayload []byte, rootKey *[32]byte) (*handshakeResult, error) {
	nh := newNoiseHandshake()
	if err := nh.start(noiseStartPattern, waConnHeader); err != nil {
		return nil, err
	}

	eph, err := generateKeypair()
	if err != nil {
		return nil, err
	}
	nh.authenticate(eph.pub[:])

	// msg1: ClientHello{ephemeral}
	if err := rw.writeFrame(marshalClientHello(eph.pub[:])); err != nil {
		return nil, fmt.Errorf("whatsapp: send ClientHello: %w", err)
	}

	// msg2: ServerHello{ephemeral, static, payload}
	respBytes, err := rw.readFrame()
	if err != nil {
		return nil, fmt.Errorf("whatsapp: read ServerHello: %w", err)
	}
	sh, err := unmarshalServerHello(respBytes)
	if err != nil {
		return nil, err
	}
	serverEph := [32]byte(sh.ephemeral)

	nh.authenticate(sh.ephemeral)
	if err := nh.mixSharedSecretIntoKey(eph.priv, serverEph); err != nil {
		return nil, fmt.Errorf("whatsapp: mix server ephemeral: %w", err)
	}
	staticDec, err := nh.decrypt(sh.static)
	if err != nil {
		return nil, fmt.Errorf("whatsapp: decrypt server static: %w", err)
	}
	if len(staticDec) != 32 {
		return nil, fmt.Errorf("whatsapp: server static length %d (expected 32)", len(staticDec))
	}
	if err := nh.mixSharedSecretIntoKey(eph.priv, [32]byte(staticDec)); err != nil {
		return nil, fmt.Errorf("whatsapp: mix server static: %w", err)
	}
	certDec, err := nh.decrypt(sh.payload)
	if err != nil {
		return nil, fmt.Errorf("whatsapp: decrypt certificate: %w", err)
	}
	if rootKey != nil {
		if err := verifyServerCert(certDec, staticDec, *rootKey); err != nil {
			return nil, fmt.Errorf("whatsapp: verify server cert: %w", err)
		}
	}

	// msg3: ClientFinish{static, payload}
	encStatic := nh.encrypt(clientStatic.pub[:])
	if err := nh.mixSharedSecretIntoKey(clientStatic.priv, serverEph); err != nil {
		return nil, fmt.Errorf("whatsapp: mix client static: %w", err)
	}
	encPayload := nh.encrypt(clientPayload)
	if err := rw.writeFrame(marshalClientFinish(encStatic, encPayload)); err != nil {
		return nil, fmt.Errorf("whatsapp: send ClientFinish: %w", err)
	}

	write, read, err := nh.finish()
	if err != nil {
		return nil, err
	}
	writeKey, err := gcmPrepare(write)
	if err != nil {
		return nil, err
	}
	readKey, err := gcmPrepare(read)
	if err != nil {
		return nil, err
	}
	return &handshakeResult{writeKey: writeKey, readKey: readKey, peerStatic: staticDec}, nil
}

// serverHandshake runs the responder side of the WhatsApp Noise_XX handshake
// over rw (which must be configured to consume the client's WA header). It is
// used for peer-to-peer noisecat-to-noisecat connections; payload is the
// (encrypted) ServerHello payload, empty for plain p2p (no certificate).
func serverHandshake(rw *framedConn, serverStatic dhKeypair, payload []byte) (*handshakeResult, error) {
	nh := newNoiseHandshake()
	if err := nh.start(noiseStartPattern, waConnHeader); err != nil {
		return nil, err
	}

	// msg1: ClientHello{ephemeral}
	m1, err := rw.readFrame()
	if err != nil {
		return nil, fmt.Errorf("whatsapp: read ClientHello: %w", err)
	}
	clientEphB, err := unmarshalClientHello(m1)
	if err != nil {
		return nil, err
	}
	clientEph := [32]byte(clientEphB)
	nh.authenticate(clientEphB)

	// msg2: ServerHello{ephemeral, static, payload}
	serverEph, err := generateKeypair()
	if err != nil {
		return nil, err
	}
	nh.authenticate(serverEph.pub[:])
	if err := nh.mixSharedSecretIntoKey(serverEph.priv, clientEph); err != nil {
		return nil, fmt.Errorf("whatsapp: mix client ephemeral: %w", err)
	}
	encStatic := nh.encrypt(serverStatic.pub[:])
	if err := nh.mixSharedSecretIntoKey(serverStatic.priv, clientEph); err != nil {
		return nil, fmt.Errorf("whatsapp: mix server static: %w", err)
	}
	encPayload := nh.encrypt(payload)
	if err := rw.writeFrame(marshalServerHello(serverEph.pub[:], encStatic, encPayload)); err != nil {
		return nil, fmt.Errorf("whatsapp: send ServerHello: %w", err)
	}

	// msg3: ClientFinish{static, payload}
	m3, err := rw.readFrame()
	if err != nil {
		return nil, fmt.Errorf("whatsapp: read ClientFinish: %w", err)
	}
	cfStatic, cfPayload, err := unmarshalClientFinish(m3)
	if err != nil {
		return nil, err
	}
	clientStaticDec, err := nh.decrypt(cfStatic)
	if err != nil {
		return nil, fmt.Errorf("whatsapp: decrypt client static: %w", err)
	}
	if len(clientStaticDec) != 32 {
		return nil, fmt.Errorf("whatsapp: client static length %d (expected 32)", len(clientStaticDec))
	}
	if err := nh.mixSharedSecretIntoKey(serverEph.priv, [32]byte(clientStaticDec)); err != nil {
		return nil, fmt.Errorf("whatsapp: mix client static: %w", err)
	}
	if _, err := nh.decrypt(cfPayload); err != nil {
		return nil, fmt.Errorf("whatsapp: decrypt client payload: %w", err)
	}

	write, read, err := nh.finish()
	if err != nil {
		return nil, err
	}
	// The responder mirrors the initiator's key directions: it sends with
	// the initiator's read key (c2) and receives with the write key (c1).
	sendKey, err := gcmPrepare(read)
	if err != nil {
		return nil, err
	}
	recvKey, err := gcmPrepare(write)
	if err != nil {
		return nil, err
	}
	return &handshakeResult{writeKey: sendKey, readKey: recvKey, peerStatic: clientStaticDec}, nil
}
