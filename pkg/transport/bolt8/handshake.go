package bolt8

import (
	"errors"
	"fmt"
	"io"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// runInitiator performs acts 1 (write), 2 (read), 3 (write). On success
// it returns the chaining key after the handshake (the splitKeys input).
func runInitiator(
	conn io.ReadWriter,
	localStatic *secp256k1.PrivateKey,
	remoteStatic *secp256k1.PublicKey,
	ephemeral *secp256k1.PrivateKey, // injectable for test vectors; nil = generate
) (ck [32]byte, err error) {
	remoteStaticPub := remoteStatic.SerializeCompressed()
	h, ck := initialState(nil, remoteStaticPub, true)

	if ephemeral == nil {
		ephemeral, err = secp256k1.GeneratePrivateKey()
		if err != nil {
			return ck, fmt.Errorf("bolt8: generate ephemeral: %w", err)
		}
	}
	ePub := ephemeral.PubKey().SerializeCompressed()
	mixHash(&h, ePub)

	// Act 1 (initiator → responder): es = ECDH(e.priv, rs)
	es := ecdh(ephemeral, remoteStatic)
	ck, tempK1 := hkdfExpand(ck, es)
	c, err := encryptWithAD(tempK1, 0, h[:], nil)
	if err != nil {
		return ck, err
	}
	mixHash(&h, c)
	act1 := append([]byte{0x00}, ePub...)
	act1 = append(act1, c...)
	if _, err := conn.Write(act1); err != nil {
		return ck, fmt.Errorf("bolt8: write act 1: %w", err)
	}

	// Act 2 (responder → initiator): 50 bytes
	buf := make([]byte, 50)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return ck, fmt.Errorf("bolt8: read act 2: %w", err)
	}
	if buf[0] != 0x00 {
		return ck, fmt.Errorf("bolt8: unsupported act 2 version 0x%02x", buf[0])
	}
	re, err := secp256k1.ParsePubKey(buf[1:34])
	if err != nil {
		return ck, fmt.Errorf("bolt8: parse act 2 ephemeral: %w", err)
	}
	mixHash(&h, buf[1:34])
	ee := ecdh(ephemeral, re)
	ck, tempK2 := hkdfExpand(ck, ee)
	if _, err := decryptWithAD(tempK2, 0, h[:], buf[34:50]); err != nil {
		return ck, fmt.Errorf("bolt8: decrypt act 2: %w", err)
	}
	mixHash(&h, buf[34:50])

	// Act 3 (initiator → responder): encrypt own static, then HKDF se, MAC.
	localStaticPub := localStaticPub(localStatic)
	cStatic, err := encryptWithAD(tempK2, 1, h[:], localStaticPub)
	if err != nil {
		return ck, err
	}
	mixHash(&h, cStatic)
	se := ecdh(localStatic, re)
	ck, tempK3 := hkdfExpand(ck, se)
	tag, err := encryptWithAD(tempK3, 0, h[:], nil)
	if err != nil {
		return ck, err
	}
	act3 := append([]byte{0x00}, cStatic...)
	act3 = append(act3, tag...)
	if _, err := conn.Write(act3); err != nil {
		return ck, fmt.Errorf("bolt8: write act 3: %w", err)
	}
	return ck, nil
}

// runResponder performs acts 1 (read), 2 (write), 3 (read). On success
// it returns the post-handshake chaining key and the initiator's static
// public key recovered from act 3.
func runResponder(
	conn io.ReadWriter,
	localStatic *secp256k1.PrivateKey,
	ephemeral *secp256k1.PrivateKey, // injectable for test vectors; nil = generate
) (ck [32]byte, remoteStatic *secp256k1.PublicKey, err error) {
	localStaticPub := localStaticPub(localStatic)
	h, ck := initialState(localStaticPub, nil, false)

	// Act 1 (initiator → responder)
	buf := make([]byte, 50)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return ck, nil, fmt.Errorf("bolt8: read act 1: %w", err)
	}
	if buf[0] != 0x00 {
		return ck, nil, fmt.Errorf("bolt8: unsupported act 1 version 0x%02x", buf[0])
	}
	re, err := secp256k1.ParsePubKey(buf[1:34])
	if err != nil {
		return ck, nil, fmt.Errorf("bolt8: parse act 1 ephemeral: %w", err)
	}
	mixHash(&h, buf[1:34])
	es := ecdh(localStatic, re)
	ck, tempK1 := hkdfExpand(ck, es)
	if _, err := decryptWithAD(tempK1, 0, h[:], buf[34:50]); err != nil {
		return ck, nil, fmt.Errorf("bolt8: decrypt act 1: %w", err)
	}
	mixHash(&h, buf[34:50])

	// Act 2 (responder → initiator)
	if ephemeral == nil {
		ephemeral, err = secp256k1.GeneratePrivateKey()
		if err != nil {
			return ck, nil, fmt.Errorf("bolt8: generate ephemeral: %w", err)
		}
	}
	ePub := ephemeral.PubKey().SerializeCompressed()
	mixHash(&h, ePub)
	ee := ecdh(ephemeral, re)
	ck, tempK2 := hkdfExpand(ck, ee)
	c, err := encryptWithAD(tempK2, 0, h[:], nil)
	if err != nil {
		return ck, nil, err
	}
	mixHash(&h, c)
	act2 := append([]byte{0x00}, ePub...)
	act2 = append(act2, c...)
	if _, err := conn.Write(act2); err != nil {
		return ck, nil, fmt.Errorf("bolt8: write act 2: %w", err)
	}

	// Act 3 (initiator → responder): 66 bytes
	buf3 := make([]byte, 66)
	if _, err := io.ReadFull(conn, buf3); err != nil {
		return ck, nil, fmt.Errorf("bolt8: read act 3: %w", err)
	}
	if buf3[0] != 0x00 {
		return ck, nil, fmt.Errorf("bolt8: unsupported act 3 version 0x%02x", buf3[0])
	}
	rsBytes, err := decryptWithAD(tempK2, 1, h[:], buf3[1:50])
	if err != nil {
		return ck, nil, fmt.Errorf("bolt8: decrypt act 3 static: %w", err)
	}
	if len(rsBytes) != 33 {
		return ck, nil, errors.New("bolt8: act 3 static key wrong length")
	}
	remoteStatic, err = secp256k1.ParsePubKey(rsBytes)
	if err != nil {
		return ck, nil, fmt.Errorf("bolt8: parse act 3 static: %w", err)
	}
	mixHash(&h, buf3[1:50])
	se := ecdh(ephemeral, remoteStatic)
	ck, tempK3 := hkdfExpand(ck, se)
	if _, err := decryptWithAD(tempK3, 0, h[:], buf3[50:66]); err != nil {
		return ck, nil, fmt.Errorf("bolt8: decrypt act 3 tag: %w", err)
	}
	return ck, remoteStatic, nil
}

// localStaticPub returns the SEC1-compressed 33-byte serialization of the
// given private key's public key.
func localStaticPub(priv *secp256k1.PrivateKey) []byte {
	return priv.PubKey().SerializeCompressed()
}
