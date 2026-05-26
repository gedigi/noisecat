package noisecat

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"

	"github.com/flynn/noise"
)

// Verbose is a logging facility
type Verbose bool

// Verb prints a line if Verbose is true.
func (l Verbose) Verb(format string, v ...interface{}) {
	if l {
		log.Printf(format, v...)
	}
}

// Errf writes an error line to stderr regardless of verbosity.
func (l Verbose) Errf(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, "noisecat: "+format+"\n", v...)
}

// Fatalf writes a message to stderr and exits with status 1.
func (l Verbose) Fatalf(format string, v ...interface{}) {
	l.Errf(format, v...)
	os.Exit(1)
}

// GenerateKeypair generates and outputs private and public keys based on the
// provided functions
func GenerateKeypair(dh, cipher, hash byte) ([]byte, error) {
	cs := noise.NewCipherSuite(DHByteObj[dh], CipherByteObj[cipher], HashByteObj[hash])
	keypair, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	return json.Marshal(keypair)
}

// noPSK is the sentinel value returned by parseProtocolName for protocols
// without a psk modifier. -1 fits the int8 type used in noise.Config's
// PresharedKeyPlacement (where 0 is a valid placement index, so a separate
// "unset" value is needed).
const noPSK int8 = -1

// protocolRegexp matches Noise protocol names like
//
//	Noise_NN_25519_AESGCM_SHA256
//	Noise_NKpsk2_25519_ChaChaPoly_SHA256
//	Noise_XX_secp256k1_ChaChaPoly_SHA256
//
// The first capture is the 2-letter base pattern; the second is the
// optional psk-modifier index (psk0, psk1, psk2, or psk3, per the Noise
// spec); then the DH, cipher, and hash function tokens.
var protocolRegexp = regexp.MustCompile(`^Noise_([A-Z]{2})(?:psk([0-3]))?_(\w+)_(\w+)_(\w+)$`)

func parseProtocolName(protoName string) (hs byte, dh byte, cipher byte, hash byte, psk int8, err error) {
	psk = noPSK
	results := protocolRegexp.FindStringSubmatch(protoName)
	if len(results) != 6 {
		err = errors.New("invalid protocol name (expected Noise_PT[pskN]_DH_CP_HS)")
		return
	}
	var missing []string
	var ok bool
	if hs, ok = PatternStrByte[results[1]]; !ok {
		missing = append(missing, "handshake pattern "+results[1])
	}
	if results[2] != "" {
		// regex already constrained to [0-3]; ParseInt cannot fail here.
		n, _ := strconv.ParseInt(results[2], 10, 8)
		psk = int8(n) //nolint:gosec // bounded by regex to [0,3]
	}
	if dh, ok = DHStrByte[results[3]]; !ok {
		missing = append(missing, "DH function "+results[3])
	}
	if cipher, ok = CipherStrByte[results[4]]; !ok {
		missing = append(missing, "cipher function "+results[4])
	}
	if hash, ok = HashStrByte[results[5]]; !ok {
		missing = append(missing, "hash function "+results[5])
	}
	if len(missing) > 0 {
		err = fmt.Errorf("unsupported %s", joinList(missing))
	}
	return
}

func joinList(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	out := items[0]
	for _, s := range items[1:] {
		out += ", " + s
	}
	return out
}
