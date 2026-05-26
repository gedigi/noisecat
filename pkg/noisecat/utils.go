package noisecat

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"

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

var protocolRegexp = regexp.MustCompile(`^Noise_(\w+)_(\w+)_(\w+)_(\w+)$`)

func parseProtocolName(protoName string) (hs byte, dh byte, cipher byte, hash byte, err error) {
	results := protocolRegexp.FindStringSubmatch(protoName)
	if len(results) != 5 {
		err = errors.New("invalid protocol name (expected Noise_PT_DH_CP_HS)")
		return
	}
	var missing []string
	var ok bool
	if hs, ok = PatternStrByte[results[1]]; !ok {
		missing = append(missing, "handshake pattern "+results[1])
	}
	if dh, ok = DHStrByte[results[2]]; !ok {
		missing = append(missing, "DH function "+results[2])
	}
	if cipher, ok = CipherStrByte[results[3]]; !ok {
		missing = append(missing, "cipher function "+results[3])
	}
	if hash, ok = HashStrByte[results[4]]; !ok {
		missing = append(missing, "hash function "+results[4])
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
