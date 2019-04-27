package noisecat

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"os"
	"regexp"

	"github.com/flynn/noise"
)

// -- Logging

// Verbose is a logging facility
type Verbose bool

// Verb prints a line if Log is true
func (l Verbose) Verb(format string, v ...interface{}) {
	if l == true {
		log.Printf(format, v...)
	}
}

// Fatalf prints a messager if Log is true and exits with an error code
func (l Verbose) Fatalf(format string, v ...interface{}) {
	l.Verb(format, v...)
	os.Exit(1)
}

// Progress struct
type Progress struct {
	Bytes int64
	Dir   string
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

func parseProtocolName(protoName string) (hs byte, dh byte, cipher byte, hash byte, err error) {
	var ok bool
	regEx := regexp.MustCompile(`Noise_(\w{2})_(\w+)_(\w+)_(\w+)`)
	results := regEx.FindStringSubmatch(protoName)
	if len(results) == 5 {
		if hs, ok = PatternStrByte[results[1]]; ok == false {
			err = errors.New("Invalid handshake pattern")
			return
		}
		if dh, ok = DHStrByte[results[2]]; ok == false {
			err = errors.New("Invalid DH function")
			return
		}
		if cipher, ok = CipherStrByte[results[3]]; ok == false {
			err = errors.New("Invalid cipher function")
			return
		}
		if hash, ok = HashStrByte[results[4]]; ok == false {
			err = errors.New("Invalid hash function")
			return
		}
	}
	err = errors.New("Invalid protocol name")
	return
}
