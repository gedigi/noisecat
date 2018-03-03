package noisecat

import (
	"crypto/rand"
	"encoding/json"
	"log"
	"os"

	"github.com/gedigi/noise"
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
	if l == true {
		log.Printf(format, v...)
	}
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
	output, _ := json.Marshal(keypair)
	if err != nil {
		return nil, err
	}
	return output, err
}
