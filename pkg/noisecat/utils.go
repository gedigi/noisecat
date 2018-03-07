package noisecat

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"os"
	"regexp"

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

func parseProtocolName(protoName string) (byte, byte, byte, byte, error) {
	var hs, dh, cipher, hash byte
	var err error
	var ok bool
	regEx := regexp.MustCompile(`Noise_(\w{2})_(\w+)_(\w+)_(\w+)`)
	results := regEx.FindStringSubmatch(protoName)
	if len(results) == 5 {
		if hs, ok = PatternStrByte[results[1]]; ok == false {
			err = errors.New("Invalid handshake pattern")
			goto exit
		}
		if dh, ok = DHStrByte[results[2]]; ok == false {
			err = errors.New("Invalid DH function")
			goto exit
		}
		if cipher, ok = CipherStrByte[results[3]]; ok == false {
			err = errors.New("Invalid cipher function")
			goto exit
		}
		if hash, ok = HashStrByte[results[4]]; ok == false {
			err = errors.New("Invalid hash function")
			goto exit
		}
		err = nil
	} else {
		err = errors.New("Invalid protocol name")
	}
exit:
	return hs, dh, cipher, hash, err
}
