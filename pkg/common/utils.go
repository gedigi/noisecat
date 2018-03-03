package common

import (
	"log"
	"os"
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
