package common

import (
	"log"
	"os"
)

// -- Logging

var l Log

// Log is a logging facility
type Log bool

// Verb prints a line if Log is true
func (l Log) Verb(format string, v ...interface{}) {
	if l == true {
		log.Printf(format, v...)
	}
}

// Fatalf prints a messager if Log is true and exits with an error code
func (l Log) Fatalf(format string, v ...interface{}) {
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
