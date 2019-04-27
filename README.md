# noisecat :smirk_cat:
The noise swiss army knife

[![Go Report Card](https://goreportcard.com/badge/github.com/gedigi/noisecat)](https://goreportcard.com/report/github.com/gedigi/noisecat) [![Build Status](https://travis-ci.org/gedigi/noisecat.svg?branch=master)](https://travis-ci.org/gedigi/noisecat)

noisecat :smirk_cat: is a featured networking utility which reads and writes data across network connections, using the Noise Protocol Framework (and TCP/IP).


## Download and build
Just `git clone` it, `make` it and you'll have `noisecat` binaries for macOS, Linux, FreeBSD, and Windows.

## Usage
### noisecat
This is how `noisecat -h` looks like:

```
Usage: noisecat [options] [address] [port]

Options:
  -e command
    	executes the given command
  -k	accepts multiple connections (-l && (-e || -proxy) required)
  -keygen
    	generates "-proto" appropriate keypair and prints it to stdout
  -l	listens for incoming connections
  -lstatic file
    	loads local keypair from file (use -keygen to generate)
  -p port
    	uses source port (default "0")
  -proto protocol name
    	sets protocol name (default "Noise_NN_25519_AESGCM_SHA256")
  -proxy address:port
    	forwards packets to address:port (-l required)
  -psk pre-shared key
    	uses pre-shared key in handshake
  -rstatic static key
    	defines remote static key (32 bytes, base64)
  -s address
    	uses source address
  -v	prints verbose output

Protocol name format: Noise_PT_DH_CP_HS

Where:
  PT: Handshake pattern
  DH: Diffie-Hellman handshake function
  CP: Cipher function
  HS: Hash function

  e.g. Noise_NN_25519_AESGCM_SHA256

Available handshake patterns:
  KK, KX, IX, NL, NX
  XN, XX, KN, NN, XK
  IN, IK
 
Available DH functions:
  25519
 
Available Cipher functions:
  ChaChaPoly, AESGCM
 
Available Hash functions:
  BLAKE2s, BLAKE2b, SHA256, SHA512
```

The flags are similar to the traditional netcat. In short:
* `-l -p 31337` listens on port 31337/tcp
* `-e /bin/sh` executes /bin/sh (reverse shell anyone?)

The main difference is the Noise Protocol-related flags:
* `-keygen` allows you to pre-generate a static keypair
* `-proto` sets the Noise Protocol name that you want to use
* `-psk` sets a pre-shared key, known to both client and server, used to authenticate a handshake
* `-rstatic` specifies the remote peer static (public) key, used in "K"-type handshakes
* `-lstatic` specifies the local file where to load static keys from

Other features are:
* `-proxy` allows to create a tunnel `client -noise-> server -tcp-> final endpoint`
* `-k` accepts multiple connections (like ncat)
* `-keygen` generates a pair of keys that, when saved to a file, can be used with the `-lstatic` flag

## TODO
- [x] write some tests
- [x] add Makefile
- [ ] add a static key validator helper function
- [ ] add new features (suggestions are welcome, pull requests too!)
