# noisecat :smirk_cat:
The noise swiss army knife

[![Go Report Card](https://goreportcard.com/badge/github.com/gedigi/noisecat)](https://goreportcard.com/report/github.com/gedigi/noisecat) [![Build Status](https://travis-ci.org/gedigi/noisecat.svg?branch=master)](https://travis-ci.org/gedigi/noisecat)

This repository contains a set of tools that allow to read and write data across network connections using the [Noise Protocol Framework](http://noiseprotocol.org) (and TCP/IP).

* `noisecat` uses the "raw" Noise protocol framework, with some custom assumptions for framing
* `noisesocat` uses the NoiseSocket protocol, which provides a framing layer on top of Noise

The Noise protocol family is still under development (i.e. the signaling/negotiation language is still being developed). This repository will host tools related to new developments of the Noise framework, as well as tools to provide additional features with the available protocools.

Currently `noisecat` and `noisesocat` share the same features. `noisesocat` makes some assumptions for you, so it's a bit more immeidate to use, but provides less flexibility in the choice of the protocol. For instance, `noisesocat` will use `Noise_XX_25519_ChaChaPoly_BLAKE2b` as default, Noise protocol and will use the `IK` handshake pattern if the static key of the remote peer is provided.

## Download and build
Just `git clone` it, `make` it and you'll have `noisecat` and `noisesocat` binaries for macOS, Linux, and Windows.

## Usage
### noisecat
This is how `noisecat -h` looks like:

```
Usage: noisecat [options] [address] [port]

Options:
  -e command
    	Executes the given command
  -k	accepts multiple connections (-l && (-e || -proxy) required)
  -keygen
    	generates "-proto" appropriate keypair and prints it to stdout
  -l	listens for incoming connections
  -lstatic file
    	file containing local keypair (use -keygen to generate)
  -p port
    	source port to use
  -proto protocol name
    	protocol name to use (default "Noise_NN_25519_AESGCM_SHA256")
  -proxy address:port
    	address:port combination to forward connections to (-l required)
  -psk pre-shared key
    	pre-shared key to use
  -rstatic static key
    	static key of the remote peer (32 bytes, base64)
  -s address
    	source address to use
  -v	more verbose output

Protocol name format: Noise_PT_DH_CP_HS

Where:
  PT: Handshake pattern
  DH: Diffie-Hellman handshake function
  CP: Cipher function
  HS: Hash function

  e.g. Noise_NN_25519_AESGCM_SHA256

Available handshake patterns:
  NN, NL, NX, XN, XX
  KN, KX, IN, XK, KK
  IK, IX
 
Available DH functions:
  25519
 
Available Cipher functions:
  ChaChaPoly, AESGCM
 
Available Hash functions:
  BLAKE2b, SHA256, SHA512, BLAKE2s
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

### noisesocat
`noisesocat -h` looks very similar as `noisecat`'s, as they share the same features:

```
Usage: noisesocat [options] [address] [port]

Options:
  -e command
    	Executes the given command
  -k	accepts multiple connections (-l && (-e || -proxy) required)
  -keygen
    	generates 25519 keypair and prints it to stdout
  -l	listens for incoming connections
  -lstatic file
    	file containing local keypair (use -keygen to generate)
  -p port
    	source port to use
  -proxy address:port
    	address:port combination to forward connections to (-l required)
  -rstatic static key
    	static key of the remote peer (32 bytes, base64)
  -s address
    	source address to use
  -v	more verbose output

The connection will automatically use:
  Noise_XX_25519_ChaChaPoly_BLAKE2b (IK if -rstatic)
```

As you can see, there is no `-proto` flag. Everything else is the same.

## TODO
- [x] write some tests
- [x] add Makefile
- [ ] add a static key validator helper function
- [ ] add new features (suggestions are welcome, pull requests too!)
