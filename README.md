# noisecat :smirk_cat:
The noise swiss army knife

[![Go Report Card](https://goreportcard.com/badge/github.com/gedigi/noisecat)](https://goreportcard.com/report/github.com/gedigi/noisecat) [![CI](https://github.com/gedigi/noisecat/actions/workflows/ci.yml/badge.svg)](https://github.com/gedigi/noisecat/actions/workflows/ci.yml)

noisecat :smirk_cat: is a featured networking utility which reads and writes data across network connections, using the Noise Protocol Framework (and TCP/IP).


## Download and build
Requires Go 1.21+. Just `git clone` it and `make` it; you'll get `noisecat` binaries for macOS, Linux, FreeBSD, and Windows under `bin/`.

## Usage
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
  KK, KX, IX, NK, NX
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
* `-proto` sets the Noise Protocol name that you want to use
* `-psk` sets a pre-shared key — **base64-encoded 32 bytes** (e.g. the output of `head -c 32 /dev/urandom | base64`). PSK only takes effect with PSK-modified Noise patterns.
* `-rstatic` specifies the remote peer static (public) key — base64-encoded 32 bytes — used in "K"-type handshakes
* `-lstatic` specifies the local file where to load static keys from (recommend `chmod 600` on the file)

Other features are:
* `-proxy` allows to create a tunnel `client -noise-> server -tcp-> final endpoint`
* `-k` accepts multiple connections (like ncat)
* `-keygen` generates a pair of keys that, when saved to a file, can be used with the `-lstatic` flag

### Example
To bind a shell on port 4444/tcp (default protocol) and accept multiple clients:

```bash
$ noisecat -k -e /bin/sh -l -p 4444
```

To connect to that shell:
```bash
$ noisecat <ip> 4444
```

That's it!

### Transports

noisecat speaks the Noise Protocol Framework over a pluggable transport layer. The same Noise handshake patterns and DH/cipher/hash combinations work regardless of transport — only the on-the-wire framing differs.

| `-transport` | Wire format | Notes |
|---|---|---|
| `raw` (default) | 2-byte BE length prefix + Noise message | noisecat's historical framing; interoperable with itself only. |
| `noisesocket`   | [NoiseSocket spec](https://noiseprotocol.org/noisesocket): handshake messages carry `negotiation_data`, encrypted payloads contain an inner `body_len` + arbitrary padding, prologue is `"NoiseSocketInit1"` + `neg_data_len` + `neg_data` + app prologue | Spec-compliant, interoperable with other NoiseSocket peers. Only the Accept negotiation outcome is supported (no Switch/Retry/Reject). |
| `bolt8`         | [Lightning Network's BOLT-8](https://github.com/lightning/bolts/blob/master/08-transport.md): `Noise_XK_secp256k1_ChaChaPoly_SHA256`, fixed-size handshake acts (50/50/66 bytes) with a 1-byte version prefix, encrypted 2-byte length headers + AEAD-tagged payloads, automatic rekey every 1000 messages, prologue defaults to `"lightning"`. | Auto-selected when the protocol name contains `secp256k1`. Interoperable with `lnd` / `cln` / `eclair` (Appendix A test vectors pass byte-for-byte). |

Companion flags (work with any transport):

* `-prologue <string>` mixes the given byte string into the handshake hash. Both peers must use the same value.
* `-negotiation <string>` (NoiseSocket only) is the initiator's first-message `negotiation_data`.

Example NoiseSocket round-trip on `localhost:4444`:

```bash
$ noisecat -transport noisesocket -negotiation 'app=demo' -l -p 4444 &
$ noisecat -transport noisesocket -negotiation 'app=demo' 127.0.0.1 4444
```

#### Lightning (BOLT-8)

Generate a secp256k1 static keypair, then connect to a node by its public key:

```bash
# 1. Generate (or reuse) a local static keypair
$ noisecat -proto Noise_XK_secp256k1_ChaChaPoly_SHA256 -keygen > node.json
$ chmod 600 node.json

# 2. Connect to a Lightning node (rstatic is the node's compressed pubkey, base64-encoded)
$ noisecat -proto Noise_XK_secp256k1_ChaChaPoly_SHA256 \
    -lstatic node.json \
    -rstatic <base64-encoded-33-byte-compressed-pubkey> \
    <host> <port>
```

The BOLT-8 transport is auto-selected when the protocol name contains `secp256k1`; the `lightning` prologue is supplied automatically. To talk to two noisecats over BOLT-8, both ends need their own `node.json` and the client needs to know the server's compressed public key (the server prints it with `-v`).

### Proxying

`-proxy` turns noisecat into a TCP tunnel: the client speaks Noise to noisecat, noisecat forwards the decrypted bytes to the backend over plain TCP, and the backend's response is encrypted on the way back. The proxy uses TCP-style half-close, so a client that sends a request and closes its write side will still receive the backend's full response:

```bash
# Terminal 1 — start a plain-TCP backend
$ python3 -m http.server 8000

# Terminal 2 — noise-protected proxy on 19999
$ noisecat -v -k -l -proxy 127.0.0.1:8000 -p 19999 127.0.0.1

# Terminal 3 — client
$ printf 'GET / HTTP/1.0\r\n\r\n' | noisecat 127.0.0.1 19999
```

## Development

```bash
make test         # go test -race with coverage
make vet          # go vet ./...
make lint         # golangci-lint (install separately)
make linux darwin windows freebsd   # cross-compile
```

CI runs build/vet/test on Linux, macOS, and Windows; lint via `golangci-lint`; and `govulncheck` for known CVEs on every push and PR. Tagging `vX.Y.Z` triggers a `goreleaser` build that publishes signed binaries and checksums to the corresponding GitHub Release.

## TODO
- [x] write some tests
- [x] add Makefile
- [x] expose Lightning's BOLT-8 transport (Noise_XK_secp256k1_ChaChaPoly_SHA256)
- [x] expose the NoiseSocket transport
- [ ] add a static key validator helper function
- [ ] expose PSK-modified Noise patterns
- [ ] add new features (suggestions are welcome, pull requests too!)
