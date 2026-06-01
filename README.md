# noisecat :smirk_cat:
The Noise swiss army knife

[![Go Reference](https://pkg.go.dev/badge/github.com/gedigi/noisecat.svg)](https://pkg.go.dev/github.com/gedigi/noisecat) [![Go Report Card](https://goreportcard.com/badge/github.com/gedigi/noisecat)](https://goreportcard.com/report/github.com/gedigi/noisecat) [![CI](https://github.com/gedigi/noisecat/actions/workflows/ci.yml/badge.svg)](https://github.com/gedigi/noisecat/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/gedigi/noisecat)](https://github.com/gedigi/noisecat/releases) [![License](https://img.shields.io/github/license/gedigi/noisecat)](LICENSE)

noisecat is a netcat-style networking utility that speaks the [Noise Protocol Framework](https://noiseprotocol.org/) over TCP. It can:

- Open authenticated, encrypted TCP sessions with any Noise handshake pattern (NN, NK, XX, IK, …) plus the standard PSK modifiers (psk0–psk3).
- Talk to Lightning Network nodes over [BOLT-8](https://github.com/lightning/bolts/blob/master/08-transport.md) (`Noise_XK_secp256k1_ChaChaPoly_SHA256` with the spec's wire framing — passes Appendix A test vectors byte-for-byte).
- Speak the [NoiseSocket](https://noiseprotocol.org/noisesocket) wire format.
- Tunnel decrypted traffic to a plain-TCP backend (`-proxy`), or run a command on connect (`-e`) — the classic netcat use cases, with the link encrypted by Noise.

## Install

**Prebuilt binaries** (Linux, macOS, FreeBSD, Windows; amd64 and arm64 where applicable) from the [Releases page](https://github.com/gedigi/noisecat/releases/latest). Each archive ships `noisecat`, `LICENSE`, and `README.md`; a `checksums.txt` is published alongside.

```bash
# macOS Apple Silicon, replace the version with the one you want from the Releases page:
$ V=1.1.1
$ curl -L "https://github.com/gedigi/noisecat/releases/download/v${V}/noisecat_${V}_darwin_arm64.tar.gz" | tar -xz noisecat
```

**Via `go install`** (requires Go 1.23+):

```bash
go install github.com/gedigi/noisecat/cmd/noisecat@latest
```

**Build from source:**

```bash
git clone https://github.com/gedigi/noisecat.git
cd noisecat
make linux darwin windows freebsd   # cross-compile into bin/
```

## Usage

`noisecat -h`:

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
  -negotiation data
    	NoiseSocket negotiation_data (only used with -transport noisesocket)
  -p port
    	uses source port (default "0")
  -prologue prologue
    	application prologue mixed into the handshake hash
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
  -transport transport
    	wire transport: raw (default), noisesocket, or bolt8 (auto-selected for secp256k1) (default "raw")
  -v	prints verbose output
  -validate key
    	validate that the base64 key is well-formed for -proto's DH function, then exit

Protocol name format: Noise_PT_DH_CP_HS

Where:
  PT: Handshake pattern
  DH: Diffie-Hellman handshake function
  CP: Cipher function
  HS: Hash function

  e.g. Noise_NN_25519_AESGCM_SHA256

Available handshake patterns:
  NN, NK, NX, XN, XK,
  XX, KN, KK, KX, IN,
  IK, IX (each combinable with the psk0..psk3 modifier)

Available DH functions:
  25519, secp256k1

Available Cipher functions:
  ChaChaPoly, AESGCM

Available Hash functions:
  BLAKE2s, BLAKE2b, SHA256, SHA512

Available transports:
  raw, noisesocket, bolt8
```

The flags mirror traditional netcat:

- `-l -p 31337` listens on TCP port 31337.
- `-e /bin/sh` runs `/bin/sh` on connect (reverse shell anyone?).

The Noise-specific flags:

- `-proto` picks the Noise protocol name.
- `-psk` is a **base64-encoded 32-byte** pre-shared key (e.g. `head -c 32 /dev/urandom | base64`). Pair it with a psk-modified protocol name such as `Noise_NNpsk0_25519_AESGCM_SHA256` ("PSK before the first message") or `Noise_NKpsk2_25519_AESGCM_SHA256` ("PSK after act 2"). The `psk[0-3]` modifier selects where the PSK token is mixed in, per [Noise spec §9.2](https://noiseprotocol.org/noise.html#pre-shared-symmetric-keys). Passing `-psk` without a psk modifier (or vice versa) is rejected at flag-parsing time.
- `-rstatic` is the remote peer's static (public) key — base64-encoded 32 bytes for Curve25519, 33 bytes (compressed) for secp256k1.
- `-lstatic` loads a local keypair JSON from disk. Generate one with `-keygen`. `chmod 600` it.
- `-validate <key>` runs the static-key validator and exits — useful for sanity-checking an `-rstatic` value before opening a connection.

Convenience flags:

- `-proxy` tunnels Noise traffic to a plain-TCP backend (`client -noise-> noisecat -tcp-> endpoint`).
- `-k` accepts multiple connections (like `ncat -k`).

### Examples

**Encrypted chat shell** (default protocol, accepts multiple clients):

```bash
# Server
$ noisecat -k -e /bin/sh -l -p 4444

# Client
$ noisecat <server-ip> 4444
```

**NoiseSocket round-trip** with negotiation_data:

```bash
$ noisecat -transport noisesocket -negotiation 'app=demo' -l -p 4444 &
$ noisecat -transport noisesocket -negotiation 'app=demo' 127.0.0.1 4444
```

**Lightning Network handshake (BOLT-8):**

```bash
# 1. Generate (or reuse) a local static keypair
$ noisecat -proto Noise_XK_secp256k1_ChaChaPoly_SHA256 -keygen > node.json
$ chmod 600 node.json

# 2. Connect to a Lightning node — rstatic is the node's compressed pubkey, base64-encoded
$ noisecat -proto Noise_XK_secp256k1_ChaChaPoly_SHA256 \
    -lstatic node.json \
    -rstatic <base64-encoded-33-byte-compressed-pubkey> \
    <host> <port>
```

The BOLT-8 transport is auto-selected when the protocol name contains `secp256k1`; the `lightning` prologue is supplied automatically.

**Noise-protected TCP proxy:**

```bash
# Backend (plain TCP)
$ python3 -m http.server 8000

# Noisecat proxy on 19999, forwarding decrypted traffic to the backend
$ noisecat -v -k -l -proxy 127.0.0.1:8000 -p 19999 127.0.0.1

# Client
$ printf 'GET / HTTP/1.0\r\n\r\n' | noisecat 127.0.0.1 19999
```

The proxy uses TCP-style half-close, so a client that sends a request and closes its write side still receives the backend's full response.

## Transports

noisecat speaks the Noise Protocol Framework over a pluggable transport layer. The same Noise handshake patterns and DH/cipher/hash combinations work regardless of transport — only the on-the-wire framing differs.

| `-transport`     | Wire format | Notes |
|---|---|---|
| `raw` (default)  | 2-byte big-endian length prefix + Noise message | noisecat's historical framing; interoperable with itself only. |
| `noisesocket`    | [NoiseSocket spec](https://noiseprotocol.org/noisesocket): handshake messages carry `negotiation_data`, encrypted payloads contain an inner `body_len` + arbitrary padding, prologue is `"NoiseSocketInit1"` + `neg_data_len` + `neg_data` + app prologue | Spec-compliant. Only the Accept negotiation outcome is supported (no Switch / Retry / Reject). |
| `bolt8`          | [BOLT-8](https://github.com/lightning/bolts/blob/master/08-transport.md): `Noise_XK_secp256k1_ChaChaPoly_SHA256`, fixed-size handshake acts (50 / 50 / 66 bytes) with a 1-byte version prefix, encrypted 2-byte length headers + AEAD-tagged payloads, automatic rekey every 1000 messages, prologue defaults to `"lightning"` | Auto-selected when `-proto` uses `secp256k1`. Interoperable with `lnd` / `cln` / `eclair` — Appendix A test vectors pass byte-for-byte. |

Companion flags that work with any transport:

- `-prologue <string>` mixes the given bytes into the handshake hash. Both peers must use the same value.
- `-negotiation <string>` (NoiseSocket only) is the initiator's first-message `negotiation_data`.

## Development

```bash
make test         # go test -race with coverage
make vet          # go vet ./...
make lint         # golangci-lint (install separately)
make linux darwin windows freebsd   # cross-compile
```

Requires Go 1.23+. CI runs build / vet / test on Linux, macOS, and Windows; lints via `golangci-lint`; and runs `govulncheck` for known CVEs on every push and PR. Tagging `vX.Y.Z` triggers a `goreleaser` build that publishes archives + sha256 checksums to the corresponding GitHub Release.

## Contributing

Bug reports, feature suggestions, and pull requests are welcome — open an issue on [GitHub](https://github.com/gedigi/noisecat/issues) or send a PR against `master`. Please run `go test -race ./...` and `golangci-lint run` before submitting.

## Credits

- [`github.com/flynn/noise`](https://github.com/flynn/noise) for the Noise Protocol Framework primitives that the `raw` and `noisesocket` transports build on.
- [`github.com/decred/dcrd/dcrec/secp256k1`](https://github.com/decred/dcrd) for the pure-Go secp256k1 implementation underpinning the BOLT-8 transport.
- [`github.com/mattn/go-shellwords`](https://github.com/mattn/go-shellwords) for parsing the `-e` command line.

## License

[MIT](LICENSE)
