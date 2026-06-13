# noisecat :smirk_cat:
The Noise swiss army knife

[![Go Reference](https://pkg.go.dev/badge/github.com/gedigi/noisecat.svg)](https://pkg.go.dev/github.com/gedigi/noisecat) [![Go Report Card](https://goreportcard.com/badge/github.com/gedigi/noisecat)](https://goreportcard.com/report/github.com/gedigi/noisecat) [![CI](https://github.com/gedigi/noisecat/actions/workflows/ci.yml/badge.svg)](https://github.com/gedigi/noisecat/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/gedigi/noisecat)](https://github.com/gedigi/noisecat/releases) [![License](https://img.shields.io/github/license/gedigi/noisecat)](LICENSE)

noisecat is a netcat-style networking utility that speaks the [Noise Protocol Framework](https://noiseprotocol.org/) over TCP. It can:

- Open authenticated, encrypted TCP sessions with any Noise handshake pattern (NN, NK, XX, IK, …) plus the standard PSK modifiers (psk0–psk3).
- Talk to Lightning Network nodes over [BOLT-8](https://github.com/lightning/bolts/blob/master/08-transport.md) (`Noise_XK_secp256k1_ChaChaPoly_SHA256` with the spec's wire framing — passes Appendix A test vectors byte-for-byte).
- Speak the [NoiseSocket](https://noiseprotocol.org/noisesocket) wire format, with an opt-in Reject/Retry/Switch negotiation layer.
- Speak [WhatsApp's multi-device](https://github.com/tulir/whatsmeow) Noise wire protocol — handshake + pinned-certificate verification against the real backend, or peer-to-peer between two noisecat instances.
- Tunnel decrypted traffic to a plain-TCP backend (`-proxy`), or run a command on connect (`-e`) — the classic netcat use cases, with the link encrypted by Noise.

## Install

**Prebuilt binaries** (Linux, macOS, FreeBSD, Windows; amd64 and arm64 where applicable) from the [Releases page](https://github.com/gedigi/noisecat/releases/latest). Each archive ships `noisecat`, `LICENSE`, and `README.md`, plus a CycloneDX SBOM; a `checksums.txt` is published alongside and **cosign-signed** (keyless). Verify it with:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/gedigi/noisecat/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

```bash
# macOS Apple Silicon, replace the version with the one you want from the Releases page:
$ V=1.2.0
$ curl -L "https://github.com/gedigi/noisecat/releases/download/v${V}/noisecat_${V}_darwin_arm64.tar.gz" | tar -xz noisecat
```

**Via `go install`** (requires Go 1.25+):

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
  -4	use IPv4 only
  -6	use IPv6 only
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
  -ns-fallback protocols
    	noisesocket client: comma-separated fallback protocols accepted on retry/switch
  -ns-policy string
    	noisesocket listener action on unsupported proposal: reject|retry|switch (default reject)
  -ns-support protocols
    	noisesocket listener: comma-separated supported protocols (enables negotiation)
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
    	wire transport: raw (default), noisesocket, bolt8 (auto-selected for secp256k1), or whatsapp (default "raw")
  -v	prints verbose output
  -validate key
    	validate that the base64 key is well-formed for -proto's DH function, then exit
  -w seconds
    	timeout in seconds for connect/handshake and idle connections (0 = none)

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
  raw, noisesocket, bolt8, whatsapp
```

The flags mirror traditional netcat:

- `-l -p 31337` listens on TCP port 31337.
- `-e /bin/sh` runs `/bin/sh` on connect (reverse shell anyone?).
- `-4` / `-6` force the IPv4 or IPv6 address family (mutually exclusive).
- `-w <seconds>` bounds the connect + handshake, and closes a connection once it has been idle for that long. `0` (the default) means no timeout.

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
| `noisesocket`    | [NoiseSocket spec](https://noiseprotocol.org/noisesocket): handshake messages carry `negotiation_data`, encrypted payloads contain an inner `body_len` + arbitrary padding, prologue is `"NoiseSocketInit1"` + `neg_data_len` + `neg_data` + app prologue | Spec-compliant, Accept-only by default. Opt into the **noisecat v1 negotiation layer** (Reject / Retry / Switch) with the `-ns-*` flags below. |
| `bolt8`          | [BOLT-8](https://github.com/lightning/bolts/blob/master/08-transport.md): `Noise_XK_secp256k1_ChaChaPoly_SHA256`, fixed-size handshake acts (50 / 50 / 66 bytes) with a 1-byte version prefix, encrypted 2-byte length headers + AEAD-tagged payloads, automatic rekey every 1000 messages, prologue defaults to `"lightning"` | Auto-selected when `-proto` uses `secp256k1`. Interoperable with `lnd` / `cln` / `eclair` — Appendix A test vectors pass byte-for-byte. |
| `whatsapp`       | [WhatsApp multi-device](https://github.com/tulir/whatsmeow): `Noise_XX_25519_AESGCM_SHA256`, a one-time `WA` header (prologue) + 3-byte length frames, handshake messages wrapped in protobuf, prologue is the WA header | Connects to WhatsApp's real backend (handshake + pinned-certificate verification, **no login**) or peers two noisecat instances. See [the WhatsApp section](#whatsapp). |

Companion flags that work with any transport:

- `-prologue <string>` mixes the given bytes into the handshake hash. Both peers must use the same value.
- `-negotiation <string>` (NoiseSocket only) is the initiator's first-message `negotiation_data`.

### NoiseSocket negotiation (Reject / Retry / Switch)

By default the `noisesocket` transport is **Accept-only** and spec-interoperable: the responder reads the initiator's `negotiation_data` and proceeds with the proposed protocol. The `-ns-*` flags activate an **opt-in, noisecat-specific** negotiation layer that adds the three remaining outcomes. It only interoperates noisecat-to-noisecat (like the `raw` transport).

- `-ns-support <p1,p2,…>` (listener) — protocols the responder accepts, in preference order. Setting this enables negotiation on the listener.
- `-ns-policy reject|retry|switch` (listener, default `reject`) — what to do when the initiator proposes a protocol not in `-ns-support`:
  - `reject` — refuse and close (initiator gets a clear error).
  - `retry` — ask the initiator to retry with the responder's preferred protocol.
  - `switch` — invert roles: the responder becomes the initiator of its preferred protocol.
- `-ns-fallback <p1,p2,…>` (client) — protocols the initiator will accept if asked to retry or switch. Setting this enables negotiation on the client. The `-proto` value is the initiator's proposal; a requested protocol outside `{proto} ∪ fallback` aborts the handshake.

Each negotiation attempt mixes the prior transcript into the handshake prologue, so a tampered or stripped retry/switch makes the handshake fail (downgrade binding). The chain is capped at 4 attempts. A `switch` requires both sides to hold the key material the target protocol needs *in their inverted roles* (e.g. `-lstatic`/`-rstatic`), or the handshake aborts with an error.

**Example — listener supports only `XX`, steers an `NN` client via retry:**

```bash
# Listener: accept only XX; retry anything else
$ noisecat -transport noisesocket -l -p 4444 \
    -ns-support Noise_XX_25519_AESGCM_SHA256 -ns-policy retry

# Client: propose NN, allow falling back to XX
$ noisecat -transport noisesocket 127.0.0.1 4444 \
    -proto Noise_NN_25519_AESGCM_SHA256 \
    -ns-fallback Noise_XX_25519_AESGCM_SHA256
```

Swap `-ns-policy retry` for `switch` to have the listener drive the `XX` handshake itself, or `reject` to refuse outright.

## WhatsApp

WhatsApp's multi-device protocol uses the Noise Protocol Framework — specifically `Noise_XX_25519_AESGCM_SHA256` — under a service-specific wire envelope: a one-time `WA` header (also mixed in as the Noise prologue), 3-byte big-endian length frames, and handshake messages wrapped in protobuf. The `whatsapp` transport implements that envelope, the way the `bolt8` transport implements Lightning's. The wire details were derived from [`whatsmeow`](https://github.com/tulir/whatsmeow).

The transport has two modes.

### Connecting to the real WhatsApp backend

With **no address**, the transport connects to WhatsApp's production websocket (`wss://web.whatsapp.com/ws/chat`), runs the Noise handshake, and **verifies the server certificate chain against WhatsApp's pinned root key** (an XEdDSA/Curve25519 chain: root → intermediate → leaf, with the leaf key bound to the handshake's server static).

```bash
$ noisecat -v -transport whatsapp
2026/06/13 23:26:45 Connected to ... using transport=whatsapp
```

This proves protocol-level interoperability with the live backend. It does **not** log in: noisecat sends an empty `ClientFinish` payload, which the Noise layer accepts but WhatsApp's application layer rejects. Real login requires WhatsApp account credentials / QR pairing and the full Signal-protocol app layer (what `whatsmeow`/`Baileys` implement), which is out of scope. Use this for protocol research and interop testing only — not for messaging or automation that would violate WhatsApp's Terms of Service.

### Peer-to-peer (two noisecat instances)

You cannot impersonate WhatsApp's real servers (you don't hold their key), but two noisecat instances can speak the WhatsApp framing to each other over plain TCP — like the other transports. With `-l` or a `host port`, the transport runs peer-to-peer with no certificate exchange. This gives you, for example, a bind shell tunneled over the WhatsApp wire protocol:

```bash
# Listener binds a shell, speaking the WhatsApp framing
$ noisecat -transport whatsapp -l -p 4444 -e /bin/sh

# Client connects (flags must precede the host/port)
$ noisecat -transport whatsapp 127.0.0.1 4444
```

(`-keygen`/`-lstatic` work as usual to give an endpoint a fixed Noise identity; otherwise an ephemeral one is generated per connection.)

### Limitations

- No login, no messaging, no Signal/E2E app layer — handshake + certificate verification only against the real backend.
- The real-backend mode is a fixed websocket endpoint; the pinned root key and `WA` header version track whatsmeow and may need updating if WhatsApp rotates them.
- The live handshake is covered by a test gated behind `NOISECAT_WA_LIVE=1` (it needs network to a third-party service and never runs in CI).

## Development

```bash
make test         # go test -race with coverage
make vet          # go vet ./...
make lint         # golangci-lint (install separately)
make linux darwin windows freebsd   # cross-compile
```

Requires Go 1.25+. CI runs build / vet / test on Linux, macOS, and Windows; lints via `golangci-lint`; and runs `govulncheck` for known CVEs on every push and PR. Tagging `vX.Y.Z` triggers a `goreleaser` build that publishes archives + sha256 checksums to the corresponding GitHub Release, each archive accompanied by a CycloneDX SBOM and the checksums file cosign-signed via GitHub OIDC. Dependabot keeps Go modules and Actions up to date weekly.

## Contributing

Bug reports, feature suggestions, and pull requests are welcome — open an issue on [GitHub](https://github.com/gedigi/noisecat/issues) or send a PR against `master`. Please run `go test -race ./...` and `golangci-lint run` before submitting.

## Credits

- [`github.com/flynn/noise`](https://github.com/flynn/noise) for the Noise Protocol Framework primitives that the `raw` and `noisesocket` transports build on.
- [`github.com/decred/dcrd/dcrec/secp256k1`](https://github.com/decred/dcrd) for the pure-Go secp256k1 implementation underpinning the BOLT-8 transport.
- [`github.com/tulir/whatsmeow`](https://github.com/tulir/whatsmeow) as the reference for WhatsApp's multi-device Noise wire format, certificate chain, and pinned root key.
- [`github.com/coder/websocket`](https://github.com/coder/websocket) for the WebSocket client the WhatsApp transport dials over, and [`filippo.io/edwards25519`](https://filippo.io/edwards25519) for the XEdDSA certificate-signature verification.
- [`github.com/mattn/go-shellwords`](https://github.com/mattn/go-shellwords) for parsing the `-e` command line.

## License

[MIT](LICENSE)
