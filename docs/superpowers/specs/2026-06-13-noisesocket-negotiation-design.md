# NoiseSocket negotiation (Reject / Retry / Switch) — design

Status: approved 2026-06-13

## Goal

Extend noisecat's `noisesocket` transport beyond the current Accept-only
behavior to the three remaining negotiation outcomes — **Reject**, **Retry**,
**Switch** — driven by `negotiation_data`.

## Activation & backward-compat

The NoiseSocket spec leaves `negotiation_data` semantics application-defined.
noisecat therefore defines its own v1 convention. To preserve spec interop on
the default path, negotiation is **opt-in**:

- No negotiation flags → unchanged: opaque `negotiation_data`, Accept-only,
  spec-interoperable. Existing tests pass untouched.
- Negotiation engages only when negotiation flags are present. The negotiation
  layer is noisecat-to-noisecat only (documented, like the `raw` transport).

## v1 `negotiation_data` text format (`;`-separated `key=value`)

- Initiator's first frame: `ns=1;proto=<name>;data=<base64(user -negotiation)>`
- Responder responses (always with empty `noise_message`, except Switch):
  - `ns=1;action=reject;reason=<text>`
  - `ns=1;action=retry;proto=<name>`
  - `ns=1;action=switch;proto=<name>` (carried *with* the switched first message)
- Accept is implicit: responder reads the proposed `noise_message` and replies
  with empty `negotiation_data`.

## CLI surface

- Initiator: `-proto` = proposed protocol (unchanged); `-ns-fallback p1,p2,…`
  = ordered protocols it will accept on retry/switch. A requested protocol
  outside `{proto} ∪ fallback` → abort.
- Responder: `-ns-support p1,p2,…` = supported protocols (preference order);
  `-ns-policy reject|retry|switch` = action when the proposed protocol is not
  supported (default `reject`). Proposed protocol supported → always Accept.

Negotiation is enabled when `-ns-fallback` (client) or `-ns-support` (server)
is non-empty. Only valid with `-transport noisesocket`.

## Handshake flow per outcome

A negotiation phase precedes the normal Noise message loop. Only the first
frame in each direction carries `negotiation_data`; all later frames carry an
empty one.

Initiator sends `[neg=ns=1;proto=P;data=…, msg=msg1(P)]`, reads response:
- empty/no `action` → Accept; the response `noise_message` is handshake msg 2.
- `action=reject` → error(reason), close.
- `action=retry;proto=P2` (empty msg) → verify P2 allowed; rebuild for P2; resend.
- `action=switch;proto=P2` → verify allowed; initiator **becomes responder of
  P2**, reading the switch frame's `noise_message` as msg 1.

Responder reads the initiator's frame, parses `proto=P`:
- P ∈ support → Accept.
- else per policy: reject / retry(top supported) / switch(**becomes initiator
  of P2**, sends its msg 1).

Retry/switch chain capped at 4 attempts.

## Prologue chaining (downgrade binding)

Each attempt mixes the prior negotiation transcript into its prologue:

```
prologue = "NoiseSocketInit1" || uint16(len(initNeg)) || initNeg
           || appPrologue || transcript
```

`transcript` = the raw wire bytes (`neg_len||neg||msg_len||msg`) of every frame
exchanged *before* the current attempt, in chronological wire order. Both peers
observe identical bytes, so they derive identical prologues; a stripped or
altered retry/switch makes the prologues diverge and the handshake fails.

For a plain Accept the transcript is empty → byte-identical to today's formula,
which is why the default path and existing tests remain valid. `initNeg` is the
negotiation_data of the frame that opened the *current* (final) attempt: the
initiator's proposal for accept/retry, or the responder's switch neg for switch.

## Switch key-material constraints

Role inversion means whichever side becomes initiator/responder of P2 must hold
the keys P2's pattern needs *in the inverted role*. noisecat validates this when
building the config (via the factory) and aborts with a clear error if a
required `-lstatic`/`-rstatic` is missing, rather than half-completing.
Documented limitation: Switch only works for protocol/key combos both sides can
satisfy inverted.

## Architecture / layering

Protocol-name→`noise.Config` parsing stays in `pkg/noisecat`. The transport is a
pure framing layer, so `transport.Options` gains a `Negotiation` struct carrying
a `BuildConfig(name string, initiator bool) (*noise.Config, error)` factory
closure (supplied by noisecat) plus the policy data (proposed/fallback for the
initiator, supported/policy for the responder, and the app data). The
noisesocket Conn calls the factory whenever it needs a HandshakeState for a
given protocol + role.

## Error handling

Malformed `negotiation_data`, unknown action, or a requested protocol outside
the allowed set → handshake error surfaced through `Handshake()` (called by
Read/Write) to the CLI's existing `Fatalf`.

## Testing

- Unit: v1 parse/encode round-trip; decision logic; prologue-chain determinism;
  retry-cap.
- Integration (in-memory `net.Pipe` / loopback, matching existing tests):
  Accept regression, Reject→error, Retry→succeeds via fallback, Switch→succeeds
  inverted, downgrade-tamper→fails.
- All existing noisesocket tests must pass unchanged.
