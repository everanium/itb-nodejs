# ITB Node.js Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`). Runtime FFI via the `koffi` package — no build
step, no C compiler at install time; the `.so` / `.dylib` / `.dll`
is resolved and dispatched at module load. Every hash-name /
MAC-name / cipher-name / profile-name is an opaque string passed
through to Go for validation; the binding carries no ITB
construction logic. The public surface is one `Pipeline` class
(init / open / rekey / close, Single Message encrypt / decrypt,
one-shot and incremental stream sessions with chunk-iterable
pumps), an `Opts` query-string builder, `registerProfile`, and the
Go runtime knobs. TypeScript-first: `.ts` sources compiled to `.js`
+ `.d.ts` under strict mode.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go nodejs npm
```

Generic Linux / macOS: a Go toolchain plus Node.js >= 22 with npm.
Windows: the same; libitb builds as `libitb.dll`.

## Build the shared library

The convenience driver builds `libitb.so`, installs npm
dependencies, and compiles the TypeScript sources in one step:

```bash
./bindings/nodejs/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/nodejs && npm install && npm run build
```

## Library lookup order

1. `ITB_LIBITB_PATH` environment variable (path to the shared
   library file).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved by walking up
   from the module directory (in-repo builds).
3. The OS default loader path (`LD_LIBRARY_PATH`, `ld.so.cache`,
   `DYLD_LIBRARY_PATH`, `PATH`).

## Usage example

```ts
import { Opts, Pipeline } from 'itb';

const opts = new Opts();
const sender = Pipeline.init('singlemsg-triple-mac-v1', opts);
const receiver = Pipeline.open('singlemsg-triple-mac-v1', sender.blob, opts);

const wire = sender.encryptMessage(Buffer.from('any text or binary data'));
const plain = receiver.decryptMessage(wire);

sender.free();
receiver.free();
```

The `Opts` builder overrides the profile default per call (chunk
size, outer cipher, parallax on/off, wrapper on/off, MAC name,
palette); every setter mutates and returns the same instance:

```ts
const opts = new Opts().withChunkSize(65536).withWrapper(false);
const sender = Pipeline.init('singlemsg-triple-mac-v1', opts);
const receiver = Pipeline.open('singlemsg-triple-mac-v1', sender.blob, opts);
```

`Pipeline.rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters through a fresh
`sender.blob` handshake:

```ts
sender.rekey(Buffer.alloc(32, 0x11), Buffer.alloc(32, 0x22));
const receiver2 = Pipeline.open('singlemsg-triple-mac-v1', sender.blob, opts);
```

For bounded-memory streaming, `encryptStreamPump` /
`decryptStreamPump` move any iterable of byte chunks into a sink
callback through an incremental session; the explicit
`encryptStream` / `decryptStream` sessions expose `write` / `end` /
`read` / `drainAll` for caller-driven loops. `Pipeline` and the
stream sessions implement `Symbol.dispose` (`using` declarations,
Node 20+) alongside explicit `free()`; a `FinalizationRegistry`
backstop releases handles the caller dropped without freeing.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as `ItbError` carrying the
status code plus the `ITB_LastError` diagnostic.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass a negative value to
query without changing:

```ts
import { setGCPercent, setMemoryLimit } from 'itb';

setMemoryLimit(512n * 1024n * 1024n); // BigInt: the limit is int64
setGCPercent(20);
```

## Testing

```bash
./bindings/nodejs/run_tests.sh
```

The harness builds `libitb.so`, exports `ITB_LIBITB_PATH`, and
invokes `npm test` (`node:test` over the compiled suite). The suite
covers Single Message round trips per shipped profile, stream
pumps, incremental sessions with pathological batch sizes,
tampered-wire failure stickiness, mid-flight cancellation, rekey,
profile registration, and error mapping — surface parity checks;
the deep suite lives in Go under the shipped tree.

## Benchmarking

```bash
./bindings/nodejs/run_bench.sh
```

Two bench scripts (`bench_message` + `bench_stream`) measure
`encryptMessage` and `encryptStreamPump` throughput at 1 / 16 /
64 MiB with `performance.now()` timing. Shape defaults match the
root Go BENCH3.md pin (`ITB_INNER_HASH=areion512`,
`ITB_KEY_BITS=1024`, `ITB_NONCE_BITS=512`, parallax + wrapper off);
override via the env vars documented in each script's header.
`ITB_BENCH_MIN_SEC` (default 5) sets the per-case wall-clock
budget.

## eitb utility

A small CLI under `bindings/nodejs/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests:

```bash
cd bindings/nodejs
./eitb/eitb version
./eitb/eitb hashes
./eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./eitb/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- All FFI calls are synchronous and block the JS thread for their
  duration (encrypts are CPU-bound in Go regardless). Callers that
  need concurrency run the binding inside `worker_threads`.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- `ITB_LastError` is process-global last-write-wins; the textual
  diagnostic attached to an `ItbError` may belong to a different
  call under concurrent FFI use. The status code is always
  attributable.
- `rekey` must not run concurrently with cipher calls or open
  stream sessions on the same `Pipeline`.
- libitb must be reachable at runtime through the lookup order
  above.
