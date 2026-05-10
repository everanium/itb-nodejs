# ITB Node.js Binding — Format-Deniability Wrapper Benchmark Results

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of three outer keystream ciphers — AES-128-CTR (libitb-side stdlib AES-NI path), ChaCha20 (RFC8439) (`golang.org/x/crypto/chacha20`), or SipHash-2-4 in CTR mode (`dchest/siphash` PRF + custom counter loop). The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `wrapInPlace` row mutates the caller's `Buffer` (zero-allocation steady state); the `wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single-message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's streaming AEAD entry points or a User-Driven Loop emitting framed chunks through the wrapped writer.

Outer-cipher overhead on a 16 HT host with hardware AES-NI is effectively zero — the AES-CTR keystream finishes well ahead of every ITB-encrypt slot, and the `wrapInPlace` path adds no allocation pressure. **On larger Triple Ouroboros hosts (e.g. AMD EPYC 9655P, 192 HT) the picture inverts for the non-AES outer ciphers**: ITB's per-pixel hashing scales across all available HT, while the wrapper's keystream XOR runs single-threaded on one core. ChaCha20 (~700 MB/s peak on a single core via `x/crypto/chacha20`) and SipHash-CTR (~250-280 MB/s peak via the `dchest/siphash` PRF + 8-byte refill loop) become the bottleneck once ITB's Triple decrypt path approaches ~1 GB/s on big-iron. AES-128-CTR retains hardware acceleration on every HT thread the goroutine lands on and stays out of the critical path even there.

The Node.js binding adds the per-call koffi-FFI crossing and a `Buffer` materialisation on the helper return path. The wrapper only row therefore reads slightly under the matching Go-native row at 16 MiB; the gap closes on the full ITB + wrapper rows, where the ITB encrypt / decrypt time dominates over the keystream XOR + FFI overhead.

## Binding asymmetry note

The Node.js binding's Streaming No MAC arm covers the User-Driven Loop variant only — there is no IO-Driven Streaming No MAC writer / reader pair on top of the wrap surface. The Streaming AEAD path covers IO-Driven for both Easy and Low-Level. See the "Binding asymmetry" section in [README.md](README.md).

## Reproduction

```sh
# Build libitb.so:
go build -trimpath -buildmode=c-shared -o dist/linux-amd64/libitb.so ./cmd/cshared

# Build the bench harness and run the full 102-case sub-bench matrix:
cd bindings/nodejs
npx tsc -p tsconfig.bench.json
node dist-bench/bench/bench-wrapper.js
```

Filter examples:

```sh
ITB_BENCH_FILTER=wrapper_only \
    node dist-bench/bench/bench-wrapper.js

ITB_BENCH_FILTER=msg_single_easy_nomac \
    node dist-bench/bench/bench-wrapper.js

ITB_BENCH_FILTER=stream_triple \
    node dist-bench/bench/bench-wrapper.js
```

## Configuration

* Outer cipher path: AES-128-CTR / ChaCha20 (RFC8439) / SipHash-2-4 in CTR mode (libitb-side).
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `nonce_bits=128`, `barrier_fill=1`, `bit_soup=0`, `lock_soup=0` (minimum config so the outer cipher delta is not masked by per-pixel feature cost).
* `setMaxWorkers(0)` (use every available HT for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single-message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.
* Decrypt-only sub-benches refresh the working wire from a pristine clone each iteration via `Buffer.from(wirePristine)`; the memcpy is included in the timed total. This overhead is small relative to ITB's Decrypt cost on this hardware.

### Wrapper only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Outer cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (zero alloc) MB/s |
|---|---|---|
| **AES-128-CTR** | 1977 | **1548** |
| **ChaCha20** | 290 | **272** |
| **SipHash-CTR** | 245 | **231** |

### Single Message — Single Ouroboros (16 MiB plaintext)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Easy** No MAC | 182 | 262 | 142 | 183 | 137 | 171 |
| **Easy** MAC Authenticated | 171 | 242 | 135 | 177 | 128 | 163 |
| **Low-Level** No MAC | 173 | 269 | 145 | 172 | 139 | 173 |
| **Low-Level** MAC Authenticated | 175 | 249 | 136 | 164 | 131 | 166 |

### Single Message — Triple Ouroboros (16 MiB plaintext)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Easy** No MAC | 254 | 298 | 181 | 205 | 170 | 190 |
| **Easy** MAC Authenticated | 225 | 281 | 167 | 194 | 158 | 183 |
| **Low-Level** No MAC | 262 | 271 | 186 | 191 | 174 | 177 |
| **Low-Level** MAC Authenticated | 233 | 254 | 171 | 183 | 160 | 170 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Streaming AEAD Easy** IO-Driven | 121 | 171 | 102 | 137 | 98 | 129 |
| **Streaming AEAD Low-Level** IO-Driven | 122 | 175 | 102 | 136 | 98 | 128 |
| **Streaming Easy** No MAC, User-Driven Loop | 162 | 240 | 129 | 176 | 123 | 163 |
| **Streaming Low-Level** No MAC, User-Driven Loop | 165 | 227 | 132 | 167 | 125 | 157 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Streaming AEAD Easy** IO-Driven | 151 | 200 | 123 | 152 | 117 | 144 |
| **Streaming AEAD Low-Level** IO-Driven | 149 | 198 | 121 | 153 | 116 | 143 |
| **Streaming Easy** No MAC, User-Driven Loop | 213 | 273 | 160 | 193 | 151 | 179 |
| **Streaming Low-Level** No MAC, User-Driven Loop | 219 | 255 | 163 | 183 | 154 | 170 |

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
