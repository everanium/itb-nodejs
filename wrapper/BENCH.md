# ITB Node.js Binding — Format-Deniability Wrapper Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of outer keystream ciphers, one per PRF-grade ITB registry primitive in CTR mode. The keystream construction is delegated libitb-side to the `ctr` package. The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `wrapInPlace` row mutates the caller's `Buffer` (no output-buffer allocation); the `wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single-message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's streaming AEAD entry points or a User-Driven Loop emitting framed chunks through the wrapped writer.

The wrapper bench covers all outer ciphers — each in CTR mode.

Outer-cipher overhead on a 16 HT host with hardware AES-NI is effectively zero — the AES-CTR keystream finishes well ahead of every ITB-encrypt slot, and the `wrapInPlace` path avoids output-buffer allocation. **On larger Triple Ouroboros hosts (e.g. AMD EPYC 9655P, 192 HT) the picture inverts for the non-AES outer ciphers**: ITB's per-pixel hashing scales across all available HT, while the wrapper's keystream XOR splits across up to 32 worker goroutines (`min(32, GOMAXPROCS, chunks)`) inside libitb for buffers at or above the 256 KiB threshold, each worker seeking its own keystream to its chunk offset via `ctr.NewAt`; buffers below the threshold run serially.

The Node.js binding adds the per-call koffi-FFI crossing and a `Buffer` materialisation on the helper return path. The wrapper only row therefore reads slightly under the matching Go-native row at 16 MiB; the gap closes on the full ITB + wrapper rows, where the ITB encrypt / decrypt time dominates over the keystream XOR + FFI overhead.

## Binding asymmetry note

The Node.js binding's Streaming No MAC arm covers the User-Driven Loop variant only — there is no IO-Driven Streaming No MAC writer / reader pair on top of the wrap surface. The Streaming AEAD path covers IO-Driven for both Easy and Low-Level.

## Reproduction

```sh
# Build libitb.so:
go build -trimpath -buildmode=c-shared -o dist/linux-amd64/libitb.so ./cmd/cshared

# Build the bench harness and run the full 306-case sub-bench matrix:
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

* Outer cipher path: all PRF-grade registry primitives, keystream built libitb-side via the `ctr` package.
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `nonce_bits=128`, `barrier_fill=1`, `bit_soup=0`, `lock_soup=0` (minimum config so the outer cipher delta is not masked by per-pixel feature cost).
* `setMaxWorkers(0)` (use every available HT for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single-message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.
* Decrypt-only sub-benches refresh the working wire from a pristine clone each iteration via `Buffer.from(wirePristine)`; the memcpy is included in the timed total. This overhead is small relative to ITB's Decrypt cost on this hardware.

Column abbreviations in the Full ITB + wrapper tables: **LL** = Low-Level, **Loop** = User-Driven Loop, **IO** = IO-Driven, **NoMAC** = No MAC, **MAC** = MAC Authenticated, **Enc** / **Dec** = encrypt / decrypt direction. All throughput is MB/s, rounded.

### Wrapper only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Outer cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (no output-buffer alloc) MB/s |
|---|---|---|
| **Areion-SoEM-256** | 1065 | 1257 |
| **Areion-SoEM-512** | 1326 | 1271 |
| **BLAKE2b-256** | 514 | 542 |
| **BLAKE2b-512** | 817 | 674 |
| **BLAKE2s** | 579 | 581 |
| **BLAKE3** | 951 | 923 |
| **AES-128-CTR** | 2268 | 2075 |
| **SipHash-2-4** | 1602 | 1519 |
| **ChaCha20** | 1538 | 1452 |

### Single Message — Single Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 148 | 241 | 168 | 237 | 187 | 246 | 171 | 243 |
| **Areion-SoEM-512** | 183 | 261 | 168 | 236 | 187 | 265 | 176 | 243 |
| **BLAKE2b-256** | 166 | 221 | 150 | 205 | 167 | 225 | 159 | 210 |
| **BLAKE2b-512** | 178 | 240 | 158 | 221 | 178 | 245 | 166 | 230 |
| **BLAKE2s** | 169 | 214 | 157 | 212 | 170 | 225 | 162 | 214 |
| **BLAKE3** | 178 | 246 | 167 | 234 | 184 | 252 | 170 | 235 |
| **AES-128-CTR** | 191 | 273 | 176 | 246 | 197 | 280 | 182 | 257 |
| **SipHash-2-4** | 166 | 267 | 168 | 242 | 190 | 271 | 177 | 249 |
| **ChaCha20** | 188 | 263 | 170 | 236 | 191 | 266 | 177 | 251 |

### Single Message — Triple Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 247 | 289 | 215 | 269 | 246 | 285 | 224 | 274 |
| **Areion-SoEM-512** | 243 | 287 | 221 | 269 | 245 | 288 | 225 | 272 |
| **BLAKE2b-256** | 212 | 240 | 190 | 227 | 217 | 243 | 199 | 233 |
| **BLAKE2b-512** | 233 | 266 | 209 | 251 | 237 | 269 | 215 | 257 |
| **BLAKE2s** | 213 | 241 | 191 | 228 | 221 | 250 | 202 | 235 |
| **BLAKE3** | 235 | 278 | 212 | 261 | 245 | 280 | 217 | 264 |
| **AES-128-CTR** | 257 | 304 | 231 | 285 | 263 | 307 | 237 | 288 |
| **SipHash-2-4** | 252 | 292 | 226 | 272 | 254 | 291 | 232 | 282 |
| **ChaCha20** | 248 | 292 | 225 | 279 | 254 | 297 | 229 | 272 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 136 | 211 | 142 | 212 |
| **Areion-SoEM-512** | 141 | 213 | 142 | 212 |
| **BLAKE2b-256** | 129 | 186 | 131 | 189 |
| **BLAKE2b-512** | 137 | 189 | 138 | 202 |
| **BLAKE2s** | 129 | 186 | 132 | 190 |
| **BLAKE3** | 137 | 208 | 139 | 208 |
| **AES-128-CTR** | 142 | 223 | 146 | 220 |
| **SipHash-2-4** | 139 | 213 | 141 | 215 |
| **ChaCha20** | 142 | 216 | 139 | 216 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 154 | 265 | 164 | 262 |
| **Areion-SoEM-512** | 152 | 270 | 163 | 261 |
| **BLAKE2b-256** | 141 | 230 | 150 | 228 |
| **BLAKE2b-512** | 147 | 254 | 160 | 248 |
| **BLAKE2s** | 145 | 235 | 148 | 235 |
| **BLAKE3** | 147 | 256 | 165 | 241 |
| **AES-128-CTR** | 157 | 285 | 169 | 278 |
| **SipHash-2-4** | 155 | 270 | 169 | 271 |
| **ChaCha20** | 155 | 276 | 171 | 279 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 178 | 245 | 180 | 245 |
| **Areion-SoEM-512** | 178 | 246 | 179 | 245 |
| **BLAKE2b-256** | 161 | 213 | 160 | 212 |
| **BLAKE2b-512** | 171 | 233 | 169 | 232 |
| **BLAKE2s** | 163 | 217 | 164 | 216 |
| **BLAKE3** | 174 | 239 | 175 | 236 |
| **AES-128-CTR** | 185 | 261 | 186 | 258 |
| **SipHash-2-4** | 180 | 253 | 183 | 250 |
| **ChaCha20** | 182 | 252 | 181 | 250 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 209 | 297 | 212 | 296 |
| **Areion-SoEM-512** | 211 | 295 | 214 | 289 |
| **BLAKE2b-256** | 185 | 251 | 184 | 251 |
| **BLAKE2b-512** | 198 | 273 | 200 | 278 |
| **BLAKE2s** | 188 | 255 | 187 | 256 |
| **BLAKE3** | 201 | 285 | 205 | 286 |
| **AES-128-CTR** | 214 | 317 | 214 | 318 |
| **SipHash-2-4** | 212 | 305 | 218 | 309 |
| **ChaCha20** | 212 | 303 | 216 | 304 |

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
