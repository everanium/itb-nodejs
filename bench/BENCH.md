# ITB Node.js / TypeScript Binding - Easy Mode Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Throughput (MB/s) of `Encryptor.encrypt` / `decrypt` / `encryptAuth`
/ `decryptAuth` over the libitb c-shared library through the
`koffi`-based Node.js binding. Single + Triple Ouroboros at 1024-bit
ITB key width on a 16 MiB CSPRNG-filled payload, four ops per
primitive. The MAC slot is bound to **HMAC-BLAKE3** — the lightest
authenticated-mode overhead among the three shipping MACs (the
`encryptAuth` row sits within a few percent of the matching
`encrypt` row, and well below HMAC-SHA256's ~15 % and KMAC-256's
~44 % overheads).

The harness lives in this directory; reproduction:

```bash
cd bindings/nodejs
npm run bench:build
ITB_BENCH_MIN_SEC=5 npm run bench:single
ITB_BENCH_MIN_SEC=5 ITB_LOCKSEED=1 ITB_LOCKBATCH=1 npm run bench:single
ITB_BENCH_MIN_SEC=5 ITB_LOCKSEED=1 npm run bench:single
ITB_BENCH_MIN_SEC=5 npm run bench:triple
ITB_BENCH_MIN_SEC=5 ITB_LOCKSEED=1 ITB_LOCKBATCH=1 npm run bench:triple
ITB_BENCH_MIN_SEC=5 ITB_LOCKSEED=1 npm run bench:triple
```

The `ITB_LOCKSEED=1 ITB_LOCKBATCH=1` lines select the Lock Batch
performance variant of Lock Soup (the preferred arm); the plain
`ITB_LOCKSEED=1` lines retain the baseline Lock Soup arm.

The default measurement window is 5 seconds per case
(`ITB_BENCH_MIN_SEC=5`), wide enough to absorb the cold-cache /
warm-up transient that distorts shorter windows on the 16 MiB
encrypt / decrypt path. `ITB_BENCH_FILTER=<substring>` narrows the
matrix to a single primitive when re-running an outlier in
isolation.

## FFI overhead vs. native Go

The Node.js path adds a `koffi`-based dynamic-library dispatch per
call, the C ABI crossing into Go, and a result-copy from the
c-shared output buffer back into a fresh `Uint8Array`. The binding
caches a per-encryptor output buffer and pre-allocates from a 1.25×
upper bound on the empirical ITB ciphertext-expansion factor
(≤ 1.155 across every primitive / mode / nonce / payload-size
combination) so the hot loop avoids the size-probe round-trip the
process-global FFI helpers use. The cache is wiped on grow and on
`close` / `free` / `[Symbol.dispose]`, so residual ciphertext /
plaintext cannot linger in heap garbage between cipher calls.

The numbers below ride the default build (no opt-out tags). On
hosts without AVX-512+VL the Go side automatically nil-routes the
4-lane batched chain-absorb arm so the per-pixel hash falls
through to the upstream stdlib asm via the single Func — see the
build-tag table in [`../README.md`](../README.md) for the
`-tags=noitbasm` opt-outs.

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode)

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 184 | 275 | 178 | 260 |
| **Areion-SoEM-512** | 512 | PRF | 199 | 289 | 183 | 270 |
| **BLAKE2b-256** | 256 | PRF | 93 | 109 | 89 | 104 |
| **BLAKE2b-512** | 512 | PRF | 134 | 166 | 126 | 159 |
| **BLAKE2s** | 256 | PRF | 93 | 117 | 95 | 115 |
| **BLAKE3** | 256 | PRF | 121 | 147 | 100 | 139 |
| **AES-CMAC** | 128 | PRF | 179 | 257 | 168 | 237 |
| **SipHash-2-4** | 128 | PRF | 148 | 191 | 140 | 182 |
| **ChaCha20** | 256 | PRF | 109 | 129 | 101 | 123 |
| **Mixed** | 256 | PRF | 105 | 126 | 102 | 122 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 263 | 314 | 234 | 294 |
| **Areion-SoEM-512** | 512 | PRF | 264 | 323 | 232 | 306 |
| **BLAKE2b-256** | 256 | PRF | 103 | 110 | 99 | 107 |
| **BLAKE2b-512** | 512 | PRF | 158 | 165 | 150 | 169 |
| **BLAKE2s** | 256 | PRF | 115 | 121 | 110 | 120 |
| **BLAKE3** | 256 | PRF | 143 | 156 | 135 | 148 |
| **AES-CMAC** | 128 | PRF | 243 | 284 | 219 | 268 |
| **SipHash-2-4** | 128 | PRF | 181 | 203 | 169 | 193 |
| **ChaCha20** | 256 | PRF | 120 | 132 | 118 | 129 |
| **Mixed** | 256 | PRF | 122 | 131 | 117 | 129 |

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode, Lock Seed + Lock Batch mode)

The Lock Batch performance variant (`ITB_LOCKSEED=1 ITB_LOCKBATCH=1` /
`Encryptor.setLockBatch(1)`) batches the per-chunk Lock Soup overlay
derivation, reducing per-chunk PRF invocations without affecting
security under the PRF assumption. Numbers below run with
`ITB_LOCKSEED=1 ITB_LOCKBATCH=1`, default nonce, 16 MiB payload,
`ITB_BENCH_MIN_SEC=5`.

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 93 | 124 | 100 | 122 |
| **Areion-SoEM-512** | 512 | PRF | 114 | 139 | 110 | 134 |
| **BLAKE2b-256** | 256 | PRF | 64 | 71 | 62 | 70 |
| **BLAKE2b-512** | 512 | PRF | 89 | 104 | 85 | 100 |
| **BLAKE2s** | 256 | PRF | 66 | 74 | 65 | 73 |
| **BLAKE3** | 256 | PRF | 70 | 81 | 69 | 79 |
| **AES-CMAC** | 128 | PRF | 88 | 108 | 88 | 105 |
| **SipHash-2-4** | 128 | PRF | 81 | 93 | 79 | 84 |
| **ChaCha20** | 256 | PRF | 68 | 76 | 66 | 73 |
| **Mixed** | 256 | PRF | 49 | 55 | 49 | 53 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 149 | 192 | 155 | 185 |
| **Areion-SoEM-512** | 512 | PRF | 187 | 212 | 174 | 203 |
| **BLAKE2b-256** | 256 | PRF | 80 | 84 | 77 | 80 |
| **BLAKE2b-512** | 512 | PRF | 128 | 136 | 120 | 132 |
| **BLAKE2s** | 256 | PRF | 85 | 94 | 83 | 87 |
| **BLAKE3** | 256 | PRF | 93 | 102 | 91 | 101 |
| **AES-CMAC** | 128 | PRF | 142 | 159 | 134 | 156 |
| **SipHash-2-4** | 128 | PRF | 116 | 128 | 112 | 128 |
| **ChaCha20** | 256 | PRF | 87 | 93 | 83 | 91 |
| **Mixed** | 256 | PRF | 52 | 54 | 51 | 53 |

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode, LockSeed mode)

The dedicated lockSeed channel (`Encryptor.setLockSeed(1)` /
`ITB_LOCKSEED=1`) auto-couples bit-soup + lock-soup on the
on-direction. Numbers below run with all three overlays active.

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 59 | 70 | 61 | 68 |
| **Areion-SoEM-512** | 512 | PRF | 50 | 56 | 49 | 55 |
| **BLAKE2b-256** | 256 | PRF | 42 | 46 | 43 | 45 |
| **BLAKE2b-512** | 512 | PRF | 47 | 51 | 47 | 50 |
| **BLAKE2s** | 256 | PRF | 45 | 49 | 43 | 47 |
| **BLAKE3** | 256 | PRF | 44 | 45 | 44 | 46 |
| **AES-CMAC** | 128 | PRF | 73 | 87 | 73 | 83 |
| **SipHash-2-4** | 128 | PRF | 68 | 78 | 66 | 73 |
| **ChaCha20** | 256 | PRF | 46 | 50 | 45 | 48 |
| **Mixed** | 256 | PRF | 49 | 55 | 48 | 54 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 59 | 62 | 56 | 61 |
| **Areion-SoEM-512** | 512 | PRF | 50 | 53 | 52 | 55 |
| **BLAKE2b-256** | 256 | PRF | 44 | 44 | 43 | 45 |
| **BLAKE2b-512** | 512 | PRF | 47 | 49 | 46 | 47 |
| **BLAKE2s** | 256 | PRF | 44 | 44 | 43 | 45 |
| **BLAKE3** | 256 | PRF | 42 | 44 | 44 | 46 |
| **AES-CMAC** | 128 | PRF | 79 | 80 | 74 | 80 |
| **SipHash-2-4** | 128 | PRF | 70 | 74 | 68 | 73 |
| **ChaCha20** | 256 | PRF | 48 | 50 | 40 | 45 |
| **Mixed** | 256 | PRF | 49 | 45 | 48 | 48 |

## Notes

- The first row in every Single-Ouroboros pass shows a transient
  asymmetry between encrypt and decrypt absorbed imperfectly even
  at 5-second windows; subsequent rows in the same pass run on
  warm caches and report symmetric encrypt-vs-decrypt numbers.
  Re-running the same primitive in isolation
  (`ITB_BENCH_FILTER=areion256 ITB_BENCH_MIN_SEC=20 npm run bench:single`)
  normalises the asymmetry.
- The LockSeed arms cap throughput in the 40-80 MB/s band because
  the dedicated lockseed slot auto-engages bit-soup + lock-soup;
  the bit-level split + per-chunk PRF-keyed bit-permutation overlay
  together dominate the per-byte cost.
- Triple Ouroboros exceeds Single Ouroboros throughput on most
  primitives because the seven-seed split exposes additional
  internal parallelism opportunities to libitb's worker pool while
  the on-the-wire chunk count remains the same.
- Bench cases run sequentially per pass; libitb's internal worker
  pool (`setMaxWorkers(0)` → all CPUs) processes each case's
  chunk-level parallelism within the case's wall-clock window.
- `koffi` calls into libitb are synchronous: the V8 main thread is
  blocked for the duration of the FFI call, so finalizers cannot
  fire mid-call. The benchmark harness therefore measures the
  steady-state cipher cost without GC interference on the hot
  loop.
