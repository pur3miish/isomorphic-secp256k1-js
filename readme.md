# Isomorphic secp256k1 JS

[![NPM Package](https://img.shields.io/npm/v/isomorphic-secp256k1-js.svg)](https://www.npmjs.org/package/isomorphic-secp256k1-js) [![CI status](https://github.com/pur3miish/isomorphic-secp256k1-js/actions/workflows/node.js.yml/badge.svg)](https://github.com/pur3miish/isomorphic-secp256k1-js/actions/workflows/node.js.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/pur3miish/isomorphic-secp256k1-js/blob/main/LICENSE)

[![Runtime dependencies: zero](https://img.shields.io/badge/runtime%20dependencies-zero-brightgreen.svg)](./package.json) [![Timing: not constant-time](https://img.shields.io/badge/timing-not%20constant--time-orange.svg)](./SECURITY.md#threat-model-and-limitations)

A small, strict, zero-runtime-dependency ECDSA implementation for the secp256k1 curve in Node.js and modern browsers. It provides:

- [`generate_private_key`](./src/generate_private_key.ts) — generates a private scalar with rejection sampling, using the native [Web Crypto CSPRNG](https://www.w3.org/TR/WebCryptoAPI/#Crypto-method-getRandomValues) by default or a caller-supplied cryptographic random source, following the key-generation requirements in [SEC 1](https://www.secg.org/sec1-v2.pdf).

- [`validate_private_key`](./src/utils.ts) — enforces the canonical 32-byte encoding and the SEC 1 scalar interval `1 <= d < n`.

- [`get_public_key`](./src/get_public_key.ts) — derives `Q = dG` and returns a compressed SEC 1 public key using the [SEC 2 secp256k1 domain parameters](https://www.secg.org/sec2-v2.pdf).

- [`sign`](./src/sign.ts) — creates canonical ECDSA signatures following [SEC 1](https://www.secg.org/sec1-v2.pdf), with deterministic per-message nonces from [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979).

- [`verify`](./src/verify.ts) — validates ECDSA signatures and public-key encodings according to SEC 1.

- [`recover_public_key`](./src/recover_public_key.ts) — performs the SEC 1 ECDSA public-key recovery operation and verifies the recovered key before returning it.

- [`sha256`](./src/sha256.ts) — computes the SHA-256 message digest specified by [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).

- [`hmac_sha256`](./src/hmac_sha256.ts) — computes the HMAC-SHA-256 message authentication code defined by [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104).

Version 5 keeps the package's own readable `BigInt` implementation while correcting its scalar arithmetic, validation, encoding, signing, verification, and recovery behavior.

## What the keys and signatures represent

A secp256k1 private key is a secret integer `d` in the range `1 <= d < n`. Its public key is the curve point `dG`. `get_public_key(private_key)` derives and returns that public point as a 33-byte compressed SEC 1 key; it does not create a new private key.

An ECDSA signature is evidence that someone controlling the private key authorized the exact 32-byte digest passed to `sign`. It does not hide the message, prove a real-world identity, or provide authorization, freshness, or replay protection by itself. The calling protocol must define unambiguous message serialization, hashing, domain separation, identity binding, and replay rules.

## Security properties

- Private keys and message digests must be exactly 32 bytes.
- Private keys must satisfy `1 <= key < n`.
- Generated private keys use rejection sampling with native Web Crypto or a caller-selected random source.
- Signature `r` and `s` components are always exactly 32 bytes.
- Signatures use deterministic RFC 6979 nonces and canonical low-S form by default.
- Public keys are validated SEC 1 encodings.
- Malformed verification inputs return `false`; signing and recovery reject malformed inputs.
- Optional hedged signing can mix CSPRNG entropy into RFC 6979 for fault-attack resistance.
- Secret scalar multiplication uses a fixed-operation-count ladder and 128-bit scalar blinding.
- There are no runtime package dependencies.

JavaScript runtimes cannot guarantee constant-time execution or reliable secret zeroization. This implementation has not received an independent cryptographic audit. Read [SECURITY.md](./SECURITY.md) before using the package with high-value or long-lived keys.

## Montgomery ladder and scalar blinding

Elliptic-curve public-key derivation and signing require scalar multiplication: computing `Q = dP`, where `d` is an integer and `P` is a curve point. A basic double-and-add implementation can perform visibly different work depending on the bits of `d`, creating an obvious timing side channel.

[`scalar_multiply`](./src/utils.ts) uses a Montgomery ladder. It starts with two adjacent multiples of the input point:

```text
lower = 0P              // point at infinity
upper = 1P
```

After processing a scalar prefix `k`, the ladder maintains this invariant:

```text
lower = kP
upper = (k + 1)P
```

For every scalar bit, from most significant to least significant, it performs one point addition and one point doubling. The bit determines which result becomes `lower` and which becomes `upper`, but it does not change the number of high-level group operations performed during that round. Secret operations always process 384 rounds, avoiding early termination and scalar-length-dependent recursion.

[`blinded_multiply`](./src/utils.ts) additionally replaces a secret scalar `d` with:

```text
d' = d + b·n
```

Here `n` is the secp256k1 subgroup order and `b` is a fresh 128-bit random blinding value. Because `nP` is the point at infinity for subgroup points, `d'P = dP`; the output is unchanged while the internal scalar representation changes for every operation. This makes repeated timing observations harder to correlate with the original private scalar or signing nonce.

This is a best-effort timing mitigation, not a constant-time guarantee. The ladder still branches on blinded bits, point addition and doubling contain exceptional-case branches and variable-time modular inversions, and JavaScript `BigInt` arithmetic, JIT compilation, and garbage collection are not specified as constant-time. The term “Montgomery ladder” describes the multiplication schedule; secp256k1 itself remains a short-Weierstrass curve, not a Montgomery-form curve.

## Randomness and private keys

Randomness is part of the security boundary for private-key generation. A predictable, repeated, biased, or truncated source can reduce the possible private-key space enough for an attacker to search it. The resulting public key can still be mathematically valid while its private key is predictable. Range validation rejects invalid scalars; it cannot prove that a source contains enough entropy.

The package supports three explicit key-input paths:

- **Native CSPRNG:** `generate_private_key()` uses `globalThis.crypto.getRandomValues`, the standard cryptographic random interface exposed by supported Node.js and browser runtimes.

- **Caller-selected CSPRNG:** `generate_private_key({ random_source })` lets an application obtain bytes from an HSM, secure enclave, platform API, or another reviewed source. The callback can be synchronous or asynchronous.

- **Existing private key:** applications can supply their own 32-byte key to `validate_private_key`, `get_public_key`, or `sign`. Each high-level secret operation validates the key before using it.

`generate_private_key()` requests 32 bytes and uses rejection sampling:

1. Interpret the candidate as an unsigned big-endian integer `d`.
2. Accept it only when `1 <= d < n`.
3. Request another candidate when it is zero or at least the curve order.

This limits the encoded key to the secp256k1 private-scalar interval and preserves a uniform distribution when the source bytes are uniform. Candidates are not reduced modulo `n`, avoiding modulo bias. After 1024 invalid candidates, generation fails rather than looping forever on a broken source.

With no options, Node.js and browsers use the same native Web Crypto interface:

```js
import { generate_private_key } from "isomorphic-secp256k1-js";

const private_key = await generate_private_key();
```

Applications with an HSM, operating-system facility, or another cryptographically secure source can provide a synchronous or asynchronous callback. The callback is requested to return exactly 32 bytes and may be called more than once:

```js
const private_key = await generate_private_key({
  random_source: async (length) => my_cryptographic_random_source(length),
});
```

The package validates and copies the callback result, but the application remains responsible for the source's unpredictability, independence, correct initialization, and entropy. Do not use `Math.random`, timestamps, UUIDs, passwords, counters, device identifiers, or general-purpose seeded generators. A deterministic source belongs only in tests and must never be reachable in a production key-generation path.

Weak-source failures are not theoretical. The [Milk Sad vulnerability (CVE-2023-39910)](https://nvd.nist.gov/vuln/detail/CVE-2023-39910) made wallet keys recoverable because cryptographic key material came from an inadequately seeded general-purpose PRNG. Arkham has also [reported that the LuBian wallet software used only 32 bits of entropy](https://info.arkm.com/research/blockchain-analytics-all-the-use-cases-for-on-chain-data), making its key space practical to search. These examples do not mean a library can certify arbitrary entropy: they show why the default must be a platform CSPRNG and why custom sources remain an explicit trust decision.

Applications may also supply an existing private key directly. `validate_private_key` throws unless it is exactly 32 bytes and represents a scalar in the valid SEC 1 interval; `get_public_key` and `sign` perform this validation internally as well.

```js
import { get_public_key, validate_private_key } from "isomorphic-secp256k1-js";

validate_private_key(private_key);
const public_key = await get_public_key(private_key);
```

Public-key derivation is deterministic: its internal random value is only 128-bit scalar blinding, which changes the calculation path without changing `Q = dG`. Signature generation uses RFC 6979, so the secret ECDSA nonce does not depend on runtime randomness by default. `sign({ extra_entropy: true })` can additionally hedge the deterministic nonce with 32 native random bytes.

Never log a private key or place it in a URL or browser `localStorage`. For high-value or long-lived keys, prefer non-extractable hardware-backed storage.

See [docs/randomness.md](./docs/randomness.md) for the exact guarantees, custom-source checklist, and integration patterns.

## Requirements

- Node.js 20.19 or newer.
- A browser or worker with `globalThis.crypto.subtle` and `globalThis.crypto.getRandomValues`.
- ECMAScript modules.

## Installation

```sh
npm install isomorphic-secp256k1-js
```

## Integration and entry points

The package is ECMAScript-module-only. The root module is the recommended application entry point:

```js
import {
  generate_private_key,
  get_public_key,
  hmac_sha256,
  recover_public_key,
  sha256,
  sign,
  validate_private_key,
  verify,
} from "isomorphic-secp256k1-js";
```

Each operation also has a typed subpath export for applications that prefer a single-function import:

| Operation | Root named export | Equivalent subpath import |
| --- | --- | --- |
| Private-key generation | `generate_private_key` | `import generate_private_key from "isomorphic-secp256k1-js/generate_private_key"` |
| Private-key validation | `validate_private_key` | `import { validate_private_key } from "isomorphic-secp256k1-js"` |
| Public-key derivation | `get_public_key` | `import get_public_key from "isomorphic-secp256k1-js/get_public_key"` |
| SHA-256 digest | `sha256` | `import sha256 from "isomorphic-secp256k1-js/sha256"` |
| ECDSA signing | `sign` | `import sign from "isomorphic-secp256k1-js/sign"` |
| ECDSA verification | `verify` | `import verify from "isomorphic-secp256k1-js/verify"` |
| Recoverable ECDSA recovery | `recover_public_key` | `import recover_public_key from "isomorphic-secp256k1-js/recover_public_key"` |
| HMAC-SHA-256 | `hmac_sha256` | `import hmac_sha256 from "isomorphic-secp256k1-js/hmac_sha256"` |
| Low-level primitives | Not re-exported at the root | `import * as secp256k1_utils from "isomorphic-secp256k1-js/utils"` |

The `package.json` export map provides explicit ESM and TypeScript declaration targets for the extensionless paths above and their `.js` equivalents. Node.js, TypeScript, and modern bundlers therefore resolve the same public API without reaching into unexported package files.

### Named imports and tree shaking

JavaScript calls these **named imports**; they are also commonly described as destructured imports:

```js
import { sign, verify } from "isomorphic-secp256k1-js";
```

The generated `index.js` consists only of static ESM re-exports, and `package.json` declares `"sideEffects": false`. A production bundler that supports ESM tree shaking can therefore follow the export graph and omit functions that the application never references. For example, importing only `sha256` does not require the ECDSA signing, recovery, or curve-arithmetic implementation in the resulting browser bundle.

Tree shaking is a bundler optimization, not a change to the cryptographic API. Its result depends on the consuming bundler and production configuration. For the most predictable output:

- Use named imports with static names.

- Keep tree shaking enabled in the production build.

- Avoid dynamic namespace access such as `secp256k1[name]`, which may force a bundler to retain more exports.

- Use a typed subpath import such as `isomorphic-secp256k1-js/sha256` when an application wants to address exactly one entry module.

The package test suite bundles a root `sha256` import with esbuild and asserts that signing, HMAC, recovery, and curve-arithmetic code are absent from the generated bundle.

### Package authors and automated tooling

The package exposes stable named exports, TypeScript declarations, typed subpath exports, a side-effect-free ESM graph, and runnable examples in this README. These make the API easier for package consumers, code-search systems, documentation indexes, and coding assistants to identify and integrate correctly.

[`llms.txt`](./llms.txt) provides a concise machine-readable API and security guide. It is supplementary documentation, not a guarantee that a particular search engine or language model will index or recommend the package. For the clearest downstream signal, use the canonical npm package name in examples and link to this repository rather than copying the implementation into another project.

### Node.js

Use an `.mjs` file, or set `"type": "module"` in the consuming application's `package.json`:

```js
import { sha256 } from "isomorphic-secp256k1-js";

const digest = await sha256(new TextEncoder().encode("message"));
```

### Browser or worker

Bundlers can use the same package import. A browser loading the installed npm package directly can map the package name to `index.js`:

```html
<script type="importmap">
  {
    "imports": {
      "isomorphic-secp256k1-js": "/vendor/isomorphic-secp256k1-js/index.js"
    }
  }
</script>
<script type="module">
  import { sha256 } from "isomorphic-secp256k1-js";

  const digest = await sha256(new TextEncoder().encode("message"));
  console.log(digest);
</script>
```

### Building and publishing

The repository tracks the TypeScript files in `src/`; generated JavaScript and declarations are written temporarily to the package root and ignored by Git. Keeping the established root-level npm layout preserves existing package, deep-import, and direct-browser paths. The npm lifecycle builds and tests these files before creating the package tarball, includes them in the published package, and removes them locally after packing.

```sh
npm run build   # clean and generate package files
npm run clean   # remove generated JavaScript and declarations
npm pack        # test, build the npm tarball, then remove generated files
npm publish     # test, build and publish, then remove generated files
```

Because cleanup uses an explicit file list in a Node.js script rather than a broad deletion or platform-specific shell command, it works on supported Node.js installations on Windows, macOS, and Linux. The script removes only compiler outputs; it does not remove `src/`.

## API guide

The later signing examples use a fixed private key only to make their output reproducible. Do not use example keys for real assets or identities.

### `generate_private_key({ random_source? })` — private-key generation

Generates a uniformly selected 32-byte scalar in the SEC 1 interval. When `random_source` is omitted, the function uses `globalThis.crypto.getRandomValues` in both supported runtime families.

```js
import { generate_private_key } from "isomorphic-secp256k1-js";

const native_private_key = await generate_private_key();

const externally_generated_key = await generate_private_key({
  random_source: (length) => audited_csprng.randomBytes(length),
});
```

### `validate_private_key(private_key)` — private-key validation

Checks the byte encoding and scalar bounds. It returns `void` for a valid key and throws `TypeError` or `RangeError` for invalid input. This proves structural validity, not randomness quality.

```js
import { validate_private_key } from "isomorphic-secp256k1-js";

validate_private_key(native_private_key);
```

```js
const private_key = Uint8Array.from([
  210, 101, 63, 247, 203, 178, 216, 255, 18, 154, 194, 126, 245, 120, 28, 230,
  139, 37, 88, 196, 26, 116, 175, 31, 45, 220, 166, 53, 203, 238, 240, 125,
]);
```

### `sha256(data)` — message digest

SHA-256 maps arbitrary binary data to a fixed 32-byte digest. Hashing is not encryption: the original data is not recoverable from the digest, and a plain hash does not authenticate who created it.

```js
import { sha256 } from "isomorphic-secp256k1-js";

const message = new TextEncoder().encode("example message");
const hash = await sha256(message); // Uint8Array(32)
```

### `get_public_key(private_key)` — public-key derivation

This function performs scalar multiplication `Q = dG`, where `d` is the private scalar and `G` is the secp256k1 generator point. It accepts exactly 32 bytes satisfying `1 <= d < n` and returns a 33-byte compressed SEC 1 public key. The public key may be shared; the private key must remain secret.

```js
import { get_public_key } from "isomorphic-secp256k1-js";

const public_key = await get_public_key(private_key); // Uint8Array(33)
```

### `sign({ private_key, hash })` — deterministic ECDSA signing

`sign` accepts an already-computed 32-byte digest. It does not hash the input again.

```js
import { sha256, sign } from "isomorphic-secp256k1-js";

const hash = await sha256(new TextEncoder().encode("example message"));
const signature = await sign({ private_key, hash });

console.log(signature.r.length); // 32
console.log(signature.s.length); // 32
console.log(signature.v); // recovery identifier: 0, 1, 2, or 3
```

The per-message secret nonce `k` is derived deterministically with [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979). `canonical` defaults to `true` and normalizes `s` into the lower half of the curve order to prevent the usual ECDSA high-S malleability. `v` identifies which ephemeral curve point permits public-key recovery; it is not part of ordinary two-component ECDSA.

Signing snapshots the private key, digest, and any caller-provided entropy before its first asynchronous Web Crypto operation. This ensures later mutation of caller-owned arrays cannot change the ECDSA calculation after the RFC 6979 state has been initialized. Every generated signature is verified internally against its derived public key before it is returned, and owned signing and HMAC temporary byte buffers are cleared on completion where JavaScript permits.

For hedged signing, set `extra_entropy: true`. RFC 6979 remains the basis of nonce derivation; the random value is an additional hedge, not a replacement for the deterministic construction. A caller may instead provide a `Uint8Array` as explicit additional entropy.

```js
const hedged_signature = await sign({
  private_key,
  hash,
  extra_entropy: true,
});
```

### `verify({ public_key, hash, signature })` — ECDSA verification

Verification proves that the `(r, s)` signature is mathematically valid for the exact digest and public key. It returns `false` for a malformed public key, malformed signature, or signature mismatch. A hash that is not exactly 32 bytes is a caller error and throws.

```js
import { get_public_key, verify } from "isomorphic-secp256k1-js";

const public_key = await get_public_key(private_key);
const valid = await verify({ public_key, hash, signature }); // true
```

Verification ignores the recovery identifier `v`. By default it rejects high-S signatures; pass `canonical: false` only when interoperating with a protocol that explicitly permits them.

### `recover_public_key({ hash, signature })` — public-key recovery

Public-key recovery uses `(r, s, v)` and the exact digest to reconstruct the candidate secp256k1 public key. The candidate is curve-validated and the signature is verified before the key is returned.

```js
import { recover_public_key } from "isomorphic-secp256k1-js";

const recovered_public_key = await recover_public_key({ hash, signature });
// Uint8Array(33), compressed SEC 1 encoding
```

Recovery identifies a key consistent with the signature; it does not establish a person's identity or decide whether that key is authorized by an application.

### `hmac_sha256(data, key)` — keyed message authentication

HMAC-SHA-256 combines a secret key with data to produce a 32-byte message authentication code. Parties that possess the same HMAC key can create and verify the value, so HMAC does not provide the public verifiability or non-repudiation properties associated with a digital signature.

```js
import { hmac_sha256 } from "isomorphic-secp256k1-js";

const hmac_key = crypto.getRandomValues(new Uint8Array(32));
const data = new TextEncoder().encode("authenticated data");
const authentication_code = await hmac_sha256(data, hmac_key);
```

This low-level helper returns the authentication code; compare received codes using a timing-safe comparison supplied by the surrounding runtime or protocol.

## Encodings

The object returned by `sign` is:

```ts
interface Signature {
  r: Uint8Array; // exactly 32 bytes
  s: Uint8Array; // exactly 32 bytes
  v: number; // integer 0 through 3
}
```

The utility module provides `signature_to_compact()` for the 64-byte `r || s` encoding and `signature_to_recovered()` for the 65-byte `v || r || s` encoding. DER-encoded ASN.1 signatures are intentionally not supported.

Public keys use SEC 1 encoding:

- Compressed: 33 bytes, prefix `0x02` or `0x03` followed by the 32-byte x-coordinate.

- Uncompressed: 65 bytes, prefix `0x04` followed by 32-byte x- and y-coordinates. Verification accepts this form, but derivation and recovery return compressed keys.

## Low-level utilities

`isomorphic-secp256k1-js/utils` exposes implementation primitives for protocol authors and testing. Application code should prefer the high-level operations because composing elliptic-curve primitives incorrectly can expose private keys.

| Group | Exports | Meaning |
| --- | --- | --- |
| Sizes | `PRIVATE_KEY_LENGTH`, `HASH_LENGTH`, `SIGNATURE_COMPONENT_LENGTH`, `COMPACT_SIGNATURE_LENGTH`, `RECOVERED_SIGNATURE_LENGTH` | Canonical byte lengths used by the public API |
| Types and parameters | `Point`, `CurvePoint`, `CompactSignature`, `Signature`, `secp256k1` | Curve points, signature shapes, and immutable secp256k1 domain parameters |
| Integer/byte conversion | `array_to_number`, `number_to_array`, `concat_bytes` | Big-endian unsigned integer encoding and byte concatenation |
| Modular arithmetic | `get_mod`, `powmod`, `mul_inverse` | Finite-field reduction, exponentiation, and checked inversion |
| Point arithmetic | `add`, `dbl`, `negate`, `scalar_multiply`, `double_and_add`, `blinded_multiply` | Elliptic-curve group operations; `null` represents the point at infinity |
| Point encoding | `point_from_x`, `encode_public_key`, `decode_public_key`, `is_on_curve` | SEC 1 point reconstruction, serialization, parsing, and validation |
| Input validation | `validate_private_key`, `validate_public_key`, `validate_hash`, `validate_signature` | Strict key, digest, point, and scalar boundary checks |
| Signature encoding | `signature_to_compact`, `signature_to_recovered` | Fixed-width concatenations of `r` with `s`, optionally prefixed by `v` |
| Verification primitive | `verify_signature_point` | Verifies a signature against an already-decoded curve point |

Low-level scalar multiplication is synchronous, but the high-level secret operations are asynchronous because SHA-256 and HMAC use the Web Crypto API.

## Hashing and protocols

Applications are responsible for canonical message serialization, choosing the correct protocol hash, and domain separation. Never sign ambiguous concatenations of user-controlled values. A signature for one protocol should not be reusable in another protocol.

## Version 5 migration

Version 5 is intentionally strict and contains breaking changes:

- Invalid keys, hashes, signatures, and recovery IDs are rejected.
- `r`, `s`, and compressed public keys now have fixed canonical lengths.
- Point arithmetic now represents infinity explicitly, handles exceptional cases, and uses iterative scalar multiplication; some low-level return types have therefore changed.
- Node.js 20.19 is the minimum supported Node version.
- A new root module and `verify` export are available.

See [changelog.md](./changelog.md) for the complete list.
