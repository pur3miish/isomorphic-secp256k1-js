# Private-key randomness

This document defines how `isomorphic-secp256k1-js` obtains and validates secp256k1 private-key material in Node.js and browsers.

## Security objective

A secp256k1 private key is an integer `d` satisfying `1 <= d < n`, where `n` is the order of the curve's generator. The key must also be computationally unpredictable. Those are separate properties:

- This package validates the 32-byte encoding and scalar range.
- A cryptographically secure random number generator (CSPRNG) must provide the unpredictability.
- Structural validation cannot detect a key drawn from a small, biased, repeated, or attacker-known set.

## Default: native Web Crypto

```js
import { generate_private_key } from "isomorphic-secp256k1-js";

const private_key = await generate_private_key();
```

With no option, the package calls `globalThis.crypto.getRandomValues(new Uint8Array(32))`. Supported Node.js and browser runtimes expose the same Web Crypto interface, which delegates cryptographic randomness to the runtime and operating system.

If `getRandomValues` is unavailable, generation fails. The package does not fall back to `Math.random` or another weaker source.

## Custom CSPRNG

```js
import { generate_private_key } from "isomorphic-secp256k1-js";

const private_key = await generate_private_key({
  random_source: async (length) => hardware_security_module.randomBytes(length),
});
```

The hook supports hardware security modules, secure enclaves, platform APIs, and application-specific entropy policies. It may return a `Uint8Array` or `Promise<Uint8Array>` and must return exactly the requested number of bytes.

The package may call the source more than once because invalid candidates are rejected. It copies an accepted result before returning it, so later mutation of the source buffer cannot alter the generated key.

A production custom source should:

- Be designed and reviewed as a CSPRNG, not merely a statistically random generator.
- Be correctly seeded before its first output and reseeded according to its design.
- Return full-width, uniformly distributed 32-byte candidates without deliberately restricting the possible values.
- Avoid shared or cloned state that could repeat output across processes, virtual machines, devices, restores, or snapshots.
- Fail closed instead of returning predictable bytes when its entropy provider is unavailable.
- Keep test fixtures and deterministic mocks unreachable from production key-generation paths.

Never use `Math.random`, a timestamp, UUID, password, counter, device identifier, Mersenne Twister, or another general-purpose seeded PRNG as a private-key source.

## Rejection sampling and the scalar limit

For every candidate, the package:

1. Requests exactly 32 bytes.
2. Interprets them as an unsigned big-endian integer `d`.
3. Accepts only `1 <= d < n`.
4. Requests another candidate if `d` is zero or at least `n`.
5. Fails after 1024 rejected candidates, indicating a broken or adversarial source.

The implementation does not calculate `d mod n`. Rejection sampling preserves a uniform distribution over valid private scalars when the input bytes are uniform and avoids modulo bias.

## Existing key material

```js
import { get_public_key, validate_private_key } from "isomorphic-secp256k1-js";

validate_private_key(existing_private_key);
const public_key = get_public_key(existing_private_key);
```

`validate_private_key` confirms that the value is an encoded secp256k1 private scalar. It does not prove where the key came from or estimate its entropy. `get_public_key` and `sign` repeat private-key validation internally.

## Randomness used elsewhere

- `sign` derives its ECDSA per-message nonce with RFC 6979 by default. Its nonce uniqueness does not depend on runtime randomness.
- `sign({ extra_entropy: true })` mixes 32 bytes from native Web Crypto into RFC 6979 as an additional hedge.
- Secret scalar multiplication uses native random scalar blinding. Blinding changes the internal calculation path, not the resulting public key or signature.

These uses are separate from private-key generation. A valid deterministic signature does not compensate for a predictable private key.

## Claims and limits

The package follows the key-generation practices described above and tests their control flow and range validation. It has not received an independent cryptographic audit. It cannot certify an application's runtime, hardware, custom CSPRNG, key storage, build pipeline, or operational security, and it does not claim that generated keys are hack-proof.

For the broader threat model, see [SECURITY.md](../SECURITY.md).
