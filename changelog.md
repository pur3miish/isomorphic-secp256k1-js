# Isomorphic-secp256k1-js

## 6.0.0 - 2026-08-07

### Breaking

- `get_public_key()` is now synchronous and returns `Uint8Array` directly instead of `Promise<Uint8Array>`.
- `recover_public_key()` is now synchronous and returns `Uint8Array` directly instead of `Promise<Uint8Array>`.
- `verify()` is now synchronous and returns `boolean` directly instead of `Promise<boolean>`.
- Errors from these synchronous APIs are now thrown immediately rather than being surfaced as rejected Promises.
- Callers using `await` remain compatible because JavaScript permits awaiting non-Promise values, but callers using `.then()`, `.catch()`, `Promise.all()`, or explicit `Promise<T>` typings for these functions must update their code.

### Changed

- Removed unnecessary `async` declarations from public-key derivation, ECDSA verification, and public-key recovery.
- Removed unnecessary Promise and microtask creation from operations implemented entirely with synchronous secp256k1 arithmetic.
- Updated tests and documentation to distinguish synchronous elliptic-curve operations from APIs that genuinely require asynchronous Web Crypto operations.

### Unchanged

- `generate_private_key()` remains asynchronous because caller-supplied random sources may return a `Promise<Uint8Array>`.
- `sha256()` remains asynchronous because Web Crypto `subtle.digest()` is asynchronous.
- `hmac_sha256()` remains asynchronous because Web Crypto key import and HMAC operations are asynchronous.
- `sign()` remains asynchronous because RFC 6979 signing uses the asynchronous HMAC-SHA-256 implementation.
- The package remains zero-runtime-dependency, native ESM, and compatible with its existing supported Node.js and browser environments.

## 5.0.3 - 2026-08-03

### Changed

- Updated the readme.

## 5.0.2 - 2026-08-03

### Documentation

- Expanded the private-key generation guidance to distinguish native Web Crypto, caller-selected CSPRNGs, and validation of existing private keys.
- Documented rejection sampling into `1 <= d < n`, the limits of entropy validation, weak-source failure modes, and requirements for custom random sources.
- Added a focused randomness guide and a concise `llms.txt` API reference for package indexes, code-search tools, coding assistants, and other automated consumers.
- Expanded npm keywords and package metadata for standards-based secp256k1, Web Crypto, entropy, TypeScript, and recoverable-signature discovery.

### Fixed

- Normalized repository text files to LF on every platform and configured Prettier to expect LF, preventing Windows GitHub Actions checkouts from reporting false formatting failures.

## 5.0.1 - 2026-08-03

### Security

- Signing now snapshots caller-owned key, digest, and explicit entropy arrays before asynchronous Web Crypto operations, preventing input mutation from separating RFC 6979 nonce derivation from the ECDSA calculation.
- Generated signatures are verified internally against the derived public key before they are returned.
- Signing and HMAC clear owned temporary byte buffers on success or failure where JavaScript permits, and signing validates the runtime `canonical` option type.

### Changed

- Generated JavaScript and TypeScript declarations are ignored by Git, built temporarily at the established package-root paths for npm compatibility, and removed automatically after packing or publishing.
- Added a cross-platform `npm run clean` script with an explicit generated-file list.

## 5.0.0 - 2026-08-03

### Security

- Reworked the package's own `BigInt` elliptic-curve core to use explicit point-at-infinity handling, checked inverses and square roots, complete exceptional-case handling, and iterative scalar multiplication.
- Added strict validation for private keys, message hashes, public keys, signature scalars, field lengths, and recovery identifiers.
- Implemented standards-compliant RFC 6979 deterministic nonces and optional hedged signing entropy.
- Added canonical low-S signing and verification by default.
- Recovery now validates curve points, field bounds, subgroup membership, and the recovered key before returning it.
- Secret scalar multiplication now uses a fixed-operation-count ladder and 128-bit scalar blinding while retaining the dependency-free implementation.
- Added fixed-width signature and public-key serialization to remove ambiguous encodings.
- Added `SECURITY.md` with disclosure guidance, threat model, and JavaScript side-channel limitations.
- Added unbiased private-key generation with strict scalar validation, bounded rejection sampling, native Web Crypto defaults, and caller-selected synchronous or asynchronous random sources.
- Documented randomness attack surfaces and separated private-key entropy, deterministic RFC 6979 nonces, optional signing entropy, and scalar blinding.

### Added

- Added a strict `verify({ hash, signature, public_key })` API.
- Added `generate_private_key({ random_source? })` and a root `validate_private_key` export.
- Added a root package export with named functions and public TypeScript types.
- Added explicit ESM and TypeScript declaration mappings for every public package subpath.
- Added Node.js, browser, high-level API, encoding, and low-level primitive integration documentation using standard cryptographic terminology.
- Added a bundler regression test and integration guidance for tree-shakeable named imports from the side-effect-free root module.
- Added honest security-status badges and documented the Montgomery-ladder invariant, fixed operation schedule, scalar blinding, and remaining JavaScript timing limitations.
- Added compact 64-byte and recoverable 65-byte signature encoding helpers.
- Added boundary, malformed-input, hashing-vector, RFC 6979 known-answer, Node.js/OpenSSL interoperability, malleability, recovery, and fixed-width tests using the Node.js test runner.
- Added a reproducible npm lockfile, Dependabot configuration, pinned GitHub Actions, least-privilege workflow permissions, and package-content checks.

### Breaking

- Invalid input that was previously accepted or failed recursively now throws or returns `false` from verification.
- `r` and `s` are always 32 bytes; compressed public keys are always 33 bytes.
- Low-level point helpers now use `null` for the point at infinity and therefore have stricter inputs and changed return types; the obsolete signing-specific `get_signature` helper was removed.
- `number_to_array` now defaults to a fixed 32-byte encoding and rejects negative or overflowing values.
- Node.js 20.19 or newer and the Web Crypto API are required.
- The package remains zero-runtime-dependency.

## 4.0.5

### Patch

- Typeo fixes
- Removal of createRequire as it was causing pkg compilation errors.

```js
const require = createRequire(import.meta.url);
```

## 4.0.4

### Patch

- Bug fixes for import/require [hmac_sha256](hmac_sha256.js) and [sha256](sha256.js)

# 4.0.0

### Main

- Changes to exports.

### Major

- TS functions added for better support.
- Now a zero dependency package.
- Now exporting a variety of utility functions.

### Patch

- Changes to read me

# 3.0.0

### Main

- Argument on `sign` and `recover_public_key` is now a hash insterad of data, the digital signature previosuly hashed the data transaction, now it takes the hash as an argument to digest.

## 2.0.4

### Patch

- dependency updates

## 2.0.3

- Added deno imports to [readme](readme.md)

## 2.0.2

- deno imports fixed

## 2.0.1

## Patch

- Dependency updates

## 2.0.0

### Major

- Changed to ESM from CJS.
- Added support for Deno.

## 1.0.2

## Patch

- readme typeo fixes

## 1.0.1

### Patch

- recovery public key bug fixes.

## 1.0.0

- Initial release
