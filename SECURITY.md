# Security policy

## Supported versions

Only the latest 5.x release receives security fixes. Versions 4.x and earlier contain custom elliptic-curve arithmetic and should not be used to protect production keys.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through the repository's **Security** tab using GitHub's private vulnerability reporting or a private security advisory. Do not include exploit details, private keys, or affected production systems in a public issue.

Include the affected version, runtime, a minimal reproduction, the expected result, and the observed result when possible.

## Threat model and limitations

Version 5 keeps the package's own pure JavaScript implementation. It performs strict input validation, uses explicit point-at-infinity handling, emits canonical fixed-width encodings, implements the RFC 6979 state machine, self-verifies generated signatures, verifies recovered keys before returning them, and uses a fixed-operation-count ladder with 128-bit scalar blinding for secret multiplications. Signing snapshots caller-owned byte arrays before asynchronous Web Crypto operations and clears owned temporary byte buffers on completion where JavaScript permits.

The package can generate private keys using native `globalThis.crypto.getRandomValues` or a caller-selected random source. Generation uses rejection sampling and accepts only 32-byte scalars satisfying `1 <= d < n`. These checks prevent invalid or biased range reduction, but they cannot measure the entropy or trustworthiness of a custom source. A weak or compromised random source can make an otherwise valid key predictable.

The package also uses native randomness for scalar blinding and optional signing entropy. If that randomness is predictable, the mathematical output remains correct but the additional side-channel and fault protections are weakened. Default signing nonces follow RFC 6979 and do not rely on random input for uniqueness.

The implementation has not received an independent cryptographic audit. The ladder and blinding reduce obvious timing leakage, but they do not make JavaScript `BigInt` operations constant-time.

The package does not protect against:

- Compromised applications, browser extensions, dependencies, build systems, or JavaScript runtimes.
- Cross-site scripting or an attacker who can read process memory.
- Reliable recovery of secrets after they have been copied into immutable JavaScript `BigInt` values or garbage-collected memory.
- All timing and microarchitectural side channels. JavaScript JIT compilers and garbage collectors prevent absolute constant-time guarantees.
- Incorrect protocol serialization, hashing, domain separation, authorization, replay protection, or key storage performed by the calling application.
- Weak, biased, predictable, or incorrectly stored private keys or custom random sources supplied by the calling application.

For hardware wallets, custodial systems, or other high-value signing services, prefer a reviewed native or hardware-backed implementation and obtain an application-specific security assessment.

## Release hygiene

Consumers should commit their lockfile, review dependency changes, and verify npm provenance for published releases. Maintainers should publish through npm trusted publishing with provenance and should not publish from an unreviewed local working tree.
