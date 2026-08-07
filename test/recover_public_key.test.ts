import assert from "node:assert/strict";
import test from "node:test";

import get_public_key from "../src/get_public_key.js";
import recover_public_key from "../src/recover_public_key.js";
import sha256 from "../src/sha256.js";
import sign from "../src/sign.js";
import { number_to_array, secp256k1 } from "../src/utils.js";

const private_key =
  number_to_array(
    0xd2653ff7cbb2d8ff129ac27ef5781ce68b2558c41a74af1f2ddca635cbeef07dn,
  );

test("recovers and verifies the expected public key", async () => {
  const hash = await sha256(new TextEncoder().encode("recover me"));
  const signature = await sign({ private_key, hash });

  assert.deepEqual(
    recover_public_key({ hash, signature }),
    get_public_key(private_key),
  );
});

test("supports high-S recovery only when explicitly requested", async () => {
  const hash = await sha256(new TextEncoder().encode("malleability check"));
  const low = await sign({ private_key, hash });

  const high = {
    r: low.r,
    s: number_to_array(
      secp256k1.n - BigInt(`0x${Buffer.from(low.s).toString("hex")}`),
    ),
    v: low.v ^ 1,
  };

  assert.throws(() => recover_public_key({ hash, signature: high }));

  assert.deepEqual(
    recover_public_key({
      hash,
      signature: high,
      canonical: false,
    }),
    get_public_key(private_key),
  );
});

test("rejects invalid recovery IDs, scalars, hashes, and oversized fields", async () => {
  const hash = new Uint8Array(32);
  const valid = await sign({ private_key, hash });

  const invalid_signatures = [
    { ...valid, v: -1 },
    { ...valid, v: 4 },
    { ...valid, v: 1.5 },
    { ...valid, r: new Uint8Array(32) },
    { ...valid, s: new Uint8Array(32) },
    { ...valid, r: new Uint8Array(33) },
    { ...valid, s: number_to_array(secp256k1.n) },
  ];

  for (const signature of invalid_signatures) {
    assert.throws(() => recover_public_key({ hash, signature }));
  }

  assert.throws(() =>
    recover_public_key({
      hash: new Uint8Array(31),
      signature: valid,
    }),
  );
});
