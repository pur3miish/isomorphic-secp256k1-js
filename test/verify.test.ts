import assert from "node:assert/strict";
import test from "node:test";

import get_public_key from "../src/get_public_key.js";
import sha256 from "../src/sha256.js";
import sign from "../src/sign.js";
import verify from "../src/verify.js";
import { number_to_array, secp256k1 } from "../src/utils.js";

const private_key = number_to_array(42n);

test("verifies valid signatures and rejects mutations", async () => {
  const hash = await sha256(new TextEncoder().encode("verify me"));
  const public_key = get_public_key(private_key);
  const signature = await sign({ private_key, hash });

  assert.equal(verify({ hash, signature, public_key }), true);

  const mutated_hash = Uint8Array.from(hash);
  mutated_hash[0] ^= 1;

  assert.equal(
    verify({
      hash: mutated_hash,
      signature,
      public_key,
    }),
    false,
  );

  const mutated_signature = {
    ...signature,
    r: Uint8Array.from(signature.r),
  };

  mutated_signature.r[31] ^= 1;

  assert.equal(
    verify({
      hash,
      signature: mutated_signature,
      public_key,
    }),
    false,
  );
});

test("returns false for malformed signatures and public keys", async () => {
  const hash = new Uint8Array(32);
  const public_key = get_public_key(private_key);
  const signature = await sign({ private_key, hash });

  const malformed = [
    { ...signature, r: new Uint8Array(32) },
    { ...signature, s: new Uint8Array(32) },
    { ...signature, r: new Uint8Array(31) },
    { ...signature, s: number_to_array(secp256k1.n) },
  ];

  for (const candidate of malformed) {
    assert.equal(
      verify({
        hash,
        signature: candidate,
        public_key,
      }),
      false,
    );
  }

  assert.equal(
    verify({
      hash,
      signature,
      public_key: new Uint8Array(33),
    }),
    false,
  );
});

test("rejects high-S signatures by default", async () => {
  const hash = await sha256(new TextEncoder().encode("low-S only"));
  const public_key = get_public_key(private_key);
  const low = await sign({ private_key, hash });

  const high = {
    r: low.r,
    s: number_to_array(
      secp256k1.n - BigInt(`0x${Buffer.from(low.s).toString("hex")}`),
    ),
  };

  assert.equal(
    verify({
      hash,
      signature: high,
      public_key,
    }),
    false,
  );

  assert.equal(
    verify({
      hash,
      signature: high,
      public_key,
      canonical: false,
    }),
    true,
  );
});

test("throws on a non-32-byte hash", () => {
  assert.throws(() =>
    verify({
      hash: new Uint8Array(31),
      signature: {
        r: number_to_array(1n),
        s: number_to_array(1n),
      },
      public_key: new Uint8Array(33),
    }),
  );
});
