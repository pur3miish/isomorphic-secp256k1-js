import assert from "node:assert/strict";
import test from "node:test";

import get_public_key from "../src/get_public_key.js";
import sha256 from "../src/sha256.js";
import sign from "../src/sign.js";
import verify from "../src/verify.js";
import { array_to_number, number_to_array, secp256k1 } from "../src/utils.js";

const private_key = number_to_array(1n);

test("creates deterministic, fixed-width, low-S signatures", async () => {
  const hash = await sha256(
    new TextEncoder().encode("deterministic signature"),
  );
  const first = await sign({ private_key, hash });
  const second = await sign({ private_key, hash });

  assert.deepEqual(first, second);
  assert.equal(first.r.length, 32);
  assert.equal(first.s.length, 32);
  assert.ok(Number.isInteger(first.v) && first.v >= 0 && first.v <= 3);
  assert.ok(array_to_number(first.s) <= secp256k1.n / 2n);
  assert.equal(
    await verify({
      hash,
      signature: first,
      public_key: await get_public_key(private_key),
    }),
    true,
  );
});

test("always emits 32-byte r and s components", async () => {
  for (let counter = 0; counter < 128; counter += 1) {
    const hash = new Uint8Array(32);
    new DataView(hash.buffer).setUint32(28, counter);
    const signature = await sign({ private_key, hash });
    assert.equal(signature.r.length, 32);
    assert.equal(signature.s.length, 32);
  }
});

test("supports optional hedged signing", async () => {
  const hash = await sha256(new TextEncoder().encode("hedged signature"));
  const signature = await sign({ private_key, hash, extra_entropy: true });
  assert.equal(
    await verify({
      hash,
      signature,
      public_key: await get_public_key(private_key),
    }),
    true,
  );
});

test("snapshots caller-owned inputs before asynchronous signing", async () => {
  const original_private_key = number_to_array(1n);
  const original_hash = await sha256(
    new TextEncoder().encode("immutable signing snapshot"),
  );
  const original_entropy = new Uint8Array(32).fill(0x42);
  const expected = await sign({
    private_key: original_private_key,
    hash: original_hash,
    extra_entropy: original_entropy,
  });
  const mutable_private_key = Uint8Array.from(original_private_key);
  const mutable_hash = Uint8Array.from(original_hash);
  const mutable_entropy = Uint8Array.from(original_entropy);

  const pending = sign({
    private_key: mutable_private_key,
    hash: mutable_hash,
    extra_entropy: mutable_entropy,
  });
  mutable_private_key.fill(0xff);
  mutable_hash.fill(0xff);
  mutable_entropy.fill(0xff);

  assert.deepEqual(await pending, expected);
});

test("rejects invalid private keys, hash lengths, and entropy options", async () => {
  const hash = new Uint8Array(32);
  await assert.rejects(() => sign({ private_key: new Uint8Array(32), hash }));
  await assert.rejects(() =>
    sign({ private_key: number_to_array(secp256k1.n), hash }),
  );
  await assert.rejects(() => sign({ private_key, hash: new Uint8Array(31) }));
  await assert.rejects(() => sign({ private_key, hash: new Uint8Array(33) }));
  await assert.rejects(() =>
    sign({
      private_key,
      hash,
      extra_entropy: "unsafe" as unknown as boolean,
    }),
  );
  await assert.rejects(() =>
    sign({ private_key, hash, canonical: "yes" as unknown as boolean }),
  );
});
