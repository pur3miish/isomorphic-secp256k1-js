import assert from "node:assert/strict";
import test from "node:test";

import generate_private_key from "../src/generate_private_key.js";
import get_public_key from "../src/get_public_key.js";
import sign from "../src/sign.js";
import {
  number_to_array,
  secp256k1,
  validate_private_key,
} from "../src/utils.js";
import verify from "../src/verify.js";

test("generates valid private keys with native Web Crypto", async () => {
  const first = await generate_private_key();
  const second = await generate_private_key();

  assert.equal(first.length, 32);
  assert.equal(second.length, 32);

  validate_private_key(first);
  validate_private_key(second);

  assert.notDeepEqual(first, second);

  const hash = new Uint8Array(32).fill(9);

  const public_key = get_public_key(first);

  const signature = await sign({
    private_key: first,
    hash,
  });

  assert.equal(
    verify({
      public_key,
      hash,
      signature,
    }),
    true,
  );
});

test("supports a caller-selected random source with rejection sampling", async () => {
  const candidates = [
    new Uint8Array(32),
    number_to_array(secp256k1.n),
    number_to_array(1n),
  ];

  const lengths: number[] = [];

  const private_key = await generate_private_key({
    random_source: async (length) => {
      lengths.push(length);
      return candidates.shift()!;
    },
  });

  assert.deepEqual(lengths, [32, 32, 32]);

  assert.deepEqual(private_key, number_to_array(1n));
});

test("copies caller-supplied random bytes before returning", async () => {
  const supplied = number_to_array(2n);

  const private_key = await generate_private_key({
    random_source: () => supplied,
  });

  assert.notEqual(private_key, supplied);

  supplied.fill(0);

  assert.deepEqual(private_key, number_to_array(2n));
});

test("rejects malformed and persistently invalid random sources", async () => {
  await assert.rejects(
    generate_private_key({
      // @ts-expect-error Testing runtime validation.
      random_source: 1,
    }),
    /random_source must be a function/,
  );

  await assert.rejects(
    generate_private_key({
      random_source: () => new Uint8Array(31),
    }),
    /random_source result must be exactly 32 bytes/,
  );

  await assert.rejects(
    generate_private_key({
      random_source: () => new Uint8Array(32),
    }),
    /after 1024 attempts/,
  );
});
