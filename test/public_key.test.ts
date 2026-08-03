import assert from "node:assert/strict";
import test from "node:test";

import get_public_key from "../src/get_public_key.js";
import { number_to_array, secp256k1 } from "../src/utils.js";

test("derives the canonical compressed generator key", async () => {
  const private_key = number_to_array(1n);
  const public_key = await get_public_key(private_key);
  assert.equal(public_key.length, 33);
  assert.equal(
    Buffer.from(public_key).toString("hex"),
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  );
});

test("left-pads public key coordinates to exactly 32 bytes", async () => {
  const public_key = await get_public_key(number_to_array(153n));
  assert.equal(public_key.length, 33);
  assert.equal(
    Buffer.from(public_key).toString("hex"),
    "0200e3ae1974566ca06cc516d47e0fb165a674a3dabcfca15e722f0e3450f45889",
  );
});

test("rejects invalid private-key scalars and lengths", async () => {
  const invalid_keys = [
    new Uint8Array(0),
    new Uint8Array(31),
    new Uint8Array(32),
    new Uint8Array(33),
    number_to_array(secp256k1.n),
  ];
  for (const private_key of invalid_keys) {
    await assert.rejects(() => get_public_key(private_key));
  }
});
