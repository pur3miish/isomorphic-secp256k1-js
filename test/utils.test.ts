import assert from "node:assert/strict";
import test from "node:test";

import hmac_sha256 from "../src/hmac_sha256.js";
import sha256 from "../src/sha256.js";
import {
  add,
  array_to_number,
  double_and_add,
  mul_inverse,
  negate,
  number_to_array,
  point_from_x,
  recovered_to_signature,
  scalar_multiply,
  secp256k1,
  signature_to_compact,
  signature_to_recovered,
} from "../src/utils.js";

test("uses fixed-width integer encodings", () => {
  assert.equal(number_to_array(1n).length, 32);
  assert.equal(array_to_number(number_to_array(1n)), 1n);
  assert.equal(
    Buffer.from(number_to_array(0x1234n, 2)).toString("hex"),
    "1234",
  );
  assert.throws(() => number_to_array(-1n));
  assert.throws(() => number_to_array(256n, 1));
  assert.throws(() => array_to_number(new Uint8Array(0)));
  assert.throws(() => array_to_number(new Uint8Array(33)));
});

test("round-trips compact and recovered signatures", () => {
  const signature = {
    r: number_to_array(1n),
    s: number_to_array(2n),
    v: 1,
  };
  assert.equal(signature_to_compact(signature).length, 64);
  const recovered = signature_to_recovered(signature);
  assert.equal(recovered.length, 65);
  assert.equal(recovered[0], 1);
  assert.deepEqual(recovered_to_signature(recovered), signature);
});

test("handles point-at-infinity and invalid-field edge cases", () => {
  const generator = { x: secp256k1.x, y: secp256k1.y };
  assert.equal(scalar_multiply(generator, 0n), null);
  assert.equal(double_and_add(generator, secp256k1.n), null);
  assert.equal(scalar_multiply(generator, secp256k1.n), null);
  assert.equal(add(generator, negate(generator)), null);
  assert.throws(() => mul_inverse(0n, secp256k1.n));
  assert.throws(() => point_from_x(0, 0n));
  assert.throws(() => point_from_x(2, secp256k1.x));
});

test("matches SHA-256 and HMAC-SHA256 known-answer vectors", async () => {
  const message = new TextEncoder().encode("abc");
  assert.equal(
    Buffer.from(await sha256(message)).toString("hex"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
  assert.equal(
    Buffer.from(
      await hmac_sha256(
        new TextEncoder().encode("The quick brown fox jumps over the lazy dog"),
        new TextEncoder().encode("key"),
      ),
    ).toString("hex"),
    "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
  );
});

test("hash helpers reject non-byte inputs", async () => {
  await assert.rejects(() => sha256("abc" as unknown as Uint8Array));
  await assert.rejects(() =>
    hmac_sha256("abc" as unknown as Uint8Array, new Uint8Array([1, 2, 3])),
  );
});
