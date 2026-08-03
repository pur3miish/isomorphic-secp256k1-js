import assert from "node:assert/strict";
import {
  createPrivateKey,
  createPublicKey,
  sign as node_sign,
  verify as node_verify,
} from "node:crypto";
import test from "node:test";

import get_public_key from "../src/get_public_key.js";
import sha256 from "../src/sha256.js";
import sign from "../src/sign.js";
import verify from "../src/verify.js";
import {
  decode_public_key,
  encode_public_key,
  number_to_array,
  scalar_multiply,
  signature_to_compact,
} from "../src/utils.js";

const private_key =
  number_to_array(
    0x1e99423a4ed27608a15a2616cf24e98bc25a19d73c0c3151b99e79f8f4f67a2dn,
  );

function key_material() {
  const public_key = decode_public_key_from_private();
  const point = decode_public_key(public_key);
  const public_jwk = {
    kty: "EC" as const,
    crv: "secp256k1",
    x: Buffer.from(number_to_array(point.x)).toString("base64url"),
    y: Buffer.from(number_to_array(point.y)).toString("base64url"),
  };
  return {
    public_key,
    public_node_key: createPublicKey({ key: public_jwk, format: "jwk" }),
    private_node_key: createPrivateKey({
      key: {
        ...public_jwk,
        d: Buffer.from(private_key).toString("base64url"),
      },
      format: "jwk",
    }),
  };
}

function decode_public_key_from_private(): Uint8Array {
  // This test intentionally uses the synchronous public arithmetic helper so
  // the Node.js key construction does not depend on another crypto package.
  const generator = decode_public_key(
    Uint8Array.from(
      Buffer.from(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "hex",
      ),
    ),
  );
  const scalar = BigInt(`0x${Buffer.from(private_key).toString("hex")}`);
  return encode_public_key(scalar_multiply(generator, scalar));
}

test("signatures verify with Node.js/OpenSSL", async () => {
  const message = new TextEncoder().encode("cross implementation signature");
  const hash = await sha256(message);
  const signature = await sign({ private_key, hash });
  const { public_node_key } = key_material();
  assert.equal(
    node_verify(
      "sha256",
      message,
      { key: public_node_key, dsaEncoding: "ieee-p1363" },
      signature_to_compact(signature),
    ),
    true,
  );
});

test("verifies Node.js/OpenSSL P1363 signatures", async () => {
  const message = new TextEncoder().encode("external signature");
  const hash = await sha256(message);
  const { private_node_key, public_key } = key_material();
  const compact = node_sign("sha256", message, {
    key: private_node_key,
    dsaEncoding: "ieee-p1363",
  });
  assert.equal(compact.length, 64);
  assert.equal(
    await verify({
      hash,
      public_key,
      canonical: false,
      signature: {
        r: compact.subarray(0, 32),
        s: compact.subarray(32),
      },
    }),
    true,
  );
});

test("matches an RFC 6979 secp256k1 known-answer signature", async () => {
  const key = number_to_array(1n);
  const hash = await sha256(new TextEncoder().encode("sample"));
  const signature = await sign({ private_key: key, hash });
  assert.equal(
    Buffer.from(signature.r).toString("hex"),
    "58db657bcd631038bea07b4941172f0167aca98f12b55e3176bd1c35435d6501",
  );
  assert.equal(
    Buffer.from(signature.s).toString("hex"),
    "3a78e73d8ff8ab554e13c10f6390d81a882f91945d6275493882676170b53a57",
  );
  assert.equal(signature.v, 1);
  assert.deepEqual(
    await get_public_key(key),
    Uint8Array.from(
      Buffer.from(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "hex",
      ),
    ),
  );
});
