import assert from "node:assert/strict";
import test from "node:test";

import {
  generate_private_key,
  get_public_key,
  hmac_sha256,
  recover_public_key,
  sha256,
  sign,
  validate_private_key,
  verify,
} from "isomorphic-secp256k1-js";
import generate_private_key_deep from "isomorphic-secp256k1-js/generate_private_key";
import get_public_key_deep from "isomorphic-secp256k1-js/get_public_key";
import hmac_sha256_deep from "isomorphic-secp256k1-js/hmac_sha256";
import recover_public_key_deep from "isomorphic-secp256k1-js/recover_public_key";
import sha256_deep from "isomorphic-secp256k1-js/sha256";
import sign_deep from "isomorphic-secp256k1-js/sign";
import * as utils_deep from "isomorphic-secp256k1-js/utils";
import verify_deep from "isomorphic-secp256k1-js/verify";

test("supports root and typed deep package exports", async () => {
  const private_key = new Uint8Array(32);
  private_key[31] = 1;
  const hash = await sha256(new TextEncoder().encode("package exports"));
  assert.deepEqual(
    hash,
    await sha256_deep(new TextEncoder().encode("package exports")),
  );

  const public_key = await get_public_key(private_key);
  assert.deepEqual(public_key, await get_public_key_deep(private_key));

  const signature = await sign({ private_key, hash });
  const deep_signature = await sign_deep({ private_key, hash });
  assert.deepEqual(signature, deep_signature);

  assert.equal(
    await verify({
      hash,
      signature,
      public_key,
    }),
    true,
  );
  assert.equal(await verify_deep({ hash, signature, public_key }), true);

  assert.deepEqual(
    await recover_public_key({ hash, signature }),
    await recover_public_key_deep({ hash, signature }),
  );

  const hmac_key = new Uint8Array(32).fill(7);
  assert.deepEqual(
    await hmac_sha256(hash, hmac_key),
    await hmac_sha256_deep(hash, hmac_key),
  );
  assert.equal(utils_deep.PRIVATE_KEY_LENGTH, 32);

  const generated = await generate_private_key();
  const generated_deep = await generate_private_key_deep();
  validate_private_key(generated);
  utils_deep.validate_private_key(generated);
  utils_deep.validate_private_key(generated_deep);

  await Promise.all([
    import("isomorphic-secp256k1-js/generate_private_key.js"),
    import("isomorphic-secp256k1-js/get_public_key.js"),
    import("isomorphic-secp256k1-js/hmac_sha256.js"),
    import("isomorphic-secp256k1-js/recover_public_key.js"),
    import("isomorphic-secp256k1-js/sha256.js"),
    import("isomorphic-secp256k1-js/sign.js"),
    import("isomorphic-secp256k1-js/utils.js"),
    import("isomorphic-secp256k1-js/verify.js"),
  ]);
});
