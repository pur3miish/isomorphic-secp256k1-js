import type { Signature } from "./utils.js";
import {
  add,
  array_to_number,
  encode_public_key,
  get_mod,
  hash_to_scalar,
  is_on_curve,
  mul_inverse,
  negate,
  point_from_x,
  scalar_multiply,
  secp256k1,
  validate_hash,
  validate_signature,
  verify_signature_point,
} from "./utils.js";

export interface RecoverArg {
  signature: Signature;
  hash: Uint8Array;
  /** Reject malleable high-S signatures. Defaults to true. */
  canonical?: boolean;
}

/** Recovers and verifies a compressed public key from a recoverable signature. */
function recover_public_key({
  hash,
  signature,
  canonical = true,
}: RecoverArg): Uint8Array {
  validate_hash(hash);
  validate_signature(signature, {
    low_s: canonical,
    require_recovery: true,
  });
  const r = array_to_number(signature.r);
  const s = array_to_number(signature.s);
  const x = r + BigInt(signature.v >> 1) * secp256k1.n;
  if (x >= secp256k1.mod) {
    throw new RangeError(
      "signature recovery x-coordinate is outside the field.",
    );
  }

  const nonce_point = point_from_x(signature.v & 1, x);
  if (scalar_multiply(nonce_point, secp256k1.n) !== null) {
    throw new RangeError(
      "signature recovery point is not in the prime-order group.",
    );
  }

  const inverse = mul_inverse(r, secp256k1.n);
  const first = scalar_multiply(nonce_point, s);
  const second = negate(
    scalar_multiply({ x: secp256k1.x, y: secp256k1.y }, hash_to_scalar(hash)),
  );
  const public_point = scalar_multiply(
    add(first, second),
    get_mod(inverse, secp256k1.n),
  );
  if (
    public_point === null ||
    !is_on_curve(public_point) ||
    !verify_signature_point(hash, signature, public_point, canonical)
  ) {
    throw new Error("Recovered public key does not verify the signature.");
  }
  return encode_public_key(public_point);
}

export default recover_public_key;
