import type { Signature } from "./utils.js";
import {
  add,
  double_and_add,
  get_mod,
  mul_inverse,
  point_from_x,
  secp256k1,
} from "./utils.js";
import { array_to_number, number_to_array } from "./utils.js";

/**
 * Recovery argument interface that contains the signature and the data.
 */
export interface RecoverArg {
  signature: Signature;
  hash: Uint8Array;
}

/**
 * Recovers a public key from a digital signature on the secp256k1 Koblitz curve.
 *
 * @param {RecoverArg} arg - The argument object containing the signature and the hash.
 * @returns {Promise<Uint8Array>} - The recovered public key.
 *
 * @example
 * ```ts
 * const signature: Signature = {
 *   r: number_to_array(50172533143525448505731076092836454339589141171079665638497512992118311974590n),
 *   s: number_to_array(3372897403575535231543296615264124933490702058654620386530787287980439847001n),
 *   v: 0
 * };
 *
 * const hash: Uint8Array = new Uint8Array([104, 101, 108, 108, 111]);  // Some hash value
 *
 * recover_public_key({ hash, signature }).then(console.log);
 * ```
 */
async function recover_public_key({
  hash,
  signature,
}: RecoverArg): Promise<Uint8Array> {
  const { n, mod, x, y } = secp256k1; // secp256k1 curve parameters
  const { s, r, v } = signature;

  // Validate the 'v' value, which is the recovery ID (either 0, 1, 2, or 3).
  const i = BigInt(v);
  if (i > 3n) throw new Error("Invalid value for v.");

  // Determine the x-coordinate based on the recovery ID and the signature 'r'.
  const x_num = i >> 1n ? array_to_number(r) + n : array_to_number(r);

  // Recover the R point from the x-coordinate and recovery ID.
  const R = point_from_x(i & 3n, x_num);

  // The message hash (the signed data) is passed in as 'hash'.
  const e = array_to_number(hash);
  const eneg = get_mod(e * -1n, n); // Negative of e modulo n

  // Compute the inverse of r modulo n.
  const rInv = mul_inverse(array_to_number(r), n);

  // Perform the elliptic curve calculations to recover the public key.
  const p1 = double_and_add(R, array_to_number(s), mod, n); // R * s
  const p2 = double_and_add({ x, y }, eneg, mod, n); // -e * G
  const p3 = add(p1, p2, mod); // Add the two points
  const P = double_and_add(p3, rInv, mod, n); // Multiply the result by r^-1

  // The recovered public key is in the point P, which is (x, y).
  // The first byte of the public key is 2 or 3 depending on the y-coordinate.
  return Uint8Array.from([P.y % 2n ? 3 : 2, ...number_to_array(P.x)]);
}

export default recover_public_key;
