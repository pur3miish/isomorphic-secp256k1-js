// @ts-check

import {
  add,
  double_and_add,
  get_mod,
  mul_inverse,
  point_from_x,
  secp256k1,
} from "./private/index.mjs";
import { array_to_number, number_to_array } from "./private/utils.mjs";

/**
 * @typedef {Object} Signature
 * @property {Uint8Array} r
 * @property {Uint8Array} s
 * @property {Number} v
 */

/**
 * Recovery argument contains a {@link Signature} and the data.
 * @typedef {Object} RecoverArg
 * @property {Signature} signature secp256k1 signature.
 * @property {Uint8Array} hash The 32 byte hash that was signed.
 */

/**
 * Recovers a public key from a digital signature on the secp256k1 Koblitz curve.
 * @param {RecoverArg} Arg {@link RecoverArg}
 * @returns {Promise<Uint8Array>} recovered Public key.
 * @example <caption>Usage `sign`.</caption>
 * ```js
 *
 *  const data = Uint8Array.from([
 *    2, 33, 65, 233, 23, 23, 123, 244, 23, 23, 123, 244
 *  ])
 *
 *  const signature = {
 *    r: number_to_array(
 *      50172533143525448505731076092836454339589141171079665638497512992118311974590n
 *    ),
 *    s: number_to_array(
 *      3372897403575535231543296615264124933490702058654620386530787287980439847001n
 *    ),
 *    v: 0
 *  }
 *
 *  const private_key = new Uint8Array([
 *    210, 101, 63, 247, 203, 178, 216, 255, 18, 154, 194, 126, 245, 120, 28, 230,
 *    139, 37, 88, 196, 26, 116, 175, 31, 45, 220, 166, 53, 203, 238, 240, 125
 *  ])
 *
 *  const data = Uint8Array.from([104, 101, 108, 108, 111])
 *  sign({ data, private_key }).then(console.log)
 *
 * ```
 */
async function recover_public_key({ hash, signature }) {
  const { n, mod, x, y } = secp256k1;
  const { s, r, v } = signature;

  const i = BigInt(v);
  if (i > 3n) throw new Error("Invalid value for v.");

  const x_num = i >> 1n ? array_to_number(r) + n : array_to_number(r);
  const R = point_from_x(i & 3n, x_num);
  const e = array_to_number(hash);
  const eneg = get_mod(e * -1n, n);
  const rInv = mul_inverse(array_to_number(r), n);

  const p1 = double_and_add(R, array_to_number(s), mod, n);
  const p2 = double_and_add({ x, y }, eneg, mod, n);
  const p3 = add(p1, p2, mod);
  const P = double_and_add(p3, rInv, mod, n);

  return Uint8Array.from([P.y % 2n ? 3 : 2, ...number_to_array(P.x)]);
}

export default recover_public_key;
