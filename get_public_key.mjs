// @ts-check

import { double_and_add, secp256k1 } from "./private/index.mjs";
import { array_to_number, number_to_array } from "./private/utils.mjs";

/**
 * Generates a compressed public key for the `secp256k1` curve.
 * @param {Uint8Array} private_key secp256k1 valid private key.
 * @returns {Uint8Array} Public key.
 * @example <caption>Usage `get_public_key`.</caption>
 * ```js
 * const private_key = new Uint8Array([
 *   210, 101, 63, 247, 203, 178, 216, 255, 18, 154, 194, 126, 245, 120, 28, 230,
 *   139, 37, 88, 196, 26, 116, 175, 31, 45, 220, 166, 53, 203, 238, 240, 125
 * ])
 *
 * get_public_key(private_key).then(console.log) // compressed public key.
 * ```
 * > The logged output was [2, …, 207].
 */
function get_public_key(private_key) {
  const { x, y, n, mod } = secp256k1;

  const k = array_to_number(private_key);

  if (n < k) throw new RangeError("Invalid private key size");
  const R = double_and_add({ x, y }, k, mod, n);

  return Uint8Array.from([R.y % 2n ? 3 : 2, ...number_to_array(R.x)]);
}

export default get_public_key;
