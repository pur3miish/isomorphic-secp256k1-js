import { double_and_add, secp256k1 } from "./utils.js";
import { array_to_number, number_to_array } from "./utils.js";
/**
 * Generates a compressed public key for the `secp256k1` curve.
 * @public
 * @param {Uint8Array} private_key - A valid secp256k1 private key.
 * @returns {Uint8Array} - The compressed public key.
 *
 * @example
 * ```ts
 * const private_key = new Uint8Array([
 *   210, 101, 63, 247, 203, 178, 216, 255, 18, 154, 194, 126, 245, 120, 28, 230,
 *   139, 37, 88, 196, 26, 116, 175, 31, 45, 220, 166, 53, 203, 238, 240, 125
 * ]);
 *
 * get_public_key(private_key).then(console.log); // compressed public key.
 * ```
 * > The logged output will be a compressed public key like [2, …, 207].
 */
async function get_public_key(private_key) {
  const { x, y, n, mod } = secp256k1;
  const k = array_to_number(private_key);
  if (n < k) {
    throw new RangeError("Invalid private key size");
  }
  const R = double_and_add({ x, y }, k, mod, n);
  return Uint8Array.from([R.y % 2n ? 3 : 2, ...number_to_array(R.x)]);
}
export default get_public_key;
