'use strict'

const { double_and_add, secp256k1 } = require('./private/index.js')
const { number_to_array, array_to_number } = require('./private/utils.js')
/**
 * Generates a compressed public key for the `secp256k1` curve.
 * @kind function
 * @name get_public_key
 * @param {Uint8Array} private_key secp256k1 valid private key.
 * @returns {Uint8Array} Public key.
 * @example <caption>Ways to `import`.</caption>
 * ```js
 * import { get_public_key } from 'isomorphic-secp256k1-js'
 * ```
 * @example <caption>Ways to `require`.</caption>
 * ```js
 * const { get_public_key } = require('isomorphic-secp256k1-js')
 * ```
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
  const { x, y, n, mod } = secp256k1

  const k = array_to_number(private_key)

  if (n < k) throw new RangeError('Invalid private key size')
  const R = double_and_add({ x, y }, k, mod, n)

  return Uint8Array.from([R.y % 2n ? 3 : 2, ...number_to_array(R.x)])
}

module.exports = get_public_key
