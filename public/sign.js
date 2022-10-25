'use strict'

const hmac_sha256 = require('universal-hmac-sha256-js')
const sha256 = require('universal-sha256-js')
const {
  secp256k1,
  double_and_add,
  mul_inverse,
  get_mod
} = require('../private/index.js')
const { array_to_number, number_to_array } = require('./utils.js')

/**
 * Generates a digital signature on the secp256k1 Koblitz curve.
 * @kind function
 * @name sign
 * @param {object} Arg Argument.
 * @param {Uin8Array} Arg.private_key secp256k1 private key.
 * @param {Uin8Array} Arg.data Data to sign.
 * @returns {Signature} Digital signature object containing `r` and `s` and `v` values.
 * @example <caption>Ways to `import`.</caption>
 * ```js
 * import { sign } from 'universal-secp256k1-js'
 * ```
 * @example <caption>Ways to `require`.</caption>
 * ```js
 * const { sign } = require('universal-secp256k1-js')
 * ```
 *  @example <caption>Usage `sign`.</caption>
 * ```js
 * const private_key = new Uint8Array([
 *   210, 101, 63, 247, 203, 178, 216, 255, 18, 154, 194, 126, 245, 120, 28, 230,
 *   139, 37, 88, 196, 26, 116, 175, 31, 45, 220, 166, 53, 203, 238, 240, 125
 * ])
 *
 * const data = Uint8Array.from([104, 101, 108, 108, 111])
 * sign({ data, private_key }).then(console.log)
 * ```
 * > The logged output is { r: [23, …, 89], s: [111, …, 142], v: 1 }
 */
async function sign({ private_key, data }) {
  let r, s, racid
  const hash = await sha256(data)

  const validate_signature = (T, e, d) => {
    const { x, y, mod, n } = secp256k1
    const G = { x, y }

    let x1 = T - n
    if (x1 >= 0n || 0n >= T) return 1n
    let val = T
    let Q = double_and_add(G, val, mod, n)
    if (Q.x == 0n && Q.y == 0n) return 1n // infinity

    // https://bitcoin.stackexchange.com/questions/83035/how-to-determine-first-byte-recovery-id-for-signatures-message-signing
    let v = 0n
    if (Q.x > secp256k1.n) v = 2n

    r = number_to_array(Q.x)
    val = get_mod(mul_inverse(T, secp256k1.n) * (Q.x * d + e), secp256k1.n)

    if (Q.y % 2n) racid = 1n | v
    else racid = 0n | v

    // Enforce low S values, see BIP62.  if x coordinate is larger than order n
    if (val > secp256k1.n / 2n) {
      val = secp256k1.n - val
      racid = racid ^ 1n // XOR recovery id
    }

    s = number_to_array(val)

    return 0
  }

  // https://tools.ietf.org/html/rfc6979#section-3.2
  const deterministically_generate_k = async (hash, private_key, nonce = 0) => {
    let msg_digest = nonce
      ? await sha256(Uint8Array.from([...hash, ...new Uint8Array(nonce)]))
      : hash

    const v = new Uint8Array(32).fill(1)
    const k = new Uint8Array(32).fill(0)

    let buff_D = await hmac_sha256(
      Uint8Array.from([...v, 0, ...private_key, ...msg_digest]),
      k
    )
    let buf_E = await hmac_sha256(v, buff_D)
    const buf_F = await hmac_sha256(
      Uint8Array.from([...buf_E, 1, ...private_key, ...msg_digest]),
      buff_D
    )
    let buf_G = await hmac_sha256(buf_E, buf_F)
    let buf_h2b = await hmac_sha256(buf_G, buf_F)

    let T = array_to_number(buf_h2b)
    let e = array_to_number(hash)
    let d = array_to_number(private_key)

    while (validate_signature(T, e, d)) {
      let buf_pad_v = Uint8Array.from([...buf_h2b, 0])
      let buf_k = await hmac_sha256(buf_pad_v, buf_F)
      let bufv = await hmac_sha256(buf_h2b, buf_k)
      let bufv2 = await hmac_sha256(bufv, buf_k)
      T = array_to_number(bufv2)
    }

    if (r[0] >= 0x80n || s[0] >= 0x80n)
      return deterministically_generate_k(hash, private_key, ++nonce)
    else return { r, s, v: racid.toString() }
  }

  return deterministically_generate_k(hash, private_key)
}

module.exports = sign
