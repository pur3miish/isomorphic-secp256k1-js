// @ts-check

import hmac_sha256 from "universal-hmac-sha256-js/hmac-sha256.mjs";
import sha256 from "universal-sha256-js/sha256.mjs";

import { get_signature } from "./private/index.mjs";
import { array_to_number } from "./private/utils.mjs";

/**
 * @typedef {Object} Signature
 * @property {Uint8Array} r
 * @property {Uint8Array} s
 * @property {Number} v
 */

/**
 * @typedef {Object} SignArg
 * @property {Uint8Array} private_key secp256k1 private key.
 * @property {Uint8Array} data Data to sign.
 */
/**
 * Generates a digital signature on the secp256k1 Koblitz curve.
 * @param {SignArg} sign_argument
 * @returns {Promise<Signature>} Digital signature object containing `r` and `s` and `v` values.
 * @example <caption>Usage `sign`.</caption>
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
  const hash = await sha256(data);
  /**
   * Deterministically generate `k` via the [IETF-rfc6979](https://tools.ietf.org/html/rfc6979#section-3.2)
   * @param {Uint8Array} hash
   * @param {Uint8Array} private_key
   * @param {Number} nonce
   * @returns {Promise<Signature>}
   */
  const deterministically_generate_k = async (hash, private_key, nonce = 0) => {
    let msg_digest = nonce
      ? await sha256(Uint8Array.from([...hash, ...new Uint8Array(nonce)]))
      : hash;

    const v = new Uint8Array(32).fill(1);
    const k = new Uint8Array(32).fill(0);

    let buff_D = await hmac_sha256(
      Uint8Array.from([...v, 0, ...private_key, ...msg_digest]),
      k
    );
    let buf_E = await hmac_sha256(v, buff_D);
    const buf_F = await hmac_sha256(
      Uint8Array.from([...buf_E, 1, ...private_key, ...msg_digest]),
      buff_D
    );
    let buf_G = await hmac_sha256(buf_E, buf_F);
    let buf_h2b = await hmac_sha256(buf_G, buf_F);

    let T = array_to_number(buf_h2b);
    let e = array_to_number(hash);
    let d = array_to_number(private_key);

    const { r, s, racid } = await get_signature(T, e, d, { buf_h2b, buf_F });

    if (r[0] >= 0x80n || s[0] >= 0x80n)
      return deterministically_generate_k(hash, private_key, ++nonce);
    else return { r, s, v: Number(racid) };
  };

  return deterministically_generate_k(hash, private_key);
}

export default sign;
