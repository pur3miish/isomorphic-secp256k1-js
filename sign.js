// @ts-check
import hmac_sha256 from "./hmac_sha256.js";
import sha256 from "./sha256.js";
import { get_signature } from "./utils.js";
import { array_to_number } from "./utils.js";
/**
 * Signs a message hash using the secp256k1 curve.
 * If `canonical` is true, ensures the signature's 's' value is in the canonical range (0 <= s <= n/2).
 *
 * @param {SignArgs} args - The sign function arguments containing the private key, message hash, and optional canonical flag.
 * @returns {Promise<Uint8Array>} The generated signature.
 *
 * @example
 * const private_key = new Uint8Array([210, 101, 63, 247, 203, 178, 216, 255]);
 * const hash = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
 *
 * sign({ private_key, hash, canonical: true }).then(console.log);
 */
async function sign({ private_key, hash, canonical = true }) {
  /**
   * Deterministically generate `k` via the [IETF-rfc6979](https://tools.ietf.org/html/rfc6979#section-3.2)
   */
  async function deterministically_generate_k(hash, private_key, nonce = 0) {
    const msg_digest = nonce
      ? await sha256(Uint8Array.from([...hash, ...new Uint8Array(nonce)]))
      : hash;
    const v = new Uint8Array(32).fill(1);
    const k = new Uint8Array(32).fill(0);
    const buff_D = await hmac_sha256(
      Uint8Array.from([...v, 0, ...private_key, ...msg_digest]),
      k
    );
    const buf_E = await hmac_sha256(v, buff_D);
    const buf_F = await hmac_sha256(
      Uint8Array.from([...buf_E, 1, ...private_key, ...msg_digest]),
      buff_D
    );
    const buf_G = await hmac_sha256(buf_E, buf_F);
    const buf_h2b = await hmac_sha256(buf_G, buf_F);
    const T = array_to_number(buf_h2b);
    const e = array_to_number(hash);
    const d = array_to_number(private_key);
    const { r, s, racid } = await get_signature(T, e, d, {
      buf_h2b,
      buf_F,
      canonical,
    });
    if (r[0] >= 0x80n || s[0] >= 0x80n)
      return deterministically_generate_k(hash, private_key, ++nonce);
    else return { r, s, v: Number(racid) };
  }
  return deterministically_generate_k(hash, private_key);
}
export default sign;
