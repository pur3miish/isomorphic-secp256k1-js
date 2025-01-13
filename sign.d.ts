import type { Signature } from "./utils.js";
export interface signArgs {
  /**
   * secp256k1 private key 32 bytes.
   */
  private_key: Uint8Array;
  /**
   * Message digest hash 32 bytes
   */
  hash: Uint8Array;
  /**
   * Enforce low S values, see BIP62.
   * If `canonical` is true, ensures the signature's 's' value is in the canonical range (0 <= s <= n/2).
   */
  canonical?: boolean;
}
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
declare function sign({
  private_key,
  hash,
  canonical,
}: signArgs): Promise<Signature>;
export default sign;
