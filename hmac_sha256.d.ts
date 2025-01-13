/**
 * Performs a HMAC SHA256 hash.
 *
 * @param {Uint8Array} data - Data to hash.
 * @param {Uint8Array} key - Secret key.
 * @returns {Promise<Uint8Array>} The HMAC-SHA256 data as a Uint8Array.
 *
 * @example
 * ```ts
 * const data = Uint8Array.from([104, 101, 108, 108, …]);
 * const key = Uint8Array.from([193, 208, 122, 108, …]);
 *
 * hmac_sha256(data, key).then(console.log);
 * ```
 * > The logged output is Uint8Array([43, …])
 */
declare function hmac_sha256(
  data: Uint8Array,
  key: Uint8Array
): Promise<Uint8Array>;
export default hmac_sha256;
