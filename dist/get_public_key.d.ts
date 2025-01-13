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
declare function get_public_key(private_key: Uint8Array): Promise<Uint8Array>;
export default get_public_key;
