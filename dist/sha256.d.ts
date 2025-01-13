/**
 * Universal SHA-256 message digest helper function.
 *
 * @param {Uint8Array} data - Binary data to hash.
 * @returns {Promise<Uint8Array>} - The SHA-256 message digest.
 *
 * @example
 * ```ts
 * const array = Uint8Array.from(
 *   Buffer.from('The quick brown fox jumped over the lazy dog')
 * );
 *
 * sha256(array).then(console.log);
 * ```
 * > The logged output will be a Uint8Array like [215, …, 146].
 */
export default function sha256(data: Uint8Array): Promise<Uint8Array>;
