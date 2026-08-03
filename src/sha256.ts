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
export default async function sha256(data: Uint8Array): Promise<Uint8Array> {
  // Check if the data is an instance of Uint8Array
  if (!(data instanceof Uint8Array)) {
    throw new TypeError("Expected Uint8Array input data.");
  }

  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API is required for SHA-256.");
  }

  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    Uint8Array.from(data),
  );
  return new Uint8Array(digest);
}
