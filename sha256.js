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
export default async function sha256(data) {
  // Check if the data is an instance of Uint8Array
  if (!(data instanceof Uint8Array)) {
    throw new TypeError("Expected Uint8Array input data.");
  }
  if (typeof window === "undefined") {
    // Node.js environment
    const { createHash } = await import("crypto");
    return new Uint8Array(createHash("sha256").update(data).digest());
  } else {
    // Browser environment
    const digest = await crypto.subtle.digest("SHA-256", data);
    return new Uint8Array(digest);
  }
}
