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
async function hmac_sha256(
  data: Uint8Array,
  key: Uint8Array
): Promise<Uint8Array> {
  // Ensure both 'data' and 'key' are Uint8Array instances
  if (!(data instanceof Uint8Array) || !(key instanceof Uint8Array)) {
    throw new TypeError("Expected Uint8Array input data.");
  }

  if (typeof window === "undefined") {
    // For Node.js environment
    let crypto;
    try {
      // eslint-disable-next-line
      crypto = require("crypto"); // Works in `pkg`
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (_err) {
      crypto = await import("crypto"); // Works in ESM
    }

    return Uint8Array.from([
      ...crypto.createHmac("SHA256", key).update(data).digest(),
    ]);
  } else {
    // For browser environment
    const importedKey = await window.crypto.subtle.importKey(
      "raw",
      key,
      { name: "HMAC", hash: { name: "SHA-256" } },
      false,
      ["sign", "verify"]
    );

    const signature = await window.crypto.subtle.sign(
      "HMAC",
      importedKey,
      data
    );
    return new Uint8Array(signature);
  }
}

export default hmac_sha256;
