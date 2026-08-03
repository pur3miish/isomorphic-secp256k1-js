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
  key: Uint8Array,
): Promise<Uint8Array> {
  // Ensure both 'data' and 'key' are Uint8Array instances
  if (!(data instanceof Uint8Array) || !(key instanceof Uint8Array)) {
    throw new TypeError("Expected Uint8Array input data.");
  }

  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API is required for HMAC-SHA256.");
  }

  const key_bytes = Uint8Array.from(key);
  const data_bytes = Uint8Array.from(data);
  try {
    const importedKey = await globalThis.crypto.subtle.importKey(
      "raw",
      key_bytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const signature = await globalThis.crypto.subtle.sign(
      "HMAC",
      importedKey,
      data_bytes,
    );
    return new Uint8Array(signature);
  } finally {
    key_bytes.fill(0);
    data_bytes.fill(0);
  }
}

export default hmac_sha256;
