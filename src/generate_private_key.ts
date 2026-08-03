import {
  array_to_number,
  assert_uint8_array,
  PRIVATE_KEY_LENGTH,
  secp256k1,
  validate_private_key,
} from "./utils.js";

/** Returns exactly `length` bytes from a caller-selected CSPRNG. */
export type RandomSource = (length: number) => Uint8Array | Promise<Uint8Array>;

export interface GeneratePrivateKeyArgs {
  /**
   * Optional caller-selected CSPRNG. It may be synchronous or asynchronous and
   * must return exactly the requested number of bytes. Native Web Crypto is
   * used when this option is omitted.
   */
  random_source?: RandomSource;
}

const MAX_GENERATION_ATTEMPTS = 1024;

function native_random_source(length: number): Uint8Array {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error(
      "Web Crypto API is required when random_source is not supplied.",
    );
  }
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Generates a uniformly distributed secp256k1 private scalar by rejection
 * sampling. The result is always a new 32-byte array satisfying `1 <= d < n`.
 */
async function generate_private_key({
  random_source = native_random_source,
}: GeneratePrivateKeyArgs = {}): Promise<Uint8Array> {
  if (typeof random_source !== "function") {
    throw new TypeError("random_source must be a function.");
  }

  for (let attempt = 0; attempt < MAX_GENERATION_ATTEMPTS; attempt += 1) {
    const random = await random_source(PRIVATE_KEY_LENGTH);
    assert_uint8_array(random, PRIVATE_KEY_LENGTH, "random_source result");
    const private_key = Uint8Array.from(random);
    const scalar = array_to_number(private_key);
    if (scalar >= 1n && scalar < secp256k1.n) {
      validate_private_key(private_key);
      return private_key;
    }
  }

  throw new Error(
    `random_source did not produce a valid secp256k1 private key after ${MAX_GENERATION_ATTEMPTS} attempts.`,
  );
}

export default generate_private_key;
