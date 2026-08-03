import hmac_sha256 from "./hmac_sha256.js";
import type { Signature } from "./utils.js";
import {
  array_to_number,
  blinded_multiply,
  concat_bytes,
  get_mod,
  hash_to_scalar,
  mul_inverse,
  number_to_array,
  secp256k1,
  validate_hash,
  validate_private_key,
  verify_signature_point,
} from "./utils.js";

export interface SignArgs {
  private_key: Uint8Array;
  /** A 32-byte message digest. The function does not hash this value again. */
  hash: Uint8Array;
  /** Normalize S into the lower half of the curve order. Defaults to true. */
  canonical?: boolean;
  /** Optional entropy mixed into RFC 6979 to harden against fault attacks. */
  extra_entropy?: boolean | Uint8Array;
}

function get_extra_entropy(value: boolean | Uint8Array): Uint8Array {
  if (value === false) return new Uint8Array(0);
  if (value === true) {
    if (!globalThis.crypto?.getRandomValues) {
      throw new Error("Web Crypto API is required for hedged signing.");
    }
    return globalThis.crypto.getRandomValues(new Uint8Array(32));
  }
  if (!(value instanceof Uint8Array)) {
    throw new TypeError("extra_entropy must be a boolean or Uint8Array.");
  }
  if (value.length > 1024) {
    throw new RangeError("extra_entropy must not exceed 1024 bytes.");
  }
  return Uint8Array.from(value);
}

async function hmac_and_erase_data(
  data: Uint8Array,
  key: Uint8Array,
): Promise<Uint8Array> {
  try {
    return await hmac_sha256(data, key);
  } finally {
    data.fill(0);
  }
}

/** Signs a 32-byte digest using RFC 6979 and fixed-width compact components. */
async function sign({
  private_key,
  hash,
  canonical = true,
  extra_entropy = false,
}: SignArgs): Promise<Signature> {
  if (!(private_key instanceof Uint8Array)) {
    throw new TypeError("private_key must be a Uint8Array.");
  }
  if (!(hash instanceof Uint8Array)) {
    throw new TypeError("hash must be a Uint8Array.");
  }
  if (typeof canonical !== "boolean") {
    throw new TypeError("canonical must be a boolean.");
  }

  // Caller-owned arrays can be mutated while Web Crypto operations are
  // pending. Snapshot them before the first await so RFC 6979 nonce derivation
  // and the ECDSA equation always use the same key and digest.
  const private_key_bytes = Uint8Array.from(private_key);
  const hash_bytes = Uint8Array.from(hash);
  let additional_data: Uint8Array = new Uint8Array(0);
  let digest_octets: Uint8Array = new Uint8Array(0);
  let seed: Uint8Array = new Uint8Array(0);
  let key: Uint8Array = new Uint8Array(32);
  let value: Uint8Array = new Uint8Array(32).fill(1);

  try {
    validate_private_key(private_key_bytes);
    validate_hash(hash_bytes);
    additional_data = get_extra_entropy(extra_entropy);
    digest_octets = number_to_array(hash_to_scalar(hash_bytes));
    seed = concat_bytes(private_key_bytes, digest_octets, additional_data);

    let next_key = await hmac_and_erase_data(
      concat_bytes(value, Uint8Array.of(0), seed),
      key,
    );
    key.fill(0);
    key = next_key;
    value = await hmac_and_erase_data(value, key);
    next_key = await hmac_and_erase_data(
      concat_bytes(value, Uint8Array.of(1), seed),
      key,
    );
    key.fill(0);
    key = next_key;
    value = await hmac_and_erase_data(value, key);

    const private_scalar = array_to_number(private_key_bytes);
    const message_scalar = hash_to_scalar(hash_bytes);
    const generator = { x: secp256k1.x, y: secp256k1.y };
    const public_point = blinded_multiply(generator, private_scalar);
    for (;;) {
      value = await hmac_and_erase_data(value, key);
      const nonce = array_to_number(value);
      if (nonce > 0n && nonce < secp256k1.n) {
        const nonce_point = blinded_multiply(generator, nonce);
        const r = get_mod(nonce_point.x, secp256k1.n);
        if (r !== 0n) {
          let s = get_mod(
            mul_inverse(nonce, secp256k1.n) *
              (message_scalar + r * private_scalar),
            secp256k1.n,
          );
          if (s !== 0n) {
            let recovery =
              (nonce_point.x === r ? 0 : 2) | Number(nonce_point.y & 1n);
            if (canonical && s > secp256k1.n / 2n) {
              s = secp256k1.n - s;
              recovery ^= 1;
            }
            const signature = {
              r: number_to_array(r),
              s: number_to_array(s),
              v: recovery,
            };
            if (
              !verify_signature_point(
                hash_bytes,
                signature,
                public_point,
                canonical,
              )
            ) {
              throw new Error("Generated signature failed self-verification.");
            }
            return signature;
          }
        }
      }

      next_key = await hmac_and_erase_data(
        concat_bytes(value, Uint8Array.of(0)),
        key,
      );
      key.fill(0);
      key = next_key;
      value = await hmac_and_erase_data(value, key);
    }
  } finally {
    private_key_bytes.fill(0);
    hash_bytes.fill(0);
    additional_data.fill(0);
    digest_octets.fill(0);
    seed.fill(0);
    key.fill(0);
    value.fill(0);
  }
}

export default sign;
