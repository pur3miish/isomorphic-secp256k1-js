import {
  array_to_number,
  blinded_multiply,
  encode_public_key,
  secp256k1,
  validate_private_key,
} from "./utils.js";

/** Derives a canonical 33-byte compressed public key from a private key. */
async function get_public_key(private_key: Uint8Array): Promise<Uint8Array> {
  validate_private_key(private_key);
  const point = blinded_multiply(
    { x: secp256k1.x, y: secp256k1.y },
    array_to_number(private_key),
  );
  return encode_public_key(point);
}

export default get_public_key;
