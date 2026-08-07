import type { CompactSignature } from "./utils.js";
import {
  decode_public_key,
  validate_hash,
  verify_signature_point,
} from "./utils.js";

export interface VerifyArgs {
  signature: CompactSignature;
  hash: Uint8Array;
  public_key: Uint8Array;
  /** Reject malleable high-S signatures. Defaults to true. */
  canonical?: boolean;
}

/** Invalid signatures and public keys return false; an invalid hash throws. */
function verify({
  signature,
  hash,
  public_key,
  canonical = true,
}: VerifyArgs): boolean {
  validate_hash(hash);
  try {
    return verify_signature_point(
      hash,
      signature,
      decode_public_key(public_key),
      canonical,
    );
  } catch {
    return false;
  }
}

export default verify;
