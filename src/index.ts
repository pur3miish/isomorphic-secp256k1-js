/**
 * Side-effect-free root ESM entry point. Prefer named imports so production
 * bundlers can statically remove operations that an application does not use.
 */
export { default as get_public_key } from "./get_public_key.js";
export { default as generate_private_key } from "./generate_private_key.js";
export { default as hmac_sha256 } from "./hmac_sha256.js";
export { default as recover_public_key } from "./recover_public_key.js";
export { default as sha256 } from "./sha256.js";
export { default as sign } from "./sign.js";
export { default as verify } from "./verify.js";

export type { RecoverArg } from "./recover_public_key.js";
export type {
  GeneratePrivateKeyArgs,
  RandomSource,
} from "./generate_private_key.js";
export type { SignArgs } from "./sign.js";
export type { CompactSignature, Signature } from "./utils.js";
export type { VerifyArgs } from "./verify.js";
export { validate_private_key } from "./utils.js";
