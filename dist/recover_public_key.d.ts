import type { Signature } from "./utils.js";
/**
 * Recovery argument interface that contains the signature and the data.
 */
export interface RecoverArg {
    signature: Signature;
    hash: Uint8Array;
}
/**
 * Recovers a public key from a digital signature on the secp256k1 Koblitz curve.
 *
 * @param {RecoverArg} arg - The argument object containing the signature and the hash.
 * @returns {Promise<Uint8Array>} - The recovered public key.
 *
 * @example
 * ```ts
 * const signature: Signature = {
 *   r: number_to_array(50172533143525448505731076092836454339589141171079665638497512992118311974590n),
 *   s: number_to_array(3372897403575535231543296615264124933490702058654620386530787287980439847001n),
 *   v: 0
 * };
 *
 * const hash: Uint8Array = new Uint8Array([104, 101, 108, 108, 111]);  // Some hash value
 *
 * recover_public_key({ hash, signature }).then(console.log);
 * ```
 */
declare function recover_public_key({ hash, signature, }: RecoverArg): Promise<Uint8Array>;
export default recover_public_key;
