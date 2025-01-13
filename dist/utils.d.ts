/**
 * Converts a byte array to a BigInt number.
 *
 * @param {Uint8Array} array - The byte array to convert.
 * @returns {bigint} The corresponding BigInt number.
 *
 * @example
 * const byteArray = new Uint8Array([ 7, 91, 205, 21, 48, 57 ]);
 * const number = arrayToNumber(byteArray);
 * console.log(number); // 123456789n
 */
export declare function number_to_array(number: bigint | number): Uint8Array;
/**
 * Converts a byte array to a BigInt number.
 *
 * @param {Uint8Array} array - The byte array to convert.
 * @returns {bigint} The corresponding BigInt number.
 *
 * @example
 * const byteArray = new Uint8Array([ 7, 91, 205, 21, 48, 57 ]);
 * const number = arrayToNumber(byteArray);
 * console.log(number); // 123456789n
 */
export declare function array_to_number(array: Uint8Array): bigint;
/**
 * Signature interface for secp256k1.
 */
export interface Signature {
    r: Uint8Array;
    s: Uint8Array;
    v: number;
}
export declare const secp256k1: Readonly<{
    x: 55066263022277343669578718895168534326250603453777594175500187360389116729240n;
    y: 32670510020758816978083085130507043184471273380659243275938904335757337482424n;
    mod: 115792089237316195423570985008687907853269984665640564039457584007908834671663n;
    n: 115792089237316195423570985008687907852837564279074904382605163141518161494337n;
    a: 0n;
    b: 7n;
    h: 1n;
}>;
export declare const powmod: (number: bigint, exponent: bigint, m: bigint) => bigint;
export declare function get_mod(val: bigint, mod: bigint): bigint;
/**
 * Calculate the Modular Multiplicative Inverse
 * @kind function
 * @name mul_inverse
 * @param {bigint} val Value to perform modular multiplicitve inverse on.
 * @param {bigint} mod Modulo
 * @returns {bigint} the modular multiplicitve inverse of a `val`.
 */
export declare function mul_inverse(val: bigint, mod: bigint): bigint;
/**
 * ECC point on the secp256k1 curve.
 * Represents the x and y coordinates of the point.
 */
export interface Point {
    x: bigint;
    y: bigint;
}
export declare function calc_new_point(Q: Point, P: Point, λ: bigint, mod: bigint): Point;
export declare function add(Q: Point, P: Point, mod: bigint): Point;
export declare function dbl(G: Point, mod: bigint): Point;
export declare function double_and_add(G: Point, k: bigint, mod: bigint, n: bigint): Point;
export declare function point_from_x(odd: bigint, x: bigint): Point;
interface SignBuffers {
    buf_h2b: Uint8Array;
    buf_F: Uint8Array;
    canonical?: boolean;
}
export declare function get_signature(T: bigint, e: bigint, d: bigint, buffers: SignBuffers, racid?: number): Promise<{
    r: Uint8Array<ArrayBufferLike>;
    s: Uint8Array<ArrayBufferLike>;
    racid: number;
}>;
export {};
