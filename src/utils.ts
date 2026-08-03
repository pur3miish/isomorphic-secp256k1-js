export const PRIVATE_KEY_LENGTH = 32;
export const HASH_LENGTH = 32;
export const SIGNATURE_COMPONENT_LENGTH = 32;
export const COMPACT_SIGNATURE_LENGTH = 64;
export const RECOVERED_SIGNATURE_LENGTH = 65;

export const secp256k1 = Object.freeze({
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
  mod: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  a: 0n,
  b: 7n,
  h: 1n,
});

export interface Point {
  x: bigint;
  y: bigint;
}

/** `null` represents the point at infinity. */
export type CurvePoint = Point | null;

export interface CompactSignature {
  r: Uint8Array;
  s: Uint8Array;
}

export interface Signature extends CompactSignature {
  v: number;
}

export function assert_uint8_array(
  value: unknown,
  expected_length: number | undefined,
  name: string,
): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array.`);
  }
  if (expected_length !== undefined && value.length !== expected_length) {
    throw new RangeError(`${name} must be exactly ${expected_length} bytes.`);
  }
}

export function array_to_number(array: Uint8Array): bigint {
  assert_uint8_array(array, undefined, "array");
  if (array.length === 0 || array.length > SIGNATURE_COMPONENT_LENGTH) {
    throw new RangeError("array must contain between 1 and 32 bytes.");
  }
  let result = 0n;
  for (const byte of array) result = (result << 8n) | BigInt(byte);
  return result;
}

export function number_to_array(
  number: bigint | number,
  length = SIGNATURE_COMPONENT_LENGTH,
): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 1 || length > 32) {
    throw new RangeError("length must be an integer between 1 and 32.");
  }
  if (typeof number === "number" && !Number.isSafeInteger(number)) {
    throw new RangeError(
      "number inputs must be safe integers; use bigint otherwise.",
    );
  }
  const value = typeof number === "bigint" ? number : BigInt(number);
  if (value < 0n || value >= 1n << BigInt(length * 8)) {
    throw new RangeError(`number does not fit in ${length} bytes.`);
  }

  const output = new Uint8Array(length);
  let remaining = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

export function concat_bytes(...arrays: Uint8Array[]): Uint8Array {
  const length = arrays.reduce((total, array) => total + array.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const array of arrays) {
    output.set(array, offset);
    offset += array.length;
  }
  return output;
}

export function get_mod(value: bigint, modulus: bigint): bigint {
  if (modulus <= 0n) throw new RangeError("modulus must be positive.");
  return ((value % modulus) + modulus) % modulus;
}

export function powmod(
  number: bigint,
  exponent: bigint,
  modulus: bigint,
): bigint {
  if (exponent < 0n) throw new RangeError("exponent must not be negative.");
  if (modulus <= 0n) throw new RangeError("modulus must be positive.");
  let result = 1n % modulus;
  let base = get_mod(number, modulus);
  let remaining = exponent;
  while (remaining > 0n) {
    if (remaining & 1n) result = (result * base) % modulus;
    remaining >>= 1n;
    base = (base * base) % modulus;
  }
  return result;
}

export function mul_inverse(value: bigint, modulus: bigint): bigint {
  if (modulus <= 1n) throw new RangeError("modulus must be greater than one.");
  let old_remainder = get_mod(value, modulus);
  if (old_remainder === 0n)
    throw new RangeError("zero has no modular inverse.");
  let remainder = modulus;
  let old_coefficient = 1n;
  let coefficient = 0n;

  while (remainder !== 0n) {
    const quotient = old_remainder / remainder;
    [old_remainder, remainder] = [
      remainder,
      old_remainder - quotient * remainder,
    ];
    [old_coefficient, coefficient] = [
      coefficient,
      old_coefficient - quotient * coefficient,
    ];
  }
  if (old_remainder !== 1n) {
    throw new RangeError("value is not invertible for this modulus.");
  }
  return get_mod(old_coefficient, modulus);
}

export function is_on_curve(point: CurvePoint): boolean {
  if (point === null) return true;
  const { mod, a, b } = secp256k1;
  if (point.x < 0n || point.x >= mod || point.y < 0n || point.y >= mod) {
    return false;
  }
  return (
    get_mod(point.y * point.y, mod) ===
    get_mod(point.x * point.x * point.x + a * point.x + b, mod)
  );
}

export function calc_new_point(
  first: Point,
  second: Point,
  slope: bigint,
  modulus = secp256k1.mod,
): Point {
  const x = get_mod(slope * slope - first.x - second.x, modulus);
  const y = get_mod(slope * (first.x - x) - first.y, modulus);
  return { x, y };
}

export function dbl(point: CurvePoint, modulus = secp256k1.mod): CurvePoint {
  if (point === null || get_mod(point.y, modulus) === 0n) return null;
  const numerator = get_mod(3n * point.x * point.x + secp256k1.a, modulus);
  const denominator = mul_inverse(2n * point.y, modulus);
  return calc_new_point(
    point,
    point,
    get_mod(numerator * denominator, modulus),
    modulus,
  );
}

export function add(
  first: CurvePoint,
  second: CurvePoint,
  modulus = secp256k1.mod,
): CurvePoint {
  if (first === null) return second;
  if (second === null) return first;
  if (first.x === second.x) {
    if (get_mod(first.y + second.y, modulus) === 0n) return null;
    return dbl(first, modulus);
  }
  const slope = get_mod(
    (second.y - first.y) * mul_inverse(second.x - first.x, modulus),
    modulus,
  );
  return calc_new_point(first, second, slope, modulus);
}

export function negate(point: CurvePoint): CurvePoint {
  if (point === null) return null;
  return { x: point.x, y: get_mod(-point.y, secp256k1.mod) };
}

/**
 * Fixed-operation-count Montgomery ladder. JavaScript BigInt and branches are
 * still not guaranteed constant-time; secret operations additionally use
 * scalar blinding through `blinded_multiply`.
 */
export function scalar_multiply(
  point: CurvePoint,
  scalar: bigint,
  bits = 256,
  modulus = secp256k1.mod,
): CurvePoint {
  if (!Number.isSafeInteger(bits) || bits < 1 || bits > 512) {
    throw new RangeError("bits must be an integer between 1 and 512.");
  }
  if (scalar < 0n || scalar >= 1n << BigInt(bits)) {
    throw new RangeError(`scalar must fit in ${bits} bits.`);
  }
  if (point === null || scalar === 0n) return null;
  if (modulus === secp256k1.mod && !is_on_curve(point)) {
    throw new RangeError("point is not on secp256k1.");
  }

  let lower: CurvePoint = null;
  let upper: CurvePoint = point;
  for (let index = bits - 1; index >= 0; index -= 1) {
    if ((scalar >> BigInt(index)) & 1n) {
      lower = add(lower, upper, modulus);
      upper = dbl(upper, modulus);
    } else {
      upper = add(lower, upper, modulus);
      lower = dbl(lower, modulus);
    }
  }
  return lower;
}

export function double_and_add(
  point: CurvePoint,
  scalar: bigint,
  modulus = secp256k1.mod,
  order = secp256k1.n,
): CurvePoint {
  const reduced = get_mod(scalar, order);
  return scalar_multiply(point, reduced, 256, modulus);
}

export function blinded_multiply(point: Point, scalar: bigint): Point {
  if (scalar < 1n || scalar >= secp256k1.n) {
    throw new RangeError(
      "secret scalar must satisfy 1 <= scalar < secp256k1.n.",
    );
  }
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("Web Crypto API is required for scalar blinding.");
  }
  const random = globalThis.crypto.getRandomValues(new Uint8Array(16));
  let blind = array_to_number(random);
  if (blind === 0n) blind = 1n;
  const blinded = scalar + blind * secp256k1.n;
  const result = scalar_multiply(point, blinded, 384);
  if (result === null) throw new Error("Unexpected point at infinity.");
  return result;
}

export function point_from_x(odd: bigint | number, x: bigint): Point {
  const parity = typeof odd === "bigint" ? odd : BigInt(odd);
  if (parity !== 0n && parity !== 1n) {
    throw new RangeError("point parity must be zero or one.");
  }
  const { mod, a, b } = secp256k1;
  if (x < 0n || x >= mod)
    throw new RangeError("point x-coordinate is invalid.");
  const alpha = get_mod(x * x * x + a * x + b, mod);
  let y = powmod(alpha, (mod + 1n) / 4n, mod);
  if (get_mod(y * y, mod) !== alpha) {
    throw new RangeError("x-coordinate does not map to a secp256k1 point.");
  }
  if ((y & 1n) !== parity) y = mod - y;
  const point = { x, y };
  if (!is_on_curve(point)) throw new RangeError("Recovered point is invalid.");
  return point;
}

export function encode_public_key(
  point: CurvePoint,
  compressed = true,
): Uint8Array {
  if (point === null || !is_on_curve(point)) {
    throw new RangeError(
      "Cannot encode an invalid point or point at infinity.",
    );
  }
  const x = number_to_array(point.x);
  if (compressed)
    return concat_bytes(Uint8Array.of(Number(2n | (point.y & 1n))), x);
  return concat_bytes(Uint8Array.of(4), x, number_to_array(point.y));
}

export function decode_public_key(public_key: Uint8Array): Point {
  assert_uint8_array(public_key, undefined, "public_key");
  let point: Point;
  if (
    public_key.length === 33 &&
    (public_key[0] === 2 || public_key[0] === 3)
  ) {
    point = point_from_x(
      BigInt(public_key[0] & 1),
      array_to_number(public_key.subarray(1)),
    );
  } else if (public_key.length === 65 && public_key[0] === 4) {
    point = {
      x: array_to_number(public_key.subarray(1, 33)),
      y: array_to_number(public_key.subarray(33, 65)),
    };
  } else {
    throw new RangeError(
      "public_key must be a 33-byte compressed or 65-byte uncompressed SEC 1 key.",
    );
  }
  if (!is_on_curve(point))
    throw new RangeError("public_key is not on secp256k1.");
  return point;
}

export function validate_hash(hash: Uint8Array): void {
  assert_uint8_array(hash, HASH_LENGTH, "hash");
}

export function hash_to_scalar(hash: Uint8Array): bigint {
  validate_hash(hash);
  return get_mod(array_to_number(hash), secp256k1.n);
}

export function validate_private_key(private_key: Uint8Array): void {
  assert_uint8_array(private_key, PRIVATE_KEY_LENGTH, "private_key");
  const scalar = array_to_number(private_key);
  if (scalar < 1n || scalar >= secp256k1.n) {
    throw new RangeError("private_key must satisfy 1 <= key < secp256k1.n.");
  }
}

export function validate_public_key(public_key: Uint8Array): void {
  decode_public_key(public_key);
}

export function validate_signature(
  signature: CompactSignature,
  { low_s = true, require_recovery = false } = {},
): void {
  if (typeof signature !== "object" || signature === null) {
    throw new TypeError("signature must be an object.");
  }
  assert_uint8_array(signature.r, SIGNATURE_COMPONENT_LENGTH, "signature.r");
  assert_uint8_array(signature.s, SIGNATURE_COMPONENT_LENGTH, "signature.s");
  const r = array_to_number(signature.r);
  const s = array_to_number(signature.s);
  if (r < 1n || r >= secp256k1.n) {
    throw new RangeError("signature.r must satisfy 1 <= r < secp256k1.n.");
  }
  if (s < 1n || s >= secp256k1.n) {
    throw new RangeError("signature.s must satisfy 1 <= s < secp256k1.n.");
  }
  if (low_s && s > secp256k1.n / 2n) {
    throw new RangeError("signature.s must use canonical low-S form.");
  }
  if (require_recovery) {
    const recovery = (signature as Signature).v;
    if (!Number.isInteger(recovery) || recovery < 0 || recovery > 3) {
      throw new RangeError("signature.v must be an integer from 0 through 3.");
    }
  }
}

export function signature_to_compact(
  signature: CompactSignature,
  low_s = true,
): Uint8Array {
  validate_signature(signature, { low_s });
  return concat_bytes(signature.r, signature.s);
}

export function signature_to_recovered(
  signature: Signature,
  low_s = true,
): Uint8Array {
  validate_signature(signature, { low_s, require_recovery: true });
  return concat_bytes(Uint8Array.of(signature.v), signature.r, signature.s);
}

export function recovered_to_signature(recovered: Uint8Array): Signature {
  assert_uint8_array(
    recovered,
    RECOVERED_SIGNATURE_LENGTH,
    "recovered signature",
  );
  const signature = {
    v: recovered[0],
    r: recovered.slice(1, 33),
    s: recovered.slice(33, 65),
  };
  validate_signature(signature, { low_s: false, require_recovery: true });
  return signature;
}

export function verify_signature_point(
  hash: Uint8Array,
  signature: CompactSignature,
  public_point: Point,
  low_s = true,
): boolean {
  validate_hash(hash);
  validate_signature(signature, { low_s });
  if (!is_on_curve(public_point)) return false;
  const r = array_to_number(signature.r);
  const s = array_to_number(signature.s);
  const inverse = mul_inverse(s, secp256k1.n);
  const first = scalar_multiply(
    { x: secp256k1.x, y: secp256k1.y },
    get_mod(hash_to_scalar(hash) * inverse, secp256k1.n),
  );
  const second = scalar_multiply(
    public_point,
    get_mod(r * inverse, secp256k1.n),
  );
  const result = add(first, second);
  return result !== null && get_mod(result.x, secp256k1.n) === r;
}
