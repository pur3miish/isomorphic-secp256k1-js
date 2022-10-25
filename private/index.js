'use strict'

const secp256k1 = Object.freeze({
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
  mod: 115792089237316195423570985008687907853269984665640564039457584007908834671663n,
  n: 115792089237316195423570985008687907852837564279074904382605163141518161494337n,
  a: 0x0000000000000000000000000000000000000000000000000000000000000000n,
  b: 0x0000000000000000000000000000000000000000000000000000000000000007n,
  h: 1n
})

const powmod = (number, exponent, m) => {
  let r = 1n
  let b = number % m
  let e = exponent

  if (b == 0n) return 0n
  while (e > 0n) {
    if (e % 2n) r = (r * b) % m
    e = e >> 1n
    b = b ** 2n % m
  }
  return r
}

const get_mod = (val, mod) => ((val % mod) + mod) % mod

/**
 * Calculate the Modular Multiplicative Inverse
 * @kind function
 * @name mul_inverse
 * @param {bigint} val Value to perform modular multiplicitve inverse on.
 * @param {bigint} mod Modulo
 * @returns {bigint} the modular multiplicitve inverse of a `val`.
 * @ignore
 */
function mul_inverse(val, mod) {
  let dst, t, q
  let b = mod
  let a = get_mod(val, mod)
  let b0 = mod
  let x0 = 0n
  let x1 = 1n

  if (mod == 1n) dst = 1n
  else
    while (a > 1n) {
      q = a / b
      t = b
      dst = a % b
      b = dst
      a = t
      t = x0
      q = x0 * q
      x0 = x1 - q
      x1 = t
    }

  if (x1 < 0n) x1 = x1 + b0
  dst = x1
  return dst
}

/* Calculates a new point on the ECC curve. */
const calc_new_point = (Q, P, λ, mod) => {
  const x = get_mod(get_mod(λ * λ, mod) - P.x - Q.x, mod)
  const y = get_mod(get_mod((P.x - x) * λ, mod) - P.y, mod)
  return { x, y }
}

/* Addition of two coordinates on an ECC curve. */
const add = (Q, P, mod) => {
  const x = mul_inverse(P.x - Q.x, mod)
  const y = get_mod(get_mod(P.y - Q.y, mod) * x, mod) // slope
  return calc_new_point(Q, P, y, mod)
}

/* Doubling of two coordinates on an ECC curve. */
const dbl = (G, mod) => {
  const numerator = get_mod(get_mod(G.x * G.x, mod) * 3n, mod)
  const denominator = get_mod(mul_inverse(2n * G.y, mod) * numerator, mod)
  return calc_new_point(G, G, denominator, mod)
}

const double_and_add = (G, k, mod, n) => {
  k = get_mod(k, n)
  if (k == 1n) return G
  else if (k % 2n) return add(double_and_add(G, k - 1n, mod, n), G, mod)
  else return double_and_add(dbl(G, mod), k / 2n, mod, n)
}

const point_from_x = (odd, x) => {
  const { mod, b } = secp256k1
  odd = BigInt(odd)
  const alpha = get_mod(BigInt(x) ** 3n + b, mod)

  let y = powmod(alpha, mod / 4n + 1n, mod)
  if (!(y % 2n) ^ !odd) y = mod - y

  return { x, y }
}

module.exports = {
  powmod,
  double_and_add,
  dbl,
  add,
  mul_inverse,
  get_mod,
  secp256k1,
  point_from_x
}
