'use strict'

const number_to_array = number => {
  let hn = number.toString(16)
  hn = hn.length % 2 ? hn.padStart(hn.length + 1, '0') : hn

  return Uint8Array.from(
    hn.match(/[a-f0-9A-F]{2}/gmu).map(i => Number(`0x${i}`))
  )
}

const array_to_number = array =>
  BigInt(
    `0x${array.reduce(
      (acc, i) => (acc += i.toString(16).padStart(2, '0')),
      ''
    )}`
  )

module.exports = {
  number_to_array,
  array_to_number
}
