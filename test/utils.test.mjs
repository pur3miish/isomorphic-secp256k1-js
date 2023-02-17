import { deepStrictEqual, rejects } from 'assert'
import crypto from 'crypto'
import {
  get_signature,
  mul_inverse,
  powmod,
  secp256k1
} from '../private/index.mjs'
import recover_public_key from '../recover_public_key.mjs'
import sign from '../sign.mjs'

export default tests => {
  tests.add('Ultils tests.', async () => {
    powmod(2n, 2n, 2n)
    mul_inverse(2n, 1n)
    rejects(() =>
      recover_public_key({
        data: new Uint8Array(10),
        signature: {
          r: Uint8Array.from([1]),
          s: Uint8Array.from([1]),
          v: 10n
        }
      })
    )
    recover_public_key({
      data: new Uint8Array(10),
      signature: {
        r: Uint8Array.from([1]),
        s: Uint8Array.from([1]),
        v: -90n
      }
    })

    get_signature(secp256k1.n * 2n, 0n, 0n, {
      buf_h2b: Uint8Array.from(crypto.randomBytes(32)),
      buf_F: Uint8Array.from(crypto.randomBytes(32))
    })

    get_signature(
      secp256k1.n / 2n,
      0n,
      0n,
      {
        buf_h2b: Uint8Array.from(crypto.randomBytes(32)),
        buf_F: Uint8Array.from(crypto.randomBytes(32))
      },
      1,
      { ...secp256k1, x: 0n, y: 0n }
    )

    get_signature(
      secp256k1.n * 2n,
      secp256k1.n * 2n,
      secp256k1.n * 2n,
      {
        buf_h2b: Uint8Array.from(crypto.randomBytes(32)),
        buf_F: Uint8Array.from(crypto.randomBytes(32))
      },
      1
    )
  })

  tests.add('private_key_negative_y', async () => {
    const private_key_negative_y = new Uint8Array([
      253, 156, 168, 92, 14, 7, 242, 47, 88, 234, 12, 42, 46, 235, 100, 3, 182,
      58, 108, 250, 164, 92, 66, 252, 93, 171, 39, 59, 188, 182, 83, 97
    ])
    const public_key_negative_y = new Uint8Array([
      3, 168, 142, 49, 253, 219, 92, 148, 48, 96, 69, 112, 118, 158, 50, 60,
      229, 222, 18, 223, 1, 16, 96, 251, 225, 221, 1, 245, 224, 136, 33, 80, 200
    ])

    const data = Uint8Array.from([1, 2, 3])

    const signature = await sign({ private_key: private_key_negative_y, data })

    deepStrictEqual(
      public_key_negative_y,
      await recover_public_key({ data, signature })
    )
  })
}
