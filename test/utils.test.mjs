import { deepStrictEqual, rejects } from 'assert'
import { mul_inverse, powmod } from '../private/index.js'
import recover_public_key from '../public/recover_public_key.js'
import sign from '../public/sign.js'

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
