![secp256k1 logo](https://raw.githubusercontent.com/pur3miish/universal-ecdsa/master/static/secp256k1.svg)

# Universal SEPC256K1 JS

[![NPM Package](https://img.shields.io/npm/v/universal-secp256k1-js.svg)](https://www.npmjs.org/package/universal-secp256k1-js) [![CI status](https://github.com/pur3miish/universal-secp256k1-js/workflows/CI/badge.svg)](https://github.com/pur3miish/universal-secp256k1-js/actions) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/pur3miish/eos-ecc/blob/main/LICENSE)

A ultra optimised [Universal](https://en.wikipedia.org/wiki/Isomorphic_JavaScript) JavaScript [Elliptic Curve Digital Signature Algorithm](https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm) (ECDSA) for the Koblitz secp256k1 curve.

### Features



# Setup

```shell
npm i universal-secp256k1-js
```

# Suport

- Node.js `>=15`
- Browser `defaults, no IE 11`

# API

- [function get_public_key](#function-get_public_key)
- [function recover_public_key](#function-recover_public_key)
- [function sign](#function-sign)

## function get_public_key

Generates a compressed public key for the `secp256k1` curve.

| Parameter     | Type       | Description                  |
| :------------ | :--------- | :--------------------------- |
| `private_key` | Uint8Array | secp256k1 valid private key. |

**Returns:** Uint8Array — Public key.

### Examples

_Ways to `import`._

> ```js
> import { get_public_key } from 'universal-ecdsa'
> ```

_Ways to `require`._

> ```js
> const { get_public_key } = require('universal-ecdsa')
> ```

_Usage `get_public_key`._

> ```js
> const private_key = new Uint8Array([
>   210, 101, 63, 247, 203, 178, 216, 255, 18, 154, 194, 126, 245, 120, 28, 230,
>   139, 37, 88, 196, 26, 116, 175, 31, 45, 220, 166, 53, 203, 238, 240, 125
> ])
>
> get_public_key(private_key).then(console.log) // compressed public key.
> ```
>
> > The logged output was \[2, …, 207].

---

## function recover_public_key

Recovers a public key from a digital signature on the secp256k1 Koblitz curve.

| Parameter       | Type      | Description                                    |
| :-------------- | :-------- | :--------------------------------------------- |
| `Arg`           | object    | Argument.                                      |
| `Arg.signature` | Uin8Array | secp256k1 signature.                           |
| `Arg.data`      | Uin8Array | Data that was signed to produce the signature. |

**Returns:** Uint8Array — recovered Public key.

### Examples

_Ways to `import`._

> ```js
> import { recover_public_key } from 'universal-secp256k1-js'
> ```

_Ways to `require`._

> ```js
> const { recover_public_key } = require('universal-secp256k1-js')
> ```

_Usage `sign`._

> ```js
> const data = Uint8Array.from([
>   2, 33, 65, 233, 23, 23, 123, 244, 23, 23, 123, 244
> ])
>
> const signature = {
>   r: number_to_array(
>     50172533143525448505731076092836454339589141171079665638497512992118311974590n
>   ),
>   s: number_to_array(
>     3372897403575535231543296615264124933490702058654620386530787287980439847001n
>   ),
>   v: 0
> }
>
> const private_key = new Uint8Array([
>   210, 101, 63, 247, 203, 178, 216, 255, 18, 154, 194, 126, 245, 120, 28, 230,
>   139, 37, 88, 196, 26, 116, 175, 31, 45, 220, 166, 53, 203, 238, 240, 125
> ])
>
> const data = Uint8Array.from([104, 101, 108, 108, 111])
> sign({ data, private_key }).then(console.log)
> ```
>
> > The logged output is \[2, 192, 222, 210, …]

---

## function sign

Generates a digital signature on the secp256k1 Koblitz curve.

| Parameter         | Type      | Description            |
| :---------------- | :-------- | :--------------------- |
| `Arg`             | object    | Argument.              |
| `Arg.private_key` | Uin8Array | secp256k1 private key. |
| `Arg.data`        | Uin8Array | Data to sign.          |

**Returns:** Signature — Digital signature object containing `r` and `s` and `v` values.

### Examples

_Ways to `import`._

> ```js
> import { sign } from 'universal-secp256k1-js'
> ```

_Ways to `require`._

> ```js
> const { sign } = require('universal-secp256k1-js')
> ```

_Usage `sign`._

> ```js
> const private_key = new Uint8Array([
>   210, 101, 63, 247, 203, 178, 216, 255, 18, 154, 194, 126, 245, 120, 28, 230,
>   139, 37, 88, 196, 26, 116, 175, 31, 45, 220, 166, 53, 203, 238, 240, 125
> ])
>
> const data = Uint8Array.from([104, 101, 108, 108, 111])
> sign({ data, private_key }).then(console.log)
> ```
>
> > The logged output is { r: \[23, …, 89], s: \[111, …, 142], v: 1 }
