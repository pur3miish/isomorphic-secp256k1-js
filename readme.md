![secp256k1 logo](https://raw.githubusercontent.com/pur3miish/universal-ecdsa/master/static/secp256k1.svg)

# Isomorphic SEPC256K1 JS

[![NPM Package](https://img.shields.io/npm/v/isomorphic-secp256k1-js.svg)](https://www.npmjs.org/package/isomorphic-secp256k1-js) [![CI status](https://github.com/pur3miish/isomorphic-secp256k1-js/workflows/CI/badge.svg)](https://github.com/pur3miish/isomorphic-secp256k1-js/actions) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/pur3miish/isomorphic-secp256k1-js/blob/main/LICENSE)

A ultra lightweight (2 KB) [Universal](https://en.wikipedia.org/wiki/Isomorphic_JavaScript) JavaScript [Elliptic Curve Digital Signature Algorithm](https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm) (ECDSA) for the Koblitz secp256k1 curve.

Cross platform support for [Node.js](https://nodejs.org) and [Deno](https://deno.land).

## Installation

For [Node.js](https://nodejs.org), to install [`isomorphic-secp256k1-js`](https://npm.im/isomorphic-secp256k1-js) run:

```sh
npm i isomorphic-secp256k1-js
```

For [Deno.js](https://deno.land), at the root of your project add a `deno.json` file and include these import paths:

```json
{
  // This will import the correct dependencies.
  "imports": {
    "universal-sha256-js/": "https://deno.land/x/sha256js/",
    "universal-hmac-sha256-js/": "https://deno.land/x/hmacsha256@nodecrypto/"
  }
}
```

## Examples

Recover public key from private key.

```js
const private_key = new Uint8Array([
  210, 101, 63, 247, 203, 178, 216, 255, 18, 154, 194, 126, 245, 120, 28, 230,
  139, 37, 88, 196, 26, 116, 175, 31, 45, 220, 166, 53, 203, 238, 240, 125,
]);

// Compressed public key.
console.log(get_public_key(private_key));
```

Generate a secp25k1 digital siganture.

```js
const private_key = new Uint8Array([
  210, 101, 63, 247, 203, 178, 216, 255, 18, 154, 194, 126, 245, 120, 28, 230,
  139, 37, 88, 196, 26, 116, 175, 31, 45, 220, 166, 53, 203, 238, 240, 125,
]);

const data = Uint8Array.from([104, 101, 108, 108, 111]);
sign({ data, private_key }).then(console.log);
```

> The logged output is { r: [23, …, 89], s: [111, …, 142], v: 1 }

> **Note**
>
> As this package is [ESM](https://nodejs.org/docs/latest-v16.x/api/esm.html) if you need to require it in a [Common JS](https://nodejs.org/docs/latest-v16.x/api/modules.html) package, then you can require like this:

```js
(async function () {
  const { default: recover_public_key } = await import(
    "isomorphic-secp256k1-js/recover_public_key.mjs"
  );
  const { number_to_array } = await import("./private/utils.mjs");

  const key_pair = await recover_public_key({
    data: Uint8Array.from([2, 33, 65, 233, 23, 23, 123, 244, 23, 23, 123, 244]),
    signature: {
      r: number_to_array(
        50172533143525448505731076092836454339589141171079665638497512992118311974590n
      ),
      s: number_to_array(
        3372897403575535231543296615264124933490702058654620386530787287980439847001n
      ),
      v: 0,
    },
  });
  console.log(key_pair);
})();
```

> Logged output was Uint8Array(33) [2,192,222,210,188,31,19,5,…

## Requirements

Supported runtime environments:

- [Node.js](https://nodejs.org) versions `>=16.0.0`.
- Browsers matching the [Browserslist](https://browsersl.ist) query [`> 0.5%, not OperaMini all, not dead`](https://browsersl.ist/?q=%3E+0.5%25%2C+not+OperaMini+all%2C+not+dead).
- [Deno](https://deno.land) versions `^1.0.0`.

## Exports

The [npm](https://npmjs.com) package [`isomorphic-secp256k1-js`](https://npm.im/isomorphic-secp25k1-js) features [optimal JavaScript module design](https://jaydenseric.com/blog/optimal-javascript-module-design). It doesn’t have a main index module, so use deep imports from the ECMAScript modules that are exported via the [`package.json`](./package.json) field [`exports`](https://nodejs.org/api/packages.html#exports):

- [`recover_public_key.mjs`](./recover_public_key.mjs)
- [`sign.mjs`](./sign.mjs)
- [`get_public_key.mjs`](./sign.mjs)
