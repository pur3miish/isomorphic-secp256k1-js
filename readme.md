![secp256k1 logo](https://raw.githubusercontent.com/pur3miish/universal-ecdsa/master/static/secp256k1.svg)

# Isomorphic SEPC256K1 JS

[![NPM Package](https://img.shields.io/npm/v/isomorphic-secp256k1-js.svg)](https://www.npmjs.org/package/isomorphic-secp256k1-js) [![CI status](https://github.com/pur3miish/isomorphic-secp256k1-js/workflows/CI/badge.svg)](https://github.com/pur3miish/isomorphic-secp256k1-js/actions) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/pur3miish/isomorphic-secp256k1-js/blob/main/LICENSE)

A ultra lightweight (2 KB) [Universal](https://en.wikipedia.org/wiki/Isomorphic_JavaScript) JavaScript [Elliptic Curve Digital Signature Algorithm](https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm) (ECDSA) for the Koblitz secp256k1 curve.

## Installation

For [Node.js](https://nodejs.org), to install [`isomorphic-secp256k1-js`](https://npm.im/isomorphic-secp256k1-js) run:

```sh
npm i isomorphic-secp256k1-js
```

> **Note**
>
> As this package is [ESM](https://nodejs.org/docs/latest-v16.x/api/esm.html) if you need to require it in a [Common JS](https://nodejs.org/docs/latest-v16.x/api/modules.html) package, then you can require like this:

## Requirements

Supported runtime environments:

- [Node.js](https://nodejs.org) versions `>=16.0.0`.
- Browsers matching the [Browserslist](https://browsersl.ist) query [`> 0.5%, not OperaMini all, not dead`](https://browsersl.ist/?q=%3E+0.5%25%2C+not+OperaMini+all%2C+not+dead).

## Exports

The [npm](https://npmjs.com) package [`Isomorphic SEPC256K1 JS`](https://npm.im/isomorphic-secp25k1-js) features [optimal JavaScript module design](https://jaydenseric.com/blog/optimal-javascript-module-design). It doesn’t have a main index module, so use deep imports from the ECMAScript modules that are exported via the [`package.json`](./package.json) field [`exports`](https://nodejs.org/api/packages.html#exports):

- [`recover_public_key.mjs`](./recover_public_key.mjs)
- [`sign.mjs`](./sign.mjs)
- [`get_public_key.mjs`](./sign.mjs)
