# Isomorphic-secp256k1-js

## 4.0.5

### Patch

- Typeo fixes
- Removal of createRequire as it was causing pkg compilation errors.

```js
const require = createRequire(import.meta.url);
```

## 4.0.4

### Patch

- Bug fixes for import/require [hmac_sha256](hmac_sha256.js) and [sha256](sha256.js)

# 4.0.0

### Main

- Changes to exports.

### Major

- TS functions added for better support.
- Now a zero dependency package.
- Now exporting a variety of utility functions.

### Patch

- Changes to read me

# 3.0.0

### Main

- Argument on `sign` and `recover_public_key` is now a hash insterad of data, the digital signature previosuly hashed the data transaction, now it takes the hash as an argument to digest.

## 2.0.4

### Patch

- dependency updates

## 2.0.3

- Added deno imports to [readme](readme.md)

## 2.0.2

- deno imports fixed

## 2.0.1

## Patch

- Dependency updates

## 2.0.0

### Major

- Changed to ESM from CJS.
- Added support for Deno.

## 1.0.2

## Patch

- readme typeo fixes

## 1.0.1

### Patch

- recovery public key bug fixes.

## 1.0.0

- Initial release
