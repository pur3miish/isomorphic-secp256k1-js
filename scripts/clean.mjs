import { rm } from "node:fs/promises";

const generated_files = [
  "generate_private_key.d.ts",
  "generate_private_key.js",
  "get_public_key.d.ts",
  "get_public_key.js",
  "hmac_sha256.d.ts",
  "hmac_sha256.js",
  "index.d.ts",
  "index.js",
  "recover_public_key.d.ts",
  "recover_public_key.js",
  "sha256.d.ts",
  "sha256.js",
  "sign.d.ts",
  "sign.js",
  "utils.d.ts",
  "utils.js",
  "verify.d.ts",
  "verify.js",
];

await Promise.all([
  ...generated_files.map((file) =>
    rm(new URL(`../${file}`, import.meta.url), { force: true }),
  ),
  rm(new URL("../dist/", import.meta.url), { recursive: true, force: true }),
]);
