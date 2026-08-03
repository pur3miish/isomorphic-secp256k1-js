import assert from "node:assert/strict";
import test from "node:test";

import { build } from "esbuild";

test("tree shakes unused root exports from a browser bundle", async () => {
  const result = await build({
    absWorkingDir: process.cwd(),
    bundle: true,
    format: "esm",
    logLevel: "silent",
    minify: false,
    platform: "browser",
    stdin: {
      contents: `
        import { sha256 } from "isomorphic-secp256k1-js";
        globalThis.tree_shaking_example = sha256;
      `,
      loader: "js",
      resolveDir: process.cwd(),
      sourcefile: "tree-shaking-entry.js",
    },
    treeShaking: true,
    write: false,
  });

  const output = result.outputFiles[0]?.text;
  assert.ok(output);
  assert.match(output, /SHA-256/);
  assert.doesNotMatch(output, /HMAC-SHA256/);
  assert.doesNotMatch(output, /RFC 6979/);
  assert.doesNotMatch(output, /Recovered public key/);
  assert.doesNotMatch(output, /secret scalar/);
  assert.doesNotMatch(output, /random_source/);
});
