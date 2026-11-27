import { build } from "esbuild";
import { copyFile, mkdir, readdir } from "node:fs/promises";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const wasmFileName = "matrix_sdk_crypto_wasm_bg.wasm";
const entryPath = fileURLToPath(import.meta.resolve("@matrix-org/matrix-sdk-crypto-wasm"));

function findPackageRoot(filePath) {
  let current = dirname(filePath);
  while (current !== dirname(current)) {
    if (current.endsWith(sep + "matrix-sdk-crypto-wasm")) return current;
    current = dirname(current);
  }
  throw new Error("Unable to locate @matrix-org/matrix-sdk-crypto-wasm package root.");
}

async function findWasmFile(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isFile() && entry.name === wasmFileName) return path;
    if (entry.isDirectory()) {
      const nested = await findWasmFile(path);
      if (nested) return nested;
    }
  }
  return null;
}

const packageRoot = findPackageRoot(entryPath);
const wasmSource = await findWasmFile(packageRoot);
if (!wasmSource) {
  throw new Error(`Required Matrix Crypto WASM asset was not found in ${packageRoot}.`);
}

const wasmOutputDirectory = resolve("public/pkg");
await mkdir(wasmOutputDirectory, { recursive: true });
await copyFile(wasmSource, resolve(wasmOutputDirectory, wasmFileName));

await build({
  entryPoints: ["public/crypto-v2.js"],
  outfile: "public/crypto-v2.bundle.js",
  bundle: true,
  minify: true,
  sourcemap: false,
  platform: "browser",
  format: "esm",
  target: ["es2022"],
  conditions: ["browser"],
  loader: { ".wasm": "file" },
  assetNames: "crypto/[name]-[hash]",
  publicPath: "/",
  legalComments: "none",
  logLevel: "info"
});
