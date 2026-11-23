import { build } from "esbuild";

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
