// Test-only preload (`node --require sea-preload.cjs <bundle>/bin/aidr ...`):
// makes a plain Node process look like the multi-call SEA binary, so the real
// dispatcher and the real hook bundles run unchanged from a staged bundle.
//
//   - process.execPath becomes <bundle>/bin/aidr (the script node runs), which
//     is what a SEA reports and what every bundle derives its root from;
//   - node:sea reports isSea() and serves getAsset(key) from
//     <bundle>/test-assets/<key with "/" -> "-">.cjs (build-sea.mjs stageAssets).
//
// Production binaries never load this file: it lives under __tests__ only.
const { readFileSync } = require("node:fs");
const { dirname, join, resolve } = require("node:path");

const script = resolve(process.argv[1]);
process.execPath = script;
const sea = require("node:sea");
const assets = join(dirname(dirname(script)), "test-assets");
sea.isSea = () => true;
sea.getAsset = (key, encoding) => {
	const bytes = readFileSync(join(assets, `${key.replaceAll("/", "-")}.cjs`));
	return encoding ? bytes.toString(encoding) : bytes.buffer;
};
