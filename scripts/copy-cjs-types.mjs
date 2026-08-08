/** Copy an ESM declaration file to the CommonJS declaration extension. */

import { copyFile } from "node:fs/promises";

const [source, destination] = process.argv.slice(2);
if (!source || !destination) {
	console.error("Usage: node scripts/copy-cjs-types.mjs <source.d.ts> <destination.d.cts>");
	process.exit(2);
}

try {
	await copyFile(source, destination);
	console.log(`Copied ${source} -> ${destination}`);
} catch (error) {
	console.error(`ERROR: cannot copy declaration file: ${error instanceof Error ? error.message : String(error)}`);
	process.exit(1);
}
