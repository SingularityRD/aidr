import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const MARKER = "__AIDR_EMBEDDED_BUILD_FLAVOR__";
const OUTPUT = resolve("dist/build-flavor.js");

export function embedBuildFlavor(source, flavor) {
	if (flavor !== "development" && flavor !== "commercial") {
		throw new Error(`Unsupported build flavor: ${flavor}`);
	}
	const quotedMarker = JSON.stringify(MARKER);
	const occurrences = source.split(quotedMarker).length - 1;
	if (occurrences !== 1) {
		throw new Error(`Expected one build flavor marker, found ${occurrences}`);
	}
	return source.replace(quotedMarker, JSON.stringify(flavor));
}

async function main() {
	const flavor = process.argv[2];
	const requested = process.env.AIDR_BUILD_FLAVOR?.trim().toLowerCase();
	if (requested && requested !== flavor) {
		throw new Error(`AIDR_BUILD_FLAVOR=${requested} conflicts with ${flavor} build`);
	}
	const source = await readFile(OUTPUT, "utf8");
	const embedded = embedBuildFlavor(source, flavor);
	await writeFile(OUTPUT, embedded, "utf8");
	if (!embedded.includes(`const EMBEDDED_BUILD_FLAVOR = ${JSON.stringify(flavor)}`)) {
		throw new Error(`Failed to embed ${flavor} build flavor`);
	}
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	await main();
}
