import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";

import { SOURCE_MAPPING_DIRECTIVE_RE, SOURCE_URL_DIRECTIVE_RE, hasForbiddenArchiveEntry } from "./package-artifact-rules.mjs";

export function inspectReleaseArchive(filePath, { tarCommand = "tar", requiredEntries = [], run = spawnSync } = {}) {
	let archive;
	try {
		archive = gunzipSync(readFileSync(filePath));
	} catch (error) {
		throw new Error(`unable to decompress ${filePath}: ${error instanceof Error ? error.message : String(error)}`);
	}
	const listed = run(tarCommand, ["-tf", "-"], { encoding: "utf8", input: archive, maxBuffer: 8 * 1024 * 1024 });
	if (listed.status !== 0) throw new Error(`unable to list ${filePath}`);
	const listing = listed.stdout ?? "";
	if (hasForbiddenArchiveEntry(listing)) throw new Error(`packed consumer artifact contains forbidden files: ${filePath}`);
	const entries = new Set(listing.split(/\r?\n/u).filter(Boolean));
	for (const required of requiredEntries) {
		if (!entries.has(required)) throw new Error(`packed consumer artifact is missing signed evidence ${required}: ${filePath}`);
	}

	const textEntries = [...entries].filter((name) => /\.(?:c|m)?js$|\.css$/iu.test(name));
	for (let index = 0; index < textEntries.length; index += 64) {
		const names = textEntries.slice(index, index + 64);
		const extracted = run(tarCommand, ["-xOf", "-", "--", ...names], {
			encoding: "utf8",
			input: archive,
			maxBuffer: 256 * 1024 * 1024,
		});
		if (extracted.status !== 0) throw new Error(`unable to inspect JavaScript/CSS in ${filePath}`);
		const source = extracted.stdout ?? "";
		if (SOURCE_MAPPING_DIRECTIVE_RE.test(source)) throw new Error(`packed consumer artifact contains sourceMappingURL: ${filePath}`);
		if (SOURCE_URL_DIRECTIVE_RE.test(source)) throw new Error(`packed consumer artifact contains sourceURL: ${filePath}`);
	}
	return { entries, listing };
}
