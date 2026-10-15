/**
 * Parse shipped YAML data files (framework mappings, toxic-flow capabilities,
 * allowlists) without running the YAML parser on every hook call (D7).
 *
 * Same safety model as the threat parse cache (scripts/compile-threat-cache.mjs):
 * entries are keyed by the SHA-256 of the file's exact content (line endings
 * normalised), so the file on disk stays authoritative. Edited, user-supplied
 * or newer content misses the cache and is parsed normally, with the same
 * errors as before. A hit returns a private copy, so a caller can never alter
 * the cache for later calls in a long-lived process.
 */

import { createHash } from "node:crypto";
import { parse as parseYaml } from "yaml";
import { DATA_PARSE_CACHE } from "./generated/threat-parse-cache.js";

export function parseShippedYaml(text: string): unknown {
	const key = createHash("sha256").update(text.replace(/\r\n/g, "\n"), "utf8").digest("hex");
	const cached = DATA_PARSE_CACHE[key];
	return cached === undefined ? parseYaml(text) : structuredClone(cached);
}
