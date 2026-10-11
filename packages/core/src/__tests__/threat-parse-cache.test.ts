import { readdirSync, readFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";
import { THREAT_PARSE_CACHE } from "../generated/threat-parse-cache.js";
import {
	loadThreats,
	loadThreatsFromDirs,
	parseThreatYaml,
	threatContentHash,
} from "../threat-loader.js";
import type { Logger } from "../types.js";
import { makeTmpDir } from "./test-utils.js";

const THREATS_DIR = resolve(__dirname, "..", "..", "..", "..", "threats");
const yamlFiles = readdirSync(THREATS_DIR).filter((f) => f.endsWith(".yaml"));

/** The shipped rule count; update deliberately when rules are added or removed. */
const SHIPPED_RULE_COUNT = 507;

function recordingLogger() {
	const errors: string[] = [];
	const logger: Logger = {
		debug() {},
		info() {},
		warn() {},
		error: (msg) => {
			errors.push(msg);
		},
	};
	return { logger, errors };
}

describe("pre-parsed threat cache", () => {
	it("covers every shipped threat file (regenerate with scripts/compile-threat-cache.mjs)", () => {
		for (const name of yamlFiles) {
			const hash = threatContentHash(readFileSync(join(THREATS_DIR, name), "utf-8"));
			expect(THREAT_PARSE_CACHE[hash], `${name} is missing from the parse cache`).toBeDefined();
		}
	});

	it("is exactly what the YAML parser produces", () => {
		for (const name of yamlFiles) {
			const content = readFileSync(join(THREATS_DIR, name), "utf-8");
			expect(parseThreatYaml(content), name).toEqual(parseYaml(content));
		}
	});

	it("loads all shipped rules without logging any error", async () => {
		const { logger, errors } = recordingLogger();
		const threats = await loadThreats(THREATS_DIR, logger);
		expect(threats).toHaveLength(SHIPPED_RULE_COUNT);
		expect(errors).toEqual([]);
	});

	it("does not serve stale rules: edited content misses the cache and is parsed from disk", async () => {
		const dir = await makeTmpDir();
		const original = readFileSync(join(THREATS_DIR, "urls.yaml"), "utf-8");
		await writeFile(
			join(dir, "urls.yaml"),
			original.replace(/title: .*/, 'title: "Edited on disk"'),
		);
		const threats = await loadThreats(dir);
		expect(threats.length).toBeGreaterThan(0);
		expect(threats[0]?.title).toBe("Edited on disk");
	});

	it("treats CRLF and LF checkouts of the same file identically", () => {
		const content = readFileSync(join(THREATS_DIR, "urls.yaml"), "utf-8").replace(/\r\n/g, "\n");
		expect(threatContentHash(content.replace(/\n/g, "\r\n"))).toBe(threatContentHash(content));
	});
});

describe("loadThreatsFromDirs on a fresh install", () => {
	it("is silent when only the optional user threats directory is absent", async () => {
		const { logger, errors } = recordingLogger();
		const missing = join(await makeTmpDir(), "no-such-user-threats");
		const threats = await loadThreatsFromDirs([THREATS_DIR, missing], logger);
		expect(threats).toHaveLength(SHIPPED_RULE_COUNT);
		expect(errors).toEqual([]);
	});

	it("still reports a missing primary threats directory", async () => {
		const { logger, errors } = recordingLogger();
		const missing = join(await makeTmpDir(), "no-such-primary");
		expect(await loadThreatsFromDirs([missing], logger)).toEqual([]);
		expect(errors.some((e) => e.includes("Threat directory does not exist"))).toBe(true);
	});
});
