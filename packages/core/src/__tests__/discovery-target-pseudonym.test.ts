import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	DISCOVERY_TARGET_ID_PATTERN,
	discoveryTargetPseudonym,
	getDiscoveryTargetKey,
} from "../discovery-target-pseudonym.js";

const TENANT = "123e4567-e89b-42d3-a456-426614174000";

describe("discovery target pseudonyms", () => {
	it("creates one per-installation key and reuses it", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-target-key-"));
		try {
			const first = await getDiscoveryTargetKey(dir);
			const second = await getDiscoveryTargetKey(dir);
			expect(first).toHaveLength(32);
			expect(second.equals(first)).toBe(true);
			expect((await readFile(join(dir, "discovery-target-key"), "utf8")).trim()).toHaveLength(43);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("fails closed on a malformed key instead of regenerating it", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-target-key-bad-"));
		try {
			await writeFile(join(dir, "discovery-target-key"), "not-a-key");
			await expect(getDiscoveryTargetKey(dir)).rejects.toThrow("discovery_target_key_invalid");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("produces a keyed, tenant-scoped identifier that does not contain the origin", () => {
		const key = Buffer.alloc(32, 1);
		const id = discoveryTargetPseudonym(key, TENANT, "http://10.0.0.4:11434/");
		expect(id).toMatch(DISCOVERY_TARGET_ID_PATTERN);
		expect(id).not.toContain("10.0.0.4");
		expect(discoveryTargetPseudonym(key, TENANT.toUpperCase(), "http://10.0.0.4:11434/")).toBe(id);
		expect(discoveryTargetPseudonym(key, TENANT, "http://10.0.0.5:11434/")).not.toBe(id);
		expect(discoveryTargetPseudonym(Buffer.alloc(32, 2), TENANT, "http://10.0.0.4:11434/")).not.toBe(id);
		expect(() => discoveryTargetPseudonym(Buffer.alloc(16), TENANT, "http://10.0.0.4/")).toThrow(
			"discovery_target_key_invalid",
		);
	});
});
