import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { resetSignerHealthCache, signerHealthy } from "../_shared/signing-health.ts";

const FUNCTIONS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");

describe("per-isolate signer healthcheck cache", () => {
	beforeEach(() => resetSignerHealthCache());

	it("probes once per TTL while healthy and re-probes after it expires", async () => {
		let now = 1_000_000;
		const probe = vi.fn(async () => true);
		for (let i = 0; i < 5; i++) expect(await signerHealthy("key-a", probe, () => now)).toBe(true);
		expect(probe).toHaveBeenCalledOnce();
		now += 60_000;
		expect(await signerHealthy("key-a", probe, () => now)).toBe(true);
		expect(probe).toHaveBeenCalledTimes(2);
	});

	it("caches a failure only briefly and keeps failing closed meanwhile", async () => {
		let now = 1_000_000;
		const probe = vi.fn(async () => false);
		expect(await signerHealthy("key-a", probe, () => now)).toBe(false);
		expect(await signerHealthy("key-a", probe, () => now + 4_999)).toBe(false);
		expect(probe).toHaveBeenCalledOnce();
		now += 5_000;
		probe.mockResolvedValueOnce(true);
		expect(await signerHealthy("key-a", probe, () => now)).toBe(true);
		expect(probe).toHaveBeenCalledTimes(2);
	});

	it("treats a throwing probe as unhealthy", async () => {
		expect(await signerHealthy("key-a", async () => { throw new Error("import failed"); })).toBe(false);
	});

	it("does not reuse a result for a different signer configuration", async () => {
		const healthy = vi.fn(async () => true);
		const broken = vi.fn(async () => false);
		expect(await signerHealthy("key-a", healthy)).toBe(true);
		expect(await signerHealthy("key-b", broken)).toBe(false);
		expect(broken).toHaveBeenCalledOnce();
	});

	it("is used by both /enroll and /ingest before authentication", () => {
		for (const name of ["enroll", "ingest"]) {
			const source = readFileSync(resolve(FUNCTIONS_DIR, name, "index.ts"), "utf8");
			expect(source).toContain('from "../_shared/signing-health.ts"');
			expect(source).toContain("await signerHealthy(");
			expect(source).not.toMatch(/!\(await signEd25519Detached\("aidr-signing-healthcheck"\)\)/);
		}
	});
});
