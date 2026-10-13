import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	extractDomain,
	isTrustedDomain,
	isTrustedUrl,
	loadTrustedDomains,
} from "../trusted-domains.js";
import type { TrustedDomain } from "../types.js";
import { makeTmpDir } from "./test-utils.js";

describe("loadTrustedDomains", () => {
	it("loads valid domains", async () => {
		const dir = await makeTmpDir();
		await writeFile(
			join(dir, "trusted.yaml"),
			`
- domain: bun.sh
  reason: "Bun package manager"
- domain: deno.land
  reason: "Deno runtime"
`,
		);
		const domains = await loadTrustedDomains(dir);
		expect(domains).toHaveLength(2);
		expect(domains[0]?.domain).toBe("bun.sh");
		expect(domains[1]?.domain).toBe("deno.land");
	});

	it("returns empty for nonexistent directory", async () => {
		const domains = await loadTrustedDomains("/nonexistent/dir");
		expect(domains).toEqual([]);
	});

	it("skips entries with missing domain", async () => {
		const dir = await makeTmpDir();
		await writeFile(
			join(dir, "trusted.yaml"),
			`
- reason: "No domain"
`,
		);
		const domains = await loadTrustedDomains(dir);
		expect(domains).toHaveLength(0);
	});

	it("skips entries with missing reason", async () => {
		const dir = await makeTmpDir();
		await writeFile(
			join(dir, "trusted.yaml"),
			`
- domain: test.com
`,
		);
		const domains = await loadTrustedDomains(dir);
		expect(domains).toHaveLength(0);
	});

	it("loads real allowlist files", async () => {
		const dir = join(import.meta.dirname, "../../../../allowlists");
		const domains = await loadTrustedDomains(dir);
		expect(domains.length).toBeGreaterThan(0);
	});
});

describe("extractDomain", () => {
	it("extracts domain from URL", () => {
		expect(extractDomain("https://example.com/path")).toBe("example.com");
	});

	it("lowercases domain", () => {
		expect(extractDomain("https://Example.COM/path")).toBe("example.com");
	});

	it("returns null for invalid URL", () => {
		expect(extractDomain("not a url")).toBeNull();
	});
});

describe("isTrustedDomain", () => {
	const trusted: TrustedDomain[] = [
		{ domain: "bun.sh", reason: "Bun" },
		{ domain: "github.com", reason: "GitHub" },
	];

	it("matches exact domain", () => {
		expect(isTrustedDomain("bun.sh", trusted)).toBe(true);
	});

	it("matches subdomain", () => {
		expect(isTrustedDomain("cdn.bun.sh", trusted)).toBe(true);
	});

	it("rejects partial prefix", () => {
		expect(isTrustedDomain("notbun.sh", trusted)).toBe(false);
	});

	it("is case-insensitive", () => {
		expect(isTrustedDomain("BUN.SH", trusted)).toBe(true);
	});

	it("returns false for unknown domain", () => {
		expect(isTrustedDomain("evil.com", trusted)).toBe(false);
	});
});

describe("path-scoped trusted domains (GA audit DET-5)", () => {
	const scoped: TrustedDomain[] = [
		{ domain: "bun.sh", reason: "installer" },
		{ domain: "deno.land", reason: "installer", paths: ["/install.sh", "/x/install/install.sh"] },
	];

	it("trusts only the listed installer paths on the exact host", () => {
		expect(isTrustedUrl("https://deno.land/install.sh", scoped)).toBe(true);
		expect(isTrustedUrl("https://deno.land/x/install/install.sh", scoped)).toBe(true);
		expect(isTrustedUrl("https://deno.land/x/someones-module/mod.sh", scoped)).toBe(false);
		expect(isTrustedUrl("https://cdn.deno.land/install.sh", scoped)).toBe(false);
		expect(isTrustedUrl("https://deno.land/install.sh?x=1", scoped)).toBe(false);
		expect(isTrustedUrl("https://user@deno.land/install.sh", scoped)).toBe(false);
	});

	it("keeps suffix matching for whole-domain entries and never trusts a scoped domain as a whole", () => {
		expect(isTrustedUrl("https://cdn.bun.sh/install", scoped)).toBe(true);
		expect(isTrustedDomain("deno.land", scoped)).toBe(false);
	});

	it("skips an entry whose paths are malformed instead of trusting the whole domain", async () => {
		const dir = await makeTmpDir();
		await writeFile(
			join(dir, "trusted.yaml"),
			"- domain: example.org\n  reason: test\n  paths: install.sh\n",
		);
		expect(await loadTrustedDomains(dir)).toEqual([]);
	});

	it("ships deno.land path-scoped", async () => {
		const shipped = await loadTrustedDomains(join(__dirname, "..", "..", "..", "..", "allowlists"));
		const deno = shipped.find((d) => d.domain === "deno.land");
		expect(deno?.paths?.length).toBeGreaterThan(0);
	});
});
