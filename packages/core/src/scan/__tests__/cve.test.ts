import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	checkFrameworkCves,
	checkPackageAgainstCveIndex,
	getCveStats,
	resetCveIndexCache,
	setTestIndexPath,
} from "../cve.js";

const MOCK_INDEX = {
	version: 1,
	generated: "2025-05-26T00:00:00.000Z",
	cves: [
		{
			id: "CVE-2025-0001",
			p: "lodash",
			e: "npm",
			s: "critical",
			r: "<=4.17.20",
			c: 9.8,
		},
		{
			id: "CVE-2025-0002",
			p: "lodash",
			e: "npm",
			s: "high",
			r: ">=4.17.21 <4.17.25",
			c: 7.5,
		},
		{
			id: "CVE-2025-0003",
			p: "requests",
			e: "pypi",
			s: "medium",
			r: "<2.32.0",
			c: 5.5,
		},
		{
			id: "CVE-2025-0004",
			p: "langchain-core",
			e: "pypi",
			s: "critical",
			r: "<0.3.0",
			c: 9.5,
			f: "langchain",
		},
	],
	frameworks: {
		langchain: ["CVE-2025-0004"],
	},
	ecosystems: {
		npm: ["lodash"],
		pypi: ["requests", "langchain-core"],
	},
};

let tmpDir: string;

function writeIndex(data: Record<string, unknown> = MOCK_INDEX): string {
	const filePath = join(tmpDir, "scan-cve-index.json");
	writeFileSync(filePath, JSON.stringify(data), "utf-8");
	return filePath;
}

describe("CVE Checker", () => {
	beforeEach(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "cve-test-"));
		resetCveIndexCache();
	});

	afterEach(() => {
		setTestIndexPath(null);
		resetCveIndexCache();
		rmSync(tmpDir, { recursive: true, force: true });
	});

	describe("checkPackageAgainstCveIndex", () => {
		it("returns empty array when index file does not exist", () => {
			setTestIndexPath(join(tmpDir, "nonexistent.json"));
			const result = checkPackageAgainstCveIndex("lodash", "4.17.20", "npm");
			expect(result).toEqual([]);
		});

		it("finds critical CVE for vulnerable lodash version", () => {
			setTestIndexPath(writeIndex());
			const result = checkPackageAgainstCveIndex("lodash", "4.17.20", "npm");

			expect(result).toHaveLength(1);
			expect(result[0]?.cve_id).toBe("CVE-2025-0001");
			expect(result[0]?.severity).toBe("critical");
			expect(result[0]?.cvss_score).toBe(9.8);
			expect(result[0]?.package_name).toBe("lodash");
			expect(result[0]?.ecosystem).toBe("npm");
		});

		it("finds correct CVE for different vulnerable version", () => {
			setTestIndexPath(writeIndex());
			const result = checkPackageAgainstCveIndex("lodash", "4.17.22", "npm");
			expect(result).toHaveLength(1);
			expect(result[0]?.cve_id).toBe("CVE-2025-0002");
		});

		it("returns empty for non-vulnerable version", () => {
			setTestIndexPath(writeIndex());
			const result = checkPackageAgainstCveIndex("lodash", "5.0.0", "npm");
			expect(result).toEqual([]);
		});

		it("matches by ecosystem correctly (pypi only)", () => {
			setTestIndexPath(writeIndex());
			const result = checkPackageAgainstCveIndex("requests", "2.31.0", "pypi");
			expect(result).toHaveLength(1);
			expect(result[0]?.cve_id).toBe("CVE-2025-0003");
			expect(result[0]?.ecosystem).toBe("pypi");
		});

		it("does not match if ecosystem differs", () => {
			setTestIndexPath(writeIndex());
			const result = checkPackageAgainstCveIndex("requests", "2.31.0", "npm");
			expect(result).toEqual([]);
		});

		it("handles invalid JSON in index gracefully", () => {
			const badPath = join(tmpDir, "bad-index.json");
			writeFileSync(badPath, "not valid json{{{", "utf-8");
			setTestIndexPath(badPath);

			const result = checkPackageAgainstCveIndex("lodash", "4.17.20", "npm");
			expect(result).toEqual([]);
		});

		it("returns empty array for unknown package", () => {
			setTestIndexPath(writeIndex());
			const result = checkPackageAgainstCveIndex("nonexistent-package", "1.0.0", "npm");
			expect(result).toEqual([]);
		});
	});

	describe("checkFrameworkCves", () => {
		it("returns empty when framework has no known CVEs", () => {
			setTestIndexPath(writeIndex());
			const result = checkFrameworkCves("llamaindex");
			expect(result).toEqual([]);
		});

		it("finds CVEs for known framework (langchain)", () => {
			setTestIndexPath(writeIndex());
			const result = checkFrameworkCves("langchain");
			expect(result).toHaveLength(1);
			expect(result[0]?.cve_id).toBe("CVE-2025-0004");
			expect(result[0]?.package_name).toBe("langchain-core");
		});
	});

	describe("getCveStats", () => {
		it("returns zero stats when index is missing", () => {
			setTestIndexPath(join(tmpDir, "nonexistent.json"));
			const stats = getCveStats();
			expect(stats.total).toBe(0);
			expect(stats.by_severity).toEqual({});
			expect(stats.by_ecosystem).toEqual({});
		});

		it("returns correct aggregate stats", () => {
			setTestIndexPath(writeIndex());
			const stats = getCveStats();
			expect(stats.total).toBe(4);
			expect(stats.by_severity).toEqual({
				critical: 2,
				high: 1,
				medium: 1,
			});
			expect(stats.by_ecosystem).toEqual({
				npm: 2,
				pypi: 2,
			});
		});
	});

	describe("index cache behavior", () => {
		it("caches the index after first load", () => {
			setTestIndexPath(writeIndex());

			const r1 = checkPackageAgainstCveIndex("lodash", "4.17.20", "npm");
			expect(r1).toHaveLength(1);

			rmSync(join(tmpDir, "scan-cve-index.json"), { force: true });

			const r2 = checkPackageAgainstCveIndex("lodash", "4.17.20", "npm");
			expect(r2).toHaveLength(1);

			resetCveIndexCache();
			setTestIndexPath(join(tmpDir, "nonexistent.json"));
			const r3 = checkPackageAgainstCveIndex("lodash", "4.17.20", "npm");
			expect(r3).toEqual([]);
		});
	});
});
