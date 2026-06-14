/**
 * Tests for the AIDR Scan MCP risk categories module.
 *
 * Validates the 14-category taxonomy and the tool-call classifier.
 */

import { afterEach, describe, expect, it } from "vitest";
import {
	classifyMcpTool,
	getAllCategories,
	loadScanMcpCategories,
	resetCategoryCache,
	scanRiskToPolicyAction,
} from "../mcp-categories.js";

describe("AIDR Scan MCP categories", () => {
	afterEach(() => {
		resetCategoryCache();
	});

	describe("taxonomy", () => {
		it("ships exactly 14 canonical categories", () => {
			const cats = getAllCategories();
			expect(cats.length).toBe(14);
		});

		it("every category has a stable id, name, risk, and action", () => {
			const cats = getAllCategories();
			for (const c of cats) {
				expect(c.id).toMatch(/^aidr-mcp-/);
				expect(c.name.length).toBeGreaterThan(0);
				expect(["critical", "high", "medium", "low"]).toContain(c.risk);
				expect(["deny", "ask", "audit", "allow"]).toContain(c.aidr_policy_action);
				expect(c.detection_patterns.length).toBeGreaterThan(0);
			}
		});

		it("contains the expected high-risk categories", () => {
			const ids = getAllCategories().map((c) => c.id);
			expect(ids).toContain("aidr-mcp-code-exec");
			expect(ids).toContain("aidr-mcp-shell-access");
			expect(ids).toContain("aidr-mcp-data-exfil");
			expect(ids).toContain("aidr-mcp-credential-access");
		});
	});

	describe("classifyMcpTool", () => {
		it("detects code-exec category from exec pattern", () => {
			const result = classifyMcpTool(
				"mcp__shell__run_command",
				"Execute arbitrary system commands",
				{ command: "rm -rf /" },
			);
			expect(result.matchedCategories.length).toBeGreaterThan(0);
			const ids = result.matchedCategories.map((c) => c.id);
			expect(ids).toContain("aidr-mcp-code-exec");
			expect(result.riskLevel).toBe("critical");
		});

		it("detects file-write category", () => {
			const result = classifyMcpTool(
				"mcp__fs__write_file",
				"Write to a file on disk",
				{ path: "/tmp/x", content: "hello" },
			);
			const ids = result.matchedCategories.map((c) => c.id);
			expect(ids).toContain("aidr-mcp-file-write");
		});

		it("detects network-egress category from fetch", () => {
			const result = classifyMcpTool(
				"mcp__http__fetch",
				"Make outbound HTTP request",
				{ url: "https://example.com" },
			);
			const ids = result.matchedCategories.map((c) => c.id);
			expect(ids).toContain("aidr-mcp-network-egress");
		});

		it("detects credential-access category from get_secret", () => {
			const result = classifyMcpTool(
				"mcp__vault__get_secret",
				"Read a secret from vault",
				{ key: "API_KEY" },
			);
			const ids = result.matchedCategories.map((c) => c.id);
			expect(ids).toContain("aidr-mcp-credential-access");
		});

		it("returns no matches for safe tools", () => {
			const result = classifyMcpTool(
				"mcp__search__query",
				"Search the documentation",
				{ query: "how to install" },
			);
			expect(result.matchedCategories.length).toBe(0);
			expect(result.riskLevel).toBe("low");
		});

		it("handles bare tool names without server prefix", () => {
			const result = classifyMcpTool(
				"execute_command",
				"Run a shell command",
				{ command: "ls" },
			);
			const ids = result.matchedCategories.map((c) => c.id);
			expect(ids).toContain("aidr-mcp-code-exec");
		});
	});

	describe("scanRiskToPolicyAction", () => {
		it("maps critical → deny", () => {
			expect(scanRiskToPolicyAction("critical")).toBe("deny");
		});
		it("maps high → ask", () => {
			expect(scanRiskToPolicyAction("high")).toBe("ask");
		});
		it("maps medium → audit", () => {
			expect(scanRiskToPolicyAction("medium")).toBe("audit");
		});
		it("maps low → allow", () => {
			expect(scanRiskToPolicyAction("low")).toBe("allow");
		});
	});

	describe("loadScanMcpCategories", () => {
		it("returns the same array on repeated calls (cached)", () => {
			const a = loadScanMcpCategories();
			const b = loadScanMcpCategories();
			expect(a).toBe(b);
		});

		it("returns 14 categories from fallback when JSON missing", () => {
			resetCategoryCache();
			const cats = loadScanMcpCategories();
			expect(cats.length).toBeGreaterThanOrEqual(14);
		});
	});
});
