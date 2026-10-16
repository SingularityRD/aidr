import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	aigRiskToPolicyAction,
	classifyMcpServer,
	classifyMcpTool,
	getAigMcpDataStatus,
	getAllCategories,
	isAigMcpDataReady,
	resetCategoryCache,
} from "../mcp-aig-categories.js";
import { detectMcpConfigSecrets } from "../mcp-config-secrets.js";
import { discoverMcpServers } from "../mcp-discovery.js";
import { inspectMcpServerInventory } from "../mcp-inventory.js";

const EXPECTED_IDS = Array.from({ length: 14 }, (_, i) => `mcp-${String(i + 1).padStart(2, "0")}`);
// Built at runtime so no literal token-shaped string sits in the repository.
const GITHUB_TOKEN_VALUE = `ghp_${"A1b2C3d4E5".repeat(4)}`;

afterEach(() => resetCategoryCache());

describe("AIG MCP category index", () => {
	it("loads the 14 generated categories mcp-01..mcp-14", () => {
		resetCategoryCache();
		const categories = getAllCategories();
		expect(categories.map((category) => category.id)).toEqual(EXPECTED_IDS);
		expect(getAigMcpDataStatus()).toMatchObject({ source: "generated", valid: true });
		expect(isAigMcpDataReady()).toBe(true);
		expect(categories.find((category) => category.id === "mcp-01")).toMatchObject({
			risk: "critical",
			aidr_policy_action: "deny",
		});
	});

	it("maps risk levels to policy actions", () => {
		expect(aigRiskToPolicyAction("critical")).toBe("deny");
		expect(aigRiskToPolicyAction("high")).toBe("ask");
		expect(aigRiskToPolicyAction("medium")).toBe("audit");
		expect(aigRiskToPolicyAction("low")).toBe("allow");
	});
});

describe("classifyMcpTool", () => {
	it("matches categories from the server and tool name", () => {
		const result = classifyMcpTool("mcp__runner__shell_exec", "Runs a command", {});
		expect(result.matchedCategories.map((category) => category.id)).toContain("mcp-05");
		expect(result.riskLevel).toBe("critical");
	});

	it("reports low risk with no categories for an unrelated tool", () => {
		const result = classifyMcpTool("mcp__weather__forecast", "Returns a forecast", { city: "x" });
		expect(result.matchedCategories).toEqual([]);
		expect(result.riskLevel).toBe("low");
	});
});

describe("classifyMcpServer", () => {
	const base = { name: "github", command: "npx", args: ["@example/github-mcp"], riskHints: [] };

	it("maps a hardcoded secret to mcp-01 as evidence without the value", () => {
		const matches = classifyMcpServer({
			...base,
			secretFindings: [{ location: "env", key: "GITHUB_TOKEN", kind: "github_token" }],
		});
		expect(matches.find((match) => match.id === "mcp-01")).toMatchObject({
			basis: "evidence",
			risk: "critical",
			evidence: ["hardcoded_secret:env:GITHUB_TOKEN:github_token"],
		});
	});

	it("maps shell-wrapper and broad-filesystem hints to mcp-05 and mcp-02", () => {
		const matches = classifyMcpServer({
			...base,
			riskHints: ["shell_wrapper_command", "broad_filesystem_access_arg"],
			secretFindings: [],
		});
		expect(matches.filter((match) => match.basis === "evidence").map((match) => match.id)).toEqual([
			"mcp-02",
			"mcp-05",
		]);
	});

	it("labels pattern-only matches as keyword and never infers mcp-01 from words", () => {
		const matches = classifyMcpServer({
			name: "runner",
			command: "/usr/bin/node",
			args: ["server.js", "--token", "${TOKEN}", "--spawn"],
			riskHints: [],
			secretFindings: [],
		});
		expect(matches.find((match) => match.id === "mcp-05")).toMatchObject({ basis: "keyword" });
		expect(matches.some((match) => match.id === "mcp-01")).toBe(false);
	});

	it("returns no category for an unremarkable server", () => {
		expect(classifyMcpServer({ ...base, secretFindings: [] })).toEqual([]);
	});
});

describe("hardcoded secret detection", () => {
	it("finds literal secrets in env, headers, args and URL and never returns values", () => {
		const findings = detectMcpConfigSecrets({
			env: [
				{ GITHUB_TOKEN: GITHUB_TOKEN_VALUE, DB_PASSWORD: "hunter2hunter2", LOG_LEVEL: "debug" },
			],
			headers: { Authorization: "Bearer abcdefghijklmnop" },
			args: ["--api-key", "k3y-value-123456", "--port", "8080", GITHUB_TOKEN_VALUE],
			url: ["https://mcp.example/sse?access", "_token=", "abcdef", "123456"].join(""),
		});
		expect(findings).toEqual([
			{ location: "env", key: "GITHUB_TOKEN", kind: "github_token" },
			{ location: "env", key: "DB_PASSWORD", kind: "credential_named_value" },
			{ location: "headers", key: "Authorization", kind: "bearer_credential" },
			{ location: "args", key: "--api-key", kind: "credential_named_value" },
			{ location: "args", key: "args[4]", kind: "github_token" },
			{ location: "url", key: "query:access_token", kind: "credential_named_value" },
		]);
		const serialized = JSON.stringify(findings);
		for (const value of [
			GITHUB_TOKEN_VALUE,
			"hunter2hunter2",
			"abcdefghijklmnop",
			"k3y-value-123456",
			"abcdef123456",
		]) {
			expect(serialized).not.toContain(value);
		}
	});

	it("ignores env references, placeholders and non-credential locations", () => {
		expect(
			detectMcpConfigSecrets({
				env: [
					{
						GITHUB_TOKEN: "${GITHUB_TOKEN}",
						API_KEY: "${env:API_KEY}",
						SECRET: "$SECRET",
						PASSWORD: "<your-password>",
						TOKEN_URL: "https://auth.example/token",
						SECRET_FILE: "/run/secrets/token",
						AUTH_HEADER_NAME: "x-api",
					},
				],
				headers: { Authorization: "Bearer ${input:token}" },
				args: ["--token", "${TOKEN}"],
				url: "https://mcp.example/sse",
			}),
		).toEqual([]);
	});
});

describe("discovery wiring", () => {
	it("attaches matching categories and secret locations to inventory and discovery output", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-mcp-categories-"));
		try {
			const path = join(dir, "mcp.json");
			await writeFile(
				path,
				JSON.stringify({
					mcpServers: {
						github: {
							command: "npx",
							args: ["-y", "@modelcontextprotocol/server-github"],
							env: { GITHUB_TOKEN: GITHUB_TOKEN_VALUE },
						},
						referenced: {
							command: "npx",
							args: ["-y", "@modelcontextprotocol/server-github"],
							env: { GITHUB_TOKEN: "${GITHUB_TOKEN}" },
						},
						shell: { command: "bash", args: ["-c", "serve"] },
					},
				}),
			);

			const inventory = await inspectMcpServerInventory([path]);
			const github = inventory.items.find((item) => item.name === "github");
			expect(github?.secretFindings).toEqual([
				{ location: "env", key: "GITHUB_TOKEN", kind: "github_token" },
			]);
			expect(github?.aigCategories.map((category) => category.id)).toContain("mcp-01");

			const report = await discoverMcpServers([path]);
			const byName = new Map(report.servers.map((server) => [server.name, server]));
			expect(byName.get("github")?.aig_categories.find((c) => c.id === "mcp-01")).toMatchObject({
				basis: "evidence",
			});
			expect(byName.get("github")?.secret_findings).toHaveLength(1);
			expect(byName.get("referenced")?.secret_findings).toEqual([]);
			expect(byName.get("referenced")?.aig_categories.some((c) => c.id === "mcp-01")).toBe(false);
			expect(byName.get("shell")?.aig_categories.map((c) => c.id)).toContain("mcp-05");
			for (const server of report.servers) {
				expect(server.aig_categories.every((c) => EXPECTED_IDS.includes(c.id))).toBe(true);
			}
			expect(JSON.stringify(report)).not.toContain(GITHUB_TOKEN_VALUE);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});
});
