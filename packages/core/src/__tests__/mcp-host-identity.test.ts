import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	canonicalMcpToolName,
	fallbackMcpServerIdentity,
	loadKnownMcpServers,
	matchMcpServerDeclaration,
	mcpIdentityFromCanonicalName,
	mcpIdentityFromOpenClawName,
	mcpIdentityFromOpenCodeName,
	mcpIdentityFromVsCodeName,
	mcpPolicyServerIds,
} from "../mcp-host-identity.js";
import { evaluatePolicy } from "../policy.js";
import { ConfigSchema } from "../types.js";

describe("host MCP tool names", () => {
	it("reads the canonical Claude Code / Codex name", () => {
		expect(mcpIdentityFromCanonicalName("mcp__github__create_issue")).toEqual({
			server: "github",
			tool: "create_issue",
		});
		expect(mcpIdentityFromCanonicalName("mcp__github")).toBeNull();
		expect(mcpIdentityFromCanonicalName("Bash")).toBeNull();
	});

	it("splits VS Code mcp_<server>_<tool> by the longest known server", () => {
		expect(mcpIdentityFromVsCodeName("mcp_my_github_create_issue", ["my", "my_github"])).toEqual({
			server: "my_github",
			tool: "create_issue",
		});
		// Without known servers the first separator is used.
		expect(mcpIdentityFromVsCodeName("mcp_github_create_issue")).toEqual({
			server: "github",
			tool: "create_issue",
		});
		expect(mcpIdentityFromVsCodeName("runInTerminal")).toBeNull();
	});

	it("splits OpenClaw <server>__<tool> and matches sanitized server keys", () => {
		expect(mcpIdentityFromOpenClawName("vigil-harbor__memory_search")).toEqual({
			server: "vigil-harbor",
			tool: "memory_search",
		});
		expect(mcpIdentityFromOpenClawName("my.srv__run", ["my.srv"])).toEqual({
			server: "my.srv",
			tool: "run",
		});
		expect(mcpIdentityFromOpenClawName("web_fetch")).toBeNull();
	});

	it("only treats OpenCode names with a known server prefix as MCP", () => {
		expect(mcpIdentityFromOpenCodeName("github_create_issue", ["github"])).toEqual({
			server: "github",
			tool: "create_issue",
		});
		expect(mcpIdentityFromOpenCodeName("my_srv_run", ["my.srv"])).toEqual({
			server: "my.srv",
			tool: "run",
		});
		expect(mcpIdentityFromOpenCodeName("plan_exit", ["github"])).toBeNull();
		expect(mcpIdentityFromOpenCodeName("aidr_allowlist_add", [])).toBeNull();
	});

	it("matches Cursor's command/url to a declared server", () => {
		const declarations = [
			{ name: "github", command: "npx", args: ["-y", "@mcp/github"], url: null },
			{ name: "notion", command: null, url: "https://mcp.notion.example/sse" },
		];
		expect(matchMcpServerDeclaration(declarations, { command: "npx  -y @mcp/github" })).toBe(
			"github",
		);
		expect(matchMcpServerDeclaration(declarations, { url: "https://mcp.notion.example/sse" })).toBe(
			"notion",
		);
		// Cursor builds that send the configuration key in `command`.
		expect(matchMcpServerDeclaration(declarations, { command: "notion" })).toBe("notion");
		expect(matchMcpServerDeclaration(declarations, { command: "other" })).toBeNull();
		expect(fallbackMcpServerIdentity({ url: "https://api.example.com/mcp" })).toBe(
			"api.example.com",
		);
		expect(fallbackMcpServerIdentity({ command: "playwright" })).toBe("playwright");
		expect(fallbackMcpServerIdentity({})).toBeNull();
	});

	it("collects every server id the MCP policy names", () => {
		expect(
			mcpPolicyServerIds({
				deny_servers: ["evil"],
				require_approval_servers: [" review "],
				allow_servers: ["ok"],
				deny_tools: ["github.delete_repo", JSON.stringify(["my.srv", "run"])],
			}).sort(),
		).toEqual(["evil", "github", "my.srv", "ok", "review"]);
	});

	it("loads declared names from host config and policy ids from the AIDR config", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-mcp-known-"));
		const file = join(dir, "mcp.json");
		await writeFile(file, JSON.stringify({ servers: { my_github: { command: "npx" } } }));
		const known = await loadKnownMcpServers([file, join(dir, "missing.json")]);
		expect(known.names).toContain("my_github");
		expect(known.declarations).toContainEqual(
			expect.objectContaining({ name: "my_github", command: "npx" }),
		);
	});
});

/**
 * Parity: one server rule written once must apply to the same MCP call on all
 * six connectors once each host's naming is mapped to the canonical identity.
 */
describe("MCP server policy parity across connectors", () => {
	const known = ["my_github"];
	const calls: [connector: string, toolName: string, toolInput: Record<string, unknown>][] = [
		["claude-code", "mcp__my_github__create_issue", { title: "x" }],
		["codex", "mcp__my_github__create_issue", { title: "x" }],
		[
			"vscode",
			canonicalMcpToolName(
				mcpIdentityFromVsCodeName("mcp_my_github_create_issue", known) ?? {
					server: "?",
					tool: "?",
				},
			),
			{ title: "x" },
		],
		[
			"openclaw",
			canonicalMcpToolName(
				mcpIdentityFromOpenClawName("my_github__create_issue", known) ?? {
					server: "?",
					tool: "?",
				},
			),
			{ title: "x" },
		],
		[
			"opencode",
			canonicalMcpToolName(
				mcpIdentityFromOpenCodeName("my_github_create_issue", known) ?? {
					server: "?",
					tool: "?",
				},
			),
			{ title: "x" },
		],
		// Cursor beforeMCPExecution: the generic MCP shape with an explicit server.
		[
			"cursor",
			"MCP",
			{ tool_input: { server: "my_github", name: "create_issue", arguments: { title: "x" } } },
		],
	];

	it.each(calls)("%s: deny_servers denies the call", async (_connector, toolName, toolInput) => {
		const config = ConfigSchema.parse({
			policy: { enabled: true, mcp: { enabled: true, deny_servers: ["my_github"] } },
		});
		const verdict = await evaluatePolicy(toolName, [], config, toolInput);
		expect(verdict?.decision).toBe("deny");
		expect(verdict?.matchedThreatId).toBe("POL-MCP-006");
	});

	it.each(calls)(
		"%s: require_approval_servers holds the call",
		async (_connector, toolName, toolInput) => {
			const config = ConfigSchema.parse({
				policy: {
					enabled: true,
					mcp: { enabled: true, require_approval_servers: ["my_github"] },
				},
			});
			const verdict = await evaluatePolicy(toolName, [], config, toolInput);
			expect(verdict?.decision).toBe("ask");
			expect(verdict?.matchedThreatId).toBe("POL-MCP-007");
		},
	);

	it.each(calls)("%s: a tool selector denies the call", async (_connector, toolName, toolInput) => {
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: { enabled: true, deny_tools: ["my_github.create_issue"] },
			},
		});
		const verdict = await evaluatePolicy(toolName, [], config, toolInput);
		expect(verdict?.decision).toBe("deny");
		expect(verdict?.matchedThreatId).toBe("POL-MCP-002");
	});

	it("denies a server whose name contains the canonical separator", async () => {
		const config = ConfigSchema.parse({
			policy: { enabled: true, mcp: { enabled: true, deny_servers: ["team__github"] } },
		});
		const verdict = await evaluatePolicy("mcp__team__github__create_issue", [], config, {});
		expect(verdict?.decision).toBe("deny");
	});

	it("treats an MCP call without an identifiable server as an unknown server", async () => {
		const config = ConfigSchema.parse({
			policy: { enabled: true, mcp: { enabled: true, unknown_server_action: "block" } },
		});
		const verdict = await evaluatePolicy("MCP", [], config, { tool_input: { name: "x" } });
		expect(verdict?.decision).toBe("deny");
		expect(verdict?.reasons.join(" ")).toContain("could not be identified");
	});
});
