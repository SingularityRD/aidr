import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "../policy.js";
import { ConfigSchema } from "../types.js";

describe("MCP policy enforcement", () => {
	async function writeMcpConfigDocument(
		document: unknown,
		fileName = "claude_desktop_config.json",
	): Promise<string> {
		const dir = await mkdtemp(join(tmpdir(), "aidr-mcp-policy-"));
		const cfg = join(dir, fileName);
		await writeFile(cfg, JSON.stringify(document, null, 2));
		return cfg;
	}

	async function writeMcpConfig(servers: Record<string, unknown>): Promise<string> {
		return writeMcpConfigDocument({ mcpServers: servers });
	}

	it("blocks risky MCP servers before the tool call runs", async () => {
		const cfg = await writeMcpConfig({
			filesystem: { command: "bash", args: ["--allow-all", "/"] },
		});
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					inventory_paths: [cfg],
				},
			},
		});

		const verdict = await evaluatePolicy("mcp__filesystem__read_file", [], config, {});

		expect(verdict?.decision).toBe("deny");
		expect(verdict?.category).toBe("mcp_tool_call");
		expect(verdict?.matchedThreatId).toBe("POL-MCP-001");
		expect(verdict?.reasons.join(" ")).toContain("shell_wrapper_command");
	});

	it("asks for approval when an MCP server is missing from inventory", async () => {
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					inventory_paths: [],
				},
			},
		});

		const verdict = await evaluatePolicy("mcp__unknownServer__query", [], config, {});

		expect(verdict?.decision).toBe("ask");
		expect(verdict?.reasons.join(" ")).toContain("not in inventory");
	});

	it("allows explicitly approved MCP servers even when inventory risk hints exist", async () => {
		const cfg = await writeMcpConfig({
			filesystem: { command: "bash", args: ["--allow-all", "/"] },
		});
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					inventory_paths: [cfg],
					allow_servers: ["filesystem"],
				},
			},
		});

		const verdict = await evaluatePolicy("mcp__filesystem__read_file", [], config, {});

		expect(verdict).toBeNull();
	});

	it.each(["allow_servers", "allow_tools"] as const)(
		"does not let %s override an unreadable inventory",
		async (allowField) => {
			const cfg = await writeMcpConfigDocument({ mcpServers: "malformed", servers: {} });
			const config = ConfigSchema.parse({
				policy: {
					enabled: true,
					mcp: {
						enabled: true,
						inventory_paths: [cfg],
						[allowField]: [allowField === "allow_tools" ? "filesystem.read_file" : "filesystem"],
						unknown_server_action: "allow",
						default_action: "allow",
					},
				},
			});
			const verdict = await evaluatePolicy("mcp__filesystem__read_file", [], config, {});
			expect(verdict?.decision).toBe("ask");
			expect(verdict?.matchedThreatId).toBe("POL-MCP-008");
		},
	);

	it("does not let an explicit allow replace absent inventory evidence", async () => {
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					inventory_paths: [],
					allow_tools: ["filesystem.read_file"],
					unknown_server_action: "allow",
					default_action: "allow",
				},
			},
		});
		const verdict = await evaluatePolicy("mcp__filesystem__read_file", [], config, {});
		expect(verdict?.decision).toBe("ask");
	});

	it("does not trust one readable alias when another source is invalid", async () => {
		const valid = await writeMcpConfig({ filesystem: { command: "node" } });
		const invalid = await writeMcpConfigDocument({ mcpServers: "malformed", servers: {} });
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					inventory_paths: [valid, invalid],
					allow_servers: ["filesystem"],
				},
			},
		});
		const verdict = await evaluatePolicy("mcp__filesystem__read_file", [], config, {});
		expect(verdict?.decision).toBe("ask");
		expect(verdict?.matchedThreatId).toBe("POL-MCP-008");
	});

	it("does not trust conflicting same-name declarations across readable sources", async () => {
		const first = await writeMcpConfig({ filesystem: { command: "node", args: ["one.js"] } });
		const second = await writeMcpConfig({ filesystem: { command: "node", args: ["two.js"] } });
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					inventory_paths: [first, second],
					allow_servers: ["filesystem"],
				},
			},
		});
		const verdict = await evaluatePolicy("mcp__filesystem__read_file", [], config, {});
		expect(verdict?.decision).toBe("ask");
		expect(verdict?.matchedThreatId).toBe("POL-MCP-008");
	});

	it("does not treat a partial source as complete because the target alias is valid", async () => {
		const cfg = await writeMcpConfig({
			filesystem: { command: "node" },
			other: { args: ["missing transport"] },
		});
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					inventory_paths: [cfg],
					allow_servers: ["filesystem"],
				},
			},
		});
		const verdict = await evaluatePolicy("mcp__filesystem__read_file", [], config, {});
		expect(verdict?.decision).toBe("ask");
		expect(verdict?.matchedThreatId).toBe("POL-MCP-008");
	});

	it("matches exact-case runtime IDs to configured server names", async () => {
		const cfg = await writeMcpConfig({ FileSystem: { command: "bash" } });
		const config = ConfigSchema.parse({
			policy: { enabled: true, mcp: { enabled: true, inventory_paths: [cfg] } },
		});
		const verdict = await evaluatePolicy("mcp__FileSystem__read_file", [], config, {});
		expect(verdict?.decision).toBe("deny");
		expect(verdict?.matchedThreatId).toBe("POL-MCP-001");
	});

	it("does not let a case-variant tool inherit an explicit allow", async () => {
		const cfg = await writeMcpConfig({ github: { command: "node" } });
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					inventory_paths: [cfg],
					allow_tools: ["github.read_file"],
					default_action: "block",
				},
			},
		});

		expect(await evaluatePolicy("mcp__github__read_file", [], config, {})).toBeNull();
		const caseVariant = await evaluatePolicy("mcp__github__READ_FILE", [], config, {});
		expect(caseVariant?.decision).toBe("deny");
		expect(caseVariant?.matchedThreatId).toBe("POL-MCP-005");
	});

	it("does not let a case-variant server inherit inventory or allow rules", async () => {
		const cfg = await writeMcpConfig({ FileSystem: { command: "node" } });
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					inventory_paths: [cfg],
					allow_servers: ["filesystem"],
					unknown_server_action: "block",
				},
			},
		});

		const variant = await evaluatePolicy("mcp__filesystem__read_file", [], config, {});
		expect(variant?.decision).toBe("deny");
		expect(variant?.matchedThreatId).toBe("POL-MCP-008");
	});

	it("keeps dotted server/tool pairs distinct instead of flattening them", async () => {
		const cfg = await writeMcpConfig({
			"a.b": { command: "node" },
			a: { command: "node" },
		});
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					inventory_paths: [cfg],
					allow_tools: [JSON.stringify(["a.b", "c"])],
					default_action: "block",
				},
			},
		});

		const allowed = await evaluatePolicy("MCP", [], config, {
			tool_input: { server: "a.b", name: "c" },
		});
		const distinct = await evaluatePolicy("MCP", [], config, {
			tool_input: { server: "a", name: "b.c" },
		});

		expect(allowed).toBeNull();
		expect(distinct?.decision).toBe("deny");
		expect(distinct?.matchedThreatId).toBe("POL-MCP-005");
	});

	it.each([
		["remote endpoint", { url: "https://mcp.example.test/tools" }, "remote_mcp_url"],
		["broad filesystem", { command: "node", args: ["/"] }, "broad_filesystem_access_arg"],
		[
			"shell executable path",
			{ command: "C:\\Windows\\System32\\cmd.exe" },
			"shell_wrapper_command",
		],
	] as const)("escalates %s risk hints at runtime", async (_label, server, hint) => {
		const cfg = await writeMcpConfig({ filesystem: server });
		const config = ConfigSchema.parse({
			policy: { enabled: true, mcp: { enabled: true, inventory_paths: [cfg] } },
		});
		const verdict = await evaluatePolicy("mcp__filesystem__read_file", [], config, {});
		expect(verdict?.decision).toBe("deny");
		expect(verdict?.reasons.join(" ")).toContain(hint);
	});

	it("blocks an explicitly denied MCP tool even when the server is allowed", async () => {
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					allow_servers: ["github"],
					deny_tools: ["github.delete_repo"],
				},
			},
		});

		const verdict = await evaluatePolicy("mcp__github__delete_repo", [], config, {});

		expect(verdict?.decision).toBe("deny");
		expect(verdict?.artifacts).toEqual(["github.delete_repo"]);
		expect(verdict?.reasons.join(" ")).toContain("MCP tool");
	});

	it("matches exact-case MCP tool policies and keeps tool denial ahead of a server allow", async () => {
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					allow_servers: ["GitHub"],
					deny_tools: ["GitHub.delete_repo"],
				},
			},
		});

		const verdict = await evaluatePolicy("mcp__GitHub__delete_repo", [], config, {});

		expect(verdict?.decision).toBe("deny");
		expect(verdict?.matchedThreatId).toBe("POL-MCP-002");
	});

	it("applies per-tool approval from nested MCP tool_input identity", async () => {
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					unknown_server_action: "allow",
					require_approval_tools: ["filesystem.read_file"],
				},
			},
		});

		const verdict = await evaluatePolicy("MCP", [], config, {
			tool_input: {
				server: "filesystem",
				name: "read_file",
				arguments: { path: "/etc/shadow" },
			},
		});

		expect(verdict?.decision).toBe("ask");
		expect(verdict?.artifacts).toEqual(["filesystem.read_file"]);
		expect(verdict?.reasons.join(" ")).toContain("requires approval");
	});

	it("does not treat an unparseable inventory file as an empty inventory", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-mcp-policy-"));
		const cfg = join(dir, "claude_desktop_config.json");
		// Truncated mid-document. `JSON.parse` throws, so the server used to fall
		// through to `unknown_server_action: "allow"` and be allowed silently.
		await writeFile(cfg, '{ "mcpServers": { "filesystem": { "command": "bash" ');
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					inventory_paths: [cfg],
					unknown_server_action: "allow",
				},
			},
		});

		const verdict = await evaluatePolicy("mcp__filesystem__read_file", [], config, {});

		expect(verdict?.decision).toBe("ask");
		expect(verdict?.matchedThreatId).toBe("POL-MCP-008");
		expect(verdict?.reasons.join(" ")).toContain("inventory unreadable");
		expect(verdict?.reasons.join(" ")).not.toContain("not in inventory");
	});

	it("reads a JSONC inventory file so risk escalation still applies", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-mcp-policy-jsonc-"));
		const cfg = join(dir, "mcp.json");
		await writeFile(
			cfg,
			[
				"{",
				"  // JSONC host config",
				'  "mcpServers": {',
				'    "filesystem": { "command": "bash", "args": ["--allow-all", "/"], },',
				"  },",
				"}",
			].join("\n"),
		);
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					inventory_paths: [cfg],
				},
			},
		});

		const verdict = await evaluatePolicy("mcp__filesystem__read_file", [], config, {});

		expect(verdict?.decision).toBe("deny");
		expect(verdict?.matchedThreatId).toBe("POL-MCP-001");
		expect(verdict?.reasons.join(" ")).toContain("shell_wrapper_command");
	});

	it.each([
		["root servers", { servers: { filesystem: { command: "bash" } } }],
		["nested mcp.servers", { mcp: { servers: { filesystem: { command: "bash" } } } }],
		["direct mcp map", { mcp: { filesystem: { command: "bash" } } }],
		["command array", { mcpServers: { filesystem: { command: ["bash", "--allow-all", "/"] } } }],
	])("enforces runtime policy for discovery-supported %s config", async (_shape, document) => {
		const cfg = await writeMcpConfigDocument(document);
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					inventory_paths: [cfg],
					unknown_server_action: "allow",
				},
			},
		});

		const verdict = await evaluatePolicy("mcp__filesystem__read_file", [], config, {});

		expect(verdict?.decision).toBe("deny");
		expect(verdict?.matchedThreatId).toBe("POL-MCP-001");
	});

	it("reads a known host config without an MCP key as zero servers, not as unreadable", async () => {
		const cfg = await writeMcpConfigDocument({ preferences: { theme: "dark" } });
		const config = ConfigSchema.parse({
			policy: { enabled: true, mcp: { enabled: true, inventory_paths: [cfg] } },
		});

		const verdict = await evaluatePolicy("mcp__filesystem__read_file", [], config, {});

		// The server is simply not in the inventory; the other MCP rules still apply.
		expect(verdict).not.toBeNull();
		expect(verdict?.decision).not.toBe("allow");
		expect(verdict?.matchedThreatId).not.toBe("POL-MCP-008");
		expect(verdict?.reasons.join(" ")).not.toContain("inventory unreadable");
	});

	it("fails closed when inventory JSON has no supported MCP server-map shape", async () => {
		const cfg = await writeMcpConfigDocument(
			{ unrelated: { filesystem: { command: "bash" } } },
			"inventory.json",
		);
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					inventory_paths: [cfg],
					unknown_server_action: "allow",
				},
			},
		});

		const verdict = await evaluatePolicy("mcp__filesystem__read_file", [], config, {});

		expect(verdict?.decision).toBe("ask");
		expect(verdict?.matchedThreatId).toBe("POL-MCP-008");
		expect(verdict?.reasons.join(" ")).toContain("inventory unreadable");
	});

	it.each([
		["missing transport", { env: { TOKEN: "private" } }],
		["invalid URL", { url: "https://" }],
	])("fails closed for %s in an otherwise readable MCP inventory", async (_label, server) => {
		const cfg = await writeMcpConfig({ filesystem: server });
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					inventory_paths: [cfg],
					unknown_server_action: "allow",
					default_action: "allow",
				},
			},
		});

		const verdict = await evaluatePolicy("mcp__filesystem__read_file", [], config, {});
		expect(verdict?.decision).toBe("ask");
		expect(verdict?.matchedThreatId).toBe("POL-MCP-008");
	});
});
