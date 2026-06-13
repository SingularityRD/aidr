import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "../policy.js";
import { ConfigSchema } from "../types.js";

describe("MCP policy enforcement", () => {
	async function writeMcpConfig(servers: Record<string, unknown>): Promise<string> {
		const dir = await mkdtemp(join(tmpdir(), "aidr-mcp-policy-"));
		const cfg = join(dir, "claude_desktop_config.json");
		await writeFile(cfg, JSON.stringify({ mcpServers: servers }, null, 2));
		return cfg;
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
});
