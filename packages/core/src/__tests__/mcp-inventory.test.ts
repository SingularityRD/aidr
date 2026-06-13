import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadMcpServerInventory } from "../mcp-inventory.js";

describe("mcp-inventory", () => {
	it("parses mcpServers entries from config", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-mcp-"));
		const cfg = join(dir, "claude_desktop_config.json");
		await writeFile(
			cfg,
			JSON.stringify({
				mcpServers: {
					localFs: { command: "node", args: ["server.js"] },
				},
			}),
		);
		const items = await loadMcpServerInventory([cfg]);
		expect(items).toHaveLength(1);
		expect(items[0]?.name).toBe("localFs");
	});

	it("flags risky remote and shell-wrapper configs", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-mcp-"));
		const cfg = join(dir, "claude_desktop_config.json");
		await writeFile(
			cfg,
			JSON.stringify({
				mcpServers: {
					remote: { url: "https://mcp.example.com" },
					shell: { command: "bash", args: ["--allow-all", "/"] },
				},
			}),
		);
		const items = await loadMcpServerInventory([cfg]);
		expect(items.find((i) => i.name === "remote")?.riskHints).toContain("remote_mcp_url");
		expect(items.find((i) => i.name === "shell")?.riskHints).toContain("shell_wrapper_command");
	});

	it("parses Cursor/OpenCode/OpenClaw-style nested mcp config shapes", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-mcp-"));
		const cursorCfg = join(dir, "cursor-mcp.json");
		const opencodeCfg = join(dir, "opencode.json");
		const openclawCfg = join(dir, "openclaw.json");

		await writeFile(
			cursorCfg,
			JSON.stringify({
				servers: {
					cursorFs: { command: "node", args: ["cursor-fs.js"] },
				},
			}),
		);
		await writeFile(
			opencodeCfg,
			JSON.stringify({
				mcp: {
					servers: {
						opencodeSearch: { url: "https://mcp.example.com/search" },
					},
				},
			}),
		);
		await writeFile(
			openclawCfg,
			JSON.stringify({
				mcp: {
					openclawShell: { command: "sh", args: ["--dangerous"] },
				},
			}),
		);

		const items = await loadMcpServerInventory([cursorCfg, opencodeCfg, openclawCfg]);
		expect(items.map((i) => i.name).sort()).toEqual([
			"cursorFs",
			"openclawShell",
			"opencodeSearch",
		]);
		expect(items.find((i) => i.name === "opencodeSearch")?.riskHints).toContain("remote_mcp_url");
		expect(items.find((i) => i.name === "openclawShell")?.riskHints).toContain(
			"shell_wrapper_command",
		);
	});
});
