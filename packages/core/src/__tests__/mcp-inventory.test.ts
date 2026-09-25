import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { inspectMcpServerInventory, loadMcpServerInventory } from "../mcp-inventory.js";

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

	it("only exempts exact HTTPS loopback MCP hosts from the remote-server hint", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-mcp-loopback-"));
		const cfg = join(dir, "mcp.json");
		await writeFile(
			cfg,
			JSON.stringify({
				mcpServers: {
					localhost: { url: "https://localhost:8443/mcp" },
					ipv4: { url: "https://127.0.0.1/mcp" },
					ipv6: { url: "https://[::1]/mcp" },
					localhostLookalike: { url: "https://localhost.attacker.example/mcp" },
					ipv4Lookalike: { url: "https://127.0.0.1.attacker.example/mcp" },
				},
			}),
		);

		const report = await inspectMcpServerInventory([cfg]);
		const byName = new Map(report.items.map((item) => [item.name, item]));

		for (const name of ["localhost", "ipv4", "ipv6"]) {
			expect(byName.get(name)?.riskHints).not.toContain("remote_mcp_url");
		}
		for (const name of ["localhostLookalike", "ipv4Lookalike"]) {
			expect(byName.get(name)?.riskHints).toContain("remote_mcp_url");
			expect(byName.get(name)?.status).toBe("unknown");
		}
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

	it("treats an unsupported root shape as an inventory coverage gap", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-mcp-"));
		const cfg = join(dir, "unsupported.json");
		await writeFile(cfg, JSON.stringify({ unrelated: { server: { command: "bash" } } }));

		const report = await inspectMcpServerInventory([cfg]);

		expect(report.items).toHaveLength(0);
		expect(report.sources[0]?.status).toBe("invalid");
		expect(report.coverage.status).toBe("invalid");
	});

	it("accepts an explicitly empty supported server map", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-mcp-"));
		const cfg = join(dir, "empty.json");
		await writeFile(cfg, JSON.stringify({ mcpServers: {} }));

		const report = await inspectMcpServerInventory([cfg]);

		expect(report.sources[0]?.status).toBe("read");
		expect(report.coverage.status).toBe("read");
		expect(report.items).toHaveLength(0);
	});

	it("reports a malformed-only server map as partial coverage", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-mcp-"));
		const cfg = join(dir, "malformed.json");
		await writeFile(cfg, JSON.stringify({ mcpServers: { broken: "not a server record" } }));

		const report = await inspectMcpServerInventory([cfg]);

		expect(report.sources[0]?.status).toBe("read");
		expect(report.items).toHaveLength(0);
		expect(report.coverage.status).toBe("partial");
		expect(report.coverage.serversNotEnumerated).toBe(1);
	});

	it("does not count unusable MCP endpoints as discovered servers", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-mcp-unusable-"));
		const cfg = join(dir, "mcp.json");
		await writeFile(
			cfg,
			JSON.stringify({
				mcpServers: {
					noTransport: { env: { TOKEN: "private" } },
					badUrl: { url: "https://" },
					badCommand: { command: ["node", 7] },
					valid: { command: ["node", "server.js"] },
				},
			}),
		);

		const report = await inspectMcpServerInventory([cfg]);
		expect(report.items.map((item) => item.name)).toEqual(["valid"]);
		expect(report.coverage.status).toBe("partial");
		expect(report.coverage.serversNotEnumerated).toBe(3);
	});

	it("does not call a server known when another config shape declares it malformed", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-mcp-conflict-"));
		const cfg = join(dir, "mcp.json");
		await writeFile(
			cfg,
			JSON.stringify({
				mcpServers: { shared: { command: "node", args: ["server.js"] } },
				servers: { shared: { command: "bash", args: ["--allow-all", 42] } },
			}),
		);

		const report = await inspectMcpServerInventory([cfg]);
		expect(report.items).toHaveLength(0);
		expect(report.coverage.status).toBe("partial");
		expect(report.coverage.serversNotEnumerated).toBe(1);
	});

	describe("Claude Code user config (~/.claude.json)", () => {
		async function claudeJson(content: string): Promise<string> {
			const home = await mkdtemp(join(tmpdir(), "aidr-mcp-claude-home-"));
			const path = join(home, ".claude.json");
			await writeFile(path, content);
			return path;
		}

		it("reads a config without any MCP key as a readable source with zero servers", async () => {
			const cfg = await claudeJson(
				JSON.stringify({ numStartups: 12, theme: "dark", projects: { "/work/app": {} } }),
			);

			const report = await inspectMcpServerInventory([cfg]);

			expect(report.sources).toEqual([{ path: cfg, status: "read" }]);
			expect(report.items).toHaveLength(0);
			expect(report.coverage).toMatchObject({ status: "read", invalidSources: 0 });
		});

		it("reads an empty object as a readable source with zero servers", async () => {
			const cfg = await claudeJson("{}");
			const report = await inspectMcpServerInventory([cfg]);
			expect(report.sources[0]?.status).toBe("read");
			expect(report.coverage.status).toBe("read");
		});

		it("ignores unrelated top-level keys that the generic reader would treat as server maps", async () => {
			const cfg = await claudeJson(JSON.stringify({ servers: "unrelated", mcp: 1 }));
			const report = await inspectMcpServerInventory([cfg]);
			expect(report.sources[0]?.status).toBe("read");
		});

		it("discovers per-project servers labelled with their project", async () => {
			const cfg = await claudeJson(
				JSON.stringify({
					mcpServers: { github: { command: "npx", args: ["-y", "github-mcp"] } },
					projects: {
						"/work/app": {
							allowedTools: [],
							mcpServers: {
								postgres: { command: "npx", args: ["pg-mcp", "postgres://localhost/app"] },
								remote: { type: "http", url: "https://mcp.example.com/mcp" },
							},
						},
						"/work/other": { mcpServers: {} },
						"/work/none": { history: [] },
					},
				}),
			);

			const report = await inspectMcpServerInventory([cfg]);

			expect(report.coverage.status).toBe("read");
			const summary = report.items
				.map((item) => [item.name, item.projectPath ?? null, item.sourcePath])
				.sort();
			expect(summary).toEqual([
				["github", null, cfg],
				["postgres", "/work/app", cfg],
				["remote", "/work/app", cfg],
			]);
			expect(report.items.find((item) => item.name === "remote")?.riskHints).toContain(
				"remote_mcp_url",
			);
		});

		it("dedupes a project server identical to the user-level one but keeps overrides", async () => {
			const github = { command: "npx", args: ["-y", "github-mcp"] };
			const cfg = await claudeJson(
				JSON.stringify({
					mcpServers: { github },
					projects: {
						"/work/same": { mcpServers: { github } },
						"/work/override": {
							mcpServers: { github: { command: "bash", args: ["-c", "github-mcp"] } },
						},
					},
				}),
			);

			const report = await inspectMcpServerInventory([cfg]);

			const githubItems = report.items.filter((item) => item.name === "github");
			expect(githubItems.map((item) => item.projectPath ?? null).sort()).toEqual([
				"/work/override",
				null,
			]);
			expect(githubItems.find((item) => item.projectPath)?.riskHints).toContain(
				"shell_wrapper_command",
			);
			expect(report.coverage.status).toBe("read");
		});

		it("counts malformed project server entries as not enumerated", async () => {
			const cfg = await claudeJson(
				JSON.stringify({
					projects: { "/work/app": { mcpServers: { broken: { env: { TOKEN: "x" } } } } },
				}),
			);
			const report = await inspectMcpServerInventory([cfg]);
			expect(report.sources[0]?.status).toBe("read");
			expect(report.coverage).toMatchObject({ status: "partial", serversNotEnumerated: 1 });
		});

		it.each([
			["malformed JSON", '{"mcpServers": {'],
			["a non-object root", "[]"],
			["a user server map of the wrong type", JSON.stringify({ mcpServers: [] })],
			["a projects map of the wrong type", JSON.stringify({ projects: "x" })],
			["a project entry of the wrong type", JSON.stringify({ projects: { "/w": 1 } })],
			[
				"a project server map of the wrong type",
				JSON.stringify({ projects: { "/w": { mcpServers: "x" } } }),
			],
		])("still reports %s as invalid", async (_label, content) => {
			const cfg = await claudeJson(content);
			const report = await inspectMcpServerInventory([cfg]);
			expect(report.sources[0]?.status).toBe("invalid");
			expect(report.coverage.status).toBe("invalid");
			expect(report.items).toHaveLength(0);
		});
	});

	it("reads known host configs without an MCP key as zero servers, not invalid", async () => {
		const home = await mkdtemp(join(tmpdir(), "aidr-mcp-hosts-"));
		const files: Array<[string, string]> = [
			[join(home, ".cursor", "mcp.json"), "{}"],
			[join(home, ".vscode", "mcp.json"), '{\n  // no servers yet\n  "inputs": []\n}'],
			[join(home, ".config", "opencode", "opencode.json"), '{"$schema": "x", "model": "m"}'],
			[join(home, ".openclaw", "openclaw.json"), '{"gateway": {"port": 1}}'],
			[join(home, "project", ".mcp.json"), "{}"],
			[join(home, ".config", "claude", "claude_desktop_config.json"), '{"theme": "dark"}'],
		];
		for (const [path, content] of files) {
			await mkdir(dirname(path), { recursive: true });
			await writeFile(path, content);
		}

		const report = await inspectMcpServerInventory(files.map(([path]) => path));

		expect(report.sources.map((source) => source.status)).toEqual(files.map(() => "read"));
		expect(report.coverage.status).toBe("read");
		expect(report.items).toHaveLength(0);
	});

	it("keeps wrong-typed server maps and malformed JSON invalid in known host configs", async () => {
		const home = await mkdtemp(join(tmpdir(), "aidr-mcp-hosts-bad-"));
		const cursor = join(home, ".cursor", "mcp.json");
		const vscode = join(home, ".vscode", "mcp.json");
		await mkdir(dirname(cursor), { recursive: true });
		await mkdir(dirname(vscode), { recursive: true });
		await writeFile(cursor, JSON.stringify({ mcpServers: "x" }));
		await writeFile(vscode, '{"servers": {');

		const report = await inspectMcpServerInventory([cursor, vscode]);

		expect(report.sources.map((source) => source.status)).toEqual(["invalid", "invalid"]);
	});

	it("does not call a source complete when a declared server map is malformed", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-mcp-map-"));
		const cfg = join(dir, "mcp.json");
		await writeFile(cfg, JSON.stringify({ mcpServers: "not a map", servers: {} }));

		const report = await inspectMcpServerInventory([cfg]);
		expect(report.items).toHaveLength(0);
		expect(report.sources[0]?.status).toBe("invalid");
		expect(report.coverage.status).toBe("invalid");
		expect(report.coverage.sourcesNotEnumerated).toBe(1);
	});
});
