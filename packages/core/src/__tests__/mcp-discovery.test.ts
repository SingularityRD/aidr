import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";
import { discoverMcpServers } from "../mcp-discovery.js";

describe("MCP discovery evidence", () => {
	it("fingerprints configuration changes without exporting credentials", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-discover-"));
		try {
			const path = join(dir, "mcp.json");
			const config = {
				mcp: {
					local: { command: ["bash", "--allow-all", "private-secret"] },
					remote: { url: "https://user:private-secret@mcp.example/tool?key=private-secret" },
				},
			};
			await writeFile(path, JSON.stringify(config));
			const first = await discoverMcpServers([path]);
			expect(first.servers[0]?.risk_hints).toContain("shell_wrapper_command");
			expect(first.servers[0]?.inventory_id).toMatch(/^[0-9a-f]{64}$/);
			expect(JSON.stringify(first)).not.toContain("private-secret");
			expect(first.servers[1]?.endpoint).toBe("https://mcp.example");
			config.mcp.local.command.push("changed");
			await writeFile(path, JSON.stringify(config));
			const changed = await discoverMcpServers([path]);
			expect(changed.servers[0]?.configuration_sha256).not.toBe(
				first.servers[0]?.configuration_sha256,
			);
			expect(changed.servers[0]?.inventory_id).toBe(first.servers[0]?.inventory_id);
			await writeFile(path, "{broken");
			expect((await discoverMcpServers([path])).sources[0]?.status).toBe("invalid");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("reads a JSONC configuration with comments and a trailing comma", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-discover-jsonc-"));
		try {
			const path = join(dir, "mcp.json");
			// The shape of the `.vscode/mcp.json` family: line comments, a block
			// comment and trailing commas, plus `//` and `,` inside string values.
			await writeFile(
				path,
				[
					"{",
					"  // VS Code-style MCP hosts accept comments",
					'  "servers": {',
					'    "filesystem": {',
					'      "command": "bash",',
					'      "args": ["--allow-all", "/"], // risky wrapper',
					"    },",
					"  },",
					"  /* a block comment */",
					'  "notes": "see https://example.test/a//b, then c,",',
					"}",
				].join("\n"),
			);
			const report = await discoverMcpServers([path]);
			expect(report.sources[0]?.status).toBe("read");
			expect(report.coverage.status).toBe("read");
			expect(report.coverage.invalid_sources).toBe(0);
			expect(report.coverage.servers_not_enumerated).toBe(0);
			expect(report.servers).toHaveLength(1);
			expect(report.servers[0]?.name).toBe("filesystem");
			expect(report.servers[0]?.risk_hints).toContain("shell_wrapper_command");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("reports an unreadable inventory file as a coverage gap instead of an empty inventory", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-discover-gap-"));
		try {
			const path = join(dir, "mcp.json");
			// Truncated mid-document: no tolerant reader may accept this.
			await writeFile(path, '{ "servers": { "filesystem": { "command": "bash" ');
			const report = await discoverMcpServers([path]);
			expect(report.servers).toHaveLength(0);
			expect(report.sources[0]?.status).toBe("invalid");
			expect(report.coverage.status).toBe("invalid");
			expect(report.coverage.read_sources).toBe(0);
			expect(report.coverage.invalid_sources).toBe(1);
			expect(report.coverage.sources_not_enumerated).toBe(1);
			expect(report.coverage.status).not.toBe("read");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("distinguishes a partial inventory from a complete or empty one", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-discover-partial-"));
		try {
			const good = join(dir, "good.json");
			const broken = join(dir, "broken.json");
			await writeFile(
				good,
				JSON.stringify({
					mcpServers: { ok: { command: "node" }, malformed: "not a server record" },
				}),
			);
			await writeFile(broken, '{ "mcpServers": { "truncated":');
			const report = await discoverMcpServers([good, broken, join(dir, "absent.json")]);
			expect(report.servers.map((server) => server.name)).toEqual(["ok"]);
			expect(report.coverage.status).toBe("partial");
			expect(report.coverage.total_sources).toBe(3);
			expect(report.coverage.read_sources).toBe(1);
			expect(report.coverage.invalid_sources).toBe(1);
			expect(report.coverage.missing_sources).toBe(1);
			// A malformed record inside a readable file is countable; an unreadable
			// source is not, so it is reported as an unenumerated source instead.
			expect(report.coverage.servers_not_enumerated).toBe(1);
			expect(report.coverage.sources_not_enumerated).toBe(1);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("binds stable IDs to canonical source and configured alias", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-discover-id-"));
		try {
			const firstPath = join(dir, "first.json");
			const secondPath = join(dir, "second.json");
			await writeFile(
				firstPath,
				JSON.stringify({
					mcpServers: {
						shared: { command: "node", args: ["server.js"] },
						alias: { command: "node", args: ["server.js"] },
					},
				}),
			);
			await writeFile(
				secondPath,
				JSON.stringify({
					mcpServers: {
						shared: { command: "node", args: ["server.js"] },
					},
				}),
			);
			const first = await discoverMcpServers([firstPath, secondPath]);
			expect(first.servers).toHaveLength(3);
			const [shared, alias, otherSource] = first.servers;
			expect(new Set(first.servers.map((server) => server.inventory_id)).size).toBe(3);
			expect(shared?.configuration_sha256).toBe(alias?.configuration_sha256);
			expect(shared?.configuration_sha256).toBe(otherSource?.configuration_sha256);
			expect(shared?.inventory_id).not.toBe(alias?.inventory_id);
			expect(shared?.inventory_id).not.toBe(otherSource?.inventory_id);
			const relativeReport = await discoverMcpServers([relative(process.cwd(), firstPath)]);
			expect(relativeReport.servers[0]?.inventory_id).toBe(shared?.inventory_id);
			await writeFile(
				firstPath,
				JSON.stringify({
					mcpServers: {
						renamed: { command: "node", args: ["server.js"] },
					},
				}),
			);
			const renamed = await discoverMcpServers([firstPath]);
			expect(renamed.servers[0]?.inventory_id).not.toBe(shared?.inventory_id);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});
});
