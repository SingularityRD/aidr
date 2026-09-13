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
