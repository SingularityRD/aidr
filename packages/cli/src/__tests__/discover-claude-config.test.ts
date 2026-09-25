import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runDiscover } from "../commands/discover.js";

// Unlike discover.test.ts, this suite runs the real core discovery against a
// fixture home directory holding Claude Code's user configuration.

const initialExitCode = process.exitCode;
const previousHome = process.env.HOME;
let home: string;
let claudeJson: string;

function captureJson(): () => { servers: Array<Record<string, unknown>>; [key: string]: unknown } {
	const log = vi.spyOn(console, "log").mockImplementation(() => {});
	return () => JSON.parse(String(log.mock.calls[0]?.[0]));
}

beforeEach(async () => {
	home = await mkdtemp(join(tmpdir(), "aidr-cli-discover-home-"));
	claudeJson = join(home, ".claude.json");
	process.env.HOME = home;
});

afterEach(async () => {
	vi.restoreAllMocks();
	process.env.HOME = previousHome;
	process.exitCode = initialExitCode;
	await rm(home, { recursive: true, force: true });
});

describe("aidr discover with ~/.claude.json", () => {
	it("exits 0 with zero servers for a config that has no mcpServers key", async () => {
		await writeFile(claudeJson, JSON.stringify({ numStartups: 2, projects: { "/w": {} } }));
		const report = captureJson();
		const stderr = vi.spyOn(console, "error").mockImplementation(() => {});

		await runDiscover({ config: ["~/.claude.json"], json: true });

		expect(report()).toMatchObject({
			servers: [],
			sources: [{ path: claudeJson, status: "read" }],
			coverage: { status: "read", invalid_sources: 0 },
		});
		expect(stderr).not.toHaveBeenCalled();
		expect(process.exitCode).toBe(initialExitCode);
	});

	it("lists per-project servers with their project and deduped user-level servers", async () => {
		const shared = { command: "npx", args: ["-y", "github-mcp"] };
		await writeFile(
			claudeJson,
			JSON.stringify({
				mcpServers: { github: shared },
				projects: {
					"/work/app": {
						mcpServers: { github: shared, db: { command: "npx", args: ["pg-mcp"] } },
					},
				},
			}),
		);
		const log = vi.spyOn(console, "log").mockImplementation(() => {});

		await runDiscover({ config: [claudeJson] });

		const text = log.mock.calls.map((call) => String(call[0])).join("\n");
		expect(text).toContain("MCP discovery: 2 configured server(s)");
		expect(text).toContain(`${claudeJson} (project /work/app)`);
		expect(process.exitCode).toBe(initialExitCode);
	});

	it("exits 1 when ~/.claude.json is malformed JSON", async () => {
		await writeFile(claudeJson, '{"projects": {');
		vi.spyOn(console, "log").mockImplementation(() => {});
		const stderr = vi.spyOn(console, "error").mockImplementation(() => {});

		await runDiscover({ config: [claudeJson] });

		expect(stderr).toHaveBeenCalledWith(`Unreadable or unsupported configuration: ${claudeJson}`);
		expect(process.exitCode).toBe(1);
	});
});
