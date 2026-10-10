/**
 * OpenCode MCP server identity from every supported config file: `opencode.json`
 * and `opencode.jsonc` (comments, trailing commas) in the user config dir, the
 * project root and the project's `.opencode` dir. A server declared in any of
 * them must give the tool its canonical `mcp__<server>__<tool>` name, so MCP
 * policy (here `default_action: block`, `unknown_server_action: block`) denies
 * it with POL-MCP-005, the same as for a plain `opencode.json`.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { ApprovalStore, guardToolCall } from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeTmpDir } from "../../../core/src/__tests__/test-utils.js";
import { AidrVerdictBlockError } from "../error.js";
import { createToolHandlers } from "../tool-handler.js";

vi.mock("@singularityrd/aidr-core", async (importOriginal) => {
	const actual = await importOriginal<Record<string, unknown>>();
	return {
		...actual,
		createHostObservation: vi.fn(() => null),
		recordHostObservation: vi.fn(),
		// The real guard, observed so the evaluated tool name can be asserted.
		guardToolCall: vi.fn(actual.guardToolCall as (...args: unknown[]) => unknown),
	};
});

let root: string;
let home: string;
let project: string;

function logger() {
	return { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
}

const JSONC_CONFIG = `{
  // OpenCode config with comments and trailing commas
  "$schema": "https://opencode.ai/config.json",
  /* MCP servers */
  "mcp": {
    "my_docs": {
      "type": "local",
      "command": ["node", "docs-server.js"], // a trailing comment
      "enabled": true,
    },
  },
}
`;

const JSON_CONFIG = JSON.stringify({
	mcp: { my_docs: { type: "local", command: ["node", "docs-server.js"], enabled: true } },
});

function locations(): Record<string, string> {
	return {
		user: join(home, ".config", "opencode"),
		project,
		"project .opencode": join(project, ".opencode"),
	};
}

function writeConfig(dir: string, name: string, content: string): string {
	mkdirSync(dir, { recursive: true });
	const path = join(dir, name);
	writeFileSync(path, content);
	return path;
}

/**
 * AIDR policy: unknown MCP servers and everything not explicitly allowed are
 * blocked; the OpenCode config is the policy's server inventory, so a correctly
 * named call is a known server denied by the default action (POL-MCP-005).
 */
function writePolicy(inventoryPaths: string[]): void {
	writeFileSync(
		join(home, ".singularity-aidr", "config.json"),
		JSON.stringify({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					default_action: "block",
					unknown_server_action: "block",
					inventory_paths: inventoryPaths,
				},
			},
		}),
	);
}

async function callMcpTool(): Promise<unknown> {
	const handlers = createToolHandlers(logger(), new ApprovalStore(), "/threats", "/allowlists", {
		directory: project,
	});
	try {
		await handlers["tool.execute.before"](
			{ tool: "my_docs_read_page", sessionID: "s1", callID: "c1" },
			{ args: { page: "intro" } },
		);
		return null;
	} catch (error) {
		return error;
	}
}

async function lastVerdict(): Promise<{ decision?: string; matchedThreatId?: string | null }> {
	const result = vi.mocked(guardToolCall).mock.results.at(-1);
	const resolved = (await result?.value) as { verdict?: Record<string, unknown> } | undefined;
	return (resolved?.verdict ?? {}) as { decision?: string; matchedThreatId?: string | null };
}

async function expectDeniedAsMcp(error: unknown): Promise<void> {
	expect(evaluatedToolName()).toBe("mcp__my_docs__read_page");
	expect(error).toBeInstanceOf(AidrVerdictBlockError);
	const verdict = await lastVerdict();
	expect(verdict.decision).toBe("deny");
	expect(verdict.matchedThreatId).toBe("POL-MCP-005");
}

function evaluatedToolName(): string | undefined {
	const call = vi.mocked(guardToolCall).mock.calls.at(-1);
	return (call?.[0] as { toolName?: string } | undefined)?.toolName;
}

beforeEach(async () => {
	root = await makeTmpDir();
	home = join(root, "home");
	project = join(root, "project");
	mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
	mkdirSync(project, { recursive: true });
	vi.stubEnv("HOME", home);
	vi.stubEnv("USERPROFILE", home);
	vi.stubEnv("XDG_CONFIG_HOME", join(home, ".config"));
	vi.stubEnv("OPENCODE_CONFIG", "");
	vi.mocked(guardToolCall).mockClear();
});

afterEach(async () => {
	vi.unstubAllEnvs();
	await rm(root, { recursive: true, force: true });
});

describe("OpenCode MCP config discovery", () => {
	for (const [format, name, content] of [
		["JSON", "opencode.json", JSON_CONFIG],
		["JSONC", "opencode.jsonc", JSONC_CONFIG],
	] as const) {
		for (const location of ["user", "project", "project .opencode"] as const) {
			it(`a server declared in ${location} ${name} (${format}) is evaluated as MCP and denied`, async () => {
				writePolicy([writeConfig(locations()[location] as string, name, content)]);
				await expectDeniedAsMcp(await callMcpTool());
			});
		}
	}

	it("reads a custom config named by OPENCODE_CONFIG", async () => {
		const path = writeConfig(join(root, "custom"), "team.jsonc", JSONC_CONFIG);
		vi.stubEnv("OPENCODE_CONFIG", path);
		writePolicy([path]);
		await expectDeniedAsMcp(await callMcpTool());
	});

	it("an unreadable or malformed config does not stop a readable one from naming the server", async () => {
		writeConfig(locations().user as string, "opencode.json", "{ not json");
		// A directory where a config file is expected cannot be read (also as root).
		mkdirSync(join(project, "opencode.jsonc"), { recursive: true });
		writePolicy([writeConfig(join(project, ".opencode"), "opencode.jsonc", JSONC_CONFIG)]);
		await expectDeniedAsMcp(await callMcpTool());
	});

	it("without any config naming the server the tool keeps its host name", async () => {
		writeConfig(locations().user as string, "opencode.jsonc", "{ // broken\n");
		writePolicy([]);
		await callMcpTool();
		expect(evaluatedToolName()).toBe("my_docs_read_page");
	});
});
