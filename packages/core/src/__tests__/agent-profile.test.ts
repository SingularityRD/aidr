import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	type AgentProfile,
	type AgentProfileContext,
	type AgentProfileDocument,
	agentProfileVerdict,
	classifyAgentTool,
	evaluateAgentProfile,
	evaluateAgentProfiles,
	mergeAgentProfileVerdict,
	selectAgentProfiles,
	validateAgentProfileDocument,
	validateAgentProfileSource,
} from "../agent-profile.js";
import {
	commandMatchesAllowPrefixes,
	findDeniedPrefix,
	hostMatchesDomain,
	parseShellCommand,
	pathMatchesGlob,
} from "../agent-profile-match.js";
import {
	AGENT_PROFILE_TEMPLATE_NAMES,
	AGENT_PROFILE_TEMPLATES,
	agentProfileTemplateDocument,
} from "../agent-profile-templates.js";
import { extractFromToolCall } from "../extractors.js";
import { normalizeToolEvaluationRequest } from "../tool-normalization.js";
import type { Verdict } from "../types.js";

let root: string;
let workspace: string;
let home: string;
let outside: string;

beforeAll(async () => {
	root = await mkdtemp(join(tmpdir(), "aidr-agent-profile-"));
	workspace = join(root, "repos", "app");
	home = join(root, "home");
	outside = join(root, "elsewhere");
	await mkdir(join(workspace, "src"), { recursive: true });
	await mkdir(join(home, ".ssh"), { recursive: true });
	await mkdir(outside, { recursive: true });
	await writeFile(join(workspace, "src", "index.ts"), "export {};\n");
	await writeFile(join(outside, "notes.txt"), "outside\n");
	// A link inside the workspace that points outside it.
	await symlink(outside, join(workspace, "escape"), "junction");
});

afterAll(async () => {
	await rm(root, { recursive: true, force: true });
});

function env() {
	return { workingDirectory: workspace, home };
}

/** The same normalized shape the evaluator hands to profiles. */
function call(toolName: string, toolInput: Record<string, unknown>) {
	const normalized = normalizeToolEvaluationRequest({
		sessionId: "s",
		toolName,
		toolInput,
		artifacts: extractFromToolCall(toolName, toolInput),
	});
	return {
		toolName: normalized.toolName,
		toolInput: normalized.toolInput,
		artifacts: normalized.artifacts,
	};
}

function profile(overrides: Partial<AgentProfile> = {}): AgentProfile {
	return { name: "test", default: "allow", ...overrides };
}

async function decide(p: AgentProfile, toolName: string, input: Record<string, unknown>) {
	return evaluateAgentProfile(p, call(toolName, input), env());
}

describe("agent profile schema", () => {
	it("validates every shipped template with no diagnostics", () => {
		expect(AGENT_PROFILE_TEMPLATE_NAMES).toEqual([
			"read-only-reviewer",
			"standard-developer",
			"ci-agent",
			"locked-down",
		]);
		for (const name of AGENT_PROFILE_TEMPLATE_NAMES) {
			const result = validateAgentProfileDocument(agentProfileTemplateDocument(name));
			expect(result, name).toMatchObject({ ok: true, diagnostics: [] });
		}
	});

	it("rejects unknown fields, bad actions, relative roots and duplicate names by location", () => {
		const result = validateAgentProfileDocument({
			version: 1,
			default_profile: "missing",
			profiles: [
				{ name: "a", default: "maybe" },
				{ name: "a", default: "deny", files: { read_roots: ["src"] }, surprise: true },
			],
		});
		expect(result.ok).toBe(false);
		const errors = result.ok ? [] : result.errors.join("\n");
		expect(errors).toContain("profiles.0.default: must be one of allow, ask, deny");
		expect(errors).toContain("unsupported field(s) surprise");
		expect(errors).toContain("profiles.1.files.read_roots.0");

		const crossProfile = validateAgentProfileDocument({
			version: 1,
			default_profile: "missing",
			profiles: [
				{ name: "a", default: "deny" },
				{ name: "a", default: "allow" },
			],
		});
		const crossErrors = crossProfile.ok ? "" : crossProfile.errors.join("\n");
		expect(crossErrors).toContain("profiles.1.name: profile names must be unique");
		expect(crossErrors).toContain("default_profile: must name a profile in this document");
	});

	it("parses YAML, refuses aliases and reports allow lists that cannot take effect", () => {
		const yaml = validateAgentProfileSource(
			"version: 1\nprofiles:\n  - name: y\n    default: deny\n    commands:\n      allow_prefixes: [ls]\n",
		);
		expect(yaml).toMatchObject({
			ok: true,
			diagnostics: [{ profile: "y", code: "no_effect" }],
		});
		const aliased = validateAgentProfileSource(
			"version: 1\nx: &a {name: z, default: deny}\nprofiles: [*a]\n",
		);
		expect(aliased.ok).toBe(false);
		expect(validateAgentProfileSource("{").ok).toBe(false);
	});

	it("refuses placeholders other than a leading ${workspace}", () => {
		const result = validateAgentProfileDocument({
			version: 1,
			profiles: [{ name: "p", default: "deny", files: { deny: ["/x/${HOME}/y"] } }],
		});
		expect(result.ok).toBe(false);
	});
});

describe("agent profile matching primitives", () => {
	it("splits shell commands on operators outside quotes", () => {
		expect(parseShellCommand("git status && npm test | tee log; echo 'a;b'")).toEqual({
			complex: false,
			segments: [
				{ text: "git status", writesFile: false },
				{ text: "npm test", writesFile: false },
				{ text: "tee log", writesFile: false },
				{ text: "echo 'a;b'", writesFile: false },
			],
		});
		expect(parseShellCommand("echo $(whoami)").complex).toBe(true);
		expect(parseShellCommand('echo "`id`"').complex).toBe(true);
		expect(parseShellCommand("ls > out.txt").segments[0]?.writesFile).toBe(true);
		expect(parseShellCommand("ls 2>&1 >/dev/null").segments[0]?.writesFile).toBe(false);
	});

	it("allows only when every segment starts with an allowed prefix at a word boundary", () => {
		const allow = ["git status", "ls"];
		expect(commandMatchesAllowPrefixes("git status -s && ls -la", allow).matched).toBe(true);
		expect(commandMatchesAllowPrefixes("git statusx", allow).matched).toBe(false);
		expect(commandMatchesAllowPrefixes("ls; rm -rf build", allow).matched).toBe(false);
		expect(commandMatchesAllowPrefixes("ls $(rm x)", allow).matched).toBe(false);
		expect(commandMatchesAllowPrefixes("FOO=1 ls", allow).matched).toBe(false);
	});

	it("finds deny prefixes through wrappers, quotes, paths and substitutions", () => {
		const deny = ["rm -rf", "curl"];
		for (const command of [
			"rm -rf build",
			"sudo rm -rf build",
			"FOO=1 nohup rm -rf x",
			"/bin/rm -rf x",
			"r'm' -rf x",
			"echo ok && curl https://x",
			"echo $(curl https://x)",
			"echo `curl https://x`",
			"timeout 5 curl https://x",
		]) {
			expect(findDeniedPrefix(command, deny), command).not.toBeNull();
		}
		expect(findDeniedPrefix("rmdir build", deny)).toBeNull();
		expect(findDeniedPrefix("echo curling", deny)).toBeNull();
	});

	it("matches path globs against the path and its ancestors", () => {
		expect(pathMatchesGlob("/h/.ssh/id_rsa", "/h/.ssh", false)).toBe(true);
		expect(pathMatchesGlob("/w/app/.env", "**/.env", false)).toBe(true);
		expect(pathMatchesGlob("/w/app/key.pem", "*.pem", false)).toBe(true);
		expect(pathMatchesGlob("/w/app/src/a.ts", "/w/*/src/**", false)).toBe(true);
		expect(pathMatchesGlob("/w/app/src/a.ts", "/w/*/lib/**", false)).toBe(false);
		expect(pathMatchesGlob("/W/APP/.ENV", "**/.env", true)).toBe(true);
		expect(pathMatchesGlob("C:\\repo\\.env", "C:/repo/.env", true)).toBe(true);
	});

	it("matches domains, wildcard subdomains and IP literals exactly", () => {
		expect(hostMatchesDomain("api.github.com", "github.com")).toBe(true);
		expect(hostMatchesDomain("github.com", "*.github.com")).toBe(false);
		expect(hostMatchesDomain("evilgithub.com", "github.com")).toBe(false);
		expect(hostMatchesDomain("10.0.0.1", "10.0.0.1")).toBe(true);
		expect(hostMatchesDomain("10.0.0.10", "10.0.0.1")).toBe(false);
	});
});

describe("agent profile tool classes", () => {
	it("classifies host tool vocabularies", () => {
		expect(classifyAgentTool("Bash")).toBe("shell");
		expect(classifyAgentTool("Grep")).toBe("file_read");
		expect(classifyAgentTool("MultiEdit")).toBe("file_write");
		expect(classifyAgentTool("WebSearch")).toBe("web_fetch");
		expect(classifyAgentTool("mcp__github__create_issue")).toBe("mcp");
		expect(classifyAgentTool("MCP")).toBe("mcp");
		expect(classifyAgentTool("Task")).toBe("other");
	});

	// Enforcement matrix: each tool class against allow / ask / deny gates.
	const matrix: Array<[string, string, Record<string, unknown>]> = [
		["shell", "Bash", { command: "echo hi" }],
		["file_read", "Read", { file_path: "src/index.ts" }],
		["file_write", "Write", { file_path: "src/new.ts", content: "x" }],
		["web_fetch", "WebFetch", { url: "https://docs.example.com/a" }],
		["mcp", "mcp__docs__search", { query: "x" }],
		["other", "Task", { prompt: "x" }],
	];
	for (const [toolClass, toolName, input] of matrix) {
		for (const action of ["allow", "ask", "deny"] as const) {
			it(`${toolClass} gate ${action}`, async () => {
				const outcome = await decide(
					profile({ default: "allow", tools: { [toolClass]: action } }),
					toolName,
					input,
				);
				expect(outcome.action).toBe(action);
				if (action !== "allow") expect(outcome.rule).toBe(`tools.${toolClass}`);
			});
		}
	}

	it("uses the profile default for unlisted classes and exact tool overrides first", async () => {
		const p = profile({
			default: "deny",
			tools: { shell: "allow" },
			tool_overrides: { Task: "ask" },
		});
		expect((await decide(p, "Read", { file_path: "src/index.ts" })).rule).toBe("default");
		expect(await decide(p, "Task", { prompt: "x" })).toMatchObject({
			action: "ask",
			rule: 'tool_overrides["Task"]',
		});
	});
});

describe("agent profile scope rules", () => {
	it("applies command allow and deny prefixes", async () => {
		const p = profile({
			default: "ask",
			tools: { shell: "allow" },
			commands: { allow_prefixes: ["git status", "npm test"], deny_prefixes: ["git push"] },
		});
		expect((await decide(p, "Bash", { command: "git status" })).action).toBe("allow");
		expect(await decide(p, "Bash", { command: "npm test && git push origin" })).toMatchObject({
			action: "deny",
			rule: 'commands.deny_prefixes["git push"]',
			check: "command",
		});
		expect(await decide(p, "Bash", { command: "npm install left-pad" })).toMatchObject({
			action: "ask",
			rule: "commands.unmatched",
		});
		// argv arrays are normalized to the command line the host executes.
		expect((await decide(p, "shell", { command: ["git", "push"] })).action).toBe("deny");
	});

	it("scopes reads and writes to roots, resolving symlinks and relative paths", async () => {
		const p = profile({
			files: {
				read_roots: ["${workspace}"],
				write_roots: ["${workspace}/src"],
				outside_roots: "deny",
			},
		});
		expect((await decide(p, "Read", { file_path: "src/index.ts" })).action).toBe("allow");
		expect((await decide(p, "Read", { file_path: join(outside, "notes.txt") })).action).toBe(
			"deny",
		);
		// The path is lexically inside the workspace but resolves outside it.
		expect(await decide(p, "Read", { file_path: "escape/notes.txt" })).toMatchObject({
			action: "deny",
			rule: "files.read_roots (outside_roots)",
		});
		expect((await decide(p, "Read", { file_path: "../../../etc/passwd" })).action).toBe("deny");
		expect((await decide(p, "Write", { file_path: "src/new.ts", content: "x" })).action).toBe(
			"allow",
		);
		expect((await decide(p, "Write", { file_path: "README.md", content: "x" })).action).toBe(
			"deny",
		);
		// Search tools without a path search the working directory.
		expect((await decide(p, "Grep", { pattern: "/api/" })).action).toBe("allow");
		expect((await decide(p, "Glob", { pattern: "*.ts", path: outside })).action).toBe("deny");
	});

	it("denies protected paths for every tool, including shell words and MCP arguments", async () => {
		const p = profile({ files: { deny: ["~/.ssh", "**/.env", "*.pem"] } });
		expect(await decide(p, "Read", { file_path: join(home, ".ssh", "id_rsa") })).toMatchObject({
			action: "deny",
			rule: 'files.deny["~/.ssh"]',
		});
		expect((await decide(p, "Edit", { file_path: ".env", new_string: "x" })).action).toBe("deny");
		expect((await decide(p, "Bash", { command: "cat ~/.ssh/id_rsa" })).action).toBe("deny");
		expect((await decide(p, "Bash", { command: "openssl x509 -in server.pem" })).action).toBe(
			"deny",
		);
		expect(
			(await decide(p, "mcp__fs__read_file", { path: join(home, ".ssh", "config") })).action,
		).toBe("deny");
		expect((await decide(p, "Bash", { command: "cat README.md" })).action).toBe("allow");
	});

	it("restricts network destinations for shell and fetch tools but not file content", async () => {
		const p = profile({
			network: { allow_domains: ["github.com"], deny_domains: ["evil.example"], unmatched: "ask" },
		});
		expect((await decide(p, "WebFetch", { url: "https://api.github.com/x" })).action).toBe("allow");
		expect(await decide(p, "WebFetch", { url: "https://docs.example.org" })).toMatchObject({
			action: "ask",
			rule: "network.unmatched",
		});
		expect(await decide(p, "Bash", { command: "curl https://evil.example/x" })).toMatchObject({
			action: "deny",
			rule: 'network.deny_domains["evil.example"]',
		});
		expect(
			(await decide(p, "Write", { file_path: "a.md", content: "see https://docs.example.org" }))
				.action,
		).toBe("allow");
	});

	it("applies MCP per-server and per-tool rules, most specific first", async () => {
		const p = profile({
			tools: { mcp: "allow" },
			mcp: {
				servers: { github: "ask" },
				tools: { github: { get_issue: "allow", delete_repo: "deny" } },
				unmatched: "deny",
			},
		});
		expect((await decide(p, "mcp__github__get_issue", { id: 1 })).action).toBe("allow");
		expect(await decide(p, "mcp__github__create_issue", { title: "x" })).toMatchObject({
			action: "ask",
			rule: 'mcp.servers["github"]',
		});
		expect(await decide(p, "mcp__github__delete_repo", {})).toMatchObject({
			action: "deny",
			rule: 'mcp.tools["github"]["delete_repo"]',
		});
		expect(await decide(p, "mcp__slack__post", { text: "x" })).toMatchObject({
			action: "deny",
			rule: "mcp.unmatched",
		});
		// The host's generic MCP shape (Cursor) identifies the server and tool too.
		expect(
			(await decide(p, "MCP", { server: "github", tool_name: "get_issue", tool_input: {} })).action,
		).toBe("allow");
		// A per-tool allow cannot widen a class gate that denies MCP.
		const gated = { ...p, tools: { mcp: "deny" as const } };
		expect((await decide(gated, "mcp__github__get_issue", {})).action).toBe("deny");
	});

	it("applies the shipped read-only reviewer template", async () => {
		const reviewer = AGENT_PROFILE_TEMPLATES["read-only-reviewer"] as AgentProfile;
		expect((await decide(reviewer, "Bash", { command: "git log --oneline" })).action).toBe("allow");
		expect((await decide(reviewer, "Bash", { command: "git log > out.txt" })).action).toBe("deny");
		expect((await decide(reviewer, "Write", { file_path: "a.ts", content: "x" })).action).toBe(
			"deny",
		);
		expect((await decide(reviewer, "Read", { file_path: "src/index.ts" })).action).toBe("allow");
	});
});

describe("agent profile selection and layering", () => {
	const document: AgentProfileDocument = {
		version: 1,
		default_profile: "fallback",
		profiles: [
			{ name: "fallback", default: "deny" },
			{ name: "claude", applies_to: { connectors: ["claude-code"] }, default: "allow" },
			{
				name: "claude-app",
				applies_to: { connectors: ["claude-code"], repositories: ["**/repos/app"] },
				default: "ask",
			},
			{ name: "codex-anywhere", applies_to: { connectors: ["codex"] }, default: "allow" },
		],
	};

	it("prefers repository scope over connector scope and falls back to default_profile", () => {
		const names = (connector: "claude-code" | "codex" | "cursor", dir: string) =>
			selectAgentProfiles(document, connector, { workingDirectory: dir, home }).map((p) => p.name);
		expect(names("claude-code", workspace)).toEqual(["claude-app"]);
		expect(names("claude-code", join(workspace, "src"))).toEqual(["claude-app"]);
		expect(names("claude-code", outside)).toEqual(["claude"]);
		expect(names("codex", workspace)).toEqual(["codex-anywhere"]);
		expect(names("cursor", workspace)).toEqual(["fallback"]);
	});

	it("never lets a local document widen a managed one", async () => {
		const managed: AgentProfileDocument = {
			version: 1,
			profiles: [{ name: "managed-strict", default: "deny", tools: { file_read: "allow" } }],
		};
		const local: AgentProfileDocument = {
			version: 1,
			profiles: [{ name: "local-open", default: "allow" }],
		};
		const context: AgentProfileContext = {
			connector: "claude-code",
			layers: [
				{ status: "loaded", source: "managed", origin: "bundle", document: managed },
				{ status: "loaded", source: "local", origin: "file", document: local },
			],
		};
		const evaluation = await evaluateAgentProfiles(context, call("Bash", { command: "ls" }), env());
		expect(evaluation).toMatchObject({
			decision: "deny",
			deciding: { profile: "managed-strict", source: "managed", rule: "default" },
		});
		// ...but a local document may narrow a managed allow.
		const narrowing: AgentProfileContext = {
			connector: "claude-code",
			layers: [
				{ status: "loaded", source: "managed", origin: "bundle", document: local },
				{ status: "loaded", source: "local", origin: "file", document: managed },
			],
		};
		const narrowed = await evaluateAgentProfiles(narrowing, call("Bash", { command: "ls" }), env());
		expect(narrowed.deciding).toMatchObject({ source: "local", action: "deny" });
	});

	it("denies every call when the managed document is invalid", async () => {
		const evaluation = await evaluateAgentProfiles(
			{
				connector: "openclaw",
				layers: [{ status: "invalid", source: "managed", origin: "bundle", reason: "x: bad" }],
			},
			call("Read", { file_path: "src/index.ts" }),
			env(),
		);
		const verdict = agentProfileVerdict(evaluation);
		expect(verdict).toMatchObject({
			decision: "deny",
			category: "agent_profile_invalid",
			matchedThreatId: "AGENT-PROFILE-INVALID",
		});
		expect(verdict?.reasons[0]).toContain("invalid (x: bad)");
	});

	it("denies when an explicitly assigned profile is missing", async () => {
		const evaluation = await evaluateAgentProfiles(
			{
				connector: "mcp-gateway",
				profileName: "nope",
				layers: [{ status: "loaded", source: "local", origin: "gw", document }],
			},
			call("mcp__a__b", {}),
			env(),
		);
		expect(evaluation.deciding).toMatchObject({ action: "deny", check: "selection" });
	});
});

describe("merging a profile verdict with detection", () => {
	const threatDeny: Verdict = {
		decision: "deny",
		category: "command_injection",
		confidence: 0.95,
		severity: "critical",
		source: "heuristic",
		artifacts: [],
		matchedThreatId: "CLT-CMD-001",
		reasons: ["threat"],
	};
	const profileAsk: Verdict = { ...threatDeny, decision: "ask", source: "agent_profile" };

	it("keeps deny > ask > allow and never lets a profile soften detection", () => {
		expect(mergeAgentProfileVerdict(threatDeny, profileAsk)).toBe(threatDeny);
		expect(mergeAgentProfileVerdict(threatDeny, null)).toBe(threatDeny);
		const allow: Verdict = { ...threatDeny, decision: "allow", transformedInput: { a: 1 } };
		const merged = mergeAgentProfileVerdict(allow, profileAsk);
		expect(merged.decision).toBe("ask");
		expect(merged.transformedInput).toBeUndefined();
		const tie = mergeAgentProfileVerdict({ ...threatDeny, decision: "ask" }, profileAsk);
		expect(tie.source).toBe("heuristic");
		expect(tie.reasons).toHaveLength(2);
	});
});
