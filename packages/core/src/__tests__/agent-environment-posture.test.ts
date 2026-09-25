import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	type AgentEnvironmentOptions,
	inspectAgentEnvironment,
} from "../agent-environment-posture.js";
import { redactRemoteEvent } from "../managed.js";
import { buildAgentPostureFindingEvents, projectPostureFields } from "../posture-events.js";

let home: string;
let project: string;

function write(path: string, content: string): void {
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, content);
}

function scan(overrides: Partial<AgentEnvironmentOptions> = {}) {
	return inspectAgentEnvironment({
		home,
		projectRoot: project,
		env: {},
		uid: 1000,
		platform: "linux",
		dockerSocketPath: join(home, "no-docker.sock"),
		...overrides,
	});
}

function ids(options: Partial<AgentEnvironmentOptions> = {}): string[] {
	return scan(options).findings.map((finding) => `${finding.host}:${finding.id}`);
}

beforeEach(() => {
	home = mkdtempSync(join(tmpdir(), "aidr-agent-posture-home-"));
	project = mkdtempSync(join(tmpdir(), "aidr-agent-posture-project-"));
});

afterEach(() => {
	rmSync(home, { recursive: true, force: true });
	rmSync(project, { recursive: true, force: true });
});

describe("agent environment posture: Claude Code", () => {
	it("flags bypassPermissions, unrestricted shell allow rules and disabled hooks", () => {
		write(
			join(home, ".claude", "settings.json"),
			JSON.stringify({
				permissions: { defaultMode: "bypassPermissions", allow: ["Bash(*)", "Bash", "Read"] },
				disableAllHooks: true,
			}),
		);
		const report = scan();
		const byId = new Map(report.findings.map((finding) => [finding.id, finding]));
		expect(byId.get("permission_bypass_mode")?.severity).toBe("critical");
		expect(byId.get("broad_shell_allow_rule")?.count).toBe(2);
		expect(byId.get("hooks_disabled")?.host).toBe("claude-code");
		expect(byId.get("permission_bypass_mode")?.remediation).toMatch(/defaultMode/);
	});

	it("benign twin: scoped allow rules and default mode produce no finding", () => {
		write(
			join(home, ".claude", "settings.json"),
			JSON.stringify({
				permissions: { defaultMode: "acceptEdits", allow: ["Bash(npm run test:*)", "Read"] },
			}),
		);
		expect(ids()).toEqual([]);
	});

	it("reads project-scoped settings too", () => {
		write(
			join(project, ".claude", "settings.local.json"),
			JSON.stringify({ permissions: { allow: ["Bash(*:*)"] } }),
		);
		expect(ids()).toContain("claude-code:broad_shell_allow_rule");
	});

	it("reports an unparseable settings file as a coverage gap, not as clean", () => {
		write(join(home, ".claude", "settings.json"), "{ not json");
		const report = scan();
		expect(report.unreadable).toContain(join(home, ".claude", "settings.json"));
	});
});

describe("agent environment posture: Codex", () => {
	it("flags approval_policy never and danger-full-access, including profiles", () => {
		write(
			join(home, ".codex", "config.toml"),
			[
				'approval_policy = "never"',
				"[profiles.fast]",
				"sandbox_mode = 'danger-full-access' # yolo",
			].join("\n"),
		);
		const report = scan();
		const byId = new Map(report.findings.map((finding) => [finding.id, finding]));
		expect(byId.get("approval_policy_never")?.host).toBe("codex");
		expect(byId.get("sandbox_full_access")?.severity).toBe("critical");
	});

	it("benign twin: safe values and keys under unrelated tables are ignored", () => {
		write(
			join(home, ".codex", "config.toml"),
			[
				'approval_policy = "on-request"',
				'sandbox_mode = "workspace-write"',
				"[mcp_servers.docs]",
				'approval_policy = "never"',
			].join("\n"),
		);
		expect(ids()).toEqual([]);
	});
});

describe("agent environment posture: OpenCode", () => {
	it("flags permission allow for bash and edit", () => {
		write(
			join(home, ".config", "opencode", "opencode.json"),
			JSON.stringify({ permission: { bash: "allow", edit: "allow", webfetch: "allow" } }),
		);
		const finding = scan().findings.find((item) => item.id === "permission_allow_all");
		expect(finding?.count).toBe(2);
		expect(finding?.evidence.key).toBe("permission.bash, permission.edit");
	});

	it("benign twin: ask or per-pattern permissions produce no finding", () => {
		write(
			join(home, ".config", "opencode", "opencode.json"),
			JSON.stringify({ permission: { bash: { "git status": "allow", "*": "ask" }, edit: "ask" } }),
		);
		expect(ids()).toEqual([]);
	});
});

describe("agent environment posture: hook coverage", () => {
	it("reports a detected connector host without an AIDR hook", () => {
		mkdirSync(join(home, ".codex"), { recursive: true });
		mkdirSync(join(home, ".claude"), { recursive: true });
		const found = ids({ installedConnectors: new Set(["claude-code"]) });
		expect(found).toContain("codex:aidr_hook_missing");
		expect(found).not.toContain("claude-code:aidr_hook_missing");
	});

	it("reports hosts AIDR has no connector for, and only when detected", () => {
		mkdirSync(join(home, ".gemini"), { recursive: true });
		expect(ids()).toEqual(["gemini-cli:no_aidr_connector"]);
		rmSync(join(home, ".gemini"), { recursive: true });
		expect(ids()).toEqual([]);
	});

	it("flags a missing devcontainer only for editor hosts", () => {
		mkdirSync(join(home, ".vscode"), { recursive: true });
		expect(ids()).toContain("environment:no_devcontainer");
		write(join(project, ".devcontainer", "devcontainer.json"), "{}");
		expect(ids()).not.toContain("environment:no_devcontainer");
	});
});

describe("agent environment posture: process environment", () => {
	it("flags root, a writable docker socket and cloud credential names without values", () => {
		const socket = join(home, "docker.sock");
		write(socket, "");
		const report = scan({
			uid: 0,
			dockerSocketPath: socket,
			env: { AWS_SECRET_ACCESS_KEY: "value-that-must-not-leak", KUBECONFIG: "/k", HOME: home },
		});
		const byId = new Map(report.findings.map((finding) => [finding.id, finding]));
		expect(byId.get("running_as_root")).toBeDefined();
		expect(byId.get("docker_socket_writable")).toBeDefined();
		expect(byId.get("cloud_credentials_in_env")?.evidence.names).toEqual([
			"AWS_SECRET_ACCESS_KEY",
			"KUBECONFIG",
		]);
		expect(JSON.stringify(report)).not.toContain("value-that-must-not-leak");
	});

	it("benign twin: unprivileged user, no socket, empty credential variables", () => {
		expect(ids({ env: { AWS_ACCESS_KEY_ID: "  ", PATH: "/usr/bin" } })).toEqual([]);
	});
});

describe("agent environment posture: MCP plaintext secrets", () => {
	const mcpPath = () => join(home, ".cursor", "mcp.json");

	it("counts literal credentials in env and headers without reporting them", () => {
		const token = `ghp_${"a1B2".repeat(9)}`;
		write(
			mcpPath(),
			JSON.stringify({
				mcpServers: {
					github: { command: "npx", env: { GITHUB_TOKEN: token } },
					api: {
						url: "https://mcp.example.com",
						headers: { Authorization: "Bearer abcdefgh12345" },
					},
					clean: { command: "node", env: { API_TOKEN: "${API_TOKEN}", LOG_LEVEL: "debug" } },
				},
			}),
		);
		const report = scan({ mcpConfigPaths: [mcpPath()] });
		const finding = report.findings.find((item) => item.id === "mcp_plaintext_secret");
		expect(finding?.count).toBe(2);
		expect(JSON.stringify(report)).not.toContain(token);
		expect(JSON.stringify(report)).not.toContain("abcdefgh12345");
	});

	it("benign twin: variable references only", () => {
		write(
			mcpPath(),
			JSON.stringify({ mcpServers: { a: { command: "npx", env: { API_KEY: "{env:API_KEY}" } } } }),
		);
		expect(ids({ mcpConfigPaths: [mcpPath()] })).not.toContain("environment:mcp_plaintext_secret");
	});
});

describe("agent posture upload events", () => {
	it("carry host, check id, severity and count only", () => {
		write(
			join(home, ".claude", "settings.json"),
			JSON.stringify({ permissions: { defaultMode: "bypassPermissions" } }),
		);
		const report = scan({ env: { AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE" } });
		const events = buildAgentPostureFindingEvents(report, "20260925scan01");
		expect(events).toHaveLength(2);
		const redacted = events.map((event) => redactRemoteEvent(event, "hash"));
		expect(redacted[0]).toMatchObject({
			type: "agent_posture_finding",
			finding_kind: "agent_config",
			agent_host: "claude-code",
			check_id: "permission_bypass_mode",
			finding_severity: "critical",
			severity: "critical",
			finding_count: 1,
		});
		const serialized = JSON.stringify(redacted);
		expect(serialized).not.toContain(home);
		expect(serialized).not.toContain("AWS_ACCESS_KEY_ID");
		expect(serialized).not.toContain("AKIAIOSFODNN7EXAMPLE");
	});

	it("drops unknown hosts, checks and out-of-range counts at the projection", () => {
		expect(
			projectPostureFields({
				agent_host: "/home/user",
				check_id: "rm -rf",
				finding_count: 1e9,
				finding_kind: "agent_config",
			}),
		).toEqual({ finding_kind: "agent_config" });
	});
});
