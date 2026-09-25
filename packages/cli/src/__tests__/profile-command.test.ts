import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	agentProfileTemplateDocument,
	type DetectorProvisionedContext,
} from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runDoctor } from "../commands/doctor.js";
import {
	type ProfileCommandDeps,
	profileListCommand,
	profileShowCommand,
	profileTestCommand,
	profileValidateCommand,
} from "../commands/profile.js";
import type { ConnectorStatus } from "../utils/connector-status.js";

let dir: string;
let profilesPath: string;
let out: string[];
let err: string[];
let managed: DetectorProvisionedContext;

function deps(): ProfileCommandDeps {
	return {
		localPath: profilesPath,
		cwd: dir,
		loadContext: async () => managed,
		print: (line) => out.push(line),
		printError: (line) => err.push(line),
	};
}

function writeProfiles(document: unknown): void {
	writeFileSync(profilesPath, JSON.stringify(document));
}

beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "aidr-profile-cli-"));
	mkdirSync(join(dir, "repo"), { recursive: true });
	profilesPath = join(dir, "agent-profiles.json");
	out = [];
	err = [];
	managed = {};
	process.exitCode = undefined;
	// Doctor reads the approval store and audit log under HOME; keep them isolated.
	vi.stubEnv("HOME", dir);
});

afterEach(() => {
	vi.unstubAllEnvs();
	process.exitCode = undefined;
	rmSync(dir, { recursive: true, force: true });
});

describe("aidr profile", () => {
	it("shows every shipped template as a valid document", async () => {
		for (const name of ["read-only-reviewer", "standard-developer", "ci-agent", "locked-down"]) {
			out = [];
			await profileShowCommand(name, { template: true }, deps());
			const file = join(dir, `${name}.json`);
			writeFileSync(file, out.join("\n"));
			out = [];
			await profileValidateCommand(file, {}, deps());
			expect(out[0], name).toContain("is valid: 1 profile(s)");
		}
		expect(process.exitCode).toBeUndefined();
		await profileShowCommand("nope", { template: true }, deps());
		expect(process.exitCode).toBe(1);
	});

	it("validates the local document and reports errors by location", async () => {
		writeProfiles({ version: 1, profiles: [{ name: "x", default: "perhaps" }] });
		await profileValidateCommand(undefined, {}, deps());
		expect(process.exitCode).toBe(1);
		expect(out.join("\n")).toContain("profiles.0.default: must be one of allow, ask, deny");
	});

	it("lists local and managed profiles and flags an invalid managed section", async () => {
		writeProfiles(agentProfileTemplateDocument("standard-developer"));
		managed = {
			agentProfiles: {
				connector: "codex",
				layers: [{ status: "invalid", source: "managed", origin: "bundle", reason: "bad" }],
			},
		};
		await profileListCommand({}, deps());
		const text = out.join("\n");
		expect(text).toContain("standard-developer  default=ask");
		expect(text).toContain("INVALID — every call is denied: bad");
		expect(text).toContain("Templates: read-only-reviewer");
		expect(process.exitCode).toBe(1);
	});

	it("dry-runs a tool call and names the deciding rule", async () => {
		writeProfiles(agentProfileTemplateDocument("read-only-reviewer"));
		await profileTestCommand(
			JSON.stringify({ tool_name: "Bash", tool_input: { command: "git push origin main" } }),
			{ file: profilesPath, cwd: join(dir, "repo") },
			deps(),
		);
		const text = out.join("\n");
		expect(text).toContain("Profiles: read-only-reviewer (local)");
		expect(text).toContain("Profile decision: DENY");
		expect(text).toContain('Rule: commands.deny_prefixes["git push"]');

		out = [];
		const callFile = join(dir, "call.json");
		writeFileSync(callFile, JSON.stringify({ toolName: "Read", toolInput: { file_path: "a.ts" } }));
		await profileTestCommand(
			"@call.json",
			{ file: profilesPath, json: true, cwd: join(dir, "repo") },
			deps(),
		);
		expect(JSON.parse(out.join("\n"))).toMatchObject({
			decision: "allow",
			connector: "claude-code",
		});
	});

	it("uses the installed (managed) profiles when no file is given", async () => {
		const document = agentProfileTemplateDocument("locked-down");
		if (!document) throw new Error("template missing");
		managed = {
			agentProfiles: {
				connector: "codex",
				layers: [{ status: "loaded", source: "managed", origin: "bundle", document }],
			},
		};
		await profileTestCommand(
			'{"tool_name":"shell","tool_input":{"command":["ls"]}}',
			{ connector: "codex", json: true },
			deps(),
		);
		expect(JSON.parse(out.join("\n"))).toMatchObject({
			decision: "deny",
			deciding: { profile: "locked-down", source: "managed", rule: "tools.shell" },
		});
	});

	it("rejects malformed input and unknown connectors", async () => {
		await profileTestCommand("not json", {}, deps());
		expect(err.join("\n")).toContain("Invalid tool call");
		await profileTestCommand("{}", { connector: "vim" }, deps());
		expect(err.join("\n")).toContain("Unknown connector");
		expect(process.exitCode).toBe(1);
	});
});

describe("aidr doctor agent profile check", () => {
	const connectors = (): ConnectorStatus[] => [
		{ id: "opencode", label: "OpenCode", state: "installed", detail: "test", evidence: [] },
	];

	it("fails when the local document is invalid and was not loaded", async () => {
		writeProfiles({ version: 1, profiles: [] });
		const report = await runDoctor({
			connectors,
			loadDetectors: async () => ({}),
			agentProfilesPath: profilesPath,
			configPath: join(dir, "missing-config.json"),
		});
		const check = report.checks.find((c) => c.id === "agent_profiles");
		expect(check?.status).toBe("fail");
		expect(check?.summary).toContain("were NOT loaded");
		expect(report.ok).toBe(false);
	});

	it("reports loaded local and managed profiles", async () => {
		writeProfiles(agentProfileTemplateDocument("ci-agent"));
		const document = agentProfileTemplateDocument("locked-down");
		if (!document) throw new Error("template missing");
		const report = await runDoctor({
			connectors,
			loadDetectors: async () => ({
				agentProfiles: {
					connector: "opencode",
					layers: [{ status: "loaded", source: "managed", origin: "bundle", document }],
				},
			}),
			agentProfilesPath: profilesPath,
			configPath: join(dir, "missing-config.json"),
		});
		const check = report.checks.find((c) => c.id === "agent_profiles");
		expect(check?.status).toBe("ok");
		expect(check?.summary).toContain("1 local profile(s); managed profiles for opencode");
	});
});
