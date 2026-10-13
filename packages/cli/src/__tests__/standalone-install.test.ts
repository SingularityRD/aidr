/**
 * Standalone (desktop installer) installs: `aidr setup` running from the SEA
 * bundle registers that bundle's hook binaries for Claude Code, `aidr
 * uninstall` removes them on the strength of the receipt, `aidr status` ends
 * with a measured verdict and `aidr verify` exercises each registered hook with
 * a canary passed as data.
 *
 * The defect these pin: a customer who installed the standalone bundle had no
 * way to get Claude Code protected (setup only offered a plugin directory),
 * `aidr status` ended without saying what to do next, and nothing exercised
 * the real hook entry point after install.
 *
 * The bundle is a stand-in with shell-script "binaries": the PreToolUse script
 * denies only a pipe-to-shell command, so the canary and its benign twin are
 * both observable. Every home is a temporary directory.
 */

import { createHash } from "node:crypto";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { statusVerdictFor } from "../commands/status.js";
import { uninstallAidr } from "../commands/uninstall.js";
import { verifyHosts } from "../commands/verify.js";
import { installConnectors } from "../utils/connector-install.js";
import { detectConnectorStatuses } from "../utils/connector-status.js";
import { MANAGED_HOOK_MARKER } from "../utils/install-hooks.js";
import { writeSetupLedger } from "../utils/setup-ledger.js";
import { decisionOf, verifyStandaloneBundle } from "../utils/standalone.js";
import { buildStatusVerdict } from "../utils/status-verdict.js";

const posix = process.platform !== "win32";
const dirs: string[] = [];
afterEach(() => {
	for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});
function temp(label: string): string {
	const dir = mkdtempSync(join(tmpdir(), `aidr-standalone-${label}-`));
	dirs.push(dir);
	return dir;
}

const DENY_PIPE_TO_SHELL = `#!/bin/sh
input=$(cat)
case "$input" in
*"| bash"*) printf '%s\\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"blocked"}}' ;;
*) printf '{}\\n' ;;
esac
`;
const ALLOW_ALL = "#!/bin/sh\ncat >/dev/null\nprintf '{}\\n'\n";

function files(root: string, dir = root): string[] {
	return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
		const full = join(dir, entry.name);
		return entry.isDirectory() ? files(root, full) : [relative(root, full).split("\\").join("/")];
	});
}

function writeManifest(root: string): void {
	const listed = files(root)
		.filter((path) => path !== "aidr-artifact.manifest.json")
		.sort()
		.map((path) => ({
			path,
			sha256: createHash("sha256")
				.update(readFileSync(join(root, path)))
				.digest("hex"),
		}));
	writeFileSync(
		join(root, "aidr-artifact.manifest.json"),
		`${JSON.stringify({ schema_version: 1, artifact_id: "claude-code/sea", artifact_version: "0.6.0", files: listed }, null, 2)}\n`,
	);
}

function bundle(preToolUse = DENY_PIPE_TO_SHELL): string {
	const root = join(temp("prefix"), "bundle");
	mkdirSync(join(root, "bin"), { recursive: true });
	mkdirSync(join(root, "dist", "resources", "threats"), { recursive: true });
	writeFileSync(join(root, "dist", "resources", "threats", "rules.yaml"), "- id: T\n");
	writeFileSync(join(root, "bin", "aidr-pre-tool-use"), preToolUse, { mode: 0o755 });
	for (const name of ["aidr", "aidr-post-tool-use", "aidr-session-start"]) {
		writeFileSync(join(root, "bin", name), ALLOW_ALL, { mode: 0o755 });
	}
	writeManifest(root);
	return root;
}

const CUSTOMER_HOOK = { type: "command", command: "customer-audit", timeout: 3 };

function home(settings: Record<string, unknown> = {}): string {
	const dir = temp("home");
	mkdirSync(join(dir, ".claude"), { recursive: true });
	writeFileSync(join(dir, ".claude", "settings.json"), `${JSON.stringify(settings, null, 2)}\n`);
	return dir;
}

const settingsOf = (dir: string) =>
	JSON.parse(readFileSync(join(dir, ".claude", "settings.json"), "utf8"));
const install = (dir: string, root: string) =>
	installConnectors(
		{ home: dir, env: { PATH: process.env.PATH }, version: "0.6.0", standaloneRoot: root },
		{ hosts: ["claude-code"] },
	).find((entry) => entry.host === "claude-code");

describe.skipIf(!posix)("aidr setup from the standalone bundle (Claude Code)", () => {
	it("registers the bundle's hook binaries after a passing canary and writes a receipt", () => {
		const root = bundle();
		const dir = home({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [CUSTOMER_HOOK] }] } });
		const first = install(dir, root);
		expect(first?.action, first?.detail).toBe("installed");
		const settings = settingsOf(dir);
		expect(settings.hooks.PreToolUse[0].hooks).toEqual([CUSTOMER_HOOK]);
		const managed = ["PreToolUse", "PostToolUse", "SessionStart"].map(
			(event) => settings.hooks[event].at(-1).hooks[0],
		);
		expect(managed.map((hook) => hook.statusMessage)).toEqual(Array(3).fill(MANAGED_HOOK_MARKER));
		expect(managed[0].command).toBe(`"${join(root, "bin", "aidr-pre-tool-use")}"`);
		const receipt = JSON.parse(
			readFileSync(join(dir, ".singularity-aidr", "installation.json"), "utf8"),
		);
		expect(receipt).toMatchObject({
			connector: "claude-code",
			install_kind: "sea_bundle",
			path: root,
			local_canary: "deny",
			package_integrity: "digests_verified_unsigned",
		});

		// Idempotent: a rerun writes nothing and adds no backup.
		const before = readdirSync(join(dir, ".claude"));
		expect(install(dir, root)?.action).toBe("already_installed");
		expect(readdirSync(join(dir, ".claude"))).toEqual(before);
	});

	it("refuses a tampered bundle and a bundle whose hook does not deny the canary", () => {
		const tampered = bundle();
		writeFileSync(join(tampered, "bin", "aidr-session-start"), "#!/bin/sh\nexit 0\n");
		const dir = home();
		const refused = install(dir, tampered);
		expect(refused?.action).toBe("failed");
		expect(refused?.detail).toMatch(/does not match its manifest digest/);
		expect(settingsOf(dir)).toEqual({});

		const permissive = install(dir, bundle(ALLOW_ALL));
		expect(permissive?.action).toBe("failed");
		expect(permissive?.detail).toMatch(/returned allow for the deny canary/);
		expect(settingsOf(dir)).toEqual({});
		expect(existsSync(join(dir, ".singularity-aidr", "installation.json"))).toBe(false);
	});

	it("leaves an enabled AIDR plugin alone instead of inspecting every call twice", () => {
		const dir = home({ enabledPlugins: { "aidr@aidr": true } });
		const outcome = install(dir, bundle());
		expect(outcome?.action).toBe("already_installed");
		expect(settingsOf(dir)).toEqual({ enabledPlugins: { "aidr@aidr": true } });
	});

	it("a bundle signature must verify against the embedded release key", () => {
		const root = bundle();
		writeFileSync(
			join(root, "aidr-artifact.manifest.sig"),
			`${Buffer.alloc(64).toString("base64")}\n`,
		);
		const check = verifyStandaloneBundle(root);
		expect(check.ok).toBe(false);
		expect(check.signature).toBe("invalid");
	});
});

describe.skipIf(!posix)("aidr uninstall of a standalone install", () => {
	it("removes exactly the managed hooks named by a standalone receipt", async () => {
		const root = bundle();
		const dir = home({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [CUSTOMER_HOOK] }] } });
		expect(install(dir, root)?.action).toBe("installed");
		const report = await uninstallAidr({ home: dir });
		expect(report.outcome, report.reason?.detail).toBe("removed");
		expect(report.removed).toHaveLength(3);
		expect(settingsOf(dir).hooks).toEqual({
			PreToolUse: [{ matcher: "Bash", hooks: [CUSTOMER_HOOK] }],
		});
	});

	it("refuses, changing nothing, when the receipt's bundle is gone", async () => {
		const root = bundle();
		const dir = home();
		expect(install(dir, root)?.action).toBe("installed");
		rmSync(root, { recursive: true, force: true });
		const raw = readFileSync(join(dir, ".claude", "settings.json"));
		const report = await uninstallAidr({ home: dir });
		expect(report.outcome).toBe("refused");
		expect(report.reason?.code).toBe("receipt_connector_missing");
		expect(readFileSync(join(dir, ".claude", "settings.json"))).toEqual(raw);
	});
});

describe("aidr status verdict", () => {
	const status = (id: string, state: string, extra: Record<string, unknown> = {}) =>
		({ id, label: id, state, detail: `${id} detail`, evidence: [], ...extra }) as never;

	it("splits protected, restart-needed and manual hosts, with the exact command", () => {
		const verdict = buildStatusVerdict(
			[
				status("claude-code", "installed"),
				status("opencode", "installed"),
				status("codex", "runtime_present_not_installed", { remedy: "install aidr-codex-hook" }),
				status("openclaw", "runtime_present_not_installed"),
				status("cursor", "not_detected"),
			],
			{ schema_version: 1, completed_at: "2026-10-13T10:00:00.000Z", registered: ["opencode"] },
		);
		expect(verdict.protected).toEqual(["claude-code"]);
		expect(verdict.restart).toEqual([{ label: "opencode", since: "2026-10-13T10:00:00.000Z" }]);
		expect(verdict.manual).toEqual([
			{ label: "codex", command: "install aidr-codex-hook" },
			{ label: "openclaw", command: "aidr setup --host openclaw" },
		]);
		expect(verdict.ok).toBe(false);
	});

	it("is not ok with nothing registered, and reads the ledger setup wrote", () => {
		expect(buildStatusVerdict([status("cursor", "not_detected")], null).ok).toBe(false);
		const dir = home({
			hooks: {
				PreToolUse: [{ hooks: [{ type: "command", command: '"/opt/x/bin/aidr-pre-tool-use"' }] }],
			},
		});
		writeSetupLedger(dir, ["claude-code"], new Date("2026-10-13T09:00:00.000Z"));
		const verdict = statusVerdictFor(detectConnectorStatuses(dir, {}), dir);
		expect(verdict.restart).toEqual([{ label: "Claude Code", since: "2026-10-13T09:00:00.000Z" }]);
	});
});

describe("aidr verify", () => {
	it("reads every AIDR hook response shape", () => {
		expect(decisionOf('{"hookSpecificOutput":{"permissionDecision":"deny"}}').decision).toBe(
			"deny",
		);
		expect(decisionOf('{"permission":"deny","reason":"x"}').decision).toBe("deny");
		expect(decisionOf('{"decision":"block"}').decision).toBe("deny");
		expect(decisionOf("").decision).toBe("allow");
		expect(decisionOf("not json").decision).toBe("unknown");
	});

	it.skipIf(!posix)("PASSes a hook that denies the canary and allows the benign twin", () => {
		const root = bundle();
		const dir = home();
		expect(install(dir, root)?.action).toBe("installed");
		const results = verifyHosts({ home: dir, env: { PATH: process.env.PATH } });
		const claude = results.find((entry) => entry.host === "claude-code");
		expect(claude?.outcome, claude?.detail).toBe("pass");
		expect(
			results.filter((entry) => entry.host !== "claude-code").map((entry) => entry.outcome),
		).toEqual(Array(5).fill("not_registered"));
	});

	it("FAILs a hook that denies everything and SKIPs in-process plugins", () => {
		const dir = home({
			hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "aidr-hook" }] }] },
		});
		mkdirSync(join(dir, ".config", "opencode", "plugins"), { recursive: true });
		writeFileSync(
			join(dir, ".config", "opencode", "plugins", "aidr.js"),
			"// Singularity AIDR OpenCode plugin\n",
		);
		const seen: string[] = [];
		const results = verifyHosts({
			home: dir,
			env: {},
			run: (_command, payload) => {
				const input = (payload.tool_input as { command: string }).command;
				seen.push(input);
				return { decision: "deny", detail: "internal error" };
			},
		});
		expect(results.find((entry) => entry.host === "claude-code")?.outcome).toBe("fail");
		expect(results.find((entry) => entry.host === "opencode")?.outcome).toBe("skip");
		// The canary went to the hook as data, then the benign twin.
		expect(seen).toEqual([expect.stringMatching(/\| bash$/), "ls"]);
	});
});
