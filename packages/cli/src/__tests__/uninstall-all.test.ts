/**
 * `aidr uninstall` removes AIDR completely (PRD-9): the connector of every host,
 * the AIDR-managed hooks, `~/.singularity-aidr` and the AIDR vault items, with
 * operator confirmation, `--keep-data` and `--dry-run`.
 *
 * Every case uses a temporary HOME, fake host CLIs and an in-memory vault, so
 * no real agent host, keyring or user configuration is touched.
 */
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let testHome = "";
vi.mock("node:os", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:os")>();
	return { ...actual, homedir: () => testHome || actual.homedir() };
});

const {
	default: uninstallCommand,
	collectAidrVaultItems,
	uninstallEverything,
} = await import("../commands/uninstall.js");
const { OPERATOR_NONINTERACTIVE_ENV } = await import("../utils/operator-confirm.js");
type SecretStore = import("@singularityrd/aidr-core").SecretStore;

let root = "";
let bin = "";
let env: NodeJS.ProcessEnv = {};

function writeJson(path: string, value: unknown): void {
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function fakeVault(): SecretStore & { revoked: string[] } {
	const revoked: string[] = [];
	return {
		revoked,
		kind: "linux-secret-service",
		location: "os-vault",
		osProtected: true,
		isAvailable: () => true,
		put: () => undefined,
		get: () => null,
		revoke: (id: string) => void revoked.push(id),
	};
}

beforeEach(() => {
	root = mkdtempSync(join(tmpdir(), "aidr-uninstall-all-"));
	testHome = join(root, "home");
	bin = join(root, "bin");
	mkdirSync(testHome, { recursive: true });
	mkdirSync(bin, { recursive: true });
	env = { PATH: bin, XDG_CONFIG_HOME: join(testHome, ".config") };

	const data = join(testHome, ".singularity-aidr");
	// A managed credential reference, an audit-chain root and some local data.
	writeJson(join(data, "config.json"), {
		mode: "managed",
		secret_ref: { store: "linux-secret-service", id: "aidr-0123abcd", created_at: "x" },
		auth: {
			api_key_ref: { store: "linux-secret-service", id: "aidr-managed-key", created_at: "x" },
		},
	});
	writeJson(join(data, "audit-chain", "keys.json"), {
		roots: [{ kid: "root1234", public_key: "p" }],
	});
	writeFileSync(join(data, "audit.jsonl"), '{"decision":"deny"}\n');
	mkdirSync(join(data, "sealed"), { recursive: true });

	// Codex and OpenCode registrations.
	writeJson(join(testHome, ".codex", "hooks.json"), {
		hooks: {
			PreToolUse: [
				{ matcher: "Bash", hooks: [{ type: "command", command: "my-audit" }] },
				{
					matcher: "^(Bash|apply_patch)$",
					hooks: [{ type: "command", command: "aidr-codex-hook" }],
				},
			],
		},
	});
	writeJson(join(testHome, ".config", "opencode", "opencode.json"), {
		plugin: ["@singularityrd/aidr-opencode"],
	});
	writeJson(join(testHome, ".config", "opencode", "package.json"), {
		dependencies: { "@singularityrd/aidr-opencode": "0.6.0" },
	});
});

afterEach(() => {
	rmSync(root, { recursive: true, force: true });
	testHome = "";
	process.exitCode = undefined;
});

describe("aidr uninstall removes every connector and the local data (PRD-9)", () => {
	it("finds every AIDR vault item it can attribute", () => {
		const ids = collectAidrVaultItems(join(testHome, ".singularity-aidr")).map((item) => item.id);
		expect(ids).toEqual(
			expect.arrayContaining([
				"aidr-operator-approval-key",
				"aidr-operator-approval-ledger",
				"aidr-0123abcd",
				"aidr-managed-key",
				"aidr-audit-chain-root-root1234",
			]),
		);
	});

	it("removes the connectors, the vault items and the data directory", async () => {
		const vault = fakeVault();
		const report = await uninstallEverything({ env, resolveVault: () => vault });
		expect(report.outcome).toBe("removed");
		expect(report.connectors.find((c) => c.host === "codex")?.action).toBe("removed");
		expect(report.connectors.find((c) => c.host === "opencode")?.action).toBe("removed");
		expect(report.data.action).toBe("deleted");
		expect(existsSync(join(testHome, ".singularity-aidr"))).toBe(false);
		expect(vault.revoked).toEqual(
			expect.arrayContaining([
				"aidr-operator-approval-key",
				"aidr-operator-approval-ledger",
				"aidr-0123abcd",
				"aidr-managed-key",
				"aidr-audit-chain-root-root1234",
			]),
		);
		// The user's own Codex hook survives.
		const hooks = JSON.parse(readFileSync(join(testHome, ".codex", "hooks.json"), "utf8"));
		expect(hooks.hooks.PreToolUse).toEqual([
			{ matcher: "Bash", hooks: [{ type: "command", command: "my-audit" }] },
		]);

		// Idempotent: a second run has nothing left to do.
		const again = await uninstallEverything({ env, resolveVault: () => vault });
		expect(again.outcome).toBe("nothing_to_remove");
		expect(again.data.action).toBe("absent");
	});

	it("--keep-data removes the connectors but keeps the data and the vault items", async () => {
		const vault = fakeVault();
		const report = await uninstallEverything({ env, keepData: true, resolveVault: () => vault });
		expect(report.outcome).toBe("removed");
		expect(report.data.action).toBe("kept");
		expect(existsSync(join(testHome, ".singularity-aidr", "audit.jsonl"))).toBe(true);
		expect(vault.revoked).toEqual([]);
	});

	it("--host limits the connectors, and data is kept while an unselected one is registered", async () => {
		const vault = fakeVault();
		const report = await uninstallEverything({ env, hosts: ["codex"], resolveVault: () => vault });
		expect(report.connectors.map((c) => c.host)).toEqual(["codex"]);
		expect(report.connectors[0]?.action).toBe("removed");
		expect(readFileSync(join(testHome, ".config", "opencode", "opencode.json"), "utf8")).toContain(
			"aidr-opencode",
		);
		expect(report.data.action).toBe("kept");
		expect(report.data.reason).toContain("OpenCode");
		expect(existsSync(join(testHome, ".singularity-aidr", "config.json"))).toBe(true);
	});

	it("--dry-run changes nothing", async () => {
		const vault = fakeVault();
		const before = readFileSync(join(testHome, ".codex", "hooks.json"), "utf8");
		const report = await uninstallEverything({ env, dryRun: true, resolveVault: () => vault });
		expect(report.outcome).toBe("dry_run");
		expect(report.data.action).toBe("would_delete");
		expect(report.connectors.find((c) => c.host === "codex")?.action).toBe("would_remove");
		expect(readFileSync(join(testHome, ".codex", "hooks.json"), "utf8")).toBe(before);
		expect(existsSync(join(testHome, ".singularity-aidr", "config.json"))).toBe(true);
		expect(vault.revoked).toEqual([]);
	});

	it("keeps the data while a host it cannot remove is still registered, and says so", async () => {
		// OpenClaw is registered but its CLI is not on PATH: a manual step.
		writeJson(join(testHome, ".openclaw", "openclaw.json"), {
			plugins: { entries: { "aidr-openclaw": { enabled: true } } },
		});
		const vault = fakeVault();
		const report = await uninstallEverything({ env, resolveVault: () => vault });
		expect(report.outcome).toBe("partial");
		expect(report.connectors.find((c) => c.host === "openclaw")?.action).toBe("manual");
		expect(report.data.action).toBe("kept");
		expect(report.data.reason).toContain("OpenClaw");
		expect(existsSync(join(testHome, ".singularity-aidr"))).toBe(true);
		expect(vault.revoked).toEqual([]);

		// With the host CLI present the same run completes.
		const cli = join(bin, "openclaw");
		writeFileSync(cli, "#!/bin/sh\nexit 0\n");
		chmodSync(cli, 0o755);
		const done = await uninstallEverything({
			env,
			resolveVault: () => vault,
			run: () => {
				writeJson(join(testHome, ".openclaw", "openclaw.json"), { plugins: { entries: {} } });
				return { status: 0 };
			},
		});
		expect(done.outcome).toBe("removed");
		expect(existsSync(join(testHome, ".singularity-aidr"))).toBe(false);
	});

	it("requires operator confirmation and removes nothing without it", async () => {
		const errors: string[] = [];
		const error = vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
			errors.push(args.map(String).join(" "));
		});
		const output = new PassThrough();
		output.resume();
		try {
			await uninstallCommand(
				{},
				{ env: { ...env }, streams: { input: new PassThrough(), output } },
			);
		} finally {
			error.mockRestore();
		}
		expect(process.exitCode).toBe(1);
		expect(errors.join("\n")).toContain("Nothing was removed");
		expect(existsSync(join(testHome, ".singularity-aidr", "config.json"))).toBe(true);
		expect(readFileSync(join(testHome, ".codex", "hooks.json"), "utf8")).toContain(
			"aidr-codex-hook",
		);
	});

	it("prints what it removed and exits 0 when everything was removed", async () => {
		const lines: string[] = [];
		const log = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
			lines.push(args.map(String).join(" "));
		});
		const vault = fakeVault();
		try {
			await uninstallCommand(
				{ yes: true },
				{
					env: { ...env, [OPERATOR_NONINTERACTIVE_ENV]: "1" },
					resolveVault: () => vault,
				},
			);
		} finally {
			log.mockRestore();
		}
		const text = lines.join("\n");
		expect(process.exitCode).toBeUndefined();
		expect(text).toContain("Codex        removed");
		expect(text).toContain("Local data: deleted");
		expect(text).toContain("Vault items removed:");
		expect(text).toContain("Browser Guard");
		expect(existsSync(join(testHome, ".singularity-aidr"))).toBe(false);
	});
});
