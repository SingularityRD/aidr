/**
 * Tests for `aidr uninstall` (CLI-level managed-hook removal).
 *
 * ## The defect these pin
 *
 * Removal existed only in the fleet layer
 * (`deploy/fleet/unix/remove-managed-hooks.mjs`, `Uninstall-Aidr.ps1`). The CLI
 * registered setup/config/status/scan/collect/discover only, so a customer who
 * installed AIDR through `aidr setup` had no supported local way to remove it,
 * and the managed-only removal semantics were unreachable for them.
 *
 * ## What is asserted
 *
 *  1. Only the hook registrations carrying the installer's `statusMessage`
 *     marker are removed. A customer hook — even one nested in the same entry as
 *     a managed hook — survives with its entry's own fields intact, and the
 *     settings that are NOT hooks (plugins, permissions) survive untouched.
 *  2. The command fails CLOSED with a machine-readable reason when the
 *     installation receipt is absent or does not verify, and changes nothing.
 *  3. A second run removes nothing, writes nothing and adds no backup: the
 *     operation is idempotent rather than "successful" on every invocation.
 *  4. Nothing is ever printed as removed that was not measured as removed, and a
 *     refusal exits non-zero.
 *
 * Every fixture uses a temporary home, so these tests never read or write the
 * developer's real configuration.
 */

import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import uninstallCommand, { uninstallAidr } from "../commands/uninstall.js";
import { MANAGED_HOOK_MARKER } from "../utils/install-hooks.js";

const DIGEST = "3f".repeat(32);
const CONNECTOR_BUNDLES = ["pre-tool-use.cjs", "post-tool-use.cjs", "session-start.cjs"] as const;
const CUSTOMER_HOOK_A = { type: "command", command: "customer-command-a", timeout: 9 };
const CUSTOMER_HOOK_B = { type: "command", command: "customer-command-b" };
const ORIGINAL_CONFIG = '{"policy":"customer-owned","mode":"local"}\n';

let homes: string[] = [];

afterEach(() => {
	for (const home of homes) rmSync(home, { recursive: true, force: true });
	homes = [];
	vi.restoreAllMocks();
});

interface Fixture {
	home: string;
	settingsPath: string;
	receiptPath: string;
	configPath: string;
	connectorPath: string;
	/** Deliberately 4-space indented, so a gratuitous rewrite is detectable. */
	settingsRaw: string;
}

function createHome(): string {
	const home = mkdtempSync(join(tmpdir(), "aidr-uninstall-"));
	homes.push(home);
	return home;
}

function managedHook(home: string, bundle: string): Record<string, unknown> {
	return {
		type: "command",
		command: `"${join(home, "bin", "node")}" "${join(home, ".singularity-aidr", "connectors", "claude", DIGEST, "dist", bundle)}"`,
		timeout: 15,
		statusMessage: MANAGED_HOOK_MARKER,
	};
}

function writeReceipt(home: string, overrides: Record<string, unknown> = {}): string {
	const connectorPath = join(home, ".singularity-aidr", "connectors", "claude", DIGEST);
	const receiptPath = join(home, ".singularity-aidr", "installation.json");
	writeFileSync(
		receiptPath,
		`${JSON.stringify(
			{
				schema_version: 1,
				installed_at: new Date().toISOString(),
				connector: "claude-code",
				artifact_sha256: DIGEST,
				path: connectorPath,
				settings_path: join(home, ".claude", "settings.json"),
				local_canary: "deny",
				native_amsi_probe: "not_applicable",
				host_execution: "unverified",
				...overrides,
			},
			null,
			2,
		)}\n`,
	);
	return receiptPath;
}

function createFixture(): Fixture {
	const home = createHome();
	const connectorPath = join(home, ".singularity-aidr", "connectors", "claude", DIGEST);
	mkdirSync(join(connectorPath, "dist"), { recursive: true });
	for (const bundle of CONNECTOR_BUNDLES) {
		writeFileSync(join(connectorPath, "dist", bundle), "// installed connector bundle\n");
	}
	mkdirSync(join(connectorPath, "resources", "threats"), { recursive: true });
	mkdirSync(join(home, ".claude"), { recursive: true });

	const settings = {
		enabledPlugins: { "customer-plugin@vendor": true },
		permissions: { allow: ["Bash(ls:*)"] },
		hooks: {
			PreToolUse: [
				{
					matcher: "*",
					customFlag: "keep",
					hooks: [managedHook(home, "pre-tool-use.cjs"), CUSTOMER_HOOK_A],
				},
				{ hooks: [CUSTOMER_HOOK_B] },
			],
			PostToolUse: [{ hooks: [managedHook(home, "post-tool-use.cjs")] }],
			SessionStart: [{ hooks: [managedHook(home, "session-start.cjs")] }],
		},
	};
	const settingsPath = join(home, ".claude", "settings.json");
	const settingsRaw = `${JSON.stringify(settings, null, 4)}\n`;
	writeFileSync(settingsPath, settingsRaw);

	const receiptPath = writeReceipt(home);
	const configPath = join(home, ".singularity-aidr", "config.json");
	writeFileSync(configPath, ORIGINAL_CONFIG);
	return { home, settingsPath, receiptPath, configPath, connectorPath, settingsRaw };
}

function backupNames(home: string): string[] {
	return readdirSync(join(home, ".claude")).filter((name) => name.startsWith("settings.json.aidr-uninstall-backup-"));
}

function readSettings(settingsPath: string): Record<string, unknown> {
	return JSON.parse(readFileSync(settingsPath, "utf8")) as Record<string, unknown>;
}

/** Capture `console.log` lines from one command invocation. */
async function runCommand(options: { home: string; json?: boolean }): Promise<string> {
	const previousExitCode = process.exitCode;
	const lines: string[] = [];
	const log = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
		lines.push(args.map((value) => String(value)).join(" "));
	});
	try {
		await uninstallCommand(options);
	} finally {
		log.mockRestore();
		process.exitCode = previousExitCode;
	}
	return lines.join("\n");
}

describe("aidr uninstall", () => {
	it("removes only managed hooks and preserves a customer hook", async () => {
		const fixture = createFixture();

		const report = await uninstallAidr({ home: fixture.home });

		expect(report.outcome).toBe("removed");
		expect(report.changed).toBe(true);
		// Exactly the three managed registrations, reported verbatim.
		expect(report.removed.map((record) => record.event).sort()).toEqual([
			"PostToolUse",
			"PreToolUse",
			"SessionStart",
		]);
		expect(report.removed.every((record) => String(record.command).includes(fixture.connectorPath))).toBe(true);

		const settings = readSettings(fixture.settingsPath);
		const hooks = settings.hooks as Record<string, unknown>;
		// The entry that also held a managed hook keeps its own fields and its
		// customer hook; the entry that held only customer hooks is untouched.
		expect(hooks.PreToolUse).toEqual([
			{ matcher: "*", customFlag: "keep", hooks: [CUSTOMER_HOOK_A] },
			{ hooks: [CUSTOMER_HOOK_B] },
		]);
		// Events that held nothing else are gone rather than left empty.
		expect(hooks.PostToolUse).toBeUndefined();
		expect(hooks.SessionStart).toBeUndefined();
		// Non-hook settings are not part of the operation.
		expect(settings.enabledPlugins).toEqual({ "customer-plugin@vendor": true });
		expect(settings.permissions).toEqual({ allow: ["Bash(ls:*)"] });
		expect(readFileSync(fixture.settingsPath, "utf8")).not.toContain(MANAGED_HOOK_MARKER);

		// The report's "left alone" numbers come from the same measurement.
		expect(report.preserved).toEqual({ entries: 2, hooks: 2, events: ["PostToolUse", "SessionStart"] });

		// Configuration, connector bytes and the receipt are preserved on purpose.
		expect(readFileSync(fixture.configPath, "utf8")).toBe(ORIGINAL_CONFIG);
		expect(existsSync(fixture.receiptPath)).toBe(true);
		for (const bundle of CONNECTOR_BUNDLES) {
			expect(existsSync(join(fixture.connectorPath, "dist", bundle))).toBe(true);
		}

		// The backup is the pre-change file, byte for byte.
		const backups = backupNames(fixture.home);
		expect(backups).toHaveLength(1);
		expect(report.backup_path).toBe(join(fixture.home, ".claude", backups[0] as string));
		expect(readFileSync(report.backup_path as string, "utf8")).toBe(fixture.settingsRaw);
	});

	it("refuses to uninstall when the installation receipt is missing or tampered", async () => {
		const cases: { name: string; prepare: (fixture: Fixture) => void; code: string }[] = [
			{
				name: "receipt missing",
				prepare: (fixture) => unlinkSync(fixture.receiptPath),
				code: "receipt_missing",
			},
			{
				name: "digest not a SHA-256 digest",
				prepare: (fixture) => writeReceipt(fixture.home, { artifact_sha256: "deadbeef" }),
				code: "receipt_digest_invalid",
			},
			{
				name: "canary did not pass",
				prepare: (fixture) => writeReceipt(fixture.home, { local_canary: "allow" }),
				code: "receipt_canary_not_passed",
			},
			{
				name: "connector path outside the managed root",
				prepare: (fixture) => writeReceipt(fixture.home, { path: join(fixture.home, ".claude") }),
				code: "receipt_path_outside_managed_root",
			},
			{
				name: "connector directory renamed away from its digest",
				prepare: (fixture) => writeReceipt(fixture.home, { artifact_sha256: "ab".repeat(32) }),
				code: "receipt_digest_path_mismatch",
			},
			{
				name: "receipt names a different settings file",
				prepare: (fixture) =>
					writeReceipt(fixture.home, { settings_path: join(fixture.home, ".claude", "other.json") }),
				code: "receipt_settings_path_mismatch",
			},
			{
				name: "connector bytes deleted",
				prepare: (fixture) => rmSync(fixture.connectorPath, { recursive: true, force: true }),
				code: "receipt_connector_missing",
			},
			{
				name: "receipt is not JSON",
				prepare: (fixture) => writeFileSync(fixture.receiptPath, "not json at all"),
				code: "receipt_invalid_json",
			},
		];

		for (const testCase of cases) {
			const fixture = createFixture();
			testCase.prepare(fixture);

			const report = await uninstallAidr({ home: fixture.home });

			expect(report.outcome, `${testCase.name}: outcome`).toBe("refused");
			expect(report.reason?.code, `${testCase.name}: reason code`).toBe(testCase.code);
			expect(report.changed, `${testCase.name}: changed`).toBe(false);
			expect(report.removed, `${testCase.name}: removed`).toEqual([]);
			// Fail closed means the customer's file is untouched, not merely
			// "mostly untouched": same bytes, and no backup was even created.
			expect(readFileSync(fixture.settingsPath, "utf8"), `${testCase.name}: settings bytes`).toBe(
				fixture.settingsRaw,
			);
			expect(backupNames(fixture.home), `${testCase.name}: backups`).toEqual([]);
		}
	});

	it("is idempotent when run twice", async () => {
		const fixture = createFixture();

		const first = await uninstallAidr({ home: fixture.home });
		expect(first.outcome).toBe("removed");
		const afterFirst = readFileSync(fixture.settingsPath, "utf8");
		expect(backupNames(fixture.home)).toHaveLength(1);

		const second = await uninstallAidr({ home: fixture.home });

		// A rerun has nothing to remove, so it must not claim a removal, must not
		// rewrite the file and must not accumulate backups.
		expect(second.outcome).toBe("nothing_to_remove");
		expect(second.changed).toBe(false);
		expect(second.removed).toEqual([]);
		expect(second.backup_path).toBeNull();
		expect(second.receipt?.artifact_sha256).toBe(DIGEST);
		expect(readFileSync(fixture.settingsPath, "utf8")).toBe(afterFirst);
		expect(backupNames(fixture.home)).toHaveLength(1);

		const hooks = readSettings(fixture.settingsPath).hooks as Record<string, unknown>;
		expect(hooks.PreToolUse).toEqual([
			{ matcher: "*", customFlag: "keep", hooks: [CUSTOMER_HOOK_A] },
			{ hooks: [CUSTOMER_HOOK_B] },
		]);
	});

	it("refuses a concurrent settings edit without overwriting it", async () => {
		const fixture = createFixture();
		const fs = createRequire(import.meta.url)("node:fs") as typeof import("node:fs");
		const originalWrite = fs.writeFileSync;
		const customerEdit = '{"customerChangedDuringUninstall":true}\n';
		fs.writeFileSync = ((file, data, options) => {
			const result = originalWrite(file, data, options);
			if (String(file).endsWith(`.aidr-${process.pid}.tmp`)) originalWrite(fixture.settingsPath, customerEdit);
			return result;
		}) as typeof fs.writeFileSync;
		syncBuiltinESMExports();
		let report;
		try {
			report = await uninstallAidr({ home: fixture.home });
		} finally {
			fs.writeFileSync = originalWrite;
			syncBuiltinESMExports();
		}
		expect(report?.outcome).toBe("refused");
		expect(report?.reason?.code).toBe("settings_write_failed");
		expect(report?.removed).toEqual([]);
		expect(readFileSync(fixture.settingsPath, "utf8")).toBe(customerEdit);
		expect(backupNames(fixture.home)).toEqual([]);
		expect(existsSync(`${fixture.settingsPath}.aidr-${process.pid}.tmp`)).toBe(false);
	});

	// AIDR-SKIP: AIDR-050 qa-owner - protected Windows directory semantics require a Windows runner.
	it.skipIf(process.platform !== "win32")("rejects a home nested inside a protected Windows directory", async () => {
		const protectedRoot = createHome();
		const home = join(protectedRoot, "nested", "user");
		mkdirSync(home, { recursive: true });
		const previous = process.env.ProgramData;
		process.env.ProgramData = protectedRoot;
		try {
			const report = await uninstallAidr({ home });
			expect(report.outcome).toBe("refused");
			expect(report.reason?.code).toBe("home_invalid");
		} finally {
			if (previous === undefined) delete process.env.ProgramData;
			else process.env.ProgramData = previous;
		}
	});

	it("exits non-zero with a machine-readable refusal and changes nothing", async () => {
		const fixture = createFixture();
		unlinkSync(fixture.receiptPath);

		const output = await runCommand({ home: fixture.home, json: true });

		const report = JSON.parse(output) as { outcome: string; reason?: { code: string }; changed: boolean };
		expect(report.outcome).toBe("refused");
		expect(report.reason?.code).toBe("receipt_missing");
		expect(report.changed).toBe(false);
		expect(readFileSync(fixture.settingsPath, "utf8")).toBe(fixture.settingsRaw);
	});

	it("prints exactly what it removed and what it left alone", async () => {
		const fixture = createFixture();

		const output = await runCommand({ home: fixture.home });

		// The claim and the measurement agree: three removed, two left alone.
		expect(output).toContain("Removed 3 AIDR-managed hook registration(s):");
		expect(output).toContain("Left alone: 2 hook entries and 2 non-AIDR hook registration(s).");
		for (const bundle of CONNECTOR_BUNDLES) {
			expect(output).toContain(bundle);
		}
		expect(output).toContain("Hook events left empty and therefore deleted: PostToolUse, SessionStart");
		// It must never report the customer's own hooks as removed.
		expect(output).not.toContain("customer-command-a");
		expect(output).not.toContain("customer-command-b");
		// Nor name a backup file it did not write.
		const backups = backupNames(fixture.home);
		expect(backups).toHaveLength(1);
		expect(output).toContain("Backup of the previous settings:");
		expect(output).toContain(join(fixture.home, ".claude", backups[0] as string));
		expect(output).toContain("The local CLI credential and its vault item are also preserved");
		expect(output).toContain("use 'aidr config revoke-key' to remove that credential");
		expect(output).toContain("Protection is NOT active for this agent now");
	});

	it("never prints a removal line when nothing was removed", async () => {
		const fixture = createFixture();
		await uninstallAidr({ home: fixture.home });

		const output = await runCommand({ home: fixture.home });

		expect(output).toContain("No AIDR-managed hook entries found; agent settings were left untouched.");
		expect(output).not.toMatch(/Removed \d+ AIDR-managed/);
		expect(output).not.toContain("Backup of the previous settings:");
	});
});
