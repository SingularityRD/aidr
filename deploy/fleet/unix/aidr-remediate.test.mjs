/**
 * node --test sibling for deploy/fleet/unix/aidr-remediate.mjs.
 *
 * The invariant under test is the one the endpoint installer's suite already
 * proves for installation and for the fleet remover: AIDR touches ONLY the hook
 * registrations it created (the ones carrying its `statusMessage` marker), and a
 * customer's own hooks survive. Remediation adds a second obligation — it must
 * re-run detection and repair only what is missing, mispointed or duplicated,
 * without re-enabling a host the customer disabled and without rewriting policy.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const remover = join(dirname(fileURLToPath(import.meta.url)), "aidr-remediate.mjs");
const DIGEST = "ab".repeat(32);
const MANAGED_MARKER = "Singularity AIDR managed installation";
const BUNDLES = ["pre-tool-use.cjs", "post-tool-use.cjs", "session-start.cjs"];
const CUSTOMER_HOOK_A = { type: "command", command: "customer-command-a", timeout: 9 };
const CUSTOMER_HOOK_B = { type: "command", command: "customer-command-b" };
// A bundle that consumes stdin and denies — enough for the remediation canary.
const FAKE_BUNDLE =
	'const chunks=[];process.stdin.on("data",(c)=>chunks.push(c));process.stdin.on("end",()=>{process.stdout.write(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny"}}));process.exit(0);});\n';

function temporaryHome(context) {
	const home = mkdtempSync(join(resolve(tmpdir()), "aidr-remediate-"));
	context.after(() => rmSync(home, { recursive: true, force: true }));
	return home;
}

function writeReceipt(home, overrides = {}) {
	const receiptPath = join(home, ".singularity-aidr", "installation.json");
	mkdirSync(dirname(receiptPath), { recursive: true });
	writeFileSync(
		receiptPath,
		`${JSON.stringify(
			{
				schema_version: 1,
				installed_at: new Date().toISOString(),
				connector: "claude-code",
				artifact_sha256: DIGEST,
				path: join(home, ".singularity-aidr", "connectors", "claude", DIGEST),
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

/** A home with a verified receipt, real bundles and a mix of managed + customer hooks. */
function createFixture(context) {
	const home = temporaryHome(context);
	const connectorPath = join(home, ".singularity-aidr", "connectors", "claude", DIGEST);
	mkdirSync(join(connectorPath, "dist"), { recursive: true });
	for (const bundle of BUNDLES) writeFileSync(join(connectorPath, "dist", bundle), FAKE_BUNDLE);
	mkdirSync(join(connectorPath, "resources", "threats"), { recursive: true });
	mkdirSync(join(home, ".claude"), { recursive: true });

	const mispointed = (bundle) => ({
		type: "command",
		command: `"${join(home, "old-node")}" "${join(home, ".singularity-aidr", "connectors", "claude", "dead".repeat(16), "dist", bundle)}"`,
		timeout: 15,
		statusMessage: MANAGED_MARKER,
	});
	const settings = {
		enabledPlugins: { "customer-plugin@vendor": true },
		permissions: { allow: ["Bash(ls:*)"] },
		hooks: {
			PreToolUse: [
				{ matcher: "*", customFlag: "keep", hooks: [mispointed("pre-tool-use.cjs"), CUSTOMER_HOOK_A] },
				{ hooks: [CUSTOMER_HOOK_B] },
			],
			PostToolUse: [{ hooks: [CUSTOMER_HOOK_B] }],
			SessionStart: [{ hooks: [mispointed("session-start.cjs")] }],
		},
	};
	const settingsPath = join(home, ".claude", "settings.json");
	const settingsRaw = `${JSON.stringify(settings, null, 4)}\n`;
	writeFileSync(settingsPath, settingsRaw);
	const receiptPath = writeReceipt(home);
	const configPath = join(home, ".singularity-aidr", "config.json");
	const configRaw = '{"policy":"customer-owned"}\n';
	writeFileSync(configPath, configRaw);
	return { home, connectorPath, settingsPath, settingsRaw, receiptPath, configPath, configRaw };
}

function runRemediate(home, ...extra) {
	return spawnSync(process.execPath, [remover, "--home", home, "--json", ...extra], {
		encoding: "utf8",
		timeout: 60_000,
	});
}

function backups(home) {
	return readdirSync(join(home, ".claude")).filter((name) => name.startsWith("settings.json.aidr-remediate-backup-"));
}

function managedHooks(settings, event) {
	const entries = settings.hooks?.[event];
	if (!Array.isArray(entries)) return [];
	return entries.flatMap((entry) => (Array.isArray(entry?.hooks) ? entry.hooks : [])).filter(
		(hook) => hook?.statusMessage === MANAGED_MARKER,
	);
}

test("remediation repairs only managed hooks and preserves a customer hook", (context) => {
	const fixture = createFixture(context);

	const result = runRemediate(fixture.home);
	assert.equal(result.status, 0, result.stderr || result.stdout);
	const report = JSON.parse(result.stdout);
	assert.equal(report.outcome, "repaired");
	assert.equal(report.canary, "deny");
	assert.equal(report.host_hooks_disabled, false);
	// Two mispointed managed registrations existed; three managed hooks are the
	// converged state, one per event.
	assert.equal(report.removed_managed_hooks, 2);
	assert.equal(report.added_managed_hooks, 3);
	// Three customer registrations exist in the fixture (two in PreToolUse, one
	// in PostToolUse) and every one of them survives.
	assert.equal(report.preserved_customer_hooks, 3);
	assert.deepEqual(
		report.hooks.map((hook) => [hook.event, hook.state]),
		[
			["PreToolUse", "registered"],
			["PostToolUse", "registered"],
			["SessionStart", "registered"],
		],
	);

	const settings = JSON.parse(readFileSync(fixture.settingsPath, "utf8"));
	// The customer hook that shared an entry with a managed hook keeps its entry
	// fields and its hook; the customer-only entry is untouched.
	assert.deepEqual(settings.hooks.PreToolUse[0], { matcher: "*", customFlag: "keep", hooks: [CUSTOMER_HOOK_A] });
	assert.deepEqual(settings.hooks.PreToolUse[1], { hooks: [CUSTOMER_HOOK_B] });
	assert.deepEqual(settings.hooks.PostToolUse[0], { hooks: [CUSTOMER_HOOK_B] });
	// Non-hook configuration is untouched.
	assert.deepEqual(settings.enabledPlugins, { "customer-plugin@vendor": true });
	assert.deepEqual(settings.permissions, { allow: ["Bash(ls:*)"] });

	// Exactly one managed hook per event, pointing at the receipt's connector.
	const expected = { PreToolUse: ["pre-tool-use.cjs", 15], PostToolUse: ["post-tool-use.cjs", 5], SessionStart: ["session-start.cjs", 30] };
	for (const [event, [bundle, timeout]] of Object.entries(expected)) {
		const managed = managedHooks(settings, event);
		assert.equal(managed.length, 1, `${event} must have exactly one managed hook`);
		const hook = managed[0];
		assert.equal(hook.type, "command");
		assert.equal(hook.timeout, timeout);
		assert.ok(
			hook.command.includes(join(fixture.connectorPath, "dist", bundle).replaceAll("\\", "/")),
			`${event} command must point at the installed connector bundle`,
		);
		const entries = settings.hooks[event];
		if (event === "SessionStart") assert.equal(entries.at(-1).matcher, undefined);
		else assert.equal(entries.at(-1).matcher, "*");
	}

	// Policy, connector bytes and the receipt are preserved.
	assert.equal(readFileSync(fixture.configPath, "utf8"), fixture.configRaw);
	assert.equal(existsSync(fixture.receiptPath), true);
	for (const bundle of BUNDLES) assert.equal(existsSync(join(fixture.connectorPath, "dist", bundle)), true);

	// The backup is the pre-remediation file, byte for byte.
	const written = backups(fixture.home);
	assert.equal(written.length, 1);
	assert.equal(report.backup_path, join(fixture.home, ".claude", written[0]));
	assert.equal(readFileSync(report.backup_path, "utf8"), fixture.settingsRaw);
});

test("remediation is idempotent and reports no change on a healthy installation", (context) => {
	const fixture = createFixture(context);
	assert.equal(runRemediate(fixture.home).status, 0);
	const afterFirst = readFileSync(fixture.settingsPath, "utf8");

	const second = runRemediate(fixture.home);

	assert.equal(second.status, 0, second.stderr || second.stdout);
	const report = JSON.parse(second.stdout);
	assert.equal(report.outcome, "no_repair_needed");
	assert.equal(report.backup_path, null);
	assert.equal(report.removed_managed_hooks, 0);
	assert.equal(report.preserved_customer_hooks, 3);
	assert.equal(readFileSync(fixture.settingsPath, "utf8"), afterFirst);
	assert.equal(backups(fixture.home).length, 1);

	// --check on the repaired home reports healthy without writing.
	const check = runRemediate(fixture.home, "--check");
	assert.equal(check.status, 0, check.stderr || check.stdout);
	assert.equal(JSON.parse(check.stdout).outcome, "detection_only");
	assert.equal(readFileSync(fixture.settingsPath, "utf8"), afterFirst);
	assert.equal(backups(fixture.home).length, 1);
});

test("remediation refuses when the installation receipt is missing or tampered", (context) => {
	const cases = [
		{
			name: "missing receipt",
			prepare: (fixture) => rmSync(fixture.receiptPath),
			code: "receipt_missing",
		},
		{
			name: "canary not passed",
			prepare: (fixture) => writeReceipt(fixture.home, { local_canary: "allow" }),
			code: "receipt_canary_not_passed",
		},
		{
			name: "connector path outside the managed root",
			prepare: (fixture) => writeReceipt(fixture.home, { path: join(fixture.home, ".claude") }),
			code: "receipt_path_outside_managed_root",
		},
	];

	for (const testCase of cases) {
		const fixture = createFixture(context);
		testCase.prepare(fixture);

		const result = runRemediate(fixture.home);

		assert.equal(result.status, 1, `${testCase.name}: expected a non-zero exit`);
		const report = JSON.parse(result.stdout);
		assert.equal(report.outcome, "unrepairable", `${testCase.name}: outcome`);
		assert.equal(report.reason.code, testCase.code, `${testCase.name}: reason`);
		assert.equal(readFileSync(fixture.settingsPath, "utf8"), fixture.settingsRaw);
		assert.equal(backups(fixture.home).length, 0, `${testCase.name}: no backup may be written`);
	}
});

test("remediation refuses when the connector bytes are gone or the host is disabled", (context) => {
	const missingBundle = createFixture(context);
	rmSync(join(missingBundle.connectorPath, "dist", "post-tool-use.cjs"));
	const first = runRemediate(missingBundle.home);
	assert.equal(first.status, 1, first.stderr || first.stdout);
	assert.equal(JSON.parse(first.stdout).reason.code, "connector_bundles_missing");
	assert.equal(readFileSync(missingBundle.settingsPath, "utf8"), missingBundle.settingsRaw);
	assert.equal(backups(missingBundle.home).length, 0);

	const disabledHost = createFixture(context);
	const settings = JSON.parse(readFileSync(disabledHost.settingsPath, "utf8"));
	settings.disableAllHooks = true;
	writeFileSync(disabledHost.settingsPath, `${JSON.stringify(settings, null, 2)}\n`);
	const before = readFileSync(disabledHost.settingsPath, "utf8");
	const second = runRemediate(disabledHost.home);
	assert.equal(second.status, 1, second.stderr || second.stdout);
	const report = JSON.parse(second.stdout);
	assert.equal(report.reason.code, "host_hooks_disabled");
	// Re-enabling the host would be a customer configuration change.
	assert.equal(readFileSync(disabledHost.settingsPath, "utf8"), before);
	assert.equal(backups(disabledHost.home).length, 0);
});

test("remediation --check reports an unhealthy install without writing", (context) => {
	const fixture = createFixture(context);

	const result = runRemediate(fixture.home, "--check");

	assert.equal(result.status, 1, result.stderr || result.stdout);
	const report = JSON.parse(result.stdout);
	assert.equal(report.outcome, "detection_only");
	assert.equal(report.reason.code, "detection_unhealthy");
	assert.equal(report.backup_path, null);
	assert.equal(readFileSync(fixture.settingsPath, "utf8"), fixture.settingsRaw);
	assert.equal(backups(fixture.home).length, 0);
});
