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
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const remover = join(dirname(fileURLToPath(import.meta.url)), "aidr-remediate.mjs");
const uninstall = join(dirname(remover), "remove-managed-hooks.mjs");
const DIGEST = "ab".repeat(32);
const MANAGED_MARKER = "Singularity AIDR managed installation";
const BUNDLES = ["pre-tool-use.cjs", "post-tool-use.cjs", "session-start.cjs"];
const CUSTOMER_HOOK_A = { type: "command", command: "customer-command-a", timeout: 9 };
const CUSTOMER_HOOK_B = { type: "command", command: "customer-command-b" };
// The current hook wording, in Turkish: the canary keys on the decision, the
// product prefix and the rule id, so a localized or reworded message still passes.
const CANARY_VERDICT = {
	hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "🛡️ Singularity AIDR bu işlemi engelledi: Uzaktan kod çalıştırma (kural CLT-CMD-001). Yeniden deneme ve engeli aşmaya çalışma; ayrıntılar kullanıcıya gösterildi." },
	systemMessage: "🛡️ Singularity AIDR bu işlemi engelledi.\nNeden: Uzaktan kod çalıştırma (kritik, kural CLT-CMD-001).",
};
const bundleWithVerdict = (verdict) =>
	`process.stdin.resume();process.stdin.on("end",()=>{process.stdout.write(${JSON.stringify(JSON.stringify(verdict))});});\n`;
const FAKE_BUNDLE = bundleWithVerdict(CANARY_VERDICT);

function connectorDigest(root) {
	const files = (directory, prefix) => readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)
		.flatMap((entry) => entry.isDirectory() ? files(join(directory, entry.name), join(prefix, entry.name)) : [join(prefix, entry.name)]);
	const shipped = ["package.json", ...files(join(root, "dist"), "dist"), ...files(join(root, "resources"), "resources")];
	const hash = createHash("sha256");
	for (const file of shipped) hash.update(file.replaceAll("\\", "/")).update("\0").update(readFileSync(join(root, file)));
	return hash.digest("hex");
}

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
function createFixture(context, bundleSource = FAKE_BUNDLE) {
	const home = temporaryHome(context);
	let connectorPath = join(home, ".singularity-aidr", "connectors", "claude", DIGEST);
	mkdirSync(join(connectorPath, "dist"), { recursive: true });
	writeFileSync(join(connectorPath, "package.json"), '{"name":"remediation-fixture","private":true}\n');
	for (const bundle of BUNDLES) writeFileSync(join(connectorPath, "dist", bundle), bundleSource);
	for (const bundle of BUNDLES) writeFileSync(join(connectorPath, "dist", bundle.replace(/\.cjs$/, ".bundle.cjs")), "module.exports = {};\n");
	mkdirSync(join(connectorPath, "resources", "threats"), { recursive: true });
	const digest = connectorDigest(connectorPath);
	const installedPath = join(dirname(connectorPath), digest);
	renameSync(connectorPath, installedPath);
	connectorPath = installedPath;
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
	const receiptPath = writeReceipt(home, { path: connectorPath, artifact_sha256: digest });
	const configPath = join(home, ".singularity-aidr", "config.json");
	const configRaw = '{"policy":"customer-owned"}\n';
	writeFileSync(configPath, configRaw);
	return { home, connectorPath, settingsPath, settingsRaw, receiptPath, configPath, configRaw };
}

function writeHealthySettings(fixture) {
	const settings = JSON.parse(fixture.settingsRaw);
	for (const [index, event] of ["PreToolUse", "PostToolUse", "SessionStart"].entries()) {
		settings.hooks[event] = [{
			...(event === "SessionStart" ? {} : { matcher: "*" }),
			hooks: [{ type: "command", command: `"${process.execPath.replaceAll("\\", "/")}" "${join(fixture.connectorPath, "dist", BUNDLES[index]).replaceAll("\\", "/")}"`,
				timeout: [15, 5, 30][index], statusMessage: MANAGED_MARKER }],
		}];
	}
	writeFileSync(fixture.settingsPath, `${JSON.stringify(settings, null, 2)}\n`);
	return settings;
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
	assert.equal(report.host_hooks_disabled, true);
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

test("remediation recreates missing settings only after a passing connector canary", (context) => {
	const fixture = createFixture(context);
	rmSync(dirname(fixture.settingsPath), { recursive: true });
	const check = runRemediate(fixture.home, "--check");
	assert.equal(check.status, 1, check.stdout);
	assert.equal(existsSync(dirname(fixture.settingsPath)), false);
	const result = runRemediate(fixture.home);
	assert.equal(result.status, 0, result.stdout);
	assert.equal(JSON.parse(result.stdout).backup_path, null);
	const settings = JSON.parse(readFileSync(fixture.settingsPath, "utf8"));
	for (const event of ["PreToolUse", "PostToolUse", "SessionStart"]) assert.equal(managedHooks(settings, event).length, 1);
	assert.equal(readFileSync(fixture.configPath, "utf8"), fixture.configRaw);
});

test("malformed customer settings are refused without any rewrite", (context) => {
	const invalid = ["{", "[]", "null", '{"hooks":null}', '{"hooks":[]}', '{"hooks":{"Stop":{}}}',
		'{"hooks":{"PreToolUse":[null]}}', '{"hooks":{"Stop":[{}]}}', '{"hooks":{"Stop":[{"hooks":["customer"]}]}}',
		'{"disableAllHooks":"true"}'];
	for (const raw of invalid) {
		const fixture = createFixture(context);
		writeFileSync(fixture.settingsPath, raw);
		for (const args of [[], ["--check"]]) {
			const result = runRemediate(fixture.home, ...args);
			assert.equal(result.status, 1, result.stdout);
			assert.equal(JSON.parse(result.stdout).outcome, "unrepairable");
			assert.equal(readFileSync(fixture.settingsPath, "utf8"), raw);
			assert.equal(backups(fixture.home).length, 0);
		}
		const result = spawnSync(process.execPath, [uninstall, "--home", fixture.home], { encoding: "utf8" });
		if (raw !== '{"disableAllHooks":"true"}') assert.notEqual(result.status, 0, raw);
		assert.equal(readFileSync(fixture.settingsPath, "utf8"), raw);
	}
});

test("health detection rejects inert, scoped, asynchronous and malformed managed registrations", (context) => {
	const cases = [
		(entry) => { entry.hooks[0].command = `echo ${entry.hooks[0].command}`; },
		(entry) => { entry.hooks[0].command = entry.hooks[0].command.replace(process.execPath.replaceAll("\\", "/"), "missing-node"); },
		(entry) => { entry.hooks[0].command += " && exit 0"; },
		(entry) => { entry.matcher = "Read"; },
		(entry) => { entry.hooks[0].type = "prompt"; },
		(entry) => { entry.hooks[0].timeout = 0; },
		...[true, "true", 1, {}].map((value) => (entry) => { entry.hooks[0].async = value; }),
		...[true, "true", 1, {}].map((value) => (entry) => { entry.hooks[0].asyncRewake = value; }),
	];
	for (const mutate of cases) {
		const fixture = createFixture(context);
		assert.equal(runRemediate(fixture.home).status, 0);
		const settings = JSON.parse(readFileSync(fixture.settingsPath, "utf8"));
		mutate(settings.hooks.PreToolUse.at(-1));
		const raw = `${JSON.stringify(settings, null, 2)}\n`;
		writeFileSync(fixture.settingsPath, raw);
		const check = runRemediate(fixture.home, "--check");
		assert.equal(check.status, 1, check.stdout);
		assert.equal(JSON.parse(check.stdout).hooks[0].state, "mispointed");
		assert.equal(readFileSync(fixture.settingsPath, "utf8"), raw);
		assert.equal(backups(fixture.home).length, 1);
		const repaired = runRemediate(fixture.home);
		assert.equal(repaired.status, 0, repaired.stdout);
		assert.equal(JSON.parse(repaired.stdout).outcome, "repaired");
		assert.equal(JSON.parse(repaired.stdout).preserved_customer_hooks, 3);
	}
});

test("remediation removes unexpected and duplicate managed hooks while preserving customer hooks", (context) => {
	const fixture = createFixture(context);
	assert.equal(runRemediate(fixture.home).status, 0);
	const settings = JSON.parse(readFileSync(fixture.settingsPath, "utf8"));
	settings.hooks.Stop = [{ customFlag: "keep", hooks: [settings.hooks.PreToolUse.at(-1).hooks[0], CUSTOMER_HOOK_B] }];
	writeFileSync(fixture.settingsPath, `${JSON.stringify(settings)}\n`);
	assert.equal(runRemediate(fixture.home, "--check").status, 1);
	const repaired = runRemediate(fixture.home);
	assert.equal(repaired.status, 0, repaired.stdout);
	assert.deepEqual(JSON.parse(readFileSync(fixture.settingsPath, "utf8")).hooks.Stop, [{ customFlag: "keep", hooks: [CUSTOMER_HOOK_B] }]);
	const next = JSON.parse(readFileSync(fixture.settingsPath, "utf8"));
	next.hooks.PreToolUse.push(next.hooks.PreToolUse.at(-1));
	writeFileSync(fixture.settingsPath, `${JSON.stringify(next)}\n`);
	const check = runRemediate(fixture.home, "--check");
	assert.equal(check.status, 1, check.stdout);
	assert.equal(JSON.parse(check.stdout).hooks[0].state, "duplicated");
	assert.equal(runRemediate(fixture.home).status, 0);
});

test("generic or internal-error deny output cannot pass the local canary, including --check", (context) => {
	const invalid = [
		{ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny" } },
		{ ...CANARY_VERDICT, hookSpecificOutput: { ...CANARY_VERDICT.hookSpecificOutput, permissionDecisionReason: "Internal error: scanner unavailable" } },
		{ ...CANARY_VERDICT, systemMessage: "No detector initialized" },
		// A release-integrity or inspection failure denies everything; it is not a working canary.
		{ ...CANARY_VERDICT, systemMessage: "Singularity AIDR blocked this action because it cannot verify its own installation (release verification key missing)." },
		{ ...CANARY_VERDICT, hookSpecificOutput: { ...CANARY_VERDICT.hookSpecificOutput, hookEventName: "PostToolUse" } },
	];
	for (const verdict of invalid) {
		const fixture = createFixture(context, bundleWithVerdict(verdict));
		writeHealthySettings(fixture);
		const raw = readFileSync(fixture.settingsPath, "utf8");
		for (const args of [[], ["--check"]]) {
			const result = runRemediate(fixture.home, ...args);
			assert.equal(result.status, 1, result.stdout);
			assert.equal(JSON.parse(result.stdout).reason.code, "deny_canary_failed");
			assert.equal(JSON.parse(result.stdout).canary, "failed");
			assert.equal(readFileSync(fixture.settingsPath, "utf8"), raw);
			assert.equal(backups(fixture.home).length, 0);
		}
	}
});

test("installed connector drift is rejected before executing any canary", (context) => {
	for (const file of ["package.json", join("dist", "pre-tool-use.cjs"), join("dist", "post-tool-use.cjs"), join("dist", "session-start.cjs"), join("resources", "threats", "unexpected.json")]) {
		const fixture = createFixture(context);
		writeHealthySettings(fixture);
		const marker = join(fixture.home, "tampered-canary-executed");
		writeFileSync(join(fixture.connectorPath, file), `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "executed");\n${FAKE_BUNDLE}`);
		const raw = readFileSync(fixture.settingsPath, "utf8");
		for (const args of [[], ["--check"]]) {
			const result = runRemediate(fixture.home, ...args);
			assert.equal(result.status, 1, result.stdout);
			assert.equal(JSON.parse(result.stdout).reason.code, "connector_digest_mismatch");
			assert.equal(existsSync(marker), false);
			assert.equal(readFileSync(fixture.settingsPath, "utf8"), raw);
			assert.equal(backups(fixture.home).length, 0);
		}
	}
});

test("remediation preserves concurrent customer edits and removes its temporary file", (context) => {
	for (const phase of ["canary", "temporary"]) {
		for (const missing of [false, true]) {
			const fixture = createFixture(context);
			if (missing) rmSync(fixture.settingsPath);
			const edit = '{"customerChangedDuringRemediation":true}\n';
			const preload = join(fixture.home, "remediation-fault.cjs");
			writeFileSync(preload, `
const fs = require("node:fs");
const child = require("node:child_process");
const { syncBuiltinESMExports } = require("node:module");
const originalWrite = fs.writeFileSync;
const originalSpawn = child.spawnSync;
fs.writeFileSync = (path, data, options) => {
  const result = originalWrite(path, data, options);
  if (${JSON.stringify(phase)} === "temporary" && String(path).endsWith(".tmp")) originalWrite(process.env.AIDR_TEST_SETTINGS, ${JSON.stringify(edit)});
  return result;
};
child.spawnSync = (...args) => {
  const result = originalSpawn(...args);
  if (${JSON.stringify(phase)} === "canary") originalWrite(process.env.AIDR_TEST_SETTINGS, ${JSON.stringify(edit)});
  return result;
};
syncBuiltinESMExports();
`);
			const result = spawnSync(process.execPath, ["--require", preload, remover, "--home", fixture.home, "--json"], {
				encoding: "utf8", timeout: 30_000, env: { ...process.env, AIDR_TEST_SETTINGS: fixture.settingsPath },
			});
			assert.equal(result.status, 1, result.stdout);
			assert.equal(JSON.parse(result.stdout).reason.code, "settings_changed");
			assert.equal(readFileSync(fixture.settingsPath, "utf8"), edit);
			assert.equal(existsSync(`${fixture.settingsPath}.aidr-${result.pid}.tmp`), false);
		}
	}
});

test("settings directory symlinks and special connector entries are refused", (context) => {
	const fixture = createFixture(context);
	const saved = join(fixture.home, "customer-settings");
	renameSync(dirname(fixture.settingsPath), saved);
	symlinkSync(saved, dirname(fixture.settingsPath), process.platform === "win32" ? "junction" : "dir");
	const result = runRemediate(fixture.home);
	assert.equal(result.status, 1, result.stdout);
	assert.equal(JSON.parse(result.stdout).reason.code, "managed_path_not_a_directory");
	const removed = spawnSync(process.execPath, [uninstall, "--home", fixture.home], { encoding: "utf8" });
	assert.notEqual(removed.status, 0);
	assert.equal(readFileSync(join(saved, "settings.json"), "utf8"), fixture.settingsRaw);
	const special = createFixture(context);
	const originalDist = join(special.home, "linked-dist");
	renameSync(join(special.connectorPath, "dist"), originalDist);
	symlinkSync(originalDist, join(special.connectorPath, "dist"), process.platform === "win32" ? "junction" : "dir");
	const probe = runRemediate(special.home);
	assert.equal(probe.status, 1, probe.stdout);
	assert.equal(JSON.parse(probe.stdout).reason.code, "connector_digest_mismatch");
	assert.equal(readFileSync(special.settingsPath, "utf8"), special.settingsRaw);
});
