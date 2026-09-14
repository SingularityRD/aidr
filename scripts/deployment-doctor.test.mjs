import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const script = resolve(dirname(fileURLToPath(import.meta.url)), "deployment-doctor.mjs");
const REGIONS = {
	"self-hosted": { supabase_url: null, residency: { declared: true, location: "customer-designated host", note: "fixture declaration" } },
	unassigned: { supabase_url: null, residency: { declared: false, location: "unassigned", note: "fixture declaration" } },
};

/**
 * The doctor is an operational preflight over a prepared directory. These tests
 * write the smallest manifest it reads and assert only the checks under test;
 * every other check fails for this fixture and is deliberately not asserted.
 */
function deploymentDirectory(t, overrides = {}) {
	const directory = mkdtempSync(join(tmpdir(), "aidr-doctor-"));
	t.after(() => rmSync(directory, { recursive: true, force: true }));
	const manifest = {
		schema_version: 1,
		mode: "cloud",
		project_name: "aidr-fixture",
		development: false,
		dashboard_url: "https://console.customer.example",
		supabase_url: "https://api.customer.example",
		region: "self-hosted",
		tenant_region: "self-hosted",
		regions: REGIONS,
		migrations: [],
		artifacts: [],
		...overrides,
	};
	writeFileSync(join(directory, "deployment.json"), `${JSON.stringify(manifest, null, 2)}\n`);
	writeFileSync(join(directory, ".env"), "ANON_KEY=fixture\nSERVICE_ROLE_KEY=fixture\nDISABLE_SIGNUP=true\n");
	writeFileSync(join(directory, ".env.functions"), "AIDR_DELEGATION_ISSUER=https://api.customer.example\n");
	return directory;
}

function ingressUnits(directory) {
	mkdirSync(join(directory, "ingress"), { recursive: true });
	writeFileSync(join(directory, "ingress", "aidr-tls-renew.service"), "[Service]\n");
	writeFileSync(join(directory, "ingress", "aidr-tls-renew.timer"), "[Timer]\n");
}

function doctor(directory) {
	return spawnSync(process.execPath, [script, "--deployment", directory], { encoding: "utf8", timeout: 60_000 });
}

test("fails the tenant region check when the tenant region differs from the deployment region", (t) => {
	const result = doctor(deploymentDirectory(t, { tenant_region: "unassigned" }));
	assert.notEqual(result.status, 0);
	assert.match(result.stdout, /^FAIL tenant declared region matches the deployment region$/m);
});

test("passes the tenant region check when the tenant region matches the deployment region", (t) => {
	const result = doctor(deploymentDirectory(t));
	assert.match(result.stdout, /^PASS tenant declared region matches the deployment region$/m);
});

test("fails until the TLS renewal unit is prepared beside the ingress signer", (t) => {
	const directory = deploymentDirectory(t);
	const label = "TLS renewal unit and timer prepared for the ingress host";
	assert.match(doctor(directory).stdout, new RegExp(`^FAIL ${label}$`, "m"));
	ingressUnits(directory);
	assert.match(doctor(directory).stdout, new RegExp(`^PASS ${label}$`, "m"));
});

/*
 * SIEM delivery retry timer (A4).
 *
 * Without a shipped timer a failed SIEM delivery is never retried. The doctor
 * must report that the kit ships one, and must NOT report the host's scheduler
 * state as a pass it could not verify.
 */
const shippedUnitsLabel = "SIEM delivery retry timer present and wired to the drain worker";
const schedulerLabel = "SIEM delivery timer is enabled in the host scheduler";

test("deployment doctor reports the SIEM delivery timer as shipped and never fakes its install state", (t) => {
	const directory = deploymentDirectory(t);
	// An empty PATH makes every host probe (systemctl, docker) unavailable. That is
	// precisely the "installation state cannot be determined here" case, so the
	// doctor must record it as unverified rather than report a pass it never ran.
	const result = spawnSync(process.execPath, [script, "--deployment", directory], {
		encoding: "utf8",
		timeout: 60_000,
		env: { ...process.env, PATH: "" },
	});
	assert.equal(result.error, undefined);
	assert.match(result.stdout, new RegExp(`^PASS ${shippedUnitsLabel}$`, "m"));
	assert.match(result.stdout, new RegExp(`^UNVERIFIED ${schedulerLabel} \\(`, "m"));
	assert.doesNotMatch(result.stdout, new RegExp(`^PASS ${schedulerLabel}$`, "m"));
	assert.doesNotMatch(result.stdout, new RegExp(`^FAIL ${schedulerLabel}$`, "m"));

	const evidence = JSON.parse(readFileSync(join(directory, "doctor-evidence.json"), "utf8"));
	assert.ok(evidence.checks.includes(shippedUnitsLabel));
	assert.equal(
		evidence.checks.includes(schedulerLabel),
		false,
		"an unanswerable check must never be recorded as passed",
	);
	assert.equal(evidence.failures.includes(schedulerLabel), false);
	// recorded as a pass: the SIEM delivery timer and the retention reaper.
	const unverifiedChecks = (evidence.unverified ?? []).map((entry) => entry.check);
	assert.ok(unverifiedChecks.includes(schedulerLabel));
	assert.ok(
		unverifiedChecks.some((check) => check.startsWith("retention reaper timer not verified")),
		"the retention reaper is a host-scheduler check too and must not be reported as verified",
	);
	assert.equal(evidence.checks.includes(schedulerLabel), false);
	assert.match(evidence.unverified[0].reason, /unavailable|not available|cannot inspect/);
	assert.match(evidence.scope, /not evidence of success/);
});

test("deployment doctor fails a kit that ships no SIEM delivery timer", (t) => {
	// The doctor resolves its shipped units relative to its own location, so a kit
	// without them is exercised by copying the doctor into a throwaway kit tree
	// that has an empty maintenance directory.
	const directory = deploymentDirectory(t);
	const kit = join(directory, "kit");
	mkdirSync(join(kit, "deploy", "maintenance"), { recursive: true });
	mkdirSync(join(kit, "scripts"), { recursive: true });
	copyFileSync(script, join(kit, "scripts", "deployment-doctor.mjs"));

	// The doctor reads `.aidr-deploy` relative to its own working directory, so the
	// throwaway kit carries its own prepared deployment there.
	const deployment = join(kit, ".aidr-deploy");
	mkdirSync(join(deployment, "ingress"), { recursive: true });
	writeFileSync(
		join(deployment, "deployment.json"),
		readFileSync(join(directory, "deployment.json"), "utf8"),
	);
	writeFileSync(join(deployment, ".env"), readFileSync(join(directory, ".env"), "utf8"));
	writeFileSync(
		join(deployment, ".env.functions"),
		readFileSync(join(directory, ".env.functions"), "utf8"),
	);

	const result = spawnSync(process.execPath, [join(kit, "scripts", "deployment-doctor.mjs")], {
		encoding: "utf8",
		timeout: 60_000,
		cwd: kit,
	});
	assert.equal(result.status, 1, "a missing retry template must fail the preflight");
	assert.match(result.stdout, new RegExp(`^FAIL ${shippedUnitsLabel}$`, "m"));
	const evidence = JSON.parse(readFileSync(join(deployment, "doctor-evidence.json"), "utf8"));
	assert.ok(evidence.failures.includes(shippedUnitsLabel));
	assert.equal(evidence.passed, false);
});
