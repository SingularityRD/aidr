import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const script = resolve(dirname(fileURLToPath(import.meta.url)), "deployment-prepare.mjs");
const dashboardUrl = "https://console.customer.example";
const supabaseUrl = "https://api.customer.example";

function inTemporaryDirectory(run) {
	const directory = mkdtempSync(join(tmpdir(), "aidr-deployment-preflight-"));
	try { return run(directory); }
	finally {
		assert.equal(dirname(realpathSync(directory)), realpathSync(tmpdir()));
		rmSync(directory, { recursive: true, force: true });
	}
}

function prepare(output, ...options) {
	return spawnSync(process.execPath, [script, "--output", output, "--dashboard-url", dashboardUrl, "--supabase-url", supabaseUrl, ...options], {
		encoding: "utf8", timeout: 60_000,
	});
}

test("invalid cloud ingress and project inputs leave no partial installation or secrets", () => {
	inTemporaryDirectory((directory) => {
		const cases = [
			["public API proxy loop", ["--mode", "cloud", "--device-start-upstream-url", "https://api.customer.example/functions/v1/device-start"]],
			["insecure device-start upstream", ["--mode", "cloud", "--device-start-upstream-url", "http://api.customer.example/functions/v1/device-start"]],
			["wrong device-start route", ["--mode", "cloud", "--device-start-upstream-url", "https://project.supabase.co/functions/v1/other"]],
			["ignored self-hosted override", ["--mode", "self-hosted", "--device-start-upstream-url", "https://api.customer.example/functions/v1/device-start"]],
			["invalid Compose project", ["--mode", "cloud", "--project-name", "../other"]],
		];
		for (const [index, [label, options]] of cases.entries()) {
			const output = join(directory, `case-${index}`);
			const result = prepare(output, ...options);
			assert.notEqual(result.status, 0, `${label} unexpectedly succeeded`);
			assert.equal(existsSync(output), false, `${label} left a partial installation`);
		}
	});
});

test("cloud ingress upstream uses a provider origin behind the public API proxy", () => {
	inTemporaryDirectory((directory) => {
		const output = join(directory, "cloud");
		const upstream = "https://project.supabase.co/functions/v1/device-start";
		const result = prepare(output, "--mode", "cloud", "--device-start-upstream-url", upstream);
		assert.equal(result.status, 0, result.stderr);
		const ingressEnv = readFileSync(join(output, ".env.ingress"), "utf8");
		assert.match(ingressEnv, /^AIDR_DEVICE_START_UPSTREAM_URL=https:\/\/project\.supabase\.co\/functions\/v1\/device-start$/m);
		const deployment = JSON.parse(readFileSync(join(output, "deployment.json"), "utf8"));
		assert.equal(deployment.supabase_url, supabaseUrl);
	});
});

/*
 * The deployment doctor performs all of its work at module load against a prepared
 * deployment directory, so it has no test file of its own; its SIEM delivery timer check
 * is covered here, in the closest existing deployment-script test. Without that timer the
 * customer has no retries for a failed SIEM delivery, which is exactly what the check must
 * make visible rather than let pass silently.
 */

const doctorScript = resolve(dirname(fileURLToPath(import.meta.url)), "deployment-doctor.mjs");
const siemUnitNames = ["aidr-siem-delivery.service", "aidr-siem-delivery.timer"];
const shippedUnitsLabel = "SIEM delivery retry timer present and wired to the drain worker";
const schedulerLabel = "SIEM delivery timer is enabled in the host scheduler";

/**
 * Build a throwaway kit (the doctor resolves its shipped units relative to its own
 * location) plus a prepared deployment directory, and run the real doctor over it.
 */
function runDoctorFixture(directory, { units }) {
	const kit = join(directory, "kit");
	mkdirSync(join(kit, "scripts"), { recursive: true });
	copyFileSync(doctorScript, join(kit, "scripts", "deployment-doctor.mjs"));
	if (units) {
		mkdirSync(join(kit, "deploy", "maintenance"), { recursive: true });
		for (const name of siemUnitNames) {
			copyFileSync(join(dirname(doctorScript), "..", "deploy", "maintenance", name), join(kit, "deploy", "maintenance", name));
		}
	}
	const deployment = join(directory, "deployment");
	mkdirSync(join(deployment, "ingress"), { recursive: true });
	writeFileSync(join(deployment, "ingress", "device-start.mjs"), "");
	writeFileSync(
		join(deployment, "deployment.json"),
		JSON.stringify({
			schema_version: 1,
			project_name: "customer-project",
			mode: "cloud",
			development: true,
			dashboard_url: "http://localhost:8080",
			supabase_url: "http://localhost:8000",
			migrations: [],
		}),
	);
	writeFileSync(join(deployment, ".env"), "ANON_KEY=fixture-anon-key\nSERVICE_ROLE_KEY=fixture-service-key\nDISABLE_SIGNUP=true\n");
	const ingressSecret = "fixture-ingress-secret".padEnd(40, "x");
	writeFileSync(join(deployment, ".env.functions"), `AIDR_DEVICE_START_INGRESS_SECRET=${ingressSecret}\n`);
	writeFileSync(
		join(deployment, ".env.ingress"),
		[
			`AIDR_DEVICE_START_INGRESS_SECRET=${ingressSecret}`,
			`AIDR_DEVICE_START_PROXY_TOKEN=${"p".repeat(40)}`,
			"AIDR_DEVICE_START_UPSTREAM_URL=https://api.customer.example/functions/v1/device-start",
		].join("\n") + "\n",
	);
	// An empty PATH makes every host probe (systemctl, docker) unavailable. That is
	// precisely the "installation state cannot be determined here" case, so the doctor
	// must record it as unverified instead of reporting a pass it never verified.
	const result = spawnSync(process.execPath, [join(kit, "scripts", "deployment-doctor.mjs"), "--deployment", deployment], {
		encoding: "utf8",
		timeout: 60_000,
		env: { ...process.env, PATH: "" },
	});
	return { result, deployment };
}

test("deployment doctor reports the SIEM delivery timer as shipped and never fakes its install state", () => {
	inTemporaryDirectory((directory) => {
		const { result, deployment } = runDoctorFixture(directory, { units: true });
		assert.equal(result.error, undefined);
		assert.match(result.stdout, new RegExp(`^PASS ${shippedUnitsLabel}$`, "m"));
		assert.match(result.stdout, new RegExp(`^UNVERIFIED ${schedulerLabel} \\(`, "m"));
		assert.doesNotMatch(result.stdout, new RegExp(`^PASS ${schedulerLabel}$`, "m"));
		assert.doesNotMatch(result.stdout, new RegExp(`^FAIL ${schedulerLabel}$`, "m"));

		const evidence = JSON.parse(readFileSync(join(deployment, "doctor-evidence.json"), "utf8"));
		assert.ok(evidence.checks.includes(shippedUnitsLabel));
		assert.equal(evidence.checks.includes(schedulerLabel), false, "an unanswerable check must never be recorded as passed");
		assert.equal(evidence.failures.includes(schedulerLabel), false);
		assert.deepEqual(evidence.unverified.map((entry) => entry.check), [schedulerLabel]);
		assert.match(evidence.unverified[0].reason, /unavailable|not available/);
		assert.match(evidence.scope, /not evidence of success/);
	});
});

test("deployment doctor fails a kit that ships no SIEM delivery timer", () => {
	inTemporaryDirectory((directory) => {
		const { result, deployment } = runDoctorFixture(directory, { units: false });
		assert.equal(result.status, 1, "a missing retry template must fail the preflight");
		assert.match(result.stdout, new RegExp(`^FAIL ${shippedUnitsLabel}$`, "m"));
		const evidence = JSON.parse(readFileSync(join(deployment, "doctor-evidence.json"), "utf8"));
		assert.ok(evidence.failures.includes(shippedUnitsLabel));
		assert.equal(evidence.passed, false);
	});
});
