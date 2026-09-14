import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
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

test("a region outside the declared manifest is rejected", () => {
	inTemporaryDirectory((directory) => {
		const output = join(directory, "undeclared-region");
		const result = prepare(output, "--region", "mars-central-1");
		assert.notEqual(result.status, 0, "an undeclared region unexpectedly succeeded");
		assert.match(result.stderr, /mars-central-1.*is not declared in the deployment region manifest/);
		assert.equal(existsSync(output), false, "an undeclared region left a partial installation");
	});
});

test("a tenant region that differs from the deployment region is rejected", () => {
	inTemporaryDirectory((directory) => {
		const output = join(directory, "cross-region");
		const result = prepare(output, "--region", "self-hosted", "--tenant-region", "unassigned");
		assert.notEqual(result.status, 0, "a cross-region installation unexpectedly succeeded");
		assert.match(result.stderr, /Tenant declared region "unassigned" does not match deployment region "self-hosted"/);
		assert.equal(existsSync(output), false, "a cross-region preparation left a partial installation");
	});
});

test("the declared region and its residency are recorded in the prepared manifest", () => {
	inTemporaryDirectory((directory) => {
		const output = join(directory, "declared-region");
		const result = prepare(output, "--mode", "cloud", "--region", "self-hosted", "--tenant-region", "self-hosted");
		assert.equal(result.status, 0, result.stderr);
		const deployment = JSON.parse(readFileSync(join(output, "deployment.json"), "utf8"));
		assert.equal(deployment.region, "self-hosted");
		assert.equal(deployment.tenant_region, "self-hosted");
		assert.equal(deployment.regions["self-hosted"].supabase_url, null);
		assert.equal(typeof deployment.regions["self-hosted"].residency.declared, "boolean");
		assert.match(deployment.regions["self-hosted"].residency.location, /\S/);
	});
});
