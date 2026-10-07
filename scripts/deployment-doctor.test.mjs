import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const script = resolve(dirname(fileURLToPath(import.meta.url)), "deployment-doctor.mjs");
const maintenanceSource = resolve(dirname(fileURLToPath(import.meta.url)), "..", "deploy", "maintenance");
const REGIONS = {
	"self-hosted": { supabase_url: null, residency: { declared: true, location: "customer-designated host", note: "fixture declaration" } },
	unassigned: { supabase_url: null, residency: { declared: false, location: "unassigned", note: "fixture declaration" } },
};
const ARTIFACT_PUBLIC_KEY = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
const LICENSING_PUBLIC_KEY = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();

function writeAgentConfig(directory, artifactKey = ARTIFACT_PUBLIC_KEY, licensingKey = LICENSING_PUBLIC_KEY) {
	writeFileSync(join(directory, "agent-config.json"), JSON.stringify({
		mode: "managed",
		integrity: { enabled: true, verify_on_start: true, public_keys_pem: [artifactKey] },
		licensing: { require_signed_entitlements: true, public_keys_pem: [licensingKey] },
	}));
}

/**
 * The doctor is an operational preflight over a prepared directory. These tests
 * write the smallest manifest it reads and assert only the checks under test;
 * every other check fails for this fixture and is deliberately not asserted.
 */
function deploymentDirectory(t, overrides = {}) {
	const directory = mkdtempSync(join(tmpdir(), "aidr-doctor-"));
	t.after(() => rmSync(directory, { recursive: true, force: true }));
	mkdirSync(join(directory, "maintenance"), { recursive: true });
	const maintenanceArtifacts = ["aidr-siem-delivery.service", "aidr-siem-delivery.timer"].map((name) => {
		const content = readFileSync(join(maintenanceSource, name));
		writeFileSync(join(directory, "maintenance", name), content);
		return { path: `maintenance/${name}`, sha256: createHash("sha256").update(content).digest("hex") };
	});
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
		artifacts: maintenanceArtifacts,
		...overrides,
	};
	writeFileSync(join(directory, "deployment.json"), `${JSON.stringify(manifest, null, 2)}\n`);
	writeFileSync(join(directory, ".env"), "ANON_KEY=fixture\nSERVICE_ROLE_KEY=fixture\nAIDR_SIGNUP_MODE=closed\n");
	writeFileSync(join(directory, ".env.functions"), "AIDR_DELEGATION_ISSUER=https://api.customer.example\n");
	writeFileSync(join(directory, ".env.ingress"), "AIDR_DEVICE_START_ANON_KEY=fixture\n");
	writeAgentConfig(directory);
	return directory;
}

function ingressUnits(directory) {
	mkdirSync(join(directory, "ingress"), { recursive: true });
	writeFileSync(join(directory, "ingress", "aidr-tls-renew.service"), "[Service]\n");
	writeFileSync(join(directory, "ingress", "aidr-tls-renew.timer"), "[Timer]\n");
}

function readyDeploymentDirectory(t) {
	const directory = deploymentDirectory(t);
	const delegationKeys = generateKeyPairSync("ed25519");
	const ingressSecret = "a".repeat(32);
	writeFileSync(join(directory, ".env"), [
		"ANON_KEY=fixture-anon-key",
		"SERVICE_ROLE_KEY=fixture-service-role-key",
		"AIDR_SIGNUP_MODE=closed",
		`S3_PROTOCOL_ACCESS_KEY_SECRET=${"c".repeat(40)}`,
	].join("\n") + "\n");
	writeFileSync(join(directory, ".env.functions"), [
		`AIDR_DEVICE_START_INGRESS_SECRET=${ingressSecret}`,
		"AIDR_DELEGATION_ISSUER=https://api.customer.example",
		"AIDR_DELEGATION_SIGNING_KEY_ID=aidr-delegation-abcdef123456",
		`AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64=${delegationKeys.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64")}`,
		`AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64=${delegationKeys.publicKey.export({ type: "spki", format: "der" }).toString("base64")}`,
	].join("\n") + "\n");
	mkdirSync(join(directory, "ingress"), { recursive: true });
	writeFileSync(join(directory, "ingress", "device-start.mjs"), "// fixture\n");
	writeFileSync(join(directory, ".env.ingress"), [
		`AIDR_DEVICE_START_INGRESS_SECRET=${ingressSecret}`,
		`AIDR_DEVICE_START_PROXY_TOKEN=${"b".repeat(32)}`,
		"AIDR_DEVICE_START_UPSTREAM_URL=https://api.customer.example/functions/v1/device-start",
		"AIDR_DEVICE_START_ANON_KEY=fixture-anon-key",
	].join("\n") + "\n");
	ingressUnits(directory);
	return directory;
}

const requiredComposeServices = ["studio", "api-gw", "auth", "rest", "realtime", "storage", "imgproxy", "meta", "functions", "db", "dashboard"];

function stubbedComposeDoctor(directory, services) {
	const preload = join(directory, "docker-probe.mjs");
	writeFileSync(preload, `
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
const original = childProcess.spawnSync;
childProcess.spawnSync = (command, args, options) => command === "docker"
	? { status: 0, stdout: args.includes("--quiet") ? "" : process.env.AIDR_DOCTOR_DOCKER_ROWS, stderr: "" }
	: original(command, args, options);
syncBuiltinESMExports();
globalThis.fetch = async (input) => String(input).endsWith("/auth/v1/settings")
	? Response.json({ disable_signup: true })
	: new Response("{}", { status: 200 });
`);
	writeFileSync(join(directory, "compose.yml"), "services: {}\n");
	return doctor(directory, ["--online"], {
		...process.env,
		AIDR_DOCTOR_DOCKER_ROWS: JSON.stringify(services),
		NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
	});
}

function stubbedOnlineDoctor(directory, dashboardResponse, signupDisabled = true, dashboardSignupMode = "closed", extraArgs = []) {
	const fetchLog = join(directory, "fetch.log");
	const preload = join(directory, "fetch-stub.mjs");
	writeFileSync(preload, `
import { appendFileSync } from "node:fs";
const dashboardResponse = ${JSON.stringify(dashboardResponse)};
const signupDisabled = ${JSON.stringify(signupDisabled)};
const dashboardSignupMode = ${JSON.stringify(dashboardSignupMode)};
globalThis.fetch = async (input) => {
	const url = String(input);
	appendFileSync(process.env.AIDR_DOCTOR_FETCH_LOG, url + "\\n");
	if (url.endsWith("/readyz")) return new Response(dashboardResponse.body, {
		status: dashboardResponse.status,
		headers: { "content-type": dashboardResponse.contentType },
	});
	if (url.endsWith("/runtime-config.js")) return new Response('window.__AIDR_CONFIG__=' + JSON.stringify({ signupMode: dashboardSignupMode }) + ';', { status: 200, headers: { "content-type": "application/javascript" } });
	if (url.endsWith("/auth/v1/health")) return new Response("healthy", { status: 200 });
	if (url.endsWith("/auth/v1/settings")) return Response.json({ disable_signup: signupDisabled });
	return new Response("{}", { status: 200 });
};
`);
	const result = doctor(directory, ["--online", ...extraArgs], {
		...process.env,
		AIDR_DOCTOR_FETCH_LOG: fetchLog,
		NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
	});
	return { result, requests: readFileSync(fetchLog, "utf8") };
}

function doctor(directory, args = [], env = process.env) {
	return spawnSync(process.execPath, [script, "--deployment", directory, ...args], { encoding: "utf8", timeout: 60_000, env });
}

test("commercial doctor requires valid artifact keys independent from licensing", (t) => {
	const label = "commercial artifact verification uses valid independent Ed25519 public keys";
	const valid = deploymentDirectory(t);
	assert.match(doctor(valid).stdout, new RegExp(`^PASS ${label}$`, "m"));

	const missing = deploymentDirectory(t);
	rmSync(join(missing, "agent-config.json"));
	assert.match(doctor(missing).stdout, new RegExp(`^FAIL ${label}$`, "m"));

	const malformed = deploymentDirectory(t);
	writeFileSync(join(malformed, "agent-config.json"), "not json", "utf8");
	assert.match(doctor(malformed).stdout, new RegExp(`^FAIL ${label}$`, "m"));

	const reused = deploymentDirectory(t);
	writeAgentConfig(reused, LICENSING_PUBLIC_KEY, LICENSING_PUBLIC_KEY);
	assert.match(doctor(reused).stdout, new RegExp(`^FAIL ${label}$`, "m"));
});

test("fails the tenant region check when the tenant region differs from the deployment region", (t) => {
	const result = doctor(deploymentDirectory(t, { tenant_region: "unassigned" }));
	assert.notEqual(result.status, 0);
	assert.match(result.stdout, /^FAIL tenant declared region matches the deployment region$/m);
});

test("passes the tenant region check when the tenant region matches the deployment region", (t) => {
	const result = doctor(deploymentDirectory(t));
	assert.match(result.stdout, /^PASS tenant declared region matches the deployment region$/m);
});

test("doctor fails when the selected residency is false even if the location says Frankfurt", (t) => {
	const directory = deploymentDirectory(t, {
		region: "frankfurt",
		tenant_region: "frankfurt",
		regions: { ...REGIONS, frankfurt: { supabase_url: null, residency: { declared: false, location: "Frankfurt" } } },
	});
	const result = doctor(directory);
	assert.equal(result.status, 1);
	assert.match(result.stdout, /^FAIL deployment region requires an explicit operator residency declaration$/m);
	assert.doesNotMatch(result.stdout, /^PASS operator-declared residency location: Frankfurt/m);
	const evidence = JSON.parse(readFileSync(join(directory, "doctor-evidence.json"), "utf8"));
	assert.equal(evidence.passed, false);
	assert.ok(evidence.failures.includes("deployment region requires an explicit operator residency declaration"));
});

test("doctor reports a true residency declaration as operator-stated, not provider-verified", (t) => {
	const directory = deploymentDirectory(t, {
		region: "frankfurt",
		tenant_region: "frankfurt",
		regions: { ...REGIONS, frankfurt: { supabase_url: null, residency: { declared: true, location: "Frankfurt" } } },
	});
	const result = doctor(directory);
	assert.match(result.stdout, /^PASS operator-declared residency location: Frankfurt \(provider location not verified\)$/m);
	const evidence = JSON.parse(readFileSync(join(directory, "doctor-evidence.json"), "utf8"));
	assert.match(evidence.scope, /Residency is an operator declaration, not verification of actual provider location/);
});

test("doctor rejects development manifests that point at public HTTPS endpoints", (t) => {
	const directory = deploymentDirectory(t, { development: true });
	const result = doctor(directory);
	assert.equal(result.status, 1);
	assert.match(result.stdout, /^FAIL development mode uses loopback dashboard and Supabase endpoints$/m);
});

test("doctor accepts loopback-only development endpoint declarations", (t) => {
	const directory = deploymentDirectory(t, {
		development: true,
		dashboard_url: "http://localhost:8080",
		supabase_url: "http://127.0.0.1:8000",
	});
	const result = doctor(directory);
	assert.match(result.stdout, /^PASS development mode uses loopback dashboard and Supabase endpoints$/m);
});

test("unverified host checks make doctor evidence and exit status fail closed", (t) => {
	const directory = readyDeploymentDirectory(t);
	const result = doctor(directory, [], { ...process.env, PATH: "" });
	assert.equal(result.status, 1);
	const evidence = JSON.parse(readFileSync(join(directory, "doctor-evidence.json"), "utf8"));
	assert.deepEqual(evidence.failures, []);
	assert.ok(evidence.unverified.length > 0);
	assert.equal(evidence.passed, false);
});

test("doctor rejects a proxy token reused as the ingress signing secret", (t) => {
	const directory = readyDeploymentDirectory(t);
	const ingressEnv = readFileSync(join(directory, ".env.ingress"), "utf8");
	const signingSecret = "a".repeat(32);
	writeFileSync(join(directory, ".env.ingress"), ingressEnv.replace(`AIDR_DEVICE_START_PROXY_TOKEN=${"b".repeat(32)}`, `AIDR_DEVICE_START_PROXY_TOKEN=${signingSecret}`));
	const result = doctor(directory);
	assert.equal(result.status, 1);
	assert.match(result.stdout, /^FAIL device-start reverse-proxy token configured and independent from ingress signing secret$/m);
});

test("online doctor requires every named Compose service to be running and healthy", (t) => {
	const directory = deploymentDirectory(t, { mode: "self-hosted" });
	const healthy = requiredComposeServices.map((Service) => ({ Service, State: "running", Health: "healthy" }));
	assert.match(stubbedComposeDoctor(directory, healthy).stdout, /^PASS all required deployment services running and healthy$/m);

	const missingService = healthy.filter(({ Service }) => Service !== "functions");
	assert.equal(missingService.length, 10);
	assert.match(stubbedComposeDoctor(directory, missingService).stdout, /^FAIL all required deployment services running and healthy$/m);

	const unhealthyService = healthy.map((service) => service.Service === "dashboard" ? { ...service, Health: "unhealthy" } : service);
	assert.match(stubbedComposeDoctor(directory, unhealthyService).stdout, /^FAIL all required deployment services running and healthy$/m);
});

test("cloud doctor requires a configured device-start ingress API key", (t) => {
	const label = "cloud device-start ingress uses the selected project's configured anonymous API key";
	const configured = deploymentDirectory(t);
	assert.match(doctor(configured).stdout, new RegExp(`^PASS ${label}$`, "m"));

	const missing = deploymentDirectory(t);
	writeFileSync(join(missing, ".env.ingress"), "AIDR_DEVICE_START_PROXY_TOKEN=fixture\n");
	assert.match(doctor(missing).stdout, new RegExp(`^FAIL ${label}$`, "m"));

	const placeholder = deploymentDirectory(t);
	writeFileSync(join(placeholder, ".env"), "ANON_KEY=REPLACE_WITH_PROJECT_ANON_KEY\nSERVICE_ROLE_KEY=REPLACE_WITH_PROJECT_SERVICE_ROLE_KEY\n");
	writeFileSync(join(placeholder, ".env.ingress"), "AIDR_DEVICE_START_ANON_KEY=REPLACE_WITH_PROJECT_ANON_KEY\n");
	const result = doctor(placeholder);
	assert.notEqual(result.status, 0);
	assert.match(result.stdout, new RegExp(`^FAIL ${label}$`, "m"));
});

test("cloud doctor requires the live Auth signup setting to match the explicit dashboard mode", (t) => {
	const readyResponse = { body: JSON.stringify({ status: "ready" }), status: 200, contentType: "application/json" };
	for (const [mode, disabled] of [["closed", true], ["cloud", false]]) {
		const directory = deploymentDirectory(t);
		writeFileSync(join(directory, ".env"), `ANON_KEY=fixture\nSERVICE_ROLE_KEY=fixture\nAIDR_SIGNUP_MODE=${mode}\n`);
		const matching = stubbedOnlineDoctor(directory, readyResponse, disabled, mode).result.stdout;
		assert.match(matching, /^PASS authentication signup setting matches deployment mode$/m);
		assert.match(matching, /^PASS dashboard signup mode matches deployment configuration$/m);
		assert.match(stubbedOnlineDoctor(directory, readyResponse, !disabled, mode).result.stdout, /^FAIL authentication signup setting matches deployment mode$/m);
		assert.match(stubbedOnlineDoctor(directory, readyResponse, disabled, mode === "closed" ? "cloud" : "closed").result.stdout, /^FAIL dashboard signup mode matches deployment configuration$/m);
	}
	const invalid = deploymentDirectory(t);
	writeFileSync(join(invalid, ".env"), "ANON_KEY=fixture\nSERVICE_ROLE_KEY=fixture\nAIDR_SIGNUP_MODE=pilot\n");
	assert.match(doctor(invalid).stdout, /^FAIL cloud signup mode is explicit and valid$/m);
});

test("online doctor fails closed when managed-cloud readiness is unsupported", (t) => {
	const directory = deploymentDirectory(t);
	const { result, requests } = stubbedOnlineDoctor(directory, {
		body: JSON.stringify({ error: "readiness_not_supported" }),
		status: 501,
		contentType: "application/json",
	});
	assert.match(requests, /\/readyz$/m);
	assert.doesNotMatch(requests, /\/healthz$/m);
	assert.match(result.stdout, /^FAIL dashboard readiness$/m);
	assert.match(result.stdout, /^PASS authentication health$/m);
});

test("online doctor rejects HTTP 200 dashboard responses that are not ready JSON", (t) => {
	const responses = [
		{ body: "<html>dashboard fallback</html>", status: 200, contentType: "text/html" },
		{ body: JSON.stringify({ status: "not_ready" }), status: 200, contentType: "application/json" },
	];
	for (const dashboardResponse of responses) {
		const directory = deploymentDirectory(t);
		const { result } = stubbedOnlineDoctor(directory, dashboardResponse);
		assert.match(result.stdout, /^FAIL dashboard readiness$/m);
		assert.match(result.stdout, /^PASS authentication health$/m);
	}
});

test("online doctor accepts a successful dashboard readiness JSON response", (t) => {
	const directory = deploymentDirectory(t);
	const { result } = stubbedOnlineDoctor(directory, {
		body: JSON.stringify({ status: "ready" }),
		status: 200,
		contentType: "application/json",
	});
	assert.match(result.stdout, /^PASS dashboard readiness$/m);
	assert.match(result.stdout, /^PASS authentication health$/m);
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
const shippedUnitsLabel = "shared readiness and SIEM timer present and wired to the maintenance worker";
const schedulerLabel = "shared readiness and SIEM timer is enabled in the host scheduler";

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

test("deployment doctor rejects missing or changed deployed maintenance units", (t) => {
	const missing = deploymentDirectory(t);
	rmSync(join(missing, "maintenance", "aidr-siem-delivery.timer"));
	assert.match(doctor(missing).stdout, new RegExp(`^FAIL ${shippedUnitsLabel}$`, "m"));

	const changed = deploymentDirectory(t);
	writeFileSync(join(changed, "maintenance", "aidr-siem-delivery.service"), "[Service]\nExecStart=/bin/false\n");
	assert.match(doctor(changed).stdout, new RegExp(`^FAIL ${shippedUnitsLabel}$`, "m"));
});

test("deployment doctor fails a deployment that contains no SIEM delivery timer", (t) => {
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

const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&");

test("online doctor names the dashboard readiness checks that are not ok", (t) => {
	const directory = deploymentDirectory(t);
	const { result } = stubbedOnlineDoctor(directory, {
		body: JSON.stringify({ status: "not_ready", checks: { database: "ok", signing: "failed", backup: "failed", certificate: "failed" } }),
		status: 503,
		contentType: "application/json",
	});
	assert.equal(result.status, 1);
	assert.match(result.stdout, /^FAIL dashboard readiness \(not ok: signing, backup, certificate\)$/m);
	const evidence = JSON.parse(readFileSync(join(directory, "doctor-evidence.json"), "utf8"));
	assert.ok(evidence.failures.includes("dashboard readiness (not ok: signing, backup, certificate)"));
});

test("online doctor never echoes unexpected readiness check names", (t) => {
	for (const checks of [{ "x\nPASS forged": "failed" }, ["signing"], "signing", null]) {
		const directory = deploymentDirectory(t);
		const { result } = stubbedOnlineDoctor(directory, {
			body: JSON.stringify({ status: "not_ready", checks }),
			status: 503,
			contentType: "application/json",
		});
		assert.match(result.stdout, /^FAIL dashboard readiness$/m);
		assert.doesNotMatch(result.stdout, /^PASS forged/m);
	}
});

const readyResponse = { body: JSON.stringify({ status: "ready" }), status: 200, contentType: "application/json" };
const productionEvidencePattern = (outcome) => new RegExp(`^${outcome} ${escapeRegExp("production evidence requires a production manifest (development manifests need --development)")}$`, "m");

test("online doctor refuses a development manifest as production evidence", (t) => {
	const directory = deploymentDirectory(t, { development: true, dashboard_url: "http://localhost:8080", supabase_url: "http://127.0.0.1:8000" });
	const { result } = stubbedOnlineDoctor(directory, readyResponse);
	assert.equal(result.status, 1);
	assert.match(result.stdout, productionEvidencePattern("FAIL"));
	const evidence = JSON.parse(readFileSync(join(directory, "doctor-evidence.json"), "utf8"));
	assert.equal(evidence.passed, false);
	assert.equal(evidence.evidence_class, "development");

	const acknowledged = stubbedOnlineDoctor(directory, readyResponse, true, "closed", ["--development"]).result;
	assert.match(acknowledged.stdout, /^PASS --development run targets a development manifest$/m);
	assert.doesNotMatch(acknowledged.stdout, productionEvidencePattern("FAIL"));
	assert.equal(JSON.parse(readFileSync(join(directory, "doctor-evidence.json"), "utf8")).evidence_class, "development");
});

test("online doctor accepts a production manifest and rejects --development against it", (t) => {
	const directory = deploymentDirectory(t);
	const { result } = stubbedOnlineDoctor(directory, readyResponse);
	assert.match(result.stdout, productionEvidencePattern("PASS"));
	assert.equal(JSON.parse(readFileSync(join(directory, "doctor-evidence.json"), "utf8")).evidence_class, "production");
	const mismatched = stubbedOnlineDoctor(directory, readyResponse, true, "closed", ["--development"]).result;
	assert.equal(mismatched.status, 1);
	assert.match(mismatched.stdout, /^FAIL --development run targets a development manifest$/m);
});

test("online doctor fails closed when the manifest does not declare its development flag", (t) => {
	const directory = deploymentDirectory(t, { development: "no" });
	const { result } = stubbedOnlineDoctor(directory, readyResponse);
	assert.match(result.stdout, /^FAIL deployment manifest declares whether it is a development deployment$/m);
	assert.match(result.stdout, productionEvidencePattern("FAIL"));
});

/*
 * Windows maintenance tasks. The preload pretends to be win32 and answers
 * `schtasks /Query /XML` from a fixture map, so this branch runs on every CI host.
 */
const retentionTaskLabel = "retention reaper scheduled task installed and enabled: \\AIDR\\aidr-export-retention";

function taskXml(directory, worker, { enabled = true, triggerEnabled = true, command = "C:\\Program Files\\nodejs\\node.exe", deployment = directory } = {}) {
	const args = worker === "readiness-evidence-worker.mjs"
		? `"--env-file=${deployment}\\.env.readiness" "${deployment}\\maintenance\\${worker}"`
		: `"C:\\aidr-kit\\scripts\\${worker}" "${deployment}" --apply`;
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <TimeTrigger>
      <Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
      <StartBoundary>2026-10-07T10:00:00</StartBoundary>
      ${triggerEnabled ? "" : "<Enabled>false</Enabled>"}
    </TimeTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>true</StartWhenAvailable>
    ${enabled ? "" : "<Enabled>false</Enabled>"}
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>${command}</Command>
      <Arguments>${args.replaceAll("&", "&amp;")}</Arguments>
    </Exec>
  </Actions>
</Task>`;
}

function windowsTaskDoctor(directory, tasks) {
	const preload = join(directory, "schtasks-stub.mjs");
	writeFileSync(preload, `
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
Object.defineProperty(process, "platform", { value: "win32" });
const tasks = JSON.parse(process.env.AIDR_DOCTOR_TASKS);
const original = childProcess.spawnSync;
childProcess.spawnSync = (command, args, options) => {
	if (!/schtasks\\.exe$/i.test(String(command))) return original(command, args, options);
	const xml = tasks[args[args.indexOf("/TN") + 1]];
	return xml ? { status: 0, stdout: xml, stderr: "" } : { status: 1, stdout: "", stderr: "ERROR: not found" };
};
syncBuiltinESMExports();
`);
	return doctor(directory, [], { ...process.env, AIDR_DOCTOR_TASKS: JSON.stringify(tasks), NODE_OPTIONS: `--import=${pathToFileURL(preload).href}` });
}

function installedTasks(directory, options = {}) {
	return {
		"\\AIDR\\aidr-siem-delivery": taskXml(directory, "readiness-evidence-worker.mjs", options.siem),
		"\\AIDR\\aidr-export-retention": taskXml(directory, "deployment-maintenance.mjs", options.retention),
	};
}

function declareWindowsMaintenance(directory) {
	writeFileSync(join(directory, "windows-maintenance-tasks.json"), JSON.stringify({ schema_version: 1, scheduler: "windows-task-scheduler", task_path: "\\AIDR\\" }));
}

test("windows doctor keeps absent maintenance tasks unverified when no Windows maintenance is declared", (t) => {
	const directory = deploymentDirectory(t);
	const result = windowsTaskDoctor(directory, {});
	assert.match(result.stdout, new RegExp(`^UNVERIFIED ${schedulerLabel} \\(scheduled task .*not available`, "m"));
	assert.match(result.stdout, /^UNVERIFIED retention reaper timer not verified: aidr-export-retention\.timer/m);
	assert.doesNotMatch(result.stdout, new RegExp(`^(PASS|FAIL) ${schedulerLabel}`, "m"));
	const evidence = JSON.parse(readFileSync(join(directory, "doctor-evidence.json"), "utf8"));
	assert.equal(evidence.passed, false);
	assert.ok(evidence.unverified.some((entry) => entry.check === schedulerLabel));
});

test("windows doctor fails declared maintenance tasks that are missing", (t) => {
	const directory = deploymentDirectory(t);
	declareWindowsMaintenance(directory);
	const result = windowsTaskDoctor(directory, {});
	assert.equal(result.status, 1);
	assert.match(result.stdout, new RegExp(`^FAIL ${schedulerLabel} \\(.*declared by windows-maintenance-tasks\\.json\\)$`, "m"));
	assert.match(result.stdout, new RegExp(`^FAIL ${escapeRegExp(retentionTaskLabel)} \\(`, "m"));
	assert.doesNotMatch(result.stdout, /^UNVERIFIED .*(SIEM timer|retention reaper)/m);
});

test("windows doctor passes enabled maintenance tasks wired to this deployment", (t) => {
	const directory = deploymentDirectory(t);
	declareWindowsMaintenance(directory);
	const result = windowsTaskDoctor(directory, installedTasks(directory));
	assert.match(result.stdout, new RegExp(`^PASS ${schedulerLabel}$`, "m"));
	assert.match(result.stdout, new RegExp(`^PASS ${escapeRegExp(retentionTaskLabel)}$`, "m"));
	const evidence = JSON.parse(readFileSync(join(directory, "doctor-evidence.json"), "utf8"));
	assert.ok(evidence.checks.includes(schedulerLabel));
	assert.ok(evidence.checks.includes(retentionTaskLabel));
	assert.equal((evidence.unverified ?? []).some((entry) => /SIEM timer|retention reaper/.test(entry.check)), false);
});

test("windows doctor fails disabled, trigger-less or miswired maintenance tasks even without a declaration", (t) => {
	const cases = [
		[{ siem: { enabled: false } }, "disabled or without an active trigger"],
		[{ siem: { triggerEnabled: false } }, "disabled or without an active trigger"],
		[{ siem: { deployment: "C:\\other-deployment" } }, "not wired to this deployment's maintenance worker"],
		[(directory) => ({ siem: { deployment: `${directory}-old` } }), "not wired to this deployment's maintenance worker"],
		[{ siem: { command: "C:\\Windows\\System32\\cmd.exe" } }, "not wired to this deployment's maintenance worker"],
	];
	for (const [options, problem] of cases) {
		const directory = deploymentDirectory(t);
		const result = windowsTaskDoctor(directory, installedTasks(directory, typeof options === "function" ? options(directory) : options));
		assert.equal(result.status, 1);
		assert.match(result.stdout, new RegExp(`^FAIL ${schedulerLabel} \\(${escapeRegExp(`\\AIDR\\aidr-siem-delivery ${problem}`)}\\)$`, "m"));
		assert.match(result.stdout, new RegExp(`^PASS ${escapeRegExp(retentionTaskLabel)}$`, "m"));
	}
});
