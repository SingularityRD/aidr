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

function stubbedOnlineDoctor(directory, dashboardResponse, signupDisabled = true, dashboardSignupMode = "closed") {
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
	const result = doctor(directory, ["--online"], {
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

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCANNER_LABELS = {
	workerSecret: "Posture scanner worker shared secret configured (at least 32 characters)",
	bridgeAuth: "Posture scanner bridge authentication configured (isolated API key independent from the worker secret)",
	signingKey: "Posture scanner data signing public key matches the pinned SPKI fingerprint",
	pins: "Posture scanner bundle and source commit pins match the staged data manifest",
	signature: "Posture scanner data manifest carries a release signature (an unsigned manifest keeps bridge readiness closed)",
	sqlite: "Posture scanner bridge task registry is single-host SQLite with HA not required",
	postgres: "Posture scanner bridge PostgreSQL task registry DSN configured for HA",
	egress: "Posture scanner remote scans leave only through the deny-by-default egress gateway with a valid allowlist",
	topology: "Posture scanner control network is internal and only the authenticated bridge publishes a loopback port",
	profile: "Posture scanner Compose profile (posture-scanner) is active for this installation",
	legacyProfile: "Posture scanner Compose profile (aig) is active for this installation",
};
const SCANNER_WORKER_SECRET = "w".repeat(64);
const SCANNER_BRIDGE_KEY = "k".repeat(64);

function scannerCompose({ serverPorts = false, legacy = false } = {}) {
	const bridgePort = legacy
		? "${AIG_BIND_ADDRESS:-127.0.0.1}:${AIG_BRIDGE_PORT:-8099}:8099"
		: "${POSTURE_SCANNER_BIND_ADDRESS:-${AIG_BIND_ADDRESS:-127.0.0.1}}:${POSTURE_SCANNER_BRIDGE_PORT:-${AIG_BRIDGE_PORT:-8099}}:8099";
	return [
		"services:",
		"  aig-server:",
		"    networks: [aidr-aig-network]",
		...(serverPorts ? ["    ports: ['0.0.0.0:8088:8088']"] : []),
		"  aig-agent:",
		"    networks: [aidr-aig-network]",
		"  aig-bridge:",
		"    networks: [aidr-aig-network, aidr-aig-edge]",
		`    ports: ['${bridgePort}']`,
		"  aig-egress:",
		"    networks: [aidr-aig-network, aidr-aig-egress]",
		"networks:",
		"  aidr-aig-network:",
		"    internal: true",
		"  aidr-aig-edge:",
		"    driver_opts:",
		"      com.docker.network.bridge.enable_ip_masquerade: 'false'",
		"  aidr-aig-egress: {}",
		"",
	].join("\n");
}

/**
 * A prepared posture scanner installation. `legacy` reproduces the layout of
 * releases before the rename: an `aig` manifest block, the `aig/` staging
 * directory, the `aig` Compose profile and AIG_* settings.
 */
function scannerDeploymentDirectory(t, { env = {}, signed = false, legacy = false } = {}) {
	const releaseKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey;
	const fingerprint = createHash("sha256").update(releaseKey.export({ type: "spki", format: "der" })).digest("hex");
	const block = { enabled: true, signing_public_key_sha256: fingerprint };
	const directory = deploymentDirectory(t, { mode: "self-hosted", ...(legacy ? { aig: block } : { posture_scanner: block }) });
	const stage = join(directory, legacy ? "aig" : "posture-scanner");
	mkdirSync(join(stage, "generated"), { recursive: true });
	mkdirSync(join(stage, "egress"), { recursive: true });
	writeFileSync(join(stage, legacy ? "aig-signing-public.pem" : "signing-public.pem"), releaseKey.export({ type: "spki", format: "pem" }));
	const dataManifest = JSON.parse(readFileSync(join(repositoryRoot, "packages/core/src/generated/aig-data-manifest.json"), "utf8"));
	if (signed) dataManifest.signature = { algorithm: "RSA-SHA256", key_id: "scanner-release-2026", value: "fixture" };
	writeFileSync(join(stage, "generated", "aig-data-manifest.json"), JSON.stringify(dataManifest));
	for (const name of ["squid.conf", "allowlist.txt"]) copyFileSync(join(repositoryRoot, "deploy/onprem/egress", name), join(stage, "egress", name));
	writeFileSync(join(directory, "compose.yml"), scannerCompose({ legacy }));
	const prefix = legacy ? "AIG_" : "POSTURE_SCANNER_";
	const values = {
		ANON_KEY: "fixture", SERVICE_ROLE_KEY: "fixture",
		COMPOSE_PROFILES: legacy ? "aig" : "posture-scanner",
		[`${prefix}AGENT_SHARED_SECRET`]: SCANNER_WORKER_SECRET,
		[`${prefix}TRUSTED_SIGNING_PUBLIC_KEY_SHA256`]: fingerprint,
		[`${prefix}EXPECTED_DATA_BUNDLE_ID`]: dataManifest.bundle_id,
		[`${prefix}EXPECTED_SOURCE_COMMIT`]: dataManifest.source.commit,
		BRIDGE_AUTH_MODE: "api_key", BRIDGE_API_KEY: SCANNER_BRIDGE_KEY,
		BRIDGE_TASK_BACKEND: "sqlite", BRIDGE_HA_REQUIRED: "false",
		BRIDGE_EGRESS_PROXY_URL: "http://aig-egress:3128",
		...env,
	};
	writeFileSync(join(directory, ".env"), `${Object.entries(values).filter(([, value]) => value !== undefined).map(([name, value]) => `${name}=${value}`).join("\n")}\n`);
	return directory;
}

const line = (state, label) => new RegExp(`^${state} ${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m");

test("doctor verifies a prepared posture scanner sidecar without printing its secrets", (t) => {
	const directory = scannerDeploymentDirectory(t);
	const result = doctor(directory);
	for (const key of ["workerSecret", "bridgeAuth", "signingKey", "pins", "sqlite", "egress", "topology", "profile"]) {
		assert.match(result.stdout, line("PASS", SCANNER_LABELS[key]), key);
	}
	// The committed data manifest is unsigned, so the doctor must fail closed.
	assert.match(result.stdout, line("FAIL", SCANNER_LABELS.signature));
	assert.equal(result.status, 1);
	assert.match(result.stdout, /^INFO Posture scanner egress allowlist names 0 destination domain\(s\); every remote scan is refused until one is added$/m);
	for (const secret of [SCANNER_WORKER_SECRET, SCANNER_BRIDGE_KEY]) {
		assert.equal(result.stdout.includes(secret), false);
		assert.equal(readFileSync(join(directory, "doctor-evidence.json"), "utf8").includes(secret), false);
	}

	const signed = scannerDeploymentDirectory(t, { signed: true });
	assert.match(doctor(signed).stdout, line("PASS", SCANNER_LABELS.signature));
});

test("doctor still verifies an installation prepared before the posture scanner rename", (t) => {
	const legacy = doctor(scannerDeploymentDirectory(t, { legacy: true, signed: true }));
	for (const key of ["workerSecret", "bridgeAuth", "signingKey", "pins", "signature", "sqlite", "egress", "topology", "legacyProfile"]) {
		assert.match(legacy.stdout, line("PASS", SCANNER_LABELS[key]), key);
	}
	// The legacy layout is only accepted as a whole: a renamed profile without the new manifest block fails.
	const mixed = doctor(scannerDeploymentDirectory(t, { legacy: true, env: { COMPOSE_PROFILES: "posture-scanner" } }));
	assert.match(mixed.stdout, line("FAIL", SCANNER_LABELS.legacyProfile));
});

test("doctor fails misconfigured posture scanner trust, registry, egress and topology settings", (t) => {
	const cases = [
		[{ env: { POSTURE_SCANNER_TRUSTED_SIGNING_PUBLIC_KEY_SHA256: "0".repeat(64) } }, "signingKey"],
		[{ env: { POSTURE_SCANNER_EXPECTED_DATA_BUNDLE_ID: "1".repeat(64) } }, "pins"],
		[{ env: { POSTURE_SCANNER_AGENT_SHARED_SECRET: "short" } }, "workerSecret"],
		[{ env: { BRIDGE_API_KEY: SCANNER_WORKER_SECRET } }, "bridgeAuth"],
		[{ env: { BRIDGE_HA_REQUIRED: "true" } }, "sqlite"],
		[{ env: { BRIDGE_TASK_BACKEND: "postgres" } }, "postgres"],
		[{ env: { BRIDGE_EGRESS_PROXY_URL: "http://egress.customer.example:8080" } }, "egress"],
		[{ env: { COMPOSE_PROFILES: "" } }, "profile"],
		[{ env: { COMPOSE_PROFILES: "aig" } }, "profile"],
	];
	for (const [options, key] of cases) {
		const result = doctor(scannerDeploymentDirectory(t, options));
		assert.equal(result.status, 1);
		assert.match(result.stdout, line("FAIL", SCANNER_LABELS[key]), key);
	}

	const postgres = scannerDeploymentDirectory(t, { env: { BRIDGE_TASK_BACKEND: "postgres", BRIDGE_HA_REQUIRED: "true", BRIDGE_TASK_POSTGRES_DSN: "postgresql://bridge:secret@postgres.internal/aidr?sslmode=verify-full" } });
	assert.match(doctor(postgres).stdout, line("PASS", SCANNER_LABELS.postgres));

	const openProxy = scannerDeploymentDirectory(t);
	writeFileSync(join(openProxy, "posture-scanner", "egress", "squid.conf"), `${readFileSync(join(openProxy, "posture-scanner", "egress", "squid.conf"), "utf8")}http_access allow all\n`);
	assert.match(doctor(openProxy).stdout, line("FAIL", SCANNER_LABELS.egress));

	const badAllowlist = scannerDeploymentDirectory(t);
	writeFileSync(join(badAllowlist, "posture-scanner", "egress", "allowlist.txt"), "models.customer.example\n10.0.0.0/8\n");
	assert.match(doctor(badAllowlist).stdout, line("FAIL", SCANNER_LABELS.egress));

	const allowlisted = scannerDeploymentDirectory(t);
	writeFileSync(join(allowlisted, "posture-scanner", "egress", "allowlist.txt"), "# reviewed\nmodels.customer.example\n.mcp.customer.example\n");
	const allowlistedResult = doctor(allowlisted).stdout;
	assert.match(allowlistedResult, line("PASS", SCANNER_LABELS.egress));
	assert.match(allowlistedResult, /^INFO Posture scanner egress allowlist names 2 destination domain\(s\)$/m);

	const published = scannerDeploymentDirectory(t);
	writeFileSync(join(published, "compose.yml"), scannerCompose({ serverPorts: true }));
	assert.match(doctor(published).stdout, line("FAIL", SCANNER_LABELS.topology));
});

test("online doctor requires the posture scanner services to be running and healthy when it is enabled", (t) => {
	const directory = scannerDeploymentDirectory(t);
	const base = requiredComposeServices.map((Service) => ({ Service, State: "running", Health: "healthy" }));
	const scanner = ["aig-server", "aig-agent", "aig-bridge", "aig-egress"].map((Service) => ({ Service, State: "running", Health: "healthy" }));
	assert.match(stubbedComposeDoctor(directory, base).stdout, /^FAIL all required deployment services running and healthy$/m);
	assert.match(stubbedComposeDoctor(directory, [...base, ...scanner]).stdout, /^PASS all required deployment services running and healthy$/m);
	const unhealthyBridge = scanner.map((row) => row.Service === "aig-bridge" ? { ...row, Health: "unhealthy" } : row);
	assert.match(stubbedComposeDoctor(directory, [...base, ...unhealthyBridge]).stdout, /^FAIL all required deployment services running and healthy$/m);
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
