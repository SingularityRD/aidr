import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deploymentCredentialFailures } from "./lib/deployment-credentials.mjs";

const script = resolve(dirname(fileURLToPath(import.meta.url)), "deployment-doctor.mjs");
const maintenanceSource = resolve(dirname(fileURLToPath(import.meta.url)), "..", "deploy", "maintenance");
const REGIONS = {
	"self-hosted": { supabase_url: null, residency: { declared: true, location: "customer-designated host", note: "fixture declaration" } },
	unassigned: { supabase_url: null, residency: { declared: false, location: "unassigned", note: "fixture declaration" } },
};
const ARTIFACT_PUBLIC_KEY = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
const LICENSING_PUBLIC_KEY = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
const vendorEnv = Object.fromEntries(readFileSync(resolve(import.meta.dirname, "../deploy/upstream/docker/.env.example"), "utf8")
	.split(/\r?\n/).filter((line) => /^[A-Z][A-Z0-9_]*=/.test(line))
	.map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]));

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
		`AIDR_APPROVAL_SIGNING_WRAP_KEY_B64=${Buffer.alloc(32, 7).toString("base64")}`,
		`AIDR_NOTIFICATION_ENCRYPTION_KEYS=k1:${Buffer.alloc(32, 9).toString("base64")}`,
		`AIDR_NOTIFICATION_DISPATCH_TOKEN=${"d".repeat(43)}`,
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

for (const [name, value, kind] of [
	["SERVICE_ROLE_KEY", vendorEnv.SERVICE_ROLE_KEY, "shared vendor credentials"],
	["S3_PROTOCOL_ACCESS_KEY_SECRET", "REPLACE_WITH_THE_DEPLOYMENT_PRIVATE_S3_PROTOCOL_SECRET", "non-API placeholder"],
]) test(`doctor rejects ${kind} before making online requests`, (t) => {
	const directory = readyDeploymentDirectory(t);
	const configured = readFileSync(join(directory, ".env"), "utf8").replace(new RegExp(`^${name}=.*$`, "m"), `${name}=${value}`);
	writeFileSync(join(directory, ".env"), configured);
	const fetchLog = join(directory, "unsafe-fetch.log");
	const preload = join(directory, "unsafe-fetch.mjs");
	writeFileSync(preload, 'import { appendFileSync } from "node:fs"; globalThis.fetch = async () => { appendFileSync(process.env.AIDR_DOCTOR_FETCH_LOG, "request\\n"); return Response.json({ status: "ready", disable_signup: true }); };');
	const result = doctor(directory, ["--online"], { ...process.env, NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`, AIDR_DOCTOR_FETCH_LOG: fetchLog });
	assert.notEqual(result.status, 0);
	assert.match(result.stdout, /^FAIL selected project's public and private keys configured$/m);
	if (name === "S3_PROTOCOL_ACCESS_KEY_SECRET") assert.match(result.stdout, /^FAIL S3 protocol credential is private and differs from the upstream demonstration secret$/m);
	assert.equal(existsSync(fetchLog), false, "unsafe credentials must not reach a network check");
	assert.equal((result.stdout + result.stderr).includes(value), false);
});

test("credential guard rejects every pinned vendor secret and reserialized demo JWT without returning its value", () => {
	const credentialNames = ["POSTGRES_PASSWORD", "JWT_SECRET", "ANON_KEY", "SERVICE_ROLE_KEY", "DASHBOARD_PASSWORD", "SECRET_KEY_BASE", "REALTIME_DB_ENC_KEY", "VAULT_ENC_KEY", "PG_META_CRYPTO_KEY", "LOGFLARE_PUBLIC_ACCESS_TOKEN", "LOGFLARE_PRIVATE_ACCESS_TOKEN", "S3_PROTOCOL_ACCESS_KEY_SECRET", "MINIO_ROOT_PASSWORD", "SMTP_PASS", "OPENAI_API_KEY"];
	const configured = { ANON_KEY: "sb_publishable_customer_fixture", SERVICE_ROLE_KEY: "sb_secret_customer_fixture" };
	for (const name of credentialNames) {
		assert.deepEqual(deploymentCredentialFailures({ ...configured, [name]: vendorEnv[name] }), [name]);
		assert.deepEqual(deploymentCredentialFailures({ ...configured, [name]: `"${vendorEnv[name]}"` }), [name]);
		assert.deepEqual(deploymentCredentialFailures({ ...configured, [name]: `REPLACE_WITH_PRIVATE_${name}` }), [name]);
		assert.deepEqual(deploymentCredentialFailures({ ...configured, [name]: `"replace_with_private_${name}"` }), [name]);
		if (!["ANON_KEY", "SERVICE_ROLE_KEY"].includes(name)) {
			assert.deepEqual(deploymentCredentialFailures({ ...configured, [name]: undefined }), [], "unused cloud secrets may be absent");
			assert.deepEqual(deploymentCredentialFailures({ ...configured, [name]: "" }), [], "unused cloud secrets may be empty");
		}
	}
	const demoKey = `e30.${Buffer.from(JSON.stringify({ iss: "supabase-demo", role: "service_role", exp: 4102444800 })).toString("base64url")}.reserialized_fixture`;
	assert.deepEqual(deploymentCredentialFailures({ ...configured, SERVICE_ROLE_KEY: demoKey }), ["SERVICE_ROLE_KEY"]);
	assert.deepEqual(deploymentCredentialFailures(configured), []);
	assert.deepEqual(deploymentCredentialFailures({ ...configured, SERVICE_ROLE_KEY: "replace_with_project_key" }), ["SERVICE_ROLE_KEY"]);
	assert.deepEqual(deploymentCredentialFailures({ ...configured, ANON_KEY: "" }), ["ANON_KEY"]);
	const projectKey = `e30.${Buffer.from(JSON.stringify({ iss: "supabase", role: "service_role" })).toString("base64url")}.project_fixture`;
	assert.deepEqual(deploymentCredentialFailures({ ...configured, SERVICE_ROLE_KEY: projectKey }), []);
});

test("doctor keeps customer opaque cloud keys supported", (t) => {
	const directory = readyDeploymentDirectory(t);
	writeFileSync(join(directory, ".env"), readFileSync(join(directory, ".env"), "utf8")
		.replace(/^ANON_KEY=.*$/m, "ANON_KEY=sb_publishable_customer_fixture")
		.replace(/^SERVICE_ROLE_KEY=.*$/m, "SERVICE_ROLE_KEY=sb_secret_customer_fixture"));
	assert.match(doctor(directory).stdout, /^PASS selected project's public and private keys configured$/m);
});

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

test("self-hosted doctor fails while Supabase Studio is routed from the public gateway listener", (t) => {
	const label = "Supabase Studio is served only on a loopback-published admin listener, not on the public API gateway listener";
	const listener = (name, port, routes) => ({ name, address: { socket_address: { address: "0.0.0.0", port_value: port } }, filter_chains: [{ filters: [{ name: "envoy.filters.network.http_connection_manager", typed_config: { route_config: { virtual_hosts: [{ name: "host", routes }] } } }] }] });
	const studio = { match: { prefix: "/" }, route: { cluster: "studio" } };
	const api = { match: { prefix: "/rest/v1/" }, route: { cluster: "rest" } };
	const notFound = { match: { prefix: "/" }, direct_response: { status: 404 } };
	const fixture = (resources, ports) => {
		const directory = deploymentDirectory(t, { mode: "self-hosted" });
		mkdirSync(join(directory, "volumes/api/envoy"), { recursive: true });
		writeFileSync(join(directory, "volumes/api/envoy/lds.template.yaml"), JSON.stringify({ resources }));
		writeFileSync(join(directory, "compose.yml"), JSON.stringify({ services: { "api-gw": { ports } } }));
		return doctor(directory).stdout;
	};
	// The reviewed upstream layout: `/` -> studio on the listener the ingress proxies.
	const upstream = resolve(import.meta.dirname, "../deploy/upstream/docker/volumes/api/envoy/lds.template.yaml");
	if (existsSync(upstream)) {
		const directory = deploymentDirectory(t, { mode: "self-hosted" });
		mkdirSync(join(directory, "volumes/api/envoy"), { recursive: true });
		copyFileSync(upstream, join(directory, "volumes/api/envoy/lds.template.yaml"));
		writeFileSync(join(directory, "compose.yml"), JSON.stringify({ services: { "api-gw": { ports: ["127.0.0.1:8000:8000"] } } }));
		assert.match(doctor(directory).stdout, new RegExp(`^FAIL ${label}$`, "m"));
	}
	assert.match(fixture([listener("supabase", 8000, [api, notFound]), listener("studio_admin", 8001, [studio])], ["127.0.0.1:8000:8000", "127.0.0.1:8001:8001"]), new RegExp(`^PASS ${label}$`, "m"));
	assert.match(fixture([listener("supabase", 8000, [api, studio])], ["127.0.0.1:8000:8000"]), new RegExp(`^FAIL ${label}$`, "m"));
	assert.match(fixture([listener("supabase", 8000, [api, notFound]), listener("studio_admin", 8001, [studio])], ["127.0.0.1:8000:8000", "0.0.0.0:8001:8001"]), new RegExp(`^FAIL ${label}$`, "m"), "a non-loopback admin port is public");
	assert.match(fixture([listener("supabase", 8000, [api, notFound]), listener("studio_admin", 8001, [studio])], ["127.0.0.1:8000:8000", "8001:8001"]), new RegExp(`^FAIL ${label}$`, "m"), "an unbound host port publishes on every interface");
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
	mkdirSync(join(kit, "scripts", "lib"), { recursive: true });
	copyFileSync(script, join(kit, "scripts", "deployment-doctor.mjs"));
	copyFileSync(resolve(import.meta.dirname, "lib/deployment-credentials.mjs"), join(kit, "scripts/lib/deployment-credentials.mjs"));

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
