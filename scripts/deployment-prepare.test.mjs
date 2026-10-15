import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { inspectReviewedRuntime } from "./archive-boundary.mjs";
import { deploymentCredentialFailures } from "./lib/deployment-credentials.mjs";
import { CATALOG } from "./generate-onprem-config-reference.mjs";

const scriptsDirectory = dirname(fileURLToPath(import.meta.url));
const root = resolve(scriptsDirectory, "..");
const script = resolve(scriptsDirectory, "deployment-prepare.mjs");
const requireCore = createRequire(join(root, "packages/core/package.json"));
const { parse } = existsSync(join(root, "deploy/vendor/yaml.cjs"))
	? requireCore(join(root, "deploy/vendor/yaml.cjs"))
	: requireCore("yaml");
const dashboardUrl = "https://console.customer.example";
const supabaseUrl = "https://api.customer.example";
const artifactVerificationPublicKeyPem = generateKeyPairSync("ed25519").publicKey.export({
	type: "spki",
	format: "pem",
}).toString();

function inTemporaryDirectory(run) {
	const directory = mkdtempSync(join(tmpdir(), "aidr-deployment-preflight-"));
	try { return run(directory); }
	finally {
		assert.equal(dirname(realpathSync(directory)), realpathSync(tmpdir()));
		rmSync(directory, { recursive: true, force: true });
	}
}

function prepare(output, ...options) {
	const publicKeyFile = `${output}.artifact-verification-public.pem`;
	writeFileSync(publicKeyFile, artifactVerificationPublicKeyPem, "utf8");
	const defaultRegion = [
		...(options.includes("--region") ? [] : ["--region", "self-hosted"]),
		...(options.includes("--tenant-region") ? [] : ["--tenant-region", "self-hosted"]),
	];
	return spawnSync(process.execPath, [script, "--output", output, "--dashboard-url", dashboardUrl, "--supabase-url", supabaseUrl, "--artifact-verification-public-key-file", publicKeyFile, "--telemetry-queue-root", "/var/lib/aidr-telemetry", ...defaultRegion, ...(options.includes("--offline-policy") ? [] : ["--offline-policy", "keep_enforcing_local"]), ...options], {
		encoding: "utf8", timeout: 60_000,
	});
}

// Studio is reachable only on the gateway's loopback-published admin listener; the
// listener the ingress proxies (8000) ends in a 404 and has no Studio route.
function assertStudioNotPublic(output, compose) {
	for (const [name, service] of Object.entries(compose.services)) {
		for (const port of service.ports ?? []) assert.match(String(port), /^(127\.0\.0\.1|\[::1\]):/, `${name} publishes ${port} beyond loopback`);
	}
	assert.equal(compose.services.studio.ports, undefined, "Studio must not publish its own port");
	const lds = parse(readFileSync(join(output, "volumes/api/envoy/lds.template.yaml"), "utf8"));
	const listeners = Object.fromEntries(lds.resources.map((listener) => [listener.name, listener]));
	assert.deepEqual(Object.keys(listeners), ["supabase", "studio_admin"]);
	const routesOf = (listener) => listener.filter_chains[0].filters[0].typed_config.route_config.virtual_hosts[0].routes;
	assert.equal(listeners.supabase.address.socket_address.port_value, 8000);
	const publicRoutes = routesOf(listeners.supabase);
	assert.deepEqual(publicRoutes.filter((route) => route.route?.cluster === "studio"), [], "public listener routes to Studio");
	assert.deepEqual(publicRoutes.at(-1).match, { prefix: "/" });
	assert.deepEqual(publicRoutes.at(-1).direct_response, { status: 404 });
	assert.equal(publicRoutes.at(-1).typed_per_filter_config["envoy.filters.http.basic_auth"].disabled, true, "the public catch-all must not prompt for Studio credentials");
	assert.ok(publicRoutes.some((route) => route.match.prefix === "/rest/v1/" && route.route?.cluster === "rest"), "API routes stay on the public listener");
	assert.equal(listeners.studio_admin.address.socket_address.port_value, 8001);
	const adminRoutes = routesOf(listeners.studio_admin);
	assert.deepEqual(adminRoutes.map((route) => [route.match.prefix, route.route.cluster]), [["/api/mcp", "studio"], ["/mcp", "studio"], ["/", "studio"]]);
	assert.equal(adminRoutes.at(-1).typed_per_filter_config["envoy.filters.http.basic_auth"], undefined, "Studio keeps its basic-auth prompt on the admin listener");
	const mcpDeny = (route) => route.typed_per_filter_config["envoy.filters.http.rbac"].rbac.rules.action;
	assert.deepEqual(adminRoutes.slice(0, 2).map(mcpDeny), ["DENY", "DENY"], "Studio MCP stays denied");
	const published = compose.services["api-gw"].ports.map((port) => String(port).split(":").at(-1));
	assert.deepEqual(published, ["8000", "8001"]);
}

test("production first boot does not wait on readiness evidence that is installed later", () => {
	const installation = readFileSync(join(root, "deploy/README.md"), "utf8").split("## Isolated installation rehearsal")[0];
	assert.match(installation, /--output \/srv\/aidr/);
	assert.match(installation, /docker compose --project-directory \/srv\/aidr -f \/srv\/aidr\/compose\.yml up -d --build/);
	assert.doesNotMatch(installation, /up -d --wait/);
	assert.match(installation, /deployment-doctor\.mjs --deployment\s+\/srv\/aidr --online/);
	const airgap = readFileSync(join(root, "deploy/README.md"), "utf8").split("On the disconnected host:")[1].split("## Release boundary")[0];
	assert.match(airgap, /docker compose --project-directory \.aidr-deploy -f \.aidr-deploy\/compose\.yml up -d\s+node scripts\/deployment-migrate\.mjs \.aidr-deploy/);
	assert.doesNotMatch(airgap, /up -d --wait/);
	assert.match(airgap, /deployment-doctor\.mjs --deployment\s+\.aidr-deploy --online/);
});

test("operator runtime capability configuration is forwarded only to private function env", () => {
	inTemporaryDirectory((directory) => {
		const previous = process.env.AIDR_RUNTIME_CAPABILITIES_BY_TENANT;
		try {
			const mapping = { "tenant-approved": ["runtime_detectors", "behavioral_learning_v1"] };
			process.env.AIDR_RUNTIME_CAPABILITIES_BY_TENANT = JSON.stringify(mapping, null, 2);
			const output = join(directory, "capabilities");
			const result = prepare(output, "--mode", "cloud", "--device-start-upstream-url", "https://project.supabase.co/functions/v1/device-start");
			assert.equal(result.status, 0, result.stderr);
			assert.ok(readFileSync(join(output, ".env.functions"), "utf8").split(/\r?\n/)
				.includes(`AIDR_RUNTIME_CAPABILITIES_BY_TENANT=${JSON.stringify(mapping)}`));
			assert.doesNotMatch(readFileSync(join(output, ".env"), "utf8"), /AIDR_RUNTIME_CAPABILITIES_BY_TENANT/);
			assert.doesNotMatch(readFileSync(join(output, "compose.yml"), "utf8"), /AIDR_RUNTIME_CAPABILITIES_BY_TENANT/);
			for (const [index, invalid] of ["{", "[]", '{"tenant-approved":["behavioral_learning_v1"]}', '{"tenant-approved":["*"]}'].entries()) {
				process.env.AIDR_RUNTIME_CAPABILITIES_BY_TENANT = invalid;
				const invalidOutput = join(directory, `invalid-capabilities-${index}`);
				const invalidResult = prepare(invalidOutput, "--mode", "cloud", "--device-start-upstream-url", "https://project.supabase.co/functions/v1/device-start");
				assert.notEqual(invalidResult.status, 0);
				assert.match(invalidResult.stderr, /must be a bounded exact tenant capability map/);
				assert.equal(existsSync(invalidOutput), false);
			}
		} finally {
			if (previous === undefined) delete process.env.AIDR_RUNTIME_CAPABILITIES_BY_TENANT;
			else process.env.AIDR_RUNTIME_CAPABILITIES_BY_TENANT = previous;
		}
	});
});

test("IPv6 development origins bind matching loopback ports and device ingress upstream", () => {
	inTemporaryDirectory((directory) => {
		const output = join(directory, "ipv6-loopback");
		const result = prepare(output, "--development", "--dashboard-url", "http://[::1]:18080", "--supabase-url", "http://[::1]:18000");
		assert.equal(result.status, 0, result.stderr);
		const compose = parse(readFileSync(join(output, "compose.yml"), "utf8"));
		assert.deepEqual(compose.services.dashboard.ports, ["[::1]:18080:8080"]);
		assert.deepEqual(compose.services["api-gw"].ports, ["[::1]:18000:8000", "[::1]:18001:8001"]);
		assert.match(readFileSync(join(output, ".env.ingress"), "utf8"), /^AIDR_DEVICE_START_UPSTREAM_URL=http:\/\/\[::1\]:18000\/functions\/v1\/device-start$/m);
		const config = spawnSync("docker", ["compose", "--project-directory", output, "-f", join(output, "compose.yml"), "config", "--quiet"], { encoding: "utf8", timeout: 15_000 });
		assert.equal(config.status, 0, config.stderr);
	});
});

test("production preparation requires a readable valid artifact verification public key", () => {
	inTemporaryDirectory((directory) => {
		const missingOutput = join(directory, "missing-key");
		const missing = spawnSync(process.execPath, [script, "--mode", "cloud", "--output", missingOutput, "--dashboard-url", dashboardUrl, "--supabase-url", supabaseUrl, "--device-start-upstream-url", "https://project.supabase.co/functions/v1/device-start"], { encoding: "utf8", timeout: 60_000 });
		assert.notEqual(missing.status, 0);
		assert.match(missing.stderr, /requires --artifact-verification-public-key-file/);
		assert.equal(existsSync(missingOutput), false);

		const invalidOutput = join(directory, "invalid-key");
		const invalidKey = join(directory, "invalid.pem");
		writeFileSync(invalidKey, "not a public key", "utf8");
		const invalid = spawnSync(process.execPath, [script, "--mode", "cloud", "--output", invalidOutput, "--dashboard-url", dashboardUrl, "--supabase-url", supabaseUrl, "--device-start-upstream-url", "https://project.supabase.co/functions/v1/device-start", "--artifact-verification-public-key-file", invalidKey], { encoding: "utf8", timeout: 60_000 });
		assert.notEqual(invalid.status, 0);
		assert.match(invalid.stderr, /must be an Ed25519 SPKI public key/);
		assert.equal(existsSync(invalidOutput), false);
	});
});

test("production preparation requires an explicit fleet telemetry queue source", () => {
	inTemporaryDirectory((directory) => {
		const output = join(directory, "missing-queue-source");
		const publicKeyFile = join(directory, "artifact-verification-public.pem");
		writeFileSync(publicKeyFile, artifactVerificationPublicKeyPem, "utf8");
		const result = spawnSync(process.execPath, [script,
			"--mode", "cloud", "--output", output,
			"--dashboard-url", dashboardUrl, "--supabase-url", supabaseUrl,
			"--device-start-upstream-url", "https://project.supabase.co/functions/v1/device-start",
			"--artifact-verification-public-key-file", publicKeyFile,
		], { encoding: "utf8", timeout: 60_000 });
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /requires --telemetry-queue-root.*fleet-aggregated/);
		assert.equal(existsSync(output), false);
	});
});

test("preparation refuses the unassigned default residency region", () => {
	inTemporaryDirectory((directory) => {
		const output = join(directory, "unassigned-region");
		const publicKeyFile = join(directory, "artifact-verification-public.pem");
		writeFileSync(publicKeyFile, artifactVerificationPublicKeyPem, "utf8");
		const result = spawnSync(process.execPath, [script,
			"--mode", "cloud", "--output", output,
			"--dashboard-url", dashboardUrl, "--supabase-url", supabaseUrl,
			"--artifact-verification-public-key-file", publicKeyFile,
			"--telemetry-queue-root", "/var/lib/aidr-telemetry",
		], { encoding: "utf8", timeout: 60_000 });
		assert.notEqual(result.status, 0, "an installation with no selected declared region unexpectedly passed preparation");
		assert.match(result.stderr, /unassigned.*residency must be explicitly declared true by the operator/);
		assert.equal(existsSync(output), false);
	});
});

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

test("deployment secret root is private on every supported platform", () => {
	inTemporaryDirectory((directory) => {
		const output = join(directory, "private-root");
		const result = prepare(output, "--mode", "cloud", "--device-start-upstream-url", "https://project.supabase.co/functions/v1/device-start");
		assert.equal(result.status, 0, result.stderr);
		if (process.platform === "win32") {
			const inspect = "$item = [System.IO.DirectoryInfo]::new($env:AIDR_TEST_ACL_PATH); $acl = $item.GetAccessControl(); [pscustomobject]@{ protected = $acl.AreAccessRulesProtected; identities = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object { $_.AccessControlType -eq 'Allow' } | ForEach-Object { $_.IdentityReference.Value }) } | ConvertTo-Json -Compress";
			const acl = JSON.parse(execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(inspect, "utf16le").toString("base64")], { encoding: "utf8", env: { ...process.env, AIDR_TEST_ACL_PATH: output }, windowsHide: true }));
			assert.equal(acl.protected, true);
			assert.ok(acl.identities.some((identity) => /S-1-5-18|SYSTEM/i.test(identity)));
			assert.ok(acl.identities.some((identity) => /S-1-5-32-544|Administrators/i.test(identity)));
			// Restore inherited test ACLs so the temporary fixture can be removed.
			execFileSync("icacls.exe", [output, "/reset", "/t", "/c"], { stdio: "ignore", windowsHide: true });
		} else {
			assert.equal(statSync(output).mode & 0o777, 0o700);
			for (const name of [".env", ".env.functions", ".env.ingress"]) assert.equal(statSync(join(output, name)).mode & 0o777, 0o600);
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
		assert.doesNotMatch(ingressEnv, /^AIDR_DEVICE_START_ANON_KEY=/m);
		assert.match(readFileSync(join(output, ".env.functions"), "utf8"), /^AIDR_DEVELOPMENT_MODE=false$/m);
		const deployment = JSON.parse(readFileSync(join(output, "deployment.json"), "utf8"));
		assert.equal(deployment.supabase_url, supabaseUrl);
		const agentConfig = JSON.parse(readFileSync(join(output, "agent-config.json"), "utf8"));
		assert.equal(Object.hasOwn(agentConfig.control_plane, "allow_insecure_loopback"), false);
		assert.deepEqual(agentConfig.integrity, {
			enabled: true,
			verify_on_start: true,
			public_keys_pem: [artifactVerificationPublicKeyPem],
		});
		assert.notEqual(agentConfig.integrity.public_keys_pem[0], agentConfig.licensing.public_keys_pem[0]);
		const dashboard = parse(readFileSync(join(output, "compose.yml"), "utf8")).services.dashboard;
		assert.equal(dashboard.environment.AIDR_HEALTH_DATABASE_URL, `${supabaseUrl}/rest/v1/rpc/aidr_readiness_probe`);
		assert.equal(dashboard.environment.AIDR_HEALTH_FUNCTIONS_URL, `${supabaseUrl}/functions/v1/packs-manifest`);
		assert.equal(dashboard.environment.AIDR_PUBLIC_HTTPS_URL, dashboardUrl);
		assert.equal(dashboard.environment.SENTRY_ENVIRONMENT, "${SENTRY_ENVIRONMENT:-production}");
		assert.equal(dashboard.environment.SENTRY_TRACES_SAMPLE_RATE, "${SENTRY_TRACES_SAMPLE_RATE:-0}");
		assert.equal(dashboard.environment.AIDR_SIGNUP_MODE, "${AIDR_SIGNUP_MODE:-closed}");
		const cloudEnv = readFileSync(join(output, ".env"), "utf8");
		assert.match(cloudEnv, /^AIDR_SIGNUP_MODE=closed$/m);
		assert.doesNotMatch(cloudEnv, /^DISABLE_SIGNUP=/m, "managed provider Auth settings must not be represented as locally configured");
		assert.match(dashboard.healthcheck.test.at(-1), /\/readyz/);
		assert.doesNotMatch(dashboard.healthcheck.test.at(-1), /\/livez/);
		assert.equal(Object.hasOwn(dashboard.environment, "AIDR_AUTH_TEMPLATE_DIR"), false);
		assert.deepEqual(dashboard.volumes, [{ type: "bind", source: "./health", target: "/run/aidr-health", read_only: true }]);
	});
});

test("the offline behaviour is an explicit install-time choice, written to the agent config and the endpoint policy", () => {
	inTemporaryDirectory((directory) => {
		const unset = join(directory, "unset");
		const publicKeyFile = join(directory, "artifact.pem");
		writeFileSync(publicKeyFile, artifactVerificationPublicKeyPem, "utf8");
		const refused = spawnSync(process.execPath, [script,
			"--mode", "cloud", "--output", unset,
			"--dashboard-url", dashboardUrl, "--supabase-url", supabaseUrl,
			"--artifact-verification-public-key-file", publicKeyFile,
			"--telemetry-queue-root", "/var/lib/aidr-telemetry",
			"--region", "self-hosted", "--tenant-region", "self-hosted",
		], { encoding: "utf8", timeout: 60_000, stdio: ["ignore", "pipe", "pipe"] });
		assert.notEqual(refused.status, 0);
		assert.match(refused.stderr, /requires --offline-policy keep_enforcing_local\|block_after_grace/);
		assert.equal(existsSync(unset), false);
		const invalid = prepare(join(directory, "invalid"), "--mode", "cloud", "--offline-policy", "fail_open");
		assert.notEqual(invalid.status, 0);
		assert.match(invalid.stderr, /--offline-policy must be one of/);

		for (const choice of ["keep_enforcing_local", "block_after_grace"]) {
			const output = join(directory, choice);
			const result = prepare(output, "--mode", "cloud", "--offline-policy", choice);
			assert.equal(result.status, 0, result.stderr);
			const agentConfig = JSON.parse(readFileSync(join(output, "agent-config.json"), "utf8"));
			assert.equal(agentConfig.control_plane.offline_policy, choice);
			assert.equal(agentConfig.control_plane.remote_policy_required, choice === "block_after_grace");
			assert.equal(JSON.parse(readFileSync(join(output, "deployment.json"), "utf8")).offline_policy, choice);
			// The endpoint machine policy carries the address, the deployment's signing key and the choice.
			const policy = JSON.parse(readFileSync(join(output, "endpoint-policy/managed.json"), "utf8"));
			assert.deepEqual(Object.keys(policy).sort(), ["control_plane_url", "licensing_public_keys_pem", "offline_policy"]);
			assert.equal(policy.control_plane_url, `${supabaseUrl}/functions/v1`);
			assert.equal(policy.offline_policy, choice);
			const licensing = createPublicKey(agentConfig.licensing.public_keys_pem[0]).export({ type: "spki", format: "der" }).toString("base64");
			assert.deepEqual(policy.licensing_public_keys_pem, [licensing]);
			assert.equal(readFileSync(join(output, "endpoint-policy/licensing-public-keys.pem"), "utf8"), agentConfig.licensing.public_keys_pem[0]);
			const reg = readFileSync(join(output, "endpoint-policy/aidr-machine-policy.reg"), "utf8");
			assert.match(reg, /\[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Singularity AIDR\]/);
			assert.match(reg, new RegExp(`"offline_policy"="${choice}"`));
			const readme = readFileSync(join(output, "endpoint-policy/README.txt"), "utf8");
			assert.match(readme, new RegExp(`AIDR_POLICY_OFFLINE_POLICY=${choice}`));
			assert.doesNotMatch(readme + reg + JSON.stringify(policy), /PRIVATE KEY|aidr_fleet_[A-Za-z0-9]/);
		}
	});
});

test("development loopback agent config explicitly opts into HTTP", () => {
	inTemporaryDirectory((directory) => {
		const output = join(directory, "development-loopback");
		const result = spawnSync(process.execPath, [script,
			"--mode", "cloud",
			"--output", output,
			"--development",
			"--dashboard-url", "http://localhost:8080",
			"--supabase-url", "http://127.0.0.1:8000",
			"--region", "self-hosted", "--tenant-region", "self-hosted",
		], { encoding: "utf8", timeout: 60_000 });
		assert.equal(result.status, 0, result.stderr);
		const agentConfig = JSON.parse(readFileSync(join(output, "agent-config.json"), "utf8"));
		assert.equal(agentConfig.control_plane.endpoint, "http://127.0.0.1:8000/functions/v1");
		assert.equal(agentConfig.control_plane.allow_insecure_loopback, true);
		assert.equal(Object.hasOwn(agentConfig, "integrity"), false);
		assert.match(readFileSync(join(output, ".env.functions"), "utf8"), /^AIDR_DEVELOPMENT_MODE=true$/m);
		const compose = parse(readFileSync(join(output, "compose.yml"), "utf8"));
		assert.equal(compose.services.dashboard.environment.NODE_ENV, "development");
		assert.equal(compose.services.dashboard.environment.SENTRY_ENVIRONMENT, "${SENTRY_ENVIRONMENT:-development}");
		assert.equal(compose.services.dashboard.environment.SENTRY_TRACES_SAMPLE_RATE, "${SENTRY_TRACES_SAMPLE_RATE:-0}");
		assert.equal(Object.hasOwn(compose.services.dashboard.environment, "AIDR_PUBLIC_HTTPS_URL"), false);
		assert.match(compose.services.dashboard.healthcheck.test.at(-1), /\/livez/);
		assert.doesNotMatch(compose.services.dashboard.healthcheck.test.at(-1), /\/readyz/);
	});
});

test("development loopback origins publish matching isolated Compose ports", () => {
	inTemporaryDirectory((directory) => {
		const output = join(directory, "isolated-ports");
		const result = spawnSync(process.execPath, [script,
			"--mode", "self-hosted", "--output", output, "--development",
			"--dashboard-url", "http://localhost:38080",
			"--supabase-url", "http://localhost:38000",
			"--region", "self-hosted", "--tenant-region", "self-hosted",
		], { encoding: "utf8", timeout: 60_000 });
		assert.equal(result.status, 0, result.stderr);
		const services = parse(readFileSync(join(output, "compose.yml"), "utf8")).services;
		assert.equal(services["api-gw"].image, "envoyproxy/envoy:v1.39.2@sha256:460f8c329f24b2e1c7c5af64cb314a6f351ad1c262ba77b135ac46b35ebd5f85");
		assert.equal(services.imgproxy.image, "darthsim/imgproxy:v4.0.17@sha256:db0b4b9cd690c8b3590203dea300fb759a18c4ec2af7b37424f0bdef23ce317d");
		assert.equal(services.imgproxy.environment.IMGPROXY_USE_LAST_MODIFIED, "false");
		const scanGated = {
			studio: "supabase/studio:2026.10.05-sha-94b8b06@sha256:d878dcd9dba73b66d1c2c19aeaf53d07704e71604d93013225be1d1c51475237",
			auth: "supabase/gotrue:v2.197.0@sha256:1736a63078f5922b198c4cbe50f80ab9a2d3b54fe8b7b6cfb2e9dc5dbbc12c6b",
			storage: "supabase/storage-api:v1.80.2@sha256:95b217a9c59e0ac06c6dcb539df3189a1668a2445fb43dbf29660d6968ffd7d2",
			meta: "supabase/postgres-meta:v0.100.0@sha256:145325b7e39f8ef4931d6e8cfd3f6f4d655de09d72a2ccc96d9513542c2202bd",
			functions: "supabase/edge-runtime:v1.77.4@sha256:ad45164b7548bf5820ed7be714789c17ac2865edce79a09cfb4c3756c3d365a8",
			// Stateful bump, gated by docs/production-readiness/postgres-upgrade-restore-drill-2026-10-11.md.
			db: "supabase/postgres:17.11.0.004@sha256:06ddc7962e11ab0f4f0334fd05671e97c30ea202f6e6a7113800bd3d6e416108",
		};
		for (const [name, image] of Object.entries(scanGated)) assert.equal(services[name].image, image, name);
		const reviewed = parse(readFileSync(join(root, "deploy/upstream/docker/docker-compose.yml"), "utf8")).services;
		for (const [name, service] of Object.entries(reviewed)) {
			if (name !== "api-gw" && name !== "imgproxy" && name !== "supavisor" && !Object.hasOwn(scanGated, name)) assert.equal(services[name].image, service.image, name);
		}
		assert.equal(reviewed.db.image, "supabase/postgres:17.6.1.136", "upstream db pin moved; re-run the restore drill before following it");
		assert.deepEqual(services.imgproxy.environment, { ...reviewed.imgproxy.environment, IMGPROXY_USE_LAST_MODIFIED: "false" });
		for (const setting of ["restart", "networks", "healthcheck", "depends_on", "volumes", "environment", "entrypoint"]) {
			assert.deepEqual(services["api-gw"][setting], reviewed["api-gw"][setting], setting);
		}
		assert.deepEqual(services["api-gw"].ports, ["127.0.0.1:38000:8000", "127.0.0.1:38001:8001"]);
		assert.deepEqual(services.dashboard.ports, ["127.0.0.1:38080:8080"]);
		assert.match(readFileSync(join(output, ".env.ingress"), "utf8"), /^AIDR_DEVICE_START_UPSTREAM_URL=http:\/\/127\.0\.0\.1:38000\/functions\/v1\/device-start$/m);
	});
});

test("development preparation rejects public HTTPS endpoints", () => {
	inTemporaryDirectory((directory) => {
		const output = join(directory, "public-development");
		const result = spawnSync(process.execPath, [script,
			"--mode", "cloud", "--output", output, "--development",
			"--dashboard-url", dashboardUrl, "--supabase-url", supabaseUrl,
			"--region", "self-hosted", "--tenant-region", "self-hosted",
		], { encoding: "utf8", timeout: 60_000 });
		assert.notEqual(result.status, 0, "development mode accepted public HTTPS endpoints");
		assert.match(result.stderr, /--development requires both dashboard and Supabase URLs to use loopback hosts/);
		assert.equal(existsSync(output), false, "rejected public development configuration left a partial installation");
	});
});

test("generated self-hosted deployment wires protected monitoring without inventing evidence", () => {
	inTemporaryDirectory((directory) => {
		const output = join(directory, "self-hosted-monitoring");
		const result = prepare(output, "--mode", "self-hosted", "--region", "self-hosted", "--tenant-region", "self-hosted");
		assert.equal(result.status, 0, result.stderr);

		const envText = readFileSync(join(output, ".env"), "utf8");
		const generatedEnv = Object.fromEntries(envText.split(/\r?\n/).filter((line) => /^[A-Z][A-Z0-9_]*=/.test(line)).map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]));
		assert.deepEqual(deploymentCredentialFailures(generatedEnv), [], "fresh preparation must replace every shared vendor secret and generate private project API keys");
		assert.match(envText, /^DISABLE_SIGNUP=true$/m);
		const anonKey = envText.match(/^ANON_KEY=(.+)$/m)?.[1];
		assert.ok(anonKey, "anonymous API key was not generated in the private environment file");
		const ingressEnv = readFileSync(join(output, ".env.ingress"), "utf8");
		assert.ok(ingressEnv.split(/\r?\n/).includes(`AIDR_DEVICE_START_ANON_KEY=${anonKey}`));
		const metricsToken = envText.match(/^AIDR_METRICS_TOKEN=([a-f0-9]{64})$/m)?.[1];
		assert.ok(metricsToken, "monitoring token was not generated in the private environment file");
		const composeText = readFileSync(join(output, "compose.yml"), "utf8");
		assert.equal(composeText.includes(metricsToken), false, "monitoring token was embedded in Compose");
		const dashboard = parse(composeText).services.dashboard;
		assert.deepEqual(dashboard.environment, {
			NODE_ENV: "production",
			VITE_SUPABASE_URL: supabaseUrl,
			VITE_SUPABASE_ANON_KEY: "${ANON_KEY}",
			SENTRY_DSN: "${SENTRY_DSN:-}",
			SENTRY_ENVIRONMENT: "${SENTRY_ENVIRONMENT:-production}",
			SENTRY_TRACES_SAMPLE_RATE: "${SENTRY_TRACES_SAMPLE_RATE:-0}",
			AIDR_AUTH_METHODS: "${AIDR_AUTH_METHODS:-password}",
			AIDR_SIGNUP_MODE: "closed",
			AIDR_AUTH_TEMPLATE_DIR: "/app/auth-templates",
			AIDR_DEVELOPMENT_MODE: "false",
			AIDR_HEALTH_DATABASE_URL: "http://api-gw:8000/rest/v1/rpc/aidr_readiness_probe",
			AIDR_HEALTH_STORAGE_URL: "http://api-gw:8000/storage/v1/status",
			AIDR_HEALTH_FUNCTIONS_URL: "http://api-gw:8000/functions/v1/packs-manifest",
			AIDR_SIGNING_HEALTH_FILE: "/run/aidr-health/signing.json",
			AIDR_BACKUP_HEALTH_FILE: "/run/aidr-health/backup.json",
			AIDR_QUEUE_HEALTH_FILE: "/run/aidr-health/queue.json",
			AIDR_LICENSE_HEALTH_FILE: "/run/aidr-health/license.json",
			AIDR_PUBLIC_HTTPS_URL: dashboardUrl,
			AIDR_METRICS_TOKEN: "${AIDR_METRICS_TOKEN:?AIDR_METRICS_TOKEN is required}",
			AIDR_READINESS_REQUIRED_CHECKS: "database,storage,functions,signing,backup,queue,certificate",
			// Single sign-on switches stay off unless the operator sets them in .env.
			AIDR_OIDC_SSO: "${AIDR_OIDC_SSO:-false}",
			AIDR_SAML_PROVIDERS: "${AIDR_SAML_PROVIDERS:-}",
			AIDR_SAML_PROVIDER_ID: "${AIDR_SAML_PROVIDER_ID:-}",
			AIDR_SAML_DOMAIN: "${AIDR_SAML_DOMAIN:-}",
		});
		assert.match(dashboard.healthcheck.test.at(-1), /\/readyz/);
		assert.deepEqual(dashboard.volumes, [{ type: "bind", source: "./health", target: "/run/aidr-health", read_only: true }]);
		assert.equal(composeText.includes("http://dashboard:8080/auth-templates/recovery.html"), true);
		const compose = parse(composeText);
		assert.deepEqual(compose.services["api-gw"].ports, ["127.0.0.1:8000:8000", "127.0.0.1:8001:8001"]);
		assert.deepEqual(compose.services.dashboard.ports, ["127.0.0.1:8080:8080"]);
		assertStudioNotPublic(output, compose);
		assert.equal(compose.services.auth.environment.GOTRUE_MAILER_TEMPLATES_RECOVERY, "http://dashboard:8080/auth-templates/recovery.html");
		assert.equal(compose.services.auth.environment.GOTRUE_MAILER_SUBJECTS_RECOVERY, "Reset your AIDR password");
		assert.equal(readFileSync(join(output, "dashboard", "auth-templates", "recovery.html"), "utf8"), readFileSync(join(root, "supabase", "templates", "recovery.html"), "utf8"));
		const dashboardDockerfile = readFileSync(join(output, "dashboard", "Dockerfile"), "utf8");
		assert.match(dashboardDockerfile, /COPY --chown=node:node auth-templates \.\/auth-templates/);
		assert.match(dashboardDockerfile, /COPY --chown=node:node saml-config\.mjs \/saml-config\.mjs/);
		assert.equal(readFileSync(join(output, "dashboard", "saml-config.mjs"), "utf8"), readFileSync(join(root, "deploy", "saml-config.mjs"), "utf8"));
		assert.match(readFileSync(join(output, "dashboard", ".dockerignore"), "utf8"), /^!saml-config\.mjs$/m);
		assert.match(dashboardDockerfile, /^ENV NODE_ENV=production$/m);
		assert.deepEqual(readdirSync(join(output, "health")), [], "preparation must not fabricate readiness evidence");
		const backupService = readFileSync(join(output, "backup", "aidr-backup-offsite.service"), "utf8");
		assert.match(backupService, /--health-file \/srv\/aidr\/health\/backup\.json/);
		assert.doesNotMatch(backupService, /\/run\/aidr-health/);
		const readinessEnv = readFileSync(join(output, ".env.readiness"), "utf8");
		assert.match(readinessEnv, /^AIDR_SIGNING_KEY_EXPIRES_AT=\d{4}-\d{2}-\d{2}T/m);
		assert.match(readinessEnv, /^AIDR_DELEGATION_SIGNING_KEY_EXPIRES_AT=\d{4}-\d{2}-\d{2}T/m);
		assert.match(readinessEnv, /^AIDR_TELEMETRY_QUEUE_ROOTS=\/var\/lib\/aidr-telemetry$/m);
		const functionEnv = readFileSync(join(output, ".env.functions"), "utf8");
		assert.ok(functionEnv.split(/\r?\n/).includes(`AIDR_RUNTIME_CAPABILITIES_BY_TENANT=${JSON.stringify(JSON.parse(process.env.AIDR_RUNTIME_CAPABILITIES_BY_TENANT?.trim() || "{}"))}`));
		assert.match(functionEnv, /^AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64=\S+$/m);
		// The license import trust root is the kit's shipped registry, byte for byte.
		const licenseKeys = functionEnv.split(/\r?\n/).find((line) => line.startsWith("AIDR_LICENSE_PUBLIC_KEYS_B64="));
		assert.ok(licenseKeys, "license trust registry missing from the function environment");
		assert.equal(Buffer.from(licenseKeys.slice("AIDR_LICENSE_PUBLIC_KEYS_B64=".length), "base64").toString("utf8"),
			readFileSync(join(root, "deploy", "onprem", "license-public-keys.json"), "utf8"));
		assert.match(functionEnv, /^AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64=\S+$/m);
		assert.match(functionEnv, /^AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64=\S+$/m);
		assert.match(functionEnv, /^AIDR_PACK_DOWNLOAD_GRANT_SECRET=[A-Za-z0-9_-]{43}$/m);
		assert.match(functionEnv, /^AIDR_NOTIFICATION_ENCRYPTION_KEYS=k1:[A-Za-z0-9+/]{43}=$/m);
		assert.match(functionEnv, /^AIDR_NOTIFICATION_DISPATCH_TOKEN=[A-Za-z0-9_-]{43}$/m);
		assert.match(functionEnv, /^AIDR_APPROVAL_SIGNING_WRAP_KEY_B64=[A-Za-z0-9+/]{43}=$/m);
		// Compliance reports are sealed with their own Ed25519 key; auditors get the public half.
		const complianceKeyId = /^AIDR_COMPLIANCE_SIGNING_KEY_ID=(aidr-compliance-[a-f0-9]{12})$/m.exec(functionEnv)?.[1];
		assert.ok(complianceKeyId);
		const compliancePkcs8 = /^AIDR_COMPLIANCE_SIGNING_PRIVATE_KEY_PKCS8_B64=(\S+)$/m.exec(functionEnv)?.[1];
		const complianceKey = createPrivateKey({ key: Buffer.from(compliancePkcs8, "base64"), format: "der", type: "pkcs8" });
		assert.equal(complianceKey.asymmetricKeyType, "ed25519");
		const complianceRecord = JSON.parse(readFileSync(join(output, "deployment.json"), "utf8")).compliance_signing;
		assert.equal(complianceRecord.key_id, complianceKeyId);
		assert.ok(verify(null, Buffer.from("report"), createPublicKey(complianceRecord.public_key_pem), sign(null, Buffer.from("report"), complianceKey)));
		assert.notEqual(compliancePkcs8, /^AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64=(\S+)$/m.exec(functionEnv)?.[1]);
		assert.ok(functionEnv.split(/\r?\n/).includes(`AIDR_PUBLIC_API_ORIGIN=${supabaseUrl}`));
		assert.equal(existsSync(join(output, ".secrets")), false, "signing canaries must not verify disconnected key copies");
		assert.equal(existsSync(join(output, "upstream")), false, "the checked-out pinned Supabase submodule must not be copied into the installation root");
		const readinessService = readFileSync(join(output, "maintenance", "aidr-siem-delivery.service"), "utf8");
		assert.doesNotMatch(readinessService, /^LoadCredential=/m);
		assert.doesNotMatch(readinessService, /^ConditionPathExists=/m);
		assert.match(readinessService, /^ExecStart=\/usr\/bin\/node \/srv\/aidr\/maintenance\/readiness-evidence-worker\.mjs$/m);
		assert.equal(existsSync(join(output, "maintenance", "readiness-evidence-worker.mjs")), true);
		assert.equal(readFileSync(join(output, "ingress", "deployment-tls-renew.mjs"), "utf8"), readFileSync(join(root, "scripts", "deployment-tls-renew.mjs"), "utf8"));
		assert.match(readFileSync(join(output, "ingress", "aidr-tls-renew.service"), "utf8"), /ExecStart=\/usr\/bin\/node \/srv\/aidr\/ingress\/deployment-tls-renew\.mjs/);
		assert.doesNotMatch(readFileSync(join(output, "maintenance", "readiness-evidence-worker.mjs"), "utf8"), /\.\.\/packages\/core\/dist/);
		assert.match(readFileSync(join(output, "maintenance", "aidr-siem-delivery.timer"), "utf8"), /^OnUnitActiveSec=1min$/m);
		assert.match(readFileSync(join(output, "maintenance", "install-systemd.sh"), "utf8"), /systemctl enable --now aidr-siem-delivery\.timer/);
		assert.match(backupService, /^ExecStart=\/usr\/bin\/node \/srv\/aidr\/backup\/deployment-backup-offsite\.mjs /m);
		assert.equal(existsSync(join(output, "backup", "deployment-backup-offsite.mjs")), true);
		assert.equal(existsSync(join(output, "backup", "deployment-backup.mjs")), true);
		const deployment = JSON.parse(readFileSync(join(output, "deployment.json"), "utf8"));
		for (const file of ["node-helper-image.mjs", "node-helper.Dockerfile"]) {
			assert.equal(readFileSync(join(output, "backup", "lib", file), "utf8"), readFileSync(join("scripts", "lib", file), "utf8"));
			assert.ok(deployment.artifacts.some((entry) => entry.path === `backup/lib/${file}`));
		}
		assert.match(readFileSync(join(output, "backup", "deployment-backup.mjs"), "utf8"), /from ["']\.\/lib\/node-helper-image\.mjs["']/);
		// The bundle inlines the restore-drill and offsite modules; their CLIs must not run
		// inside it (they would print failures and leave exit code 1 after a successful recover).
		const bundledKeygen = spawnSync(process.execPath, [join(output, "backup", "deployment-backup.mjs"), "keygen", "--key-file", join(output, "..", "bundle-check", "recovery.key")], { encoding: "utf8" });
		assert.equal(bundledKeygen.status, 0, bundledKeygen.stderr);
		assert.doesNotMatch(bundledKeygen.stderr, /AIDR (restore drill|offsite backup) failed/);
		assert.equal(existsSync(join(output, "backup", "deployment-backup-health-failed.mjs")), true);
		assert.equal(existsSync(join(output, "backup", "aidr-backup-health-failed.service")), true);
		assert.ok(deployment.artifacts.some((entry) => entry.path === "backup/aidr-backup-offsite.service"));
		assert.ok(deployment.artifacts.some((entry) => entry.path === "backup/aidr-backup-health-failed.service"));
		assert.ok(deployment.artifacts.some((entry) => entry.path === "maintenance/aidr-siem-delivery.service"));
		assert.ok(deployment.artifacts.some((entry) => entry.path === "ingress/deployment-tls-renew.mjs"));
		assert.ok(deployment.artifacts.some((entry) => entry.path === "auth-templates/recovery.html"));
		deployment.source_has_changes = false;
		writeFileSync(join(output, "deployment.json"), JSON.stringify(deployment));
		assert.equal(inspectReviewedRuntime(output, { sourceCommit: deployment.source_commit }).source_commit, deployment.source_commit, "prepared runtime must satisfy the recovery inspection contract without a synthetic .secrets directory");
		assert.match(readFileSync(join(output, ".env"), "utf8"), /ADDITIONAL_REDIRECT_URLS=.*\/auth\/callback,.*\/auth\/recover/);
		if (process.platform !== "win32") {
			assert.equal(statSync(join(output, "health")).mode & 0o777, 0o755);
			assert.equal(statSync(join(output, ".env.functions")).mode & 0o777, 0o600);
		}
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
		const regionsManifest = join(directory, "regions.json");
		writeFileSync(regionsManifest, JSON.stringify({ schema_version: 1, regions: {
			"self-hosted": { supabase_url: null, residency: { declared: true, location: "customer-designated host" } },
			frankfurt: { supabase_url: null, residency: { declared: true, location: "Frankfurt" } },
		} }));
		const output = join(directory, "cross-region");
		const result = prepare(output, "--region", "self-hosted", "--tenant-region", "frankfurt", "--regions-manifest", regionsManifest);
		assert.notEqual(result.status, 0, "a cross-region installation unexpectedly succeeded");
		assert.match(result.stderr, /Tenant declared region "frankfurt" does not match deployment region "self-hosted"/);
		assert.equal(existsSync(output), false, "a cross-region preparation left a partial installation");
	});
});

test("preparation rejects an undeclared residency location and records a true declaration only as operator-stated", () => {
	inTemporaryDirectory((directory) => {
		const regionsManifest = join(directory, "regions.json");
		const manifest = { schema_version: 1, regions: { frankfurt: { supabase_url: null, residency: { declared: false, location: "Frankfurt" } } } };
		writeFileSync(regionsManifest, JSON.stringify(manifest));
		const rejectedOutput = join(directory, "undeclared-frankfurt");
		const rejected = prepare(rejectedOutput, "--mode", "cloud", "--region", "frankfurt", "--tenant-region", "frankfurt", "--regions-manifest", regionsManifest);
		assert.notEqual(rejected.status, 0, "a location string incorrectly substituted for an explicit residency declaration");
		assert.match(rejected.stderr, /frankfurt.*residency must be explicitly declared true by the operator/);
		assert.equal(existsSync(rejectedOutput), false, "failed residency validation left a partial installation");

		manifest.regions.frankfurt.residency.declared = true;
		writeFileSync(regionsManifest, JSON.stringify(manifest));
		const acceptedOutput = join(directory, "declared-frankfurt");
		const accepted = prepare(acceptedOutput, "--mode", "cloud", "--region", "frankfurt", "--tenant-region", "frankfurt", "--regions-manifest", regionsManifest);
		assert.equal(accepted.status, 0, accepted.stderr);
		const deployment = JSON.parse(readFileSync(join(acceptedOutput, "deployment.json"), "utf8"));
		assert.equal(deployment.regions.frankfurt.residency.declared, true);
		assert.equal(deployment.regions.frankfurt.residency.location, "Frankfurt");
		assert.match(deployment.note, /operator declarations, not evidence of provider placement/);
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
		assert.equal(deployment.regions["self-hosted"].residency.declared, true);
		assert.match(deployment.regions["self-hosted"].residency.location, /\S/);
	});
});

const resourceProfiles = JSON.parse(readFileSync(join(root, "deploy/onprem/resource-profile.json"), "utf8"));
const dashboardVersion = JSON.parse(readFileSync(join(root, "packages/dashboard/package.json"), "utf8")).version;
const dockerCompose = spawnSync("docker", ["compose", "version"], { encoding: "utf8", timeout: 30_000 });
const dockerComposeAvailable = !dockerCompose.error && dockerCompose.status === 0;

function assertComposeConfigResolves(output, check) {
	const config = spawnSync("docker", ["compose", "--project-directory", output, "-f", join(output, "compose.yml"), "config", ...(check ? ["--format", "json"] : ["--quiet"])], { encoding: "utf8", timeout: 60_000 });
	assert.equal(config.status, 0, `docker compose config rejected the prepared stack: ${config.stderr}`);
	if (check) check(JSON.parse(config.stdout));
}

function assertBudget(service, budget, label) {
	assert.deepEqual(service.deploy.resources.limits, { cpus: budget.cpus, memory: budget.memory, ...(budget.pids ? { pids: budget.pids } : {}) }, `${label} limits`);
	const reservations = { ...(budget.reservation_cpus ? { cpus: budget.reservation_cpus } : {}), ...(budget.reservation_memory ? { memory: budget.reservation_memory } : {}) };
	assert.deepEqual(service.deploy.resources.reservations ?? {}, reservations, `${label} reservations`);
}

test("on-prem profile applies resource budgets, runtime policy and a versioned dashboard image", (t) => {
	if (!dockerComposeAvailable) t.diagnostic("docker compose is not installed; the compose config check is skipped");
	inTemporaryDirectory((directory) => {
		const output = join(directory, "onprem-medium");
		const result = prepare(output, "--mode", "self-hosted", "--profile", "medium");
		assert.equal(result.status, 0, result.stderr);
		const compose = parse(readFileSync(join(output, "compose.yml"), "utf8"));
		const budgets = resourceProfiles.profiles.medium.services;
		assert.deepEqual(Object.keys(compose.services).sort(), ["api-gw", "auth", "dashboard", "db", "functions", "imgproxy", "meta", "realtime", "rest", "siem-forwarder", "storage", "studio"]);
		for (const [name, service] of Object.entries(compose.services)) {
			assertBudget(service, budgets[name], name);
			assert.equal(service.restart, "unless-stopped", `${name} restart policy`);
			assert.deepEqual(service.logging, { driver: "json-file", options: { "max-size": "20m", "max-file": "5", compress: "true" } }, `${name} log rotation`);
			assert.ok(service.healthcheck?.test, `${name} has no health check`);
			assert.equal(Object.hasOwn(service, "profiles"), false);
		}
		assert.equal(compose.services.db.stop_grace_period, "120s");
		// PostgREST detects pooled connections on a dead network path (load-soak drill O2);
		// operators can replace the libpq parameter string through .env.
		const keepalives = "keepalives=1&keepalives_idle=30&keepalives_interval=10&keepalives_count=3&tcp_user_timeout=20000";
		assert.equal(
			compose.services.rest.environment.PGRST_DB_URI,
			`postgres://authenticator:\${POSTGRES_PASSWORD}@\${POSTGRES_HOST}:\${POSTGRES_PORT}/\${POSTGRES_DB}?\${AIDR_POSTGREST_DB_URI_PARAMS:-${keepalives}}`,
		);
		for (const name of ["PGRST_DB_POOL_ACQUISITION_TIMEOUT", "PGRST_DB_POOL_MAX_IDLETIME", "PGRST_DB_POOL_MAX_LIFETIME"]) {
			assert.equal(Object.hasOwn(compose.services.rest.environment, name), false, `${name} keeps the PostgREST default`);
		}
		assertStudioNotPublic(output, compose);
		assert.match(compose.services.meta.healthcheck.test.at(-1), /connect\(8080/);
		assert.equal(compose.services.dashboard.image, `aidr-dashboard:${dashboardVersion}`);
		assert.equal(compose.services.dashboard.build, "./dashboard");
		assert.equal(compose.services.dashboard.healthcheck.retries, 3);
		assert.match(compose.services.dashboard.healthcheck.test.at(-1), /\/readyz/, "the overlay must not replace the production readiness probe");
		// AIDR mail reuses the Auth SMTP relay; the central SIEM forwarder sees only its token.
		for (const name of ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "SMTP_ADMIN_EMAIL", "SMTP_SENDER_NAME"]) {
			assert.equal(compose.services.functions.environment[name], `\${${name}:-}`, name);
		}
		const forwarder = compose.services["siem-forwarder"];
		assert.equal(forwarder.image, `aidr-dashboard:${dashboardVersion}`);
		assert.deepEqual(Object.keys(forwarder.environment).sort(), ["AIDR_NOTIFICATION_DISPATCH_TOKEN", "AIDR_SIEM_FORWARDER_URL", "AIDR_SIEM_FORWARD_INTERVAL_SECONDS"]);
		assert.equal(forwarder.environment.AIDR_SIEM_FORWARDER_URL, "http://functions:9000/siem-forwarder");
		assert.equal(Object.hasOwn(forwarder, "env_file"), false, "the scheduler never loads the functions keyring");
		assert.doesNotMatch(forwarder.command.join(" "), /\$/, "no Compose interpolation inside the loop script");
		const dotEnv = readFileSync(join(output, ".env"), "utf8");
		const functionsEnv = readFileSync(join(output, ".env.functions"), "utf8");
		const token = (text) => /^AIDR_NOTIFICATION_DISPATCH_TOKEN=(.+)$/m.exec(text)?.[1];
		assert.ok(token(dotEnv) && token(dotEnv) === token(functionsEnv));
		const deployment = JSON.parse(readFileSync(join(output, "deployment.json"), "utf8"));
		assert.equal(deployment.resource_profile, "medium");
		assert.equal(deployment.dashboard_image, `aidr-dashboard:${dashboardVersion}`);
		assert.deepEqual(deployment.posture_scanner, { enabled: false });
		assert.equal(Object.hasOwn(deployment, "aig"), false);
		assert.doesNotMatch(readFileSync(join(output, ".env"), "utf8"), /^(COMPOSE_PROFILES|POSTURE_SCANNER_|AIG_|BRIDGE_)/m);
		assert.equal(existsSync(join(output, "posture-scanner")), false);
		assert.equal(existsSync(join(output, "aig")), false);
		// Every variable the configuration reference promises for a self-hosted install is written.
		for (const entry of CATALOG.filter((item) => ["always", "self-hosted"].includes(item.written))) {
			assert.match(readFileSync(join(output, entry.file), "utf8"), new RegExp(`^${entry.name}=`, "m"), `${entry.file} lacks documented ${entry.name}`);
		}
		if (dockerComposeAvailable) {
			assertComposeConfigResolves(output, (resolved) => {
				assert.match(resolved.services.rest.environment.PGRST_DB_URI, new RegExp(`^postgres://authenticator:[^@]+@db:5432/postgres\\?${keepalives}$`));
			});
		}
	});
});

test("an unknown resource profile is refused before anything is written", () => {
	inTemporaryDirectory((directory) => {
		const output = join(directory, "unknown-profile");
		const result = prepare(output, "--mode", "cloud", "--profile", "huge");
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /Unknown resource profile "huge"; choose one of: small, medium, large/);
		assert.equal(existsSync(output), false);
	});
});

test("--with-posture-scanner merges the single-host posture scanner stack with an isolated deny-by-default egress gateway", (t) => {
	if (!dockerComposeAvailable) t.diagnostic("docker compose is not installed; the compose config check is skipped");
	inTemporaryDirectory((directory) => {
		const output = join(directory, "onprem-posture-scanner");
		const releaseKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey;
		const releaseKeyFile = join(directory, "posture-scanner-release-public.pem");
		writeFileSync(releaseKeyFile, releaseKey.export({ type: "spki", format: "pem" }));
		const result = prepare(output, "--mode", "self-hosted", "--profile", "large", "--with-posture-scanner", "--posture-scanner-signing-public-key-file", releaseKeyFile, "--posture-scanner-signing-key-id", "scanner-release-2026");
		assert.equal(result.status, 0, result.stderr);
		assert.doesNotMatch(result.stderr, /deprecated/);
		const compose = parse(readFileSync(join(output, "compose.yml"), "utf8"));
		const aigServices = ["aig-agent", "aig-bridge", "aig-egress", "aig-server"];
		for (const name of aigServices) {
			const service = compose.services[name];
			assert.deepEqual(service.profiles, ["posture-scanner"], `${name} profile`);
			assert.equal(Object.hasOwn(service, "container_name"), false, `${name} must be project-scoped`);
			assertBudget(service, resourceProfiles.profiles.large.services[name], name);
			assert.equal(service.restart, "unless-stopped");
			assert.equal(service.read_only, true);
			assert.deepEqual(service.cap_drop, ["ALL"]);
		}
		assert.equal(compose.services["aig-agent"].deploy.replicas, "${POSTURE_SCANNER_AGENT_COUNT:-${AIG_AGENT_COUNT:-1}}", "the single-worker replica pin must survive the resource merge");
		const aigManifest = JSON.parse(readFileSync(join(root, "packages/core/src/generated/aig-data-manifest.json"), "utf8"));
		assert.equal(compose.services["aig-server"].image, "aidr-aig-server:v4.6.1-aidr.2");
		assert.equal(compose.services["aig-agent"].image, "aidr-aig-agent:v4.6.1-aidr.2");
		assert.equal(compose.services["aig-bridge"].image, `aidr-aig-bridge:${dashboardVersion}`);
		assert.match(compose.services["aig-egress"].image, /^ubuntu\/squid:[^@]+@sha256:[a-f0-9]{64}$/);
		assert.equal(compose.services["aig-server"].build.context, "./posture-scanner/vendor/ai-infra-guard");
		assert.equal(compose.services["aig-bridge"].build.context, "./posture-scanner/bridge");

		// Only the egress gateway has an Internet route; the bridge publishes on
		// loopback through a non-masquerading edge network.
		assert.equal(compose.networks["aidr-aig-network"].internal, true);
		assert.equal(compose.networks["aidr-aig-edge"].driver_opts["com.docker.network.bridge.enable_ip_masquerade"], "false");
		for (const network of Object.values(compose.networks)) assert.equal(Object.hasOwn(network ?? {}, "name"), false, "posture scanner networks must be project-scoped");
		for (const volume of ["aig-db", "aig-logs", "aig-uploads", "aig-checker-data", "aig-bridge-state"]) assert.equal(Object.hasOwn(compose.volumes[volume] ?? {}, "name"), false);
		assert.deepEqual(compose.services["aig-egress"].networks, ["aidr-aig-network", "aidr-aig-egress"]);
		assert.deepEqual(compose.services["aig-agent"].networks, ["aidr-aig-network"]);
		assert.deepEqual(compose.services["aig-server"].networks, ["aidr-aig-network"]);
		assert.deepEqual(compose.services["aig-bridge"].networks, ["aidr-aig-network", "aidr-aig-edge"]);
		assert.deepEqual(compose.services["aig-bridge"].ports, ["${POSTURE_SCANNER_BIND_ADDRESS:-${AIG_BIND_ADDRESS:-127.0.0.1}}:${POSTURE_SCANNER_BRIDGE_PORT:-${AIG_BRIDGE_PORT:-8099}}:8099"]);
		for (const name of ["aig-server", "aig-agent", "aig-egress"]) assert.equal(Object.hasOwn(compose.services[name], "ports"), false, `${name} must not publish a port`);

		const bindSources = aigServices
			.flatMap((name) => compose.services[name].volumes.map((volume) => typeof volume === "string" ? volume.split(":")[0] : volume.type === "bind" ? volume.source : null))
			.filter((source) => source?.startsWith("."));
		assert.ok(bindSources.length >= 5);
		for (const source of bindSources) assert.ok(existsSync(join(output, source)), `bind mount source ${source} was not staged`);
		assert.equal(existsSync(join(output, "aig")), false, "the legacy staging directory is not created");
		assert.ok(existsSync(join(output, "posture-scanner/vendor/ai-infra-guard/Dockerfile_Agent")));
		assert.ok(existsSync(join(output, "posture-scanner/bridge/Dockerfile")));
		assert.ok(existsSync(join(output, "posture-scanner/signing-public.pem")));
		assert.equal(existsSync(join(output, "posture-scanner/bridge/tests")), false, "bridge tests are not part of the build context");
		assert.equal(existsSync(join(output, "posture-scanner/vendor/ai-infra-guard/.github")), false);
		assert.equal(readFileSync(join(output, "posture-scanner/egress/squid.conf"), "utf8"), readFileSync(join(root, "deploy/onprem/egress/squid.conf"), "utf8"));
		assert.match(readFileSync(join(output, "posture-scanner/egress/squid.conf"), "utf8"), /^http_access deny all$/m);

		const envText = readFileSync(join(output, ".env"), "utf8");
		const envValue = (name) => envText.match(new RegExp(`^${name}=(.*)$`, "m"))?.[1];
		assert.equal(envValue("COMPOSE_PROFILES"), "posture-scanner");
		assert.match(envValue("POSTURE_SCANNER_AGENT_SHARED_SECRET"), /^[a-f0-9]{64}$/);
		assert.match(envValue("BRIDGE_API_KEY"), /^[a-f0-9]{64}$/);
		assert.notEqual(envValue("POSTURE_SCANNER_AGENT_SHARED_SECRET"), envValue("BRIDGE_API_KEY"));
		assert.equal(envValue("BRIDGE_AUTH_MODE"), "api_key");
		assert.equal(envValue("BRIDGE_TASK_BACKEND"), "sqlite");
		assert.equal(envValue("BRIDGE_HA_REQUIRED"), "false");
		assert.equal(envValue("BRIDGE_EGRESS_PROXY_URL"), "http://aig-egress:3128");
		assert.equal(envValue("POSTURE_SCANNER_TRUSTED_SIGNING_KEY_ID"), "scanner-release-2026");
		const fingerprint = createHash("sha256").update(releaseKey.export({ type: "spki", format: "der" })).digest("hex");
		assert.equal(envValue("POSTURE_SCANNER_TRUSTED_SIGNING_PUBLIC_KEY_SHA256"), fingerprint);
		assert.equal(envValue("POSTURE_SCANNER_EXPECTED_DATA_BUNDLE_ID"), aigManifest.bundle_id);
		assert.equal(envValue("POSTURE_SCANNER_EXPECTED_SOURCE_COMMIT"), aigManifest.source.commit);
		assert.doesNotMatch(envText, /^AIG_/m, "preparation writes only the POSTURE_SCANNER_* operator names");
		const scannerKeys = envText.split(/\r?\n/).map((line) => line.split("=")[0]).filter((name) => /^(POSTURE_SCANNER_|BRIDGE_|COMPOSE_PROFILES$)/.test(name)).sort();
		assert.deepEqual(scannerKeys, CATALOG.filter((entry) => entry.written === "with-posture-scanner").map((entry) => entry.name).sort(), "the configuration reference must list exactly the posture scanner variables preparation writes");
		const composeText = readFileSync(join(output, "compose.yml"), "utf8");
		for (const name of ["POSTURE_SCANNER_AGENT_SHARED_SECRET", "BRIDGE_API_KEY"]) assert.equal(composeText.includes(envValue(name)), false, `${name} was embedded in Compose`);

		const deployment = JSON.parse(readFileSync(join(output, "deployment.json"), "utf8"));
		assert.equal(Object.hasOwn(deployment, "aig"), false);
		assert.equal(deployment.posture_scanner.enabled, true);
		assert.equal(deployment.posture_scanner.signing_public_key_sha256, fingerprint);
		assert.equal(deployment.posture_scanner.data_manifest_signed, aigManifest.signature !== null);
		assert.ok(deployment.artifacts.some((entry) => entry.path === "posture-scanner/egress/allowlist.txt"));
		assert.ok(deployment.artifacts.some((entry) => entry.path === "posture-scanner/generated/aig-data-manifest.json"));
		if (dockerComposeAvailable) assertComposeConfigResolves(output);
	});
});

test("--with-posture-scanner refuses missing, private or non-RSA release keys and cloud mode", () => {
	inTemporaryDirectory((directory) => {
		const ed25519 = join(directory, "ed25519.pem");
		writeFileSync(ed25519, artifactVerificationPublicKeyPem);
		const privateKey = join(directory, "private.pem");
		writeFileSync(privateKey, generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs8", format: "pem" }));
		const rsa = join(directory, "rsa.pem");
		writeFileSync(rsa, generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ type: "spki", format: "pem" }));
		const cases = [
			[["--mode", "self-hosted", "--with-posture-scanner", "--posture-scanner-signing-key-id", "k1"], /requires --posture-scanner-signing-public-key-file and --posture-scanner-signing-key-id/],
			[["--mode", "self-hosted", "--with-posture-scanner", "--posture-scanner-signing-public-key-file", ed25519, "--posture-scanner-signing-key-id", "k1"], /must be a readable RSA/],
			[["--mode", "self-hosted", "--with-posture-scanner", "--posture-scanner-signing-public-key-file", privateKey, "--posture-scanner-signing-key-id", "k1"], /must be a readable RSA/],
			[["--mode", "self-hosted", "--with-posture-scanner", "--posture-scanner-signing-public-key-file", rsa, "--posture-scanner-signing-key-id", "../k1"], /must be a short identifier/],
			[["--mode", "cloud", "--with-posture-scanner", "--posture-scanner-signing-public-key-file", rsa, "--posture-scanner-signing-key-id", "k1"], /only supported for self-hosted/],
		];
		for (const [index, [options, expected]] of cases.entries()) {
			const output = join(directory, `scanner-case-${index}`);
			const result = prepare(output, ...options);
			assert.notEqual(result.status, 0, `posture scanner case ${index} unexpectedly succeeded`);
			assert.match(result.stderr, expected);
			assert.equal(existsSync(output), false, `posture scanner case ${index} left a partial installation`);
		}
	});
});

test("the deprecated --with-aig spellings still select the posture scanner and say so", () => {
	inTemporaryDirectory((directory) => {
		const rsa = join(directory, "rsa.pem");
		writeFileSync(rsa, generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ type: "spki", format: "pem" }));
		const cases = [
			// The legacy flags map onto the new ones: the new validation runs and names the new flags.
			[["--mode", "self-hosted", "--with-aig", "--aig-signing-key-id", "k1"], /requires --posture-scanner-signing-public-key-file/, ["with-aig", "aig-signing-key-id"]],
			[["--mode", "cloud", "--with-aig", "--aig-signing-public-key-file", rsa, "--aig-signing-key-id", "k1"], /--with-posture-scanner is only supported for self-hosted/, ["with-aig", "aig-signing-public-key-file", "aig-signing-key-id"]],
			// Conflicting old and new values are refused rather than silently picking one.
			[["--mode", "self-hosted", "--with-posture-scanner", "--posture-scanner-signing-key-id", "k1", "--aig-signing-key-id", "k2"], /--aig-signing-key-id and --posture-scanner-signing-key-id disagree/, ["aig-signing-key-id"]],
		];
		for (const [index, [options, expected, deprecated]] of cases.entries()) {
			const output = join(directory, `legacy-case-${index}`);
			const result = prepare(output, ...options);
			assert.notEqual(result.status, 0, `legacy case ${index} unexpectedly succeeded`);
			assert.match(result.stderr, expected);
			for (const flag of deprecated) assert.match(result.stderr, new RegExp(`NOTE: --${flag} is deprecated; use --`), `legacy case ${index} did not flag --${flag}`);
			assert.equal(existsSync(output), false, `legacy case ${index} left a partial installation`);
		}
	});
});

// --- Optional privacy gateway (deploy/privacy-gateway) ---------------------------------

const privacyGatewayRuntimeBuilt = existsSync(join(root, "packages/privacy/dist/platform/serve.js"));
const gitOpenSsl = join(process.env.ProgramFiles ?? "C:\\Program Files", "Git", "usr", "bin", "openssl.exe");
const openssl = process.env.AIDR_OPENSSL ?? (process.platform === "win32" && existsSync(gitOpenSsl) ? gitOpenSsl : "openssl");
const opensslAvailable = spawnSync(openssl, ["version"], { encoding: "utf8" }).status === 0;
const privacyGatewaySkip = !opensslAvailable ? "openssl is required to mint throwaway test certificates (set AIDR_OPENSSL)"
	: !privacyGatewayRuntimeBuilt ? "packages/privacy is not built (pnpm --filter @singularityrd/aidr-privacy build)" : false;

// Throwaway, locally generated test certificates; nothing here is a real credential.
function opensslCertificate(directory, name, { ca = false, key = "ec" } = {}) {
	const keyPath = join(directory, `${name}.key`);
	const certPath = join(directory, `${name}.pem`);
	const keyArgs = key === "ec" ? ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"] : ["-newkey", key];
	execFileSync(openssl, ["req", "-x509", ...keyArgs, "-nodes", "-keyout", keyPath, "-out", certPath, "-days", "30",
		"-subj", `/CN=${name}.aidr-test.invalid`, "-addext", `basicConstraints=critical,CA:${ca ? "TRUE" : "FALSE"}`], { stdio: "ignore" });
	return { cert: certPath, key: keyPath };
}

function privacyGatewayFixture(directory) {
	const base = join(directory, "privacy-gateway-input");
	for (const sub of ["", "secrets", "trust", "trust/policy", "models"]) mkdirSync(join(base, sub), { recursive: true });
	const server = opensslCertificate(base, "server");
	const clientCa = opensslCertificate(base, "client-ca", { ca: true });
	const secrets = {
		"aidr-privacy-data1": randomKey(), "aidr-privacy-audit1": randomKey(), labels: randomKey(),
		"aidr-privacy-oidc": "oidc-client-secret-fixture-value", "aidr-privacy-broker-key": readFileSync(clientCa.key, "utf8"),
		"aidr-privacy-provider": "provider-api-key-fixture-value-0123456789",
	};
	for (const [name, value] of Object.entries(secrets)) writeFileSync(join(base, "secrets", name), `${value}\n`);
	for (const name of ["idp-ca.pem", "broker-ca.pem", "broker-client.pem"]) copyFileSync(clientCa.cert, join(base, "trust", name));
	writeFileSync(join(base, "trust/policy/policy.signed.json"), "{}\n");
	writeFileSync(join(base, "trust/policy/policy1.pub.pem"), generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }));
	const manifest = Buffer.from(JSON.stringify({ approved: true, qualificationStatus: "qualified" }));
	writeFileSync(join(base, "models/manifest.json"), manifest);
	const example = JSON.parse(readFileSync(join(root, "packages/privacy/examples/platform/service-config.example.json"), "utf8"));
	const { secretStore: _store, host: _host, port: _port, databasePath: _db, documents: _documents, tls: _tls, ...rest } = example;
	const config = {
		...rest,
		tenantId: "tenant-fixture",
		oidc: { ...rest.oidc, issuer: "https://idp.customer.example/realm", redirectUri: "https://host.customer.example/oauth/callback", caPath: "/etc/aidr-privacy/trust/idp-ca.pem" },
		broker: { ...rest.broker, issuer: "https://broker.customer.example", caPath: "/etc/aidr-privacy/trust/broker-ca.pem", certPath: "/etc/aidr-privacy/trust/broker-client.pem" },
		destination: { ...rest.destination, model: "approved-model-fixture" },
		roleGroups: { "security-reviewer": ["group-reviewers"], "security-admin": ["group-admins"] },
		policy: { signedPath: "/etc/aidr-privacy/trust/policy/policy.signed.json", keys: [{ id: "policy1", path: "/etc/aidr-privacy/trust/policy/policy1.pub.pem" }] },
		ner: { manifest: "/opt/aidr-models/manifest.json", manifestSha256: createHash("sha256").update(manifest).digest("hex") },
	};
	const configFile = join(base, "service.json");
	writeFileSync(configFile, JSON.stringify(config, null, 2));
	const options = {
		"tls-cert-file": server.cert, "tls-key-file": server.key, "client-ca-file": clientCa.cert,
		"config-file": configFile, "secrets-dir": join(base, "secrets"), "trust-dir": join(base, "trust"), "models-dir": join(base, "models"),
		"egress-cidrs": "162.159.140.0/24,10.20.30.0/24",
	};
	const args = (overrides = {}) => ["--mode", "self-hosted", "--with-privacy-gateway", ...Object.entries({ ...options, ...overrides })
		.filter(([, value]) => value !== null).flatMap(([name, value]) => [`--privacy-gateway-${name}`, value])];
	return { base, server, clientCa, secrets, config, configFile, args };
}

function randomKey() {
	return createHash("sha256").update(Math.random().toString()).digest("base64");
}

test("--with-privacy-gateway adds an opt-in, mTLS-only gateway with a hardened image, file secrets and a restricted egress network", { skip: privacyGatewaySkip }, (t) => {
	if (!dockerComposeAvailable) t.diagnostic("docker compose is not installed; the compose config check is skipped");
	inTemporaryDirectory((directory) => {
		const fixture = privacyGatewayFixture(directory);
		for (const profile of ["small", "large"]) {
			const output = join(directory, `privacy-gateway-${profile}`);
			const result = prepare(output, "--profile", profile, ...fixture.args({ "dns-cidrs": "10.0.0.53/32" }));
			assert.equal(result.status, 0, result.stderr);
			const compose = parse(readFileSync(join(output, "compose.yml"), "utf8"));
			const service = compose.services["privacy-gateway"];
			assertBudget(service, resourceProfiles.profiles[profile].services["privacy-gateway"], `privacy-gateway ${profile}`);
			if (profile === "large") continue;

			// Opt-in, hardened runtime.
			assert.deepEqual(service.profiles, ["privacy-gateway"]);
			assert.equal(service.image, `aidr-privacy-gateway:${dashboardVersion}`);
			assert.equal(service.build, "./privacy-gateway/image");
			assert.equal(service.user, "10001:10001");
			assert.equal(service.read_only, true);
			assert.deepEqual(service.cap_drop, ["ALL"]);
			assert.deepEqual(service.security_opt, ["no-new-privileges:true"]);
			assert.match(service.tmpfs[0], /^\/tmp:.*noexec/);
			assert.equal(service.restart, "unless-stopped");
			assert.equal(service.stop_grace_period, "20s");
			assert.deepEqual(service.healthcheck.test, ["CMD", "/usr/local/bin/node", "/opt/aidr-private/healthcheck.mjs"]);
			assert.deepEqual(service.ports, ["127.0.0.1:8443:8443"], "only the mTLS listener, on loopback by default");
			assert.equal(Object.hasOwn(service, "privileged"), false);
			assert.equal(Object.hasOwn(service, "env_file"), false, "no gateway secret travels through environment files");
			// Isolated network: no route to the database or other AIDR services.
			assert.deepEqual(service.networks, ["privacy-gateway"]);
			assert.deepEqual(compose.networks["privacy-gateway"].ipam.config, [{ subnet: "172.31.253.0/28" }]);
			assert.equal(compose.networks["privacy-gateway"].driver_opts["com.docker.network.bridge.enable_icc"], "false");
			for (const [name, other] of Object.entries(compose.services)) if (name !== "privacy-gateway") assert.ok(!(Array.isArray(other.networks) ? other.networks : Object.keys(other.networks ?? {})).includes("privacy-gateway"), `${name} must not join the gateway network`);
			assert.equal(Object.keys(compose.services).filter((name) => compose.services[name].profiles?.includes("privacy-gateway")).length, 1);

			// Secrets are files mounted by Compose, never values in compose.yml or .env.
			const refs = [...Object.keys(fixture.secrets), "aidr-privacy-tls-key"].sort();
			assert.deepEqual(service.secrets.map((entry) => entry.target).sort(), refs.map((ref) => `/run/secrets/aidr-privacy/${ref}`).sort());
			for (const ref of refs) assert.deepEqual(compose.secrets[`privacy-gateway-${ref}`], { file: `./privacy-gateway/secrets/${ref}` });
			const composeText = readFileSync(join(output, "compose.yml"), "utf8");
			const envText = readFileSync(join(output, ".env"), "utf8");
			for (const value of [...Object.values(fixture.secrets), readFileSync(fixture.server.key, "utf8")]) {
				const needle = value.split("\n").find((line) => line.length > 20 && !line.startsWith("-----")) ?? value;
				assert.equal(composeText.includes(needle), false, "secret value embedded in compose.yml");
				assert.equal(envText.includes(needle), false, "secret value embedded in .env");
			}
			assert.doesNotMatch(envText, /PRIVACY|COMPOSE_PROFILES/, "the gateway is not started by default");
			assert.equal(readFileSync(join(output, "privacy-gateway/secrets/aidr-privacy-tls-key"), "utf8"), readFileSync(fixture.server.key, "utf8"));
			if (process.platform !== "win32") {
				assert.equal(statSync(join(output, "privacy-gateway/secrets")).mode & 0o777, 0o700);
				for (const ref of refs) assert.equal(statSync(join(output, "privacy-gateway/secrets", ref)).mode & 0o777, 0o600, ref);
			}
			const mounts = Object.fromEntries(service.volumes.map((volume) => [volume.target, volume]));
			for (const target of ["/etc/aidr-privacy/config/service.json", "/etc/aidr-privacy/trust", "/etc/aidr-privacy/tls", "/opt/aidr-models"]) assert.equal(mounts[target].read_only, true, target);
			assert.equal(mounts["/opt/aidr-models"].source, join(fixture.base, "models"));
			assert.deepEqual(mounts["/var/lib/aidr-privacy"], { type: "volume", source: "aidr-privacy-state", target: "/var/lib/aidr-privacy" });
			for (const volume of service.volumes.filter((entry) => entry.type === "bind" && entry.source.startsWith("."))) assert.ok(existsSync(join(output, volume.source)), `${volume.source} staged`);

			// The deployment owns listener, mutual TLS, secret store and state path.
			const staged = JSON.parse(readFileSync(join(output, "privacy-gateway/service.json"), "utf8"));
			assert.equal(staged.secretStore, "mounted-files");
			assert.equal(staged.host, "0.0.0.0");
			assert.equal(staged.port, 8443);
			assert.equal(staged.databasePath, "/var/lib/aidr-privacy/control.sqlite");
			assert.deepEqual(staged.tls, { certPath: "/etc/aidr-privacy/tls/server.pem", clientCaPath: "/etc/aidr-privacy/tls/client-ca.pem", keyRef: "aidr-privacy-tls-key" });
			assert.equal(staged.ner.python, "/opt/aidr-ner/bin/python3");
			assert.equal(readFileSync(join(output, "privacy-gateway/tls/client-ca.pem"), "utf8"), readFileSync(fixture.clientCa.cert, "utf8"));
			assert.ok(existsSync(join(output, "privacy-gateway/trust/policy/policy1.pub.pem")));

			// Prepared (not applied) host egress firewall: only the allow-list, then reject.
			const firewall = readFileSync(join(output, "privacy-gateway/egress-firewall.sh"), "utf8");
			assert.match(firewall, /^SUBNET='172\.31\.253\.0\/28'$/m);
			assert.match(firewall, /-d '162\.159\.140\.0\/24' -p tcp --dport 443 -j RETURN/);
			assert.match(firewall, /-d '10\.0\.0\.53\/32' -p udp --dport 53 -j RETURN/);
			assert.match(firewall, /-A "\$NEW" -j REJECT\n/);
			assert.match(firewall, /^set -euo pipefail$/m);
			// Re-applying never flushes the live chain: the replacement chain is
			// complete before DOCKER-USER jumps to it (behaviour: deploy/privacy-gateway/privacy-gateway.test.mjs).
			assert.ok(firewall.indexOf('-A "$NEW" -j REJECT') < firewall.indexOf('-I DOCKER-USER 1 -s "$SUBNET" -j "$NEW"'));
			assert.match(firewall, /DOCKER-USER -s "\$SUBNET"/);
			assert.doesNotMatch(firewall, /0\.0\.0\.0\/0/);

			// Staged image context: hardened Dockerfile and only the compiled runtime.
			const image = join(output, "privacy-gateway/image");
			assert.equal(readFileSync(join(image, "Dockerfile"), "utf8"), readFileSync(join(root, "deploy/privacy-gateway/Dockerfile"), "utf8"));
			for (const file of ["package/dist/platform/serve.js", "package/deployment/container-service-config.mjs", "package/ner/ner_worker.py", "package/ner/requirements.linux-py311.lock.txt", "healthcheck.mjs", "wheelhouse/README.txt"]) assert.ok(existsSync(join(image, file)), file);
			const stagedFiles = readdirSync(join(image, "package/dist"), { recursive: true }).map(String);
			assert.ok(!stagedFiles.some((file) => file.endsWith(".map") || file.endsWith(".ts")), "no source maps or declarations in the image");
			assert.equal(existsSync(join(image, "package/src")), false);
			assert.equal(existsSync(join(image, "package/ner/test_ner_worker.py")), false);

			const deployment = JSON.parse(readFileSync(join(output, "deployment.json"), "utf8"));
			assert.equal(deployment.privacy_gateway.enabled, true);
			assert.match(deployment.privacy_gateway.interface, /explicit egress API.*not transparent interception/);
			assert.equal(deployment.privacy_gateway.mtls.required, true);
			assert.match(deployment.privacy_gateway.mtls.client_ca_sha256, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
			assert.deepEqual(deployment.privacy_gateway.egress.allowed_cidrs, ["162.159.140.0/24", "10.20.30.0/24"]);
			assert.match(deployment.privacy_gateway.egress.enforcement, /not applied/);
			assert.deepEqual(deployment.privacy_gateway.destination, { kind: "openai-responses", origin: "https://api.openai.com", model: "approved-model-fixture" });
			assert.ok(deployment.artifacts.some((entry) => entry.path === "privacy-gateway/image/Dockerfile"));
			assert.ok(!deployment.artifacts.some((entry) => entry.path.startsWith("privacy-gateway/secrets")), "secret files are not inventoried");
			if (dockerComposeAvailable) assertComposeConfigResolves(output);
		}
	});
});

test("--with-privacy-gateway refuses missing mutual TLS, weak material, unrestricted egress and unapproved configuration", { skip: privacyGatewaySkip }, () => {
	inTemporaryDirectory((directory) => {
		const fixture = privacyGatewayFixture(directory);
		const weak = opensslCertificate(directory, "weak-rsa", { key: "rsa:1024" });
		const configWith = (name, patch) => {
			const path = join(directory, `${name}.json`);
			writeFileSync(path, JSON.stringify({ ...fixture.config, ...patch }));
			return path;
		};
		const cases = [
			[{ "client-ca-file": null }, /requires --privacy-gateway-client-ca-file .*mutual TLS and an egress allow-list are mandatory/],
			[{ "tls-cert-file": null, "tls-key-file": null }, /requires --privacy-gateway-tls-cert-file, --privacy-gateway-tls-key-file/],
			[{ "egress-cidrs": null }, /requires --privacy-gateway-egress-cidrs/],
			[{ "client-ca-file": fixture.server.cert }, /client CA must be a CA certificate/],
			[{ "tls-cert-file": fixture.clientCa.cert, "tls-key-file": fixture.clientCa.key }, /must be a leaf certificate, not a CA/],
			[{ "tls-key-file": fixture.clientCa.key }, /server key does not match the server certificate/],
			[{ "tls-cert-file": weak.cert, "tls-key-file": weak.key }, /server key is weak/],
			[{ "egress-cidrs": "0.0.0.0/0" }, /too broad/],
			[{ "egress-cidrs": "162.159.140.0/24,169.254.169.254/32" }, /link-local/],
			[{ "egress-cidrs": "162.159.140.1/24" }, /host bits set/],
			[{ "subnet": "8.8.8.0/28" }, /must be a private IPv4 network/],
			[{ "bind-address": "localhost" }, /must be an IP address/],
			[{ "config-file": configWith("owned-tls", { tls: { certPath: "/tmp/x", clientCaPath: "/tmp/y", keyRef: "k" } }) }, /must not set tls: the deployment owns/],
			[{ "config-file": configWith("documents", { documents: { python: "/usr/bin/python3", workerSha256: "a".repeat(64) } }) }, /document parsing is not packaged/],
			[{ "config-file": configWith("placeholder", { destination: { ...fixture.config.destination, model: "REPLACE_WITH_INSTITUTION_APPROVED_MODEL" } }) }, /REPLACE placeholder/],
			[{ "config-file": configWith("provider", { destination: { ...fixture.config.destination, origin: "https://proxy.example" } }) }, /destination must be one of/],
			[{ "config-file": configWith("digest", { ner: { ...fixture.config.ner, manifestSha256: "0".repeat(64) } }) }, /does not match the approved ner\.manifestSha256/],
			[{ "config-file": configWith("trust-path", { oidc: { ...fixture.config.oidc, caPath: "/etc/ssl/certs/ca.pem" } }) }, /trust files must be paths under \/etc\/aidr-privacy\/trust/],
			[{ "secrets-dir": join(fixture.base, "trust") }, /Privacy gateway secret .* is missing/],
		];
		for (const [index, [overrides, expected]] of cases.entries()) {
			const output = join(directory, `privacy-gateway-refused-${index}`);
			const result = prepare(output, ...fixture.args(overrides));
			assert.notEqual(result.status, 0, `privacy gateway case ${index} unexpectedly succeeded`);
			assert.match(result.stderr, expected, `privacy gateway case ${index}`);
			assert.equal(existsSync(output), false, `privacy gateway case ${index} left a partial installation`);
		}
		for (const [index, options] of [["--mode", "cloud", "--device-start-upstream-url", "https://project.supabase.co/functions/v1/device-start", ...fixture.args().slice(2)], ["--mode", "self-hosted", "--privacy-gateway-egress-cidrs", "10.0.0.0/24"]].entries()) {
			const output = join(directory, `privacy-gateway-mode-${index}`);
			const result = prepare(output, ...options);
			assert.notEqual(result.status, 0);
			assert.match(result.stderr, index === 0 ? /only supported for self-hosted/ : /--privacy-gateway-egress-cidrs requires --with-privacy-gateway/);
			assert.equal(existsSync(output), false);
		}
	});
});

test("the privacy gateway image definition is hardened and matches the in-image configuration contract", () => {
	const dockerfile = readFileSync(join(root, "deploy/privacy-gateway/Dockerfile"), "utf8");
	const from = [...dockerfile.matchAll(/^FROM (\S+)/gm)].map((match) => match[1]);
	assert.ok(from.length >= 2);
	for (const image of from) assert.match(image, /^[a-z0-9./-]+:[A-Za-z0-9_.-]+@sha256:[a-f0-9]{64}$/, `${image} must be pinned by digest`);
	assert.match(dockerfile, /^USER 10001:10001$/m, "numeric non-root user");
	assert.match(dockerfile, /^HEALTHCHECK .*healthcheck\.mjs/m);
	assert.match(dockerfile, /--require-hashes/);
	assert.doesNotMatch(dockerfile, /^USER (root|0)\b/m);
	assert.doesNotMatch(dockerfile, /^(ADD|COPY) .*https?:/m, "no remote files in the image");
	assert.match(dockerfile, /^ENTRYPOINT \[.*serve\.js", "--config", ".*deployment\/container-service-config\.mjs"\]$/m);
	// The executable in-image configuration enforces the same fixed layout preparation stages.
	const containerConfig = readFileSync(join(root, "packages/privacy/deployment/container-service-config.mjs"), "utf8");
	const layout = readFileSync(join(root, "deploy/privacy-gateway/privacy-gateway.mjs"), "utf8");
	for (const key of ["config", "secrets", "models", "state", "nerPython", "tlsCert", "tlsClientCa", "tlsKeyRef"]) {
		const value = new RegExp(`\\b${key}: (['"])([^'"]+)\\1`).exec(layout)?.[2];
		assert.ok(value, `layout ${key}`);
		assert.ok(containerConfig.includes(`${key}: '${value}'`), `container-service-config ${key} must be ${value}`);
	}
	assert.match(containerConfig, /config\.secretStore !== 'mounted-files'/);
	assert.match(containerConfig, /fail\('SERVICE_TLS_CONFIG'\)/);
});

// --- On-prem SSO (scripts/lib/onprem-sso.mjs, docs/operations/onprem-sso.md) ---------

test("on-prem SSO options wire the IdP CA, internal IdP hosts and GoTrue SAML; the default stays unchanged", { skip: opensslAvailable ? false : "openssl is required to mint throwaway test certificates (set AIDR_OPENSSL)" }, () => {
	inTemporaryDirectory((directory) => {
		const baseline = join(directory, "sso-default");
		const plain = prepare(baseline, "--mode", "self-hosted");
		assert.equal(plain.status, 0, plain.stderr);
		const plainCompose = parse(readFileSync(join(baseline, "compose.yml"), "utf8"));
		assert.equal(plainCompose.services.functions.environment.SSL_CERT_FILE, undefined);
		assert.equal(plainCompose.services.functions.environment.DENO_TLS_CA_STORE, undefined);
		assert.equal(plainCompose.services.dashboard.environment.AIDR_OIDC_SSO, "${AIDR_OIDC_SSO:-false}");
		assert.equal(plainCompose.services.auth.environment.GOTRUE_SAML_ENABLED, "${GOTRUE_SAML_ENABLED:-false}");
		assert.ok(readFileSync(join(baseline, ".env.functions"), "utf8").split(/\r?\n/).includes("AIDR_OIDC_INTERNAL_IDP_HOSTS="));
		assert.doesNotMatch(readFileSync(join(baseline, ".env"), "utf8"), /^GOTRUE_SAML_/m);
		assert.deepEqual(JSON.parse(readFileSync(join(baseline, "deployment.json"), "utf8")).identity, { oidc_internal_idp_hosts: [], idp_ca: null, gotrue_saml: false });
		assert.equal(existsSync(join(baseline, "functions-trust")), false);

		const ca = opensslCertificate(directory, "corp-root-ca", { ca: true });
		const output = join(directory, "sso");
		const result = prepare(output, "--mode", "self-hosted", "--idp-ca-file", ca.cert, "--oidc-internal-idp-hosts", "Keycloak.corp.example:8443,adfs.corp.local", "--with-saml");
		assert.equal(result.status, 0, result.stderr);
		const compose = parse(readFileSync(join(output, "compose.yml"), "utf8"));
		assert.equal(compose.services.functions.environment.DENO_TLS_CA_STORE, "mozilla,system", "public roots stay trusted");
		assert.equal(compose.services.functions.environment.SSL_CERT_FILE, "/etc/aidr/idp-ca.pem");
		assert.deepEqual(compose.services.functions.volumes.at(-1), { type: "bind", source: "./functions-trust/idp-ca.pem", target: "/etc/aidr/idp-ca.pem", read_only: true });
		const mounted = join(output, "functions-trust/idp-ca.pem");
		assert.equal(readFileSync(mounted, "utf8").trim(), readFileSync(ca.cert, "utf8").trim());
		if (process.platform !== "win32") assert.equal(statSync(mounted).mode & 0o777, 0o644);
		assert.ok(readFileSync(join(output, ".env.functions"), "utf8").split(/\r?\n/).includes("AIDR_OIDC_INTERNAL_IDP_HOSTS=keycloak.corp.example:8443,adfs.corp.local"));
		const envText = readFileSync(join(output, ".env"), "utf8");
		assert.match(envText, /^GOTRUE_SAML_ENABLED=true$/m);
		const samlKey = /^GOTRUE_SAML_PRIVATE_KEY=([A-Za-z0-9+/=]+)$/m.exec(envText)?.[1];
		assert.ok(samlKey, "the SAML signing key is generated on this host");
		assert.equal(createPrivateKey({ key: Buffer.from(samlKey, "base64"), format: "der", type: "pkcs1" }).asymmetricKeyType, "rsa");
		assert.equal(readFileSync(join(output, "compose.yml"), "utf8").includes(samlKey.slice(0, 40)), false, "the key stays in .env");
		const deployment = JSON.parse(readFileSync(join(output, "deployment.json"), "utf8"));
		assert.deepEqual(deployment.identity.oidc_internal_idp_hosts, ["keycloak.corp.example:8443", "adfs.corp.local"]);
		assert.equal(deployment.identity.gotrue_saml, true);
		assert.equal(deployment.identity.idp_ca.file, "functions-trust/idp-ca.pem");
		assert.equal(deployment.identity.idp_ca.certificates[0].ca, true);
		assert.ok(deployment.artifacts.some((artifact) => artifact.path === "functions-trust/idp-ca.pem"));

		const refusals = [
			["cloud SAML", ["--mode", "cloud", "--with-saml"], /self-hosted stack only/],
			["cloud CA", ["--mode", "cloud", "--idp-ca-file", ca.cert], /self-hosted stack only/],
			["missing CA", ["--mode", "self-hosted", "--idp-ca-file", join(directory, "missing.pem")], /missing or unreadable/],
			["private key as CA", ["--mode", "self-hosted", "--idp-ca-file", ca.key], /private key/],
			["IP literal host", ["--mode", "self-hosted", "--oidc-internal-idp-hosts", "10.0.0.5"], /--oidc-internal-idp-hosts/],
		];
		for (const [index, [label, options, pattern]] of refusals.entries()) {
			const refused = join(directory, `sso-refused-${index}`);
			const outcome = prepare(refused, ...options);
			assert.notEqual(outcome.status, 0, `${label} unexpectedly succeeded`);
			assert.match(outcome.stderr, pattern, label);
			assert.equal(existsSync(refused), false, `${label} left a partial installation`);
		}
	});
});
