import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { inspectReviewedRuntime } from "./archive-boundary.mjs";

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
	return spawnSync(process.execPath, [script, "--output", output, "--dashboard-url", dashboardUrl, "--supabase-url", supabaseUrl, "--artifact-verification-public-key-file", publicKeyFile, "--telemetry-queue-root", "/var/lib/aidr-telemetry", ...defaultRegion, ...options], {
		encoding: "utf8", timeout: 60_000,
	});
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
		assert.deepEqual(services["api-gw"].ports, ["127.0.0.1:38000:8000"]);
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
			AIDR_PUBLIC_HTTPS_URL: dashboardUrl,
			AIDR_METRICS_TOKEN: "${AIDR_METRICS_TOKEN:?AIDR_METRICS_TOKEN is required}",
			AIDR_READINESS_REQUIRED_CHECKS: "database,storage,functions,signing,backup,queue,certificate",
		});
		assert.match(dashboard.healthcheck.test.at(-1), /\/readyz/);
		assert.deepEqual(dashboard.volumes, [{ type: "bind", source: "./health", target: "/run/aidr-health", read_only: true }]);
		assert.equal(composeText.includes("http://dashboard:8080/auth-templates/recovery.html"), true);
		const compose = parse(composeText);
		assert.deepEqual(compose.services["api-gw"].ports, ["127.0.0.1:8000:8000"]);
		assert.deepEqual(compose.services.dashboard.ports, ["127.0.0.1:8080:8080"]);
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
		assert.match(functionEnv, /^AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64=\S+$/m);
		assert.match(functionEnv, /^AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64=\S+$/m);
		assert.match(functionEnv, /^AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64=\S+$/m);
		assert.match(functionEnv, /^AIDR_PACK_DOWNLOAD_GRANT_SECRET=[A-Za-z0-9_-]{43}$/m);
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
		assert.equal(existsSync(join(output, "backup", "deployment-backup-health-failed.mjs")), true);
		assert.equal(existsSync(join(output, "backup", "aidr-backup-health-failed.service")), true);
		const deployment = JSON.parse(readFileSync(join(output, "deployment.json"), "utf8"));
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
