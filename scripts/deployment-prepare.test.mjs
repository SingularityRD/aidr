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

const resourceProfiles = JSON.parse(readFileSync(join(root, "deploy/onprem/resource-profile.json"), "utf8"));
const dashboardVersion = JSON.parse(readFileSync(join(root, "packages/dashboard/package.json"), "utf8")).version;
const dockerCompose = spawnSync("docker", ["compose", "version"], { encoding: "utf8", timeout: 30_000 });
const dockerComposeAvailable = !dockerCompose.error && dockerCompose.status === 0;

function assertComposeConfigResolves(output) {
	const config = spawnSync("docker", ["compose", "--project-directory", output, "-f", join(output, "compose.yml"), "config", "--quiet"], { encoding: "utf8", timeout: 60_000 });
	assert.equal(config.status, 0, `docker compose config rejected the prepared stack: ${config.stderr}`);
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
		assert.deepEqual(Object.keys(compose.services).sort(), ["api-gw", "auth", "dashboard", "db", "functions", "imgproxy", "meta", "realtime", "rest", "storage", "studio"]);
		for (const [name, service] of Object.entries(compose.services)) {
			assertBudget(service, budgets[name], name);
			assert.equal(service.restart, "unless-stopped", `${name} restart policy`);
			assert.deepEqual(service.logging, { driver: "json-file", options: { "max-size": "20m", "max-file": "5", compress: "true" } }, `${name} log rotation`);
			assert.ok(service.healthcheck?.test, `${name} has no health check`);
			assert.equal(Object.hasOwn(service, "profiles"), false);
		}
		assert.equal(compose.services.db.stop_grace_period, "120s");
		assert.match(compose.services.meta.healthcheck.test.at(-1), /connect\(8080/);
		assert.equal(compose.services.dashboard.image, `aidr-dashboard:${dashboardVersion}`);
		assert.equal(compose.services.dashboard.build, "./dashboard");
		assert.equal(compose.services.dashboard.healthcheck.retries, 3);
		assert.match(compose.services.dashboard.healthcheck.test.at(-1), /\/readyz/, "the overlay must not replace the production readiness probe");
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
		if (dockerComposeAvailable) assertComposeConfigResolves(output);
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
		assert.equal(compose.services["aig-server"].image, "aidr-aig-server:v4.6.1-aidr.1");
		assert.equal(compose.services["aig-agent"].image, "aidr-aig-agent:v4.6.1-aidr.1");
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
