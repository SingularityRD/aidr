#!/usr/bin/env node
import { createHash, createHmac, createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, rmdirSync, writeFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { parseArgs } from "node:util";
import { cpSync } from "./lib/deployment-input-copy.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const requireCore = createRequire(join(root, "packages/core/package.json"));
const { parse, stringify } = existsSync(join(root, "deploy/vendor/yaml.cjs")) ? requireCore(join(root, "deploy/vendor/yaml.cjs")) : requireCore("yaml");
async function stageMaintenanceRuntime(output) {
	const readinessSource = join(root, "scripts/readiness-evidence-worker.mjs");
	const backupSource = join(root, "scripts/deployment-backup.mjs");
	const readinessOutput = join(output, "maintenance/readiness-evidence-worker.mjs");
	const backupOutput = join(output, "backup/deployment-backup.mjs");
	const compiledCoreReady = ["telemetry-queue.js", "siem-incident-producer.js"]
		.every((file) => existsSync(join(root, "packages/core/dist", file)));
	if (compiledCoreReady) {
		const requireBuilder = createRequire(join(root, "packages/claude-code/package.json"));
		const esbuild = requireBuilder("esbuild");
		await Promise.all([
			esbuild.build({ entryPoints: [readinessSource], outfile: readinessOutput, bundle: true, platform: "node", format: "esm", target: "node24", sourcemap: false, legalComments: "inline" }),
			esbuild.build({ entryPoints: [backupSource], outfile: backupOutput, bundle: true, platform: "node", format: "esm", target: "node24", sourcemap: false, legalComments: "inline", external: ["./lib/node-helper-image.mjs"] }),
		]);
	} else if (!readFileSync(readinessSource, "utf8").includes("../packages/core/dist/")) {
		cpSync(readinessSource, readinessOutput);
		cpSync(backupSource, backupOutput);
	} else throw new Error("Maintenance runtime requires a complete core build before deployment preparation");
	cpSync(join(root, "scripts/deployment-backup-offsite.mjs"), join(output, "backup/deployment-backup-offsite.mjs"));
	for (const file of ["node-helper-image.mjs", "node-helper.Dockerfile"]) {
		cpSync(join(root, "scripts/lib", file), join(output, "backup/lib", file));
	}
	for (const path of [readinessOutput, backupOutput, join(output, "backup/deployment-backup-offsite.mjs")]) chmodSync(path, 0o644);
}

// Node's 0o700/0o600 modes do not restrict Windows ACLs. Protect the
// deployment root before copying or writing anything that may contain secrets.
const WINDOWS_PRIVATE_DIRECTORY_ACL = `
$ErrorActionPreference = 'Stop'
$path = [Environment]::GetEnvironmentVariable('AIDR_PRIVATE_ACL_PATH')
$item = [System.IO.DirectoryInfo]::new($path)
$acl = $item.GetAccessControl()
$owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administrators = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$acl.SetAccessRuleProtection($true, $false)
foreach ($entry in @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) {
  $acl.PurgeAccessRules($entry.IdentityReference)
}
$inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
foreach ($sid in @($owner, $system, $administrators)) {
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritance,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow))
}
$item.SetAccessControl($acl)
$updated = $item.GetAccessControl()
if (-not $updated.AreAccessRulesProtected) { throw 'ACL inheritance remains enabled' }
foreach ($entry in $updated.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
  if ($entry.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
      $entry.IdentityReference.Value -notin @($owner.Value, $system.Value, $administrators.Value)) {
    throw 'ACL grants another identity access'
  }
}
`;

function hardenPrivateDirectory(directory) {
	if (process.platform !== "win32") {
		chmodSync(directory, 0o700);
		if ((statSync(directory).mode & 0o077) !== 0) throw new Error("Deployment directory permits group or world access");
		return "posix-owner-only";
	}
	try {
		execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(WINDOWS_PRIVATE_DIRECTORY_ACL, "utf16le").toString("base64")], {
			stdio: "ignore", windowsHide: true, env: { ...process.env, AIDR_PRIVATE_ACL_PATH: directory },
		});
	} catch (error) {
		throw new Error(`Deployment directory Windows ACL could not be made private: ${error instanceof Error ? error.message : "unknown error"}`);
	}
	return "windows-current-user-system-administrators";
}
const { values } = parseArgs({ options: {
	mode: { type: "string", default: "self-hosted" }, output: { type: "string", default: ".aidr-deploy" },
	"upstream-dir": { type: "string" }, "dashboard-url": { type: "string" }, "supabase-url": { type: "string" }, development: { type: "boolean", default: false },
	"artifact-verification-public-key-file": { type: "string" },
	"project-name": { type: "string" }, "device-start-upstream-url": { type: "string" },
	"telemetry-queue-root": { type: "string" },
	region: { type: "string" }, "tenant-region": { type: "string" }, "regions-manifest": { type: "string" },
} });
if (!["self-hosted", "cloud"].includes(values.mode)) throw new Error("mode must be self-hosted or cloud");
const output = resolve(values.output);
if (existsSync(output)) throw new Error("Output already exists; reuse its secrets and data. Choose a new output for a separate installation.");
const runtimeCapabilitiesRaw = process.env.AIDR_RUNTIME_CAPABILITIES_BY_TENANT?.trim() || "{}";
let runtimeCapabilitiesConfig;
try {
	if (runtimeCapabilitiesRaw.length > 65_536) throw new Error();
	const map = JSON.parse(runtimeCapabilitiesRaw);
	const names = ["runtime_detectors", "behavioral_learning_v1"];
	if (!map || typeof map !== "object" || Array.isArray(map)) throw new Error();
	const entries = Object.entries(map);
	if (entries.length > 256 || entries.some(([id, grants]) =>
		!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(id) || !Array.isArray(grants) || grants.length > 2
		|| grants.some((grant) => !names.includes(grant)) || new Set(grants).size !== grants.length
		|| (grants.includes("behavioral_learning_v1") && !grants.includes("runtime_detectors"))
	)) throw new Error();
	runtimeCapabilitiesConfig = JSON.stringify(map);
} catch {
	throw new Error("AIDR_RUNTIME_CAPABILITIES_BY_TENANT must be a bounded exact tenant capability map");
}
let artifactVerificationPublicKeyPem;
const artifactVerificationPublicKeyFile = values["artifact-verification-public-key-file"];
if (artifactVerificationPublicKeyFile) {
	let supplied;
	try {
		supplied = readFileSync(resolve(artifactVerificationPublicKeyFile), "utf8");
	} catch {
		throw new Error("Artifact verification public key file is missing or unreadable");
	}
	try {
		if (!supplied.includes("-----BEGIN PUBLIC KEY-----") || supplied.includes("PRIVATE KEY")) throw new Error();
		const key = createPublicKey(supplied);
		if (key.asymmetricKeyType !== "ed25519") throw new Error();
		artifactVerificationPublicKeyPem = key.export({ type: "spki", format: "pem" }).toString();
	} catch {
		throw new Error("Artifact verification public key must be an Ed25519 SPKI public key");
	}
} else if (!values.development) {
	throw new Error("Production deployment requires --artifact-verification-public-key-file");
}
const telemetryQueueRoot = values["telemetry-queue-root"]?.trim() ?? "";
if (!values.development && !telemetryQueueRoot) {
	throw new Error("Production deployment requires --telemetry-queue-root bound to a real fleet-aggregated DurableTelemetryQueue source");
}
if (telemetryQueueRoot && (
	(telemetryQueueRoot !== "/var/lib/aidr-telemetry" && !telemetryQueueRoot.startsWith("/var/lib/aidr-telemetry/")) ||
	telemetryQueueRoot.split("/").includes("..") || /[\0\r\n,=]/.test(telemetryQueueRoot)
)) throw new Error("--telemetry-queue-root must be a single absolute path under /var/lib/aidr-telemetry");
function origin(value, fallback) {
	const url = new URL(value || (values.development ? fallback : ""));
	if (url.username || url.password || url.search || url.hash || url.pathname !== "/") throw new Error("Deployment URLs must be origins without credentials or paths");
	const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
	if (url.protocol !== "https:" && !(values.development && local && url.protocol === "http:")) throw new Error("HTTPS required; --development permits loopback HTTP only");
	return url.origin;
}
const dashboardUrl = origin(values["dashboard-url"], "http://localhost:8080");
const supabaseUrl = origin(values["supabase-url"], "http://localhost:8000");
const isLoopbackOrigin = (value) => ["localhost", "127.0.0.1", "[::1]"].includes(new URL(value).hostname);
if (values.development && (!isLoopbackOrigin(dashboardUrl) || !isLoopbackOrigin(supabaseUrl))) {
	throw new Error("--development requires both dashboard and Supabase URLs to use loopback hosts");
}
// A loopback development URL is the directly published Compose endpoint. In
// production the public HTTPS origins sit behind ingress, so keep the internal
// host bindings at their documented defaults.
const developmentHostPort = (url, fallback) => {
	if (!values.development) return fallback;
	const parsed = new URL(url);
	return parsed.port || (parsed.protocol === "https:" ? "443" : "80");
};
const loopbackBinding = (url) => values.development && new URL(url).hostname === "[::1]" ? "[::1]" : "127.0.0.1";
const projectName = values["project-name"] || `aidr-${randomBytes(6).toString("hex")}`;
if (!/^[a-z][a-z0-9_-]{0,62}$/.test(projectName)) throw new Error("Invalid Compose project name");
// Region and residency entries are operator declarations, not verified legal or
// provider facts. Preparation refuses an undeclared region or residency, a tenant
// region that differs from the deployment region, a placeholder location and a
// region whose declared public API origin is not this installation's origin.
const regionsManifestPath = resolve(values["regions-manifest"] || join(root, "deploy/regions.manifest.json"));
if (!existsSync(regionsManifestPath)) throw new Error("Deployment region manifest is missing; declare the regions this installation may use before preparing deployment");
let regionManifest;
try {
	regionManifest = JSON.parse(readFileSync(regionsManifestPath, "utf8"));
} catch {
	throw new Error("Deployment region manifest is not valid JSON");
}
const regions = regionManifest.regions;
if (regionManifest.schema_version !== 1 || !regions || typeof regions !== "object" || Array.isArray(regions) || Object.keys(regions).length === 0) {
	throw new Error("Deployment region manifest must declare schema_version 1 and a non-empty regions object");
}
if (Object.keys(regions).some((id) => !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(id))) throw new Error("Deployment region manifest contains an invalid region id");
function declaredRegion(id, kind) {
	if (typeof id !== "string" || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(id)) {
		throw new Error(`${kind} region must be a lowercase identifier declared in the deployment region manifest`);
	}
	const entry = regions[id];
	if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
		throw new Error(`${kind} region "${id}" is not declared in the deployment region manifest; declare it before preparing this installation`);
	}
	if (entry.supabase_url !== null && (typeof entry.supabase_url !== "string" || origin(entry.supabase_url) !== entry.supabase_url)) {
		throw new Error(`Deployment region "${id}" must declare supabase_url as null or as an HTTPS origin without credentials or paths`);
	}
	const { residency } = entry;
	if (!residency || typeof residency !== "object" || Array.isArray(residency) || typeof residency.declared !== "boolean" || typeof residency.location !== "string" || residency.location.length === 0) {
		throw new Error(`Deployment region "${id}" must declare residency with a declared flag and a location`);
	}
	if (residency.declared !== true) throw new Error(`Deployment region "${id}" residency must be explicitly declared true by the operator`);
	if (/^REPLACE/i.test(residency.location)) throw new Error(`Deployment region "${id}" still holds a placeholder residency location; declare the real location before preparing this installation`);
	return entry;
}
const regionId = values.region ?? "unassigned";
const tenantRegionId = values["tenant-region"] ?? regionId;
const deploymentRegion = declaredRegion(regionId, "Deployment");
declaredRegion(tenantRegionId, "Tenant");
if (deploymentRegion.supabase_url !== null && deploymentRegion.supabase_url !== supabaseUrl) {
	throw new Error(`Deployment region "${regionId}" declares public API origin ${deploymentRegion.supabase_url}, which is not this installation's --supabase-url origin`);
}
if (tenantRegionId !== regionId) {
	throw new Error(`Tenant declared region "${tenantRegionId}" does not match deployment region "${regionId}"; refusing to prepare a cross-region installation`);
}
const deviceUpstream = values.mode === "self-hosted"
	? `http://${loopbackBinding(supabaseUrl)}:${developmentHostPort(supabaseUrl, "8000")}/functions/v1/device-start`
	: (values["device-start-upstream-url"] ?? "REPLACE_WITH_PROVIDER_DEVICE_START_URL");
if (values["device-start-upstream-url"]) {
	if (values.mode !== "cloud") throw new Error("Custom device-start upstream is only valid in cloud mode");
	const parsed = new URL(deviceUpstream);
	if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== "/functions/v1/device-start" || parsed.origin === supabaseUrl) {
		throw new Error("Cloud device-start upstream must use a provider HTTPS origin distinct from the public API proxy and the exact /functions/v1/device-start path");
	}
}
if (!existsSync(join(root, "packages/dashboard/dist/index.html"))) throw new Error("Build the dashboard before preparing deployment");
const upstreamSha = "8c7a4d9dbbaf8b552893822e89d7bf06f33f9220";
const bundledUpstream = !values["upstream-dir"] && existsSync(join(root, "deploy/upstream-manifest.json"));
const repositoryUpstream = !values["upstream-dir"] && !bundledUpstream
	&& existsSync(join(root, "deploy/upstream/.git"))
	&& existsSync(join(root, "deploy/upstream/docker/docker-compose.yml"));
const temporaryUpstream = !values["upstream-dir"] && !bundledUpstream && !repositoryUpstream;
const upstream = resolve(values["upstream-dir"] || (bundledUpstream || repositoryUpstream ? join(root, "deploy/upstream") : join(output, "upstream")));
function verifyUpstream(path) {
	const actual = execFileSync("git", ["-C", path, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
	if (actual !== upstreamSha) throw new Error("Upstream commit does not match the reviewed Supabase release");
	if (execFileSync("git", ["-C", path, "status", "--porcelain", "--", "docker"], { encoding: "utf8" }).trim()) throw new Error("Upstream Docker configuration has local changes");
}
if (values.mode === "self-hosted" && bundledUpstream) {
	const template = JSON.parse(readFileSync(join(root, "deploy/upstream-manifest.json"), "utf8"));
	if (template.commit !== upstreamSha || !Array.isArray(template.files) || template.files.length === 0) throw new Error("Invalid bundled upstream provenance");
	for (const entry of template.files) {
		if (!/^docker\/[a-zA-Z0-9_./-]+$/.test(entry.path) || entry.path.split("/").includes("..")) throw new Error("Invalid template path");
		if (createHash("sha256").update(readFileSync(join(upstream, entry.path))).digest("hex") !== entry.sha256) throw new Error(`Bundled upstream changed: ${entry.path}`);
	}
} else if (values.mode === "self-hosted") {
	if (temporaryUpstream) {
		mkdirSync(output, { recursive: true, mode: 0o700 });
		try {
			execFileSync("git", ["clone", "--depth", "1", "--branch", "self-hosted/v0.8.1", "--filter=blob:none", "--sparse", "https://github.com/supabase/supabase.git", upstream], { stdio: "inherit" });
			execFileSync("git", ["-C", upstream, "sparse-checkout", "set", "docker"], { stdio: "inherit" });
			verifyUpstream(upstream);
		} catch (error) {
			rmSync(upstream, { recursive: true, force: true });
			try { rmdirSync(output); } catch {}
			throw error;
		}
	} else verifyUpstream(upstream);
}
mkdirSync(output, { recursive: true, mode: 0o700 });
// Fail closed before any copied or generated file can contain credentials.
hardenPrivateDirectory(output);
const healthStateDirectory = join(output, "health");
mkdirSync(healthStateDirectory, { mode: 0o755 });
if (process.platform !== "win32") chmodSync(healthStateDirectory, 0o755);
const compose = values.mode === "self-hosted" ? parse(readFileSync(join(upstream, "docker/docker-compose.yml"), "utf8")) : { services: {}, volumes: {} };
compose.name = projectName;
if (values.mode === "self-hosted") cpSync(join(upstream, "docker/volumes"), join(output, "volumes"), { recursive: true });
const secret = (bytes = 32) => randomBytes(bytes).toString("hex");
const deviceIngressSecret = secret(32);
const deviceProxyToken = secret(32);
const env = values.mode === "self-hosted" ? Object.fromEntries(readFileSync(join(upstream, "docker/.env.example"), "utf8").split(/\r?\n/).filter((line) => /^[A-Z][A-Z0-9_]*=/.test(line)).map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)])) : {};
if (values.mode === "self-hosted" && temporaryUpstream) rmSync(upstream, { recursive: true, force: true });
const signing = generateKeyPairSync("ed25519");
const delegationSigning = generateKeyPairSync("ed25519");
const signingPrivateKeyDer = signing.privateKey.export({ type: "pkcs8", format: "der" });
const delegationPrivateKeyDer = delegationSigning.privateKey.export({ type: "pkcs8", format: "der" });
const delegationPublicKeyDer = delegationSigning.publicKey.export({ type: "spki", format: "der" });
const preparedAt = new Date();
const signingKeyExpiresAt = new Date(preparedAt.getTime() + 365 * 86400 * 1000).toISOString();
const keyId = `aidr-${secret(6)}`;
const delegationKeyId = `aidr-delegation-${secret(6)}`;
Object.assign(env, {
	COMPOSE_FILE: "compose.yml",
	SUPABASE_PUBLIC_URL: supabaseUrl, API_EXTERNAL_URL: `${supabaseUrl}/auth/v1`, SITE_URL: dashboardUrl,
	ADDITIONAL_REDIRECT_URLS: `${dashboardUrl}/auth/callback,${dashboardUrl}/auth/recover`,
	...(values.mode === "cloud" ? { AIDR_SIGNUP_MODE: "closed" } : { DISABLE_SIGNUP: "true" }),
	ENABLE_ANONYMOUS_USERS: "false", ENABLE_PHONE_SIGNUP: "false", ENABLE_PHONE_AUTOCONFIRM: "false",
	POSTGRES_PASSWORD: secret(), JWT_SECRET: secret(), DASHBOARD_PASSWORD: secret(), SECRET_KEY_BASE: secret(64), VAULT_ENC_KEY: secret(16), REALTIME_DB_ENC_KEY: secret(8), PG_META_CRYPTO_KEY: secret(),
	LOGFLARE_PUBLIC_ACCESS_TOKEN: secret(), LOGFLARE_PRIVATE_ACCESS_TOKEN: secret(), POOLER_TENANT_ID: `aidr-${secret(8)}`, MINIO_ROOT_PASSWORD: secret(),
	S3_PROTOCOL_ACCESS_KEY_ID: secret(16), S3_PROTOCOL_ACCESS_KEY_SECRET: secret(),
	AIDR_METRICS_TOKEN: secret(),
	OPENAI_API_KEY: "", SMTP_HOST: "", SMTP_USER: "", SMTP_PASS: "", SMTP_ADMIN_EMAIL: "", SMTP_SENDER_NAME: "AIDR", FUNCTIONS_VERIFY_JWT: "false",
});
const jwt = (role) => {
	const now = Math.floor(Date.now() / 1000);
	const unsigned = `${Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url")}.${Buffer.from(JSON.stringify({ role, iss: "supabase", iat: now, exp: now + 365 * 86400 })).toString("base64url")}`;
	return `${unsigned}.${createHmac("sha256", env.JWT_SECRET).update(unsigned).digest("base64url")}`;
};
env.ANON_KEY = values.mode === "cloud" ? "REPLACE_WITH_PROJECT_ANON_KEY" : jwt("anon");
env.SERVICE_ROLE_KEY = values.mode === "cloud" ? "REPLACE_WITH_PROJECT_SERVICE_ROLE_KEY" : jwt("service_role");
const functionEnv = {
	AIDR_ALLOWED_ORIGINS: dashboardUrl, AIDR_DASHBOARD_URL: dashboardUrl, AIDR_DASHBOARD_VERIFY_URL: `${dashboardUrl}/verify`,
	AIDR_PUBLIC_API_ORIGIN: supabaseUrl,
	AIDR_DEVELOPMENT_MODE: String(values.development),
	AIDR_ENTITLEMENT_SIGNING_KEY_ID: keyId, AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64: signingPrivateKeyDer.toString("base64"),
	AIDR_RUNTIME_CAPABILITIES_BY_TENANT: runtimeCapabilitiesConfig,
	AIDR_REVOCATION_SIGNING_KEY_ID: keyId, AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64: signingPrivateKeyDer.toString("base64"),
	AIDR_DELEGATION_ISSUER: supabaseUrl, AIDR_DELEGATION_SIGNING_KEY_ID: delegationKeyId,
	AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64: delegationPrivateKeyDer.toString("base64"),
	AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64: delegationPublicKeyDer.toString("base64"),
	AIDR_PACK_MASTER_KEY_B64: randomBytes(32).toString("base64"), AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING: "false",
	AIDR_PACK_DOWNLOAD_GRANT_SECRET: randomBytes(32).toString("base64url"),
	AIDR_BILLING_PROVIDER: "",
	AIDR_DEVICE_START_INGRESS_SECRET: deviceIngressSecret,
};
for (const service of Object.values(compose.services)) {
	delete service.container_name; delete service.ports;
	service.logging = { driver: "json-file", options: { "max-size": "20m", "max-file": "3" } };
}
if (values.mode === "self-hosted") {
	delete compose.services.supavisor;
	compose.services["api-gw"].image = "envoyproxy/envoy:v1.39.2@sha256:460f8c329f24b2e1c7c5af64cb314a6f351ad1c262ba77b135ac46b35ebd5f85";
	compose.services.imgproxy.image = "darthsim/imgproxy:v4.0.17@sha256:db0b4b9cd690c8b3590203dea300fb759a18c4ec2af7b37424f0bdef23ce317d";
	compose.services.imgproxy.environment.IMGPROXY_USE_LAST_MODIFIED = "false";
	// Scan-gated upstream bumps (docs/production-readiness/runtime-image-security-2026-10-07.md):
	// each strictly reduces CRITICAL+HIGH with no new CRITICAL; native acceptance still pending.
	compose.services.studio.image = "supabase/studio:2026.10.05-sha-94b8b06@sha256:d878dcd9dba73b66d1c2c19aeaf53d07704e71604d93013225be1d1c51475237";
	compose.services.auth.image = "supabase/gotrue:v2.197.0@sha256:1736a63078f5922b198c4cbe50f80ab9a2d3b54fe8b7b6cfb2e9dc5dbbc12c6b";
	compose.services.storage.image = "supabase/storage-api:v1.80.0@sha256:15aa712fdda0dab83d6345c79b54230c1466c41161f1f3756651778b22c3b292";
	compose.services.meta.image = "supabase/postgres-meta:v0.100.0@sha256:145325b7e39f8ef4931d6e8cfd3f6f4d655de09d72a2ccc96d9513542c2202bd";
	compose.services.functions.image = "supabase/edge-runtime:v1.77.4@sha256:ad45164b7548bf5820ed7be714789c17ac2865edce79a09cfb4c3756c3d365a8";
	compose.services["api-gw"].ports = [`${loopbackBinding(supabaseUrl)}:${developmentHostPort(supabaseUrl, "8000")}:8000`];
	compose.services.functions.env_file = [".env.functions"];
	compose.services.auth.environment.GOTRUE_MAILER_TEMPLATES_RECOVERY = "http://dashboard:8080/auth-templates/recovery.html";
	compose.services.auth.environment.GOTRUE_MAILER_SUBJECTS_RECOVERY = "Reset your AIDR password";
	compose.services.db.volumes = compose.services.db.volumes.map((v) => v.startsWith("./volumes/db/data:") ? "aidr-db:/var/lib/postgresql/data" : v);
	compose.services.storage.volumes = ["aidr-storage:/var/lib/storage"];
	compose.services.imgproxy.volumes = ["aidr-storage:/var/lib/storage:ro"];
	compose.volumes["aidr-db"] = {};
	compose.volumes["aidr-storage"] = {};
}
const healthApiOrigin = values.mode === "self-hosted" ? "http://api-gw:8000" : supabaseUrl;
const dashboardHealthPath = values.development ? "/livez" : "/readyz";
compose.services.dashboard = {
	build: "./dashboard", restart: "unless-stopped", ports: [`${loopbackBinding(dashboardUrl)}:${developmentHostPort(dashboardUrl, "8080")}:8080`], read_only: true,
	cap_drop: ["ALL"], security_opt: ["no-new-privileges:true"],
	healthcheck: {
		test: ["CMD", "node", "-e", `fetch('http://127.0.0.1:8080${dashboardHealthPath}').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))`],
		interval: "10s", timeout: "3s", start_period: "5s",
	},
	environment: {
		NODE_ENV: values.development ? "development" : "production",
		VITE_SUPABASE_URL: supabaseUrl,
		VITE_SUPABASE_ANON_KEY: "${ANON_KEY}",
		SENTRY_DSN: "${SENTRY_DSN:-}",
		SENTRY_ENVIRONMENT: `\${SENTRY_ENVIRONMENT:-${values.development ? "development" : "production"}}`,
		SENTRY_TRACES_SAMPLE_RATE: "${SENTRY_TRACES_SAMPLE_RATE:-0}",
		AIDR_AUTH_METHODS: "${AIDR_AUTH_METHODS:-password}",
		AIDR_SIGNUP_MODE: values.mode === "cloud" ? "${AIDR_SIGNUP_MODE:-closed}" : "closed",
		...(values.mode === "self-hosted" ? { AIDR_AUTH_TEMPLATE_DIR: "/app/auth-templates" } : {}),
		AIDR_DEVELOPMENT_MODE: String(values.development),
		AIDR_HEALTH_DATABASE_URL: `${healthApiOrigin}/rest/v1/rpc/aidr_readiness_probe`,
		AIDR_HEALTH_STORAGE_URL: `${healthApiOrigin}/storage/v1/status`,
		AIDR_HEALTH_FUNCTIONS_URL: `${healthApiOrigin}/functions/v1/packs-manifest`,
		AIDR_SIGNING_HEALTH_FILE: "/run/aidr-health/signing.json",
		AIDR_BACKUP_HEALTH_FILE: "/run/aidr-health/backup.json",
		AIDR_QUEUE_HEALTH_FILE: "/run/aidr-health/queue.json",
		...(!values.development ? { AIDR_PUBLIC_HTTPS_URL: dashboardUrl } : {}),
		AIDR_METRICS_TOKEN: "${AIDR_METRICS_TOKEN:?AIDR_METRICS_TOKEN is required}",
		AIDR_READINESS_REQUIRED_CHECKS: "database,storage,functions,signing,backup,queue,certificate",
	},
	volumes: [{ type: "bind", source: "./health", target: "/run/aidr-health", read_only: true }],
};
cpSync(join(root, "deploy/dashboard"), join(output, "dashboard"), { recursive: true });
cpSync(join(root, "deploy/saml-config.mjs"), join(output, "dashboard/saml-config.mjs"));
cpSync(join(root, "deploy/ingress"), join(output, "ingress"), { recursive: true, filter: (p) => !p.includes(".test.") });
cpSync(join(root, "scripts/deployment-tls-renew.mjs"), join(output, "ingress/deployment-tls-renew.mjs"));
cpSync(join(root, "deploy/backup"), join(output, "backup"), { recursive: true });
cpSync(join(root, "deploy/maintenance"), join(output, "maintenance"), { recursive: true });
await stageMaintenanceRuntime(output);
cpSync(join(root, "supabase/templates"), join(output, "auth-templates"), { recursive: true });
cpSync(join(root, "supabase/templates"), join(output, "dashboard/auth-templates"), { recursive: true });
cpSync(join(root, "packages/dashboard/dist"), join(output, "dashboard/public"), { recursive: true });
cpSync(join(root, "supabase/functions"), join(output, "volumes/functions"), { recursive: true, filter: (p) => !p.includes("__tests__") });
cpSync(join(root, "supabase/migrations"), join(output, "migrations"), { recursive: true });
const write = (path, content) => writeFileSync(join(output, path), content, { mode: 0o600, flag: "wx" });
const envText = (items) => Object.entries(items).map(([name, value]) => `${name}=${value}`).join("\n") + "\n";
write(".env", envText(env));
write(".env.functions", envText(functionEnv));
write(".env.readiness", envText({
	AIDR_DEPLOYMENT_DIR: "/srv/aidr",
	AIDR_HEALTH_STATE_DIR: "/srv/aidr/health",
	AIDR_SIGNING_KEY_EXPIRES_AT: signingKeyExpiresAt,
	AIDR_DELEGATION_SIGNING_KEY_EXPIRES_AT: signingKeyExpiresAt,
	AIDR_TELEMETRY_QUEUE_ROOTS: telemetryQueueRoot,
	AIDR_DRAIN_SIEM: "true",
}));
write(".env.ingress", envText({
	AIDR_DEVICE_START_INGRESS_SECRET: deviceIngressSecret,
	AIDR_DEVICE_START_PROXY_TOKEN: deviceProxyToken,
	AIDR_DEVICE_START_UPSTREAM_URL: deviceUpstream,
	...(values.mode === "self-hosted" ? { AIDR_DEVICE_START_ANON_KEY: env.ANON_KEY } : {}),
	AIDR_DEVICE_START_LISTEN_HOST: "127.0.0.1",
	AIDR_DEVICE_START_TRUSTED_PEERS: "127.0.0.1,::1",
	AIDR_DEVICE_START_LISTEN_PORT: "8191",
}));
write("compose.yml", stringify(compose));
const insecureDevelopmentLoopback = values.development && new URL(supabaseUrl).protocol === "http:";
write("agent-config.json", JSON.stringify({ mode: "managed", control_plane: { enabled: true, endpoint: `${supabaseUrl}/functions/v1`, ...(insecureDevelopmentLoopback ? { allow_insecure_loopback: true } : {}), timeout_seconds: 5, remote_policy_required: true, remote_policy_offline_grace_seconds: 3600 }, ...(artifactVerificationPublicKeyPem ? { integrity: { enabled: true, verify_on_start: true, public_keys_pem: [artifactVerificationPublicKeyPem] } } : {}), licensing: { require_signed_entitlements: true, public_keys_pem: [signing.publicKey.export({ type: "spki", format: "pem" })] } }, null, 2));
const migrations = readdirSync(join(output, "migrations")).filter((name) => name.endsWith(".sql")).sort().map((name) => ({ name, sha256: createHash("sha256").update(readFileSync(join(output, "migrations", name))).digest("hex") }));
function inventory(dir, prefix = "") {
	return readdirSync(dir).sort().flatMap((name) => {
		const path = join(dir, name);
		const relative = prefix ? `${prefix}/${name}` : name;
		return statSync(path).isDirectory() ? inventory(path, relative) : [{ path: relative, sha256: createHash("sha256").update(readFileSync(path)).digest("hex") }];
	});
}
const artifacts = [...inventory(join(output, "dashboard"), "dashboard"), ...inventory(join(output, "ingress"), "ingress"), ...inventory(join(output, "backup"), "backup"), ...inventory(join(output, "maintenance"), "maintenance"), ...inventory(join(output, "auth-templates"), "auth-templates"), ...inventory(join(output, "volumes/functions"), "volumes/functions")];
const source = existsSync(join(root, "release-source.json")) ? JSON.parse(readFileSync(join(root, "release-source.json"), "utf8")) : { commit: execFileSync("git", ["-C", root, "rev-parse", "HEAD"], { encoding: "utf8" }).trim(), dirty: !!execFileSync("git", ["-C", root, "status", "--porcelain"], { encoding: "utf8" }).trim() };
write("deployment.json", JSON.stringify({ schema_version: 1, project_name: compose.name, mode: values.mode, development: values.development, prepared_at: preparedAt.toISOString(), source_commit: source.commit, source_has_changes: source.dirty, upstream_sha: values.mode === "self-hosted" ? upstreamSha : null, dashboard_url: dashboardUrl, supabase_url: supabaseUrl, region: regionId, tenant_region: tenantRegionId, regions, migrations, artifacts, note: "Prepared configuration, not a deployment acceptance record. Region and residency fields are operator declarations, not evidence of provider placement. The readiness, TLS renewal and backup timer units are prepared but not installed or enabled. TLS, authentication, backups and live smoke evidence required." }, null, 2));
console.log(`Prepared ${values.mode} installation at ${output}. Secrets written to private .env files; none printed.`);
