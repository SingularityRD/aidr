#!/usr/bin/env node
import { createHash, createHmac, createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, rmdirSync, writeFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { parseArgs } from "node:util";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const requireCore = createRequire(join(root, "packages/core/package.json"));
const { parse, stringify } = existsSync(join(root, "deploy/vendor/yaml.cjs")) ? requireCore(join(root, "deploy/vendor/yaml.cjs")) : requireCore("yaml");
// Avoid Node's recursive cp binding failing on Windows paths with non-ASCII characters.
function cpSync(source, destination, options = {}) {
	if (options.filter && !options.filter(source)) return;
	if (statSync(source).isDirectory()) {
		mkdirSync(destination, { recursive: true });
		for (const entry of readdirSync(source)) cpSync(join(source, entry), join(destination, entry), options);
	} else { mkdirSync(dirname(destination), { recursive: true }); copyFileSync(source, destination); }
}

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
			esbuild.build({ entryPoints: [backupSource], outfile: backupOutput, bundle: true, platform: "node", format: "esm", target: "node24", sourcemap: false, legalComments: "inline" }),
		]);
	} else if (!readFileSync(readinessSource, "utf8").includes("../packages/core/dist/")) {
		cpSync(readinessSource, readinessOutput);
		cpSync(backupSource, backupOutput);
	} else throw new Error("Maintenance runtime requires a complete core build before deployment preparation");
	cpSync(join(root, "scripts/deployment-backup-offsite.mjs"), join(output, "backup/deployment-backup-offsite.mjs"));
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
	profile: { type: "string" }, "with-aig": { type: "boolean", default: false },
	"aig-signing-public-key-file": { type: "string" }, "aig-signing-key-id": { type: "string" },
} });
if (!["self-hosted", "cloud"].includes(values.mode)) throw new Error("mode must be self-hosted or cloud");
const isPlainObject = (value) => !!value && typeof value === "object" && !Array.isArray(value);
function deepMerge(target, patch) {
	for (const [key, value] of Object.entries(patch)) {
		if (isPlainObject(value) && isPlainObject(target[key])) deepMerge(target[key], value);
		else target[key] = structuredClone(value);
	}
	return target;
}
// On-prem runtime policy: restart, log rotation and health checks come from the
// reviewed overlay; CPU, memory and PID budgets from the selected resource profile.
const onprem = join(root, "deploy/onprem");
let resourceProfiles;
let overlay;
try {
	resourceProfiles = JSON.parse(readFileSync(join(onprem, "resource-profile.json"), "utf8"));
	overlay = parse(readFileSync(join(onprem, "compose.onprem.overlay.yml"), "utf8"));
} catch {
	throw new Error("On-prem resource profiles or Compose overlay are missing or invalid (deploy/onprem)");
}
if (resourceProfiles?.schema_version !== 1 || !isPlainObject(resourceProfiles.profiles)) throw new Error("deploy/onprem/resource-profile.json must declare schema_version 1 and profiles");
if (overlay?.["x-aidr-onprem"]?.schema_version !== 1 || !isPlainObject(overlay["x-aidr-onprem"].defaults) || !isPlainObject(overlay.services)) {
	throw new Error("deploy/onprem/compose.onprem.overlay.yml must declare x-aidr-onprem schema_version 1, defaults and services");
}
const profileName = values.profile ?? resourceProfiles.default_profile;
const resourceProfile = resourceProfiles.profiles[profileName];
if (!isPlainObject(resourceProfile) || !isPlainObject(resourceProfile.services)) {
	throw new Error(`Unknown resource profile "${profileName}"; choose one of: ${Object.keys(resourceProfiles.profiles).join(", ")}`);
}
for (const [name, budget] of Object.entries(resourceProfile.services)) {
	const cpus = (value) => typeof value === "string" && /^\d+(\.\d+)?$/.test(value) && Number(value) > 0;
	const memory = (value) => typeof value === "string" && /^[1-9]\d*[kmg]$/i.test(value);
	if (!isPlainObject(budget) || !cpus(budget.cpus) || !memory(budget.memory) ||
		(budget.reservation_cpus !== undefined && !cpus(budget.reservation_cpus)) ||
		(budget.reservation_memory !== undefined && !memory(budget.reservation_memory)) ||
		(budget.pids !== undefined && !(Number.isInteger(budget.pids) && budget.pids > 0))) {
		throw new Error(`Resource profile "${profileName}" has an invalid budget for ${name}`);
	}
}
// Built images are tagged with the dashboard release version so the air-gap
// bundle can save them by name (build-airgap-images.mjs --compose).
let aidrVersion;
try { aidrVersion = JSON.parse(readFileSync(join(root, "packages/dashboard/package.json"), "utf8")).version; } catch { aidrVersion = undefined; }
if (typeof aidrVersion !== "string" || !/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(aidrVersion)) throw new Error("packages/dashboard/package.json must declare a version usable as an image tag");
// AIG is an optional scanning sidecar. It needs the release operator's RSA data
// signing public key and key id; it is never started with placeholder trust.
const aigServices = ["aig-server", "aig-agent", "aig-bridge", "aig-egress"];
let aig = null;
if (values["with-aig"]) {
	if (values.mode !== "self-hosted") throw new Error("--with-aig is only supported for self-hosted on-prem installations");
	const sources = ["docker-compose.aig.yml", ".env.aig.example", "services/aig-bridge/Dockerfile", "vendor/ai-infra-guard/Dockerfile", "vendor/ai-infra-guard/Dockerfile_Agent", "packages/core/src/generated/aig-data-manifest.json", "deploy/onprem/egress/squid.conf", "deploy/onprem/egress/allowlist.txt"];
	const missing = sources.filter((path) => !existsSync(join(root, path)));
	if (missing.length) throw new Error(`--with-aig requires the AIG sources from the release checkout; missing: ${missing.join(", ")}`);
	const keyId = values["aig-signing-key-id"];
	if (!values["aig-signing-public-key-file"] || !keyId) throw new Error("--with-aig requires --aig-signing-public-key-file and --aig-signing-key-id from the AIG release operator");
	if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(keyId)) throw new Error("--aig-signing-key-id must be a short identifier");
	let publicKeyPem;
	let publicKeySha256;
	try {
		const supplied = readFileSync(resolve(values["aig-signing-public-key-file"]), "utf8");
		if (!supplied.includes("-----BEGIN PUBLIC KEY-----") || supplied.includes("PRIVATE KEY")) throw new Error();
		const key = createPublicKey(supplied);
		if (key.asymmetricKeyType !== "rsa" || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new Error();
		publicKeyPem = key.export({ type: "spki", format: "pem" }).toString();
		publicKeySha256 = createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
	} catch {
		throw new Error("AIG signing public key must be a readable RSA (2048-bit or larger) SPKI public key");
	}
	const dataManifest = JSON.parse(readFileSync(join(root, "packages/core/src/generated/aig-data-manifest.json"), "utf8"));
	const sourceVersion = readFileSync(join(root, ".env.aig.example"), "utf8").match(/^AIG_SOURCE_VERSION=([A-Za-z0-9_.-]+)$/m)?.[1];
	if (!sourceVersion || !/^[a-f0-9]{64}$/.test(dataManifest.bundle_id ?? "") || !/^[a-f0-9]{40}$/.test(dataManifest.source?.commit ?? "")) {
		throw new Error("AIG source version or generated data manifest is invalid; run pnpm compile:aig and pnpm aig:verify");
	}
	aig = { keyId, publicKeyPem, publicKeySha256, sourceVersion, bundleId: dataManifest.bundle_id, sourceCommit: dataManifest.source.commit, signed: !!dataManifest.signature };
}
for (const name of Object.keys(overlay.services)) {
	if (!aigServices.includes(name) && !resourceProfile.services[name]) throw new Error(`On-prem overlay names unknown service "${name}"`);
}
const output = resolve(values.output);
if (existsSync(output)) throw new Error("Output already exists; reuse its secrets and data. Choose a new output for a separate installation.");
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
	? `http://127.0.0.1:${developmentHostPort(supabaseUrl, "8000")}/functions/v1/device-start`
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
	...(aig ? {
		COMPOSE_PROFILES: overlay["x-aidr-onprem"].aig.profiles.join(","),
		AIG_SOURCE_VERSION: aig.sourceVersion, AIG_TZ: "UTC",
		AIG_AGENT_SHARED_SECRET: secret(32),
		AIG_TRUSTED_SIGNING_KEY_ID: aig.keyId, AIG_TRUSTED_SIGNING_PUBLIC_KEY_SHA256: aig.publicKeySha256,
		AIG_EXPECTED_DATA_BUNDLE_ID: aig.bundleId, AIG_EXPECTED_SOURCE_COMMIT: aig.sourceCommit,
		BRIDGE_AUTH_MODE: "api_key", BRIDGE_API_KEY: secret(32),
		BRIDGE_TASK_BACKEND: "sqlite", BRIDGE_HA_REQUIRED: "false", BRIDGE_EGRESS_PROXY_URL: "http://aig-egress:3128",
	} : {}),
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
	AIDR_REVOCATION_SIGNING_KEY_ID: keyId, AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64: signingPrivateKeyDer.toString("base64"),
	AIDR_DELEGATION_ISSUER: supabaseUrl, AIDR_DELEGATION_SIGNING_KEY_ID: delegationKeyId,
	AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64: delegationPrivateKeyDer.toString("base64"),
	AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64: delegationPublicKeyDer.toString("base64"),
	AIDR_PACK_MASTER_KEY_B64: randomBytes(32).toString("base64"), AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING: "false",
	AIDR_PACK_DOWNLOAD_GRANT_SECRET: randomBytes(32).toString("base64url"),
	AIDR_BILLING_PROVIDER: "",
	AIDR_DEVICE_START_INGRESS_SECRET: deviceIngressSecret,
	// Alert integrations: channel destinations are encrypted with this keyring
	// (`<key id>:<base64 32 bytes>`, first entry encrypts) and the dispatcher
	// timer authenticates with the dedicated token (docs/control-plane.md).
	AIDR_NOTIFICATION_ENCRYPTION_KEYS: `k1:${randomBytes(32).toString("base64")}`,
	AIDR_NOTIFICATION_DISPATCH_TOKEN: randomBytes(32).toString("base64url"),
};
for (const service of Object.values(compose.services)) {
	delete service.container_name; delete service.ports;
	service.logging = { driver: "json-file", options: { "max-size": "20m", "max-file": "3" } };
}
if (values.mode === "self-hosted") {
	delete compose.services.supavisor;
	compose.services["api-gw"].ports = [`127.0.0.1:${developmentHostPort(supabaseUrl, "8000")}:8000`];
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
	image: `aidr-dashboard:${aidrVersion}`, build: "./dashboard", restart: "unless-stopped", ports: [`127.0.0.1:${developmentHostPort(dashboardUrl, "8080")}:8080`], read_only: true,
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
if (aig) {
	// Merge the reviewed AIG stack with build contexts and mounts rebased into the
	// installation root. Volumes and networks become project-scoped so two
	// installations on one host never share scan state.
	const aigCompose = parse(readFileSync(join(root, "docker-compose.aig.yml"), "utf8"));
	const rebase = [
		["./services/aig-bridge/aig_compat", "./aig/bridge/aig_compat"],
		["./services/aig-bridge", "./aig/bridge"],
		["./vendor/ai-infra-guard", "./aig/vendor/ai-infra-guard"],
		["./packages/core/src/generated", "./aig/generated"],
		["./deploy/onprem/egress/squid.conf", "./aig/egress/squid.conf"],
		["${AIG_EGRESS_ALLOWLIST_PATH:-./deploy/onprem/egress/allowlist.txt}", "./aig/egress/allowlist.txt"],
		["${AIG_SIGNING_PUBLIC_KEY_HOST_PATH:?set AIG_SIGNING_PUBLIC_KEY_HOST_PATH}", "./aig/aig-signing-public.pem"],
	];
	const rebased = (path) => {
		if (!path.startsWith(".") && !path.startsWith("${")) return path;
		for (const [from, to] of rebase) if (path === from || path.startsWith(`${from}/`) || path.startsWith(`${from}:`)) return to + path.slice(from.length);
		throw new Error(`AIG Compose references an unreviewed host path: ${path}`);
	};
	const images = {
		"aig-server": `aidr-aig-server:${aig.sourceVersion}`,
		"aig-agent": `aidr-aig-agent:${aig.sourceVersion}`,
		"aig-bridge": `aidr-aig-bridge:${aidrVersion}`,
	};
	if (Object.keys(aigCompose.services).sort().join(",") !== [...aigServices].sort().join(",")) throw new Error("docker-compose.aig.yml services do not match the reviewed AIG service set");
	for (const [name, service] of Object.entries(aigCompose.services)) {
		delete service.container_name;
		if (images[name]) service.image = images[name];
		if (service.build) service.build.context = rebased(service.build.context);
		service.volumes = (service.volumes ?? []).map((volume) => typeof volume === "string"
			? rebased(volume)
			: { ...volume, ...(volume.type === "bind" ? { source: rebased(volume.source) } : {}) });
		service.profiles = [...overlay["x-aidr-onprem"].aig.profiles];
		compose.services[name] = service;
	}
	compose.volumes ??= {};
	for (const [name, volume] of Object.entries(aigCompose.volumes ?? {})) { const { name: _global, ...rest } = volume ?? {}; compose.volumes[name] = rest; }
	compose.networks ??= {};
	for (const [name, network] of Object.entries(aigCompose.networks ?? {})) { const { name: _global, ...rest } = network ?? {}; compose.networks[name] = rest; }
}
// Apply the on-prem overlay and resource budgets to every generated service.
for (const [name, service] of Object.entries(compose.services)) {
	deepMerge(service, overlay["x-aidr-onprem"].defaults);
	if (overlay.services[name]) deepMerge(service, overlay.services[name]);
	const budget = resourceProfile.services[name];
	if (!budget) throw new Error(`Resource profile "${profileName}" has no budget for service ${name}`);
	service.deploy = {
		...(service.deploy ?? {}),
		resources: {
			limits: { cpus: budget.cpus, memory: budget.memory, ...(budget.pids ? { pids: budget.pids } : {}) },
			...(budget.reservation_cpus || budget.reservation_memory ? { reservations: {
				...(budget.reservation_cpus ? { cpus: budget.reservation_cpus } : {}),
				...(budget.reservation_memory ? { memory: budget.reservation_memory } : {}),
			} } : {}),
		},
	};
}
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
if (aig) {
	// Build contexts only: skip paths the AIG .dockerignore already excludes,
	// release PDFs, and the bridge's test suite.
	const without = (names) => (path) => !names.includes(path.split(/[\\/]/).pop()) && !path.endsWith(".pdf");
	cpSync(join(root, "vendor/ai-infra-guard"), join(output, "aig/vendor/ai-infra-guard"), { filter: without([".git", ".github", "img", "testcase", "node_modules", "__pycache__"]) });
	cpSync(join(root, "services/aig-bridge"), join(output, "aig/bridge"), { filter: without(["tests", "__pycache__", ".pytest_cache"]) });
	for (const name of ["aig-data-manifest.json", "aig-cve-index.json", "aig-fingerprints.json", "aig-mcp-categories.json"]) {
		cpSync(join(root, "packages/core/src/generated", name), join(output, "aig/generated", name));
	}
	cpSync(join(root, "deploy/onprem/egress"), join(output, "aig/egress"));
	writeFileSync(join(output, "aig/aig-signing-public.pem"), aig.publicKeyPem, { mode: 0o644, flag: "wx" });
}
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
const artifacts = [...(aig ? ["aig/bridge", "aig/egress", "aig/generated"].flatMap((path) => inventory(join(output, path), path)) : []), ...inventory(join(output, "dashboard"), "dashboard"), ...inventory(join(output, "ingress"), "ingress"), ...inventory(join(output, "backup"), "backup"), ...inventory(join(output, "maintenance"), "maintenance"), ...inventory(join(output, "auth-templates"), "auth-templates"), ...inventory(join(output, "volumes/functions"), "volumes/functions")];
const source = existsSync(join(root, "release-source.json")) ? JSON.parse(readFileSync(join(root, "release-source.json"), "utf8")) : { commit: execFileSync("git", ["-C", root, "rev-parse", "HEAD"], { encoding: "utf8" }).trim(), dirty: !!execFileSync("git", ["-C", root, "status", "--porcelain"], { encoding: "utf8" }).trim() };
write("deployment.json", JSON.stringify({ schema_version: 1, project_name: compose.name, mode: values.mode, development: values.development, prepared_at: preparedAt.toISOString(), source_commit: source.commit, source_has_changes: source.dirty, upstream_sha: values.mode === "self-hosted" ? upstreamSha : null, dashboard_url: dashboardUrl, supabase_url: supabaseUrl, region: regionId, tenant_region: tenantRegionId, regions, resource_profile: profileName, dashboard_image: compose.services.dashboard.image, aig: aig ? { enabled: true, source_version: aig.sourceVersion, source_commit: aig.sourceCommit, bundle_id: aig.bundleId, data_manifest_signed: aig.signed, signing_key_id: aig.keyId, signing_public_key_sha256: aig.publicKeySha256, images: Object.fromEntries(aigServices.map((name) => [name, compose.services[name].image])), task_backend: "sqlite", ha_required: false, egress: "aig-egress deny-by-default allowlist (aig/egress/allowlist.txt)" } : { enabled: false }, migrations, artifacts, note: "Prepared configuration, not a deployment acceptance record. Region and residency fields are operator declarations, not evidence of provider placement. The readiness, TLS renewal and backup timer units are prepared but not installed or enabled. TLS, authentication, backups and live smoke evidence required." }, null, 2));
console.log(`Prepared ${values.mode} installation at ${output}. Secrets written to private .env files; none printed.`);
