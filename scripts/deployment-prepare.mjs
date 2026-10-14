#!/usr/bin/env node
import { createHash, createHmac, createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, rmdirSync, writeFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { parseArgs } from "node:util";
import { cpSync } from "./lib/deployment-input-copy.mjs";
import { DEFAULT_PUBLIC_KEYS_PATH, loadPublicKeyRegistry } from "./license-verify.mjs";
import { isIP } from "node:net";
import {
	PRIVACY_GATEWAY_LAYOUT, PRIVACY_GATEWAY_PROFILE, PRIVACY_GATEWAY_SERVICE, PRIVACY_GATEWAY_UID,
	normalizePrivacyGatewayConfig, parsePrivacyGatewayCidrs, parsePrivacyGatewaySubnet,
	renderPrivacyGatewayFirewall, stagePrivacyGatewayImage, validatePrivacyGatewayTls,
} from "../deploy/privacy-gateway/privacy-gateway.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const requireCore = createRequire(join(root, "packages/core/package.json"));
const { parse, parseDocument, stringify } = existsSync(join(root, "deploy/vendor/yaml.cjs")) ? requireCore(join(root, "deploy/vendor/yaml.cjs")) : requireCore("yaml");
// Supabase Studio is an operator tool, never part of the public API surface.
// The reviewed upstream Envoy listener (port 8000, the one the ingress proxies)
// ends in `/` -> studio behind HTTP basic auth only. Move the Studio routes to a
// separate listener that Compose publishes on loopback only, and end the public
// listener in a plain 404. Operators reach Studio through an SSH tunnel.
const STUDIO_ADMIN_LISTENER_PORT = 8001;
// libpq dead-peer detection for PostgREST's pooled connections
// (docs/production-readiness/load-soak-drill-2026-10-11.md, O2 addendum). Without
// it, a connection that was mid-query when the database's network path died sat
// in TCP retransmission backoff and kept its pool slot well after the network
// returned. Keepalives probe idle connections (first after 30 s idle, every 10 s,
// dropped after 3 misses); tcp_user_timeout drops a connection whose sent data
// stays unacknowledged for 20 s. Neither bounds query or request duration, and
// the PostgREST pool timeouts keep their defaults. Operators override the whole
// parameter string with AIDR_POSTGREST_DB_URI_PARAMS in `.env`.
const POSTGREST_DB_URI_PARAMS = "keepalives=1&keepalives_idle=30&keepalives_interval=10&keepalives_count=3&tcp_user_timeout=20000";
const ENVOY_ROUTES = ["filter_chains", 0, "filters", 0, "typed_config", "route_config", "virtual_hosts", 0, "routes"];
function isolateStudioListener(path) {
	const doc = parseDocument(readFileSync(path, "utf8"));
	const resources = doc.get("resources");
	const listener = resources?.items?.length === 1 ? resources.items[0] : null;
	const routes = listener?.getIn(ENVOY_ROUTES);
	const isStudio = (route) => route?.getIn?.(["route", "cluster"]) === "studio";
	const studioRoutes = routes?.items?.filter(isStudio) ?? [];
	if (!listener || listener.get("name") !== "supabase" || listener.getIn(["address", "socket_address", "port_value"]) !== 8000
		|| studioRoutes.map((route) => route.getIn(["match", "prefix"])).join(",") !== "/api/mcp,/mcp,/" || routes.items.at(-1) !== studioRoutes.at(-1)) {
		throw new Error("The reviewed upstream Envoy listener layout changed; refusing to prepare a gateway that could expose Studio");
	}
	const admin = listener.clone();
	admin.set("name", "studio_admin");
	admin.setIn(["address", "socket_address", "port_value"], STUDIO_ADMIN_LISTENER_PORT);
	admin.setIn(["filter_chains", 0, "filters", 0, "typed_config", "stat_prefix"], "studio_admin_http");
	admin.setIn(["filter_chains", 0, "filters", 0, "typed_config", "route_config", "name"], "studio_admin_route");
	admin.setIn(["filter_chains", 0, "filters", 0, "typed_config", "route_config", "virtual_hosts", 0, "name"], "studio_admin_host");
	admin.getIn(ENVOY_ROUTES).items = studioRoutes.map((route) => route.clone());
	routes.items = routes.items.filter((route) => !isStudio(route));
	routes.items.push(doc.createNode({
		name: "studio-not-public",
		match: { prefix: "/" },
		direct_response: { status: 404 },
		typed_per_filter_config: {
			"envoy.filters.http.basic_auth": { "@type": "type.googleapis.com/envoy.config.route.v3.FilterConfig", disabled: true },
			"envoy.filters.http.rbac": { "@type": "type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBACPerRoute", rbac: { rules: { action: "ALLOW", policies: { allow_all: { permissions: [{ any: true }], principals: [{ any: true }] } } } } },
		},
	}));
	resources.items.push(admin);
	writeFileSync(path, doc.toString({ lineWidth: 0 }));
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
	profile: { type: "string" }, "with-posture-scanner": { type: "boolean", default: false },
	"posture-scanner-signing-public-key-file": { type: "string" }, "posture-scanner-signing-key-id": { type: "string" },
	// Optional privacy gateway (deploy/privacy-gateway/README.md). Every input is
	// operator-supplied; preparation generates no gateway credential.
	"with-privacy-gateway": { type: "boolean", default: false },
	"privacy-gateway-config-file": { type: "string" }, "privacy-gateway-secrets-dir": { type: "string" },
	"privacy-gateway-trust-dir": { type: "string" }, "privacy-gateway-models-dir": { type: "string" },
	"privacy-gateway-tls-cert-file": { type: "string" }, "privacy-gateway-tls-key-file": { type: "string" },
	"privacy-gateway-client-ca-file": { type: "string" }, "privacy-gateway-egress-cidrs": { type: "string" },
	"privacy-gateway-dns-cidrs": { type: "string" }, "privacy-gateway-subnet": { type: "string" },
	"privacy-gateway-bind-address": { type: "string" },
	// Deprecated spellings kept so existing runbooks keep working; not documented.
	"with-aig": { type: "boolean", default: false },
	"aig-signing-public-key-file": { type: "string" }, "aig-signing-key-id": { type: "string" },
} });
for (const [legacy, current] of [["with-aig", "with-posture-scanner"], ["aig-signing-public-key-file", "posture-scanner-signing-public-key-file"], ["aig-signing-key-id", "posture-scanner-signing-key-id"]]) {
	if (!values[legacy]) continue;
	console.error(`NOTE: --${legacy} is deprecated; use --${current}.`);
	if (values[current] && values[current] !== values[legacy]) throw new Error(`--${legacy} and --${current} disagree; pass only --${current}`);
	values[current] = values[legacy];
}
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
// The AI Security Posture scanner is an optional sidecar. It needs the release
// operator's RSA data signing public key and key id; it is never started with
// placeholder trust. Its Compose service and volume names stay stable so
// existing installations keep their scan state.
const postureScannerServices = ["aig-server", "aig-agent", "aig-bridge", "aig-egress"];
const postureScannerDir = "posture-scanner";
let postureScanner = null;
if (values["with-posture-scanner"]) {
	if (values.mode !== "self-hosted") throw new Error("--with-posture-scanner is only supported for self-hosted on-prem installations");
	const sources = ["docker-compose.posture-scanner.yml", ".env.posture-scanner.example", "services/aig-bridge/Dockerfile", "vendor/ai-infra-guard/Dockerfile", "vendor/ai-infra-guard/Dockerfile_Agent", "packages/core/src/generated/aig-data-manifest.json", "deploy/onprem/egress/squid.conf", "deploy/onprem/egress/allowlist.txt"];
	const missing = sources.filter((path) => !existsSync(join(root, path)));
	if (missing.length) throw new Error(`--with-posture-scanner requires the posture scanner sources from the release checkout; missing: ${missing.join(", ")}`);
	const keyId = values["posture-scanner-signing-key-id"];
	if (!values["posture-scanner-signing-public-key-file"] || !keyId) throw new Error("--with-posture-scanner requires --posture-scanner-signing-public-key-file and --posture-scanner-signing-key-id from the posture scanner release operator");
	if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(keyId)) throw new Error("--posture-scanner-signing-key-id must be a short identifier");
	let publicKeyPem;
	let publicKeySha256;
	try {
		const supplied = readFileSync(resolve(values["posture-scanner-signing-public-key-file"]), "utf8");
		if (!supplied.includes("-----BEGIN PUBLIC KEY-----") || supplied.includes("PRIVATE KEY")) throw new Error();
		const key = createPublicKey(supplied);
		if (key.asymmetricKeyType !== "rsa" || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new Error();
		publicKeyPem = key.export({ type: "spki", format: "pem" }).toString();
		publicKeySha256 = createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
	} catch {
		throw new Error("Posture scanner signing public key must be a readable RSA (2048-bit or larger) SPKI public key");
	}
	const dataManifest = JSON.parse(readFileSync(join(root, "packages/core/src/generated/aig-data-manifest.json"), "utf8"));
	const sourceVersion = readFileSync(join(root, ".env.posture-scanner.example"), "utf8").match(/^POSTURE_SCANNER_SOURCE_VERSION=([A-Za-z0-9_.-]+)$/m)?.[1];
	if (!sourceVersion || !/^[a-f0-9]{64}$/.test(dataManifest.bundle_id ?? "") || !/^[a-f0-9]{40}$/.test(dataManifest.source?.commit ?? "")) {
		throw new Error("Posture scanner source version or generated data manifest is invalid; run pnpm compile:aig and pnpm aig:verify");
	}
	postureScanner = { keyId, publicKeyPem, publicKeySha256, sourceVersion, bundleId: dataManifest.bundle_id, sourceCommit: dataManifest.source.commit, signed: !!dataManifest.signature };
}
// The privacy gateway is an optional, explicit egress API (POST /v1/egress over
// mutual TLS). Preparation refuses it without mutual TLS material, an egress
// allow-list, the operator's secret files and an approved NER model manifest;
// it never generates or defaults any of them.
const privacyGatewayOptions = Object.keys(values).filter((name) => name.startsWith("privacy-gateway-") && values[name] !== undefined);
if (!values["with-privacy-gateway"] && privacyGatewayOptions.length) throw new Error(`--${privacyGatewayOptions[0]} requires --with-privacy-gateway`);
let privacyGateway = null;
if (values["with-privacy-gateway"]) {
	if (values.mode !== "self-hosted") throw new Error("--with-privacy-gateway is only supported for self-hosted installations");
	const requiredOptions = ["tls-cert-file", "tls-key-file", "client-ca-file", "config-file", "secrets-dir", "trust-dir", "models-dir", "egress-cidrs"];
	const missingOptions = requiredOptions.filter((name) => !values[`privacy-gateway-${name}`]);
	if (missingOptions.length) throw new Error(`--with-privacy-gateway requires ${missingOptions.map((name) => `--privacy-gateway-${name}`).join(", ")} (mutual TLS and an egress allow-list are mandatory)`);
	const readInput = (name) => {
		const path = resolve(values[`privacy-gateway-${name}`]);
		try {
			const info = statSync(path);
			if (!info.isFile() || info.size === 0 || info.size > 1024 * 1024) throw new Error();
			return readFileSync(path, "utf8");
		} catch {
			throw new Error(`--privacy-gateway-${name} must name a readable, non-empty file`);
		}
	};
	const inputDirectory = (name) => {
		const path = resolve(values[`privacy-gateway-${name}`]);
		if (!existsSync(path) || !statSync(path).isDirectory()) throw new Error(`--privacy-gateway-${name} must name an existing directory`);
		return path;
	};
	const tls = { cert: readInput("tls-cert-file"), key: readInput("tls-key-file"), clientCa: readInput("client-ca-file") };
	const tlsSummary = validatePrivacyGatewayTls(tls);
	const configText = readInput("config-file");
	let operatorConfig;
	try { operatorConfig = JSON.parse(configText); } catch { throw new Error("--privacy-gateway-config-file must be valid JSON"); }
	const normalized = normalizePrivacyGatewayConfig(operatorConfig);
	const directoryFile = (directory, relative, label) => {
		const path = resolve(directory, relative);
		if (!path.startsWith(`${directory}${sep}`)) throw new Error(`${label} ${relative} escapes its directory`);
		let info;
		try { info = lstatSync(path); } catch { info = null; }
		if (!info?.isFile() || info.size === 0) throw new Error(`${label} ${relative} is missing, empty or not a regular file`);
		return path;
	};
	const secretsDirectory = inputDirectory("secrets-dir");
	const trustDirectory = inputDirectory("trust-dir");
	const modelsDirectory = inputDirectory("models-dir");
	const secretFiles = normalized.secretRefs.map((ref) => [ref, directoryFile(secretsDirectory, ref, "Privacy gateway secret")]);
	const trustFiles = normalized.trustFiles.map((relative) => [relative, directoryFile(trustDirectory, relative, "Privacy gateway trust file")]);
	const manifestDigest = createHash("sha256").update(readFileSync(directoryFile(modelsDirectory, normalized.modelManifest, "Privacy gateway NER model manifest"))).digest("hex");
	if (manifestDigest !== normalized.config.ner.manifestSha256) throw new Error("Privacy gateway NER model manifest does not match the approved ner.manifestSha256");
	const bindAddress = values["privacy-gateway-bind-address"] ?? "127.0.0.1";
	if (!isIP(bindAddress)) throw new Error("--privacy-gateway-bind-address must be an IP address");
	privacyGateway = {
		tls, tlsSummary, config: normalized.config, secretFiles, trustFiles, modelsDirectory, bindAddress,
		egressCidrs: parsePrivacyGatewayCidrs(values["privacy-gateway-egress-cidrs"], "--privacy-gateway-egress-cidrs"),
		dnsCidrs: parsePrivacyGatewayCidrs(values["privacy-gateway-dns-cidrs"], "--privacy-gateway-dns-cidrs", { required: false }),
		subnet: parsePrivacyGatewaySubnet(values["privacy-gateway-subnet"] ?? "172.31.253.0/28"),
	};
}
for (const name of Object.keys(overlay.services)) {
	if (!postureScannerServices.includes(name) && !resourceProfile.services[name]) throw new Error(`On-prem overlay names unknown service "${name}"`);
}
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
// Development installs derive the Studio port from the API port so isolated
// installations on one host do not collide.
const studioAdminHostPort = values.development ? String(Number(developmentHostPort(supabaseUrl, "8000")) + 1) : String(STUDIO_ADMIN_LISTENER_PORT);
if (Number(studioAdminHostPort) > 65535) throw new Error("--development needs a Supabase URL port below 65535; the next port is Studio's loopback admin listener");
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
if (values.mode === "self-hosted") {
	cpSync(join(upstream, "docker/volumes"), join(output, "volumes"), { recursive: true });
	isolateStudioListener(join(output, "volumes/api/envoy/lds.template.yaml"));
}
const secret = (bytes = 32) => randomBytes(bytes).toString("hex");
const deviceIngressSecret = secret(32);
const deviceProxyToken = secret(32);
const env = values.mode === "self-hosted" ? Object.fromEntries(readFileSync(join(upstream, "docker/.env.example"), "utf8").split(/\r?\n/).filter((line) => /^[A-Z][A-Z0-9_]*=/.test(line)).map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)])) : {};
if (values.mode === "self-hosted" && temporaryUpstream) rmSync(upstream, { recursive: true, force: true });
const signing = generateKeyPairSync("ed25519");
const delegationSigning = generateKeyPairSync("ed25519");
// Compliance evidence packs are sealed with their own Ed25519 key (never the
// entitlement key); auditors verify with the public key recorded in
// deployment.json (`compliance_signing.public_key_pem`).
const complianceSigning = generateKeyPairSync("ed25519");
const complianceKeyId = `aidr-compliance-${randomBytes(6).toString("hex")}`;
const compliancePublicKeyPem = complianceSigning.publicKey.export({ type: "spki", format: "pem" });
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
	...(postureScanner ? {
		COMPOSE_PROFILES: overlay["x-aidr-onprem"].posture_scanner.profiles.join(","),
		POSTURE_SCANNER_SOURCE_VERSION: postureScanner.sourceVersion, POSTURE_SCANNER_TZ: "UTC",
		POSTURE_SCANNER_AGENT_SHARED_SECRET: secret(32),
		POSTURE_SCANNER_TRUSTED_SIGNING_KEY_ID: postureScanner.keyId, POSTURE_SCANNER_TRUSTED_SIGNING_PUBLIC_KEY_SHA256: postureScanner.publicKeySha256,
		POSTURE_SCANNER_EXPECTED_DATA_BUNDLE_ID: postureScanner.bundleId, POSTURE_SCANNER_EXPECTED_SOURCE_COMMIT: postureScanner.sourceCommit,
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
// The license trust registry shipped with this kit becomes the Edge runtime's
// trust root for dashboard license imports (supabase/functions/_shared/license.ts).
// A malformed registry stops preparation; an empty one is valid and makes the
// import refuse every license until the vendor registry is installed.
loadPublicKeyRegistry(DEFAULT_PUBLIC_KEYS_PATH);
const licensePublicKeysB64 = readFileSync(DEFAULT_PUBLIC_KEYS_PATH).toString("base64");
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
	AIDR_APPROVAL_SIGNING_WRAP_KEY_B64: randomBytes(32).toString("base64"),
	AIDR_COMPLIANCE_SIGNING_KEY_ID: complianceKeyId,
	AIDR_COMPLIANCE_SIGNING_PRIVATE_KEY_PKCS8_B64: complianceSigning.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
	AIDR_BILLING_PROVIDER: "",
	AIDR_LICENSE_PUBLIC_KEYS_B64: licensePublicKeysB64,
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
	compose.services["api-gw"].image = "envoyproxy/envoy:v1.39.2@sha256:460f8c329f24b2e1c7c5af64cb314a6f351ad1c262ba77b135ac46b35ebd5f85";
	compose.services.imgproxy.image = "darthsim/imgproxy:v4.0.17@sha256:db0b4b9cd690c8b3590203dea300fb759a18c4ec2af7b37424f0bdef23ce317d";
	compose.services.imgproxy.environment.IMGPROXY_USE_LAST_MODIFIED = "false";
	// Scan-gated upstream bumps (docs/production-readiness/runtime-image-security-2026-10-07.md):
	// each strictly reduces CRITICAL+HIGH with no new CRITICAL; native acceptance still pending.
	// storage v1.80.2 (docs/production-readiness/upstream-image-triage-2026-10-11.md): same
	// scan findings as v1.80.0, adds the vendor's signed-TUS/Iceberg authorization hardening.
	compose.services.studio.image = "supabase/studio:2026.10.05-sha-94b8b06@sha256:d878dcd9dba73b66d1c2c19aeaf53d07704e71604d93013225be1d1c51475237";
	compose.services.auth.image = "supabase/gotrue:v2.197.0@sha256:1736a63078f5922b198c4cbe50f80ab9a2d3b54fe8b7b6cfb2e9dc5dbbc12c6b";
	compose.services.storage.image = "supabase/storage-api:v1.80.2@sha256:95b217a9c59e0ac06c6dcb539df3189a1668a2445fb43dbf29660d6968ffd7d2";
	compose.services.meta.image = "supabase/postgres-meta:v0.100.0@sha256:145325b7e39f8ef4931d6e8cfd3f6f4d655de09d72a2ccc96d9513542c2202bd";
	compose.services.functions.image = "supabase/edge-runtime:v1.77.4@sha256:ad45164b7548bf5820ed7be714789c17ac2865edce79a09cfb4c3756c3d365a8";
	// Stateful in-major bump 17.6 -> 17.11, gated by docs/production-readiness/postgres-upgrade-restore-drill-2026-10-11.md;
	// existing installs follow the operator procedure in deploy/backup/README.md.
	compose.services.db.image = "supabase/postgres:17.11.0.004@sha256:06ddc7962e11ab0f4f0334fd05671e97c30ea202f6e6a7113800bd3d6e416108";
	// Studio's admin listener is published on loopback only; the ingress never proxies it.
	compose.services["api-gw"].ports = [
		`${loopbackBinding(supabaseUrl)}:${developmentHostPort(supabaseUrl, "8000")}:8000`,
		`${loopbackBinding(supabaseUrl)}:${studioAdminHostPort}:${STUDIO_ADMIN_LISTENER_PORT}`,
	];
	compose.services.functions.env_file = [".env.functions"];
	const restDbUri = compose.services.rest.environment.PGRST_DB_URI;
	if (typeof restDbUri !== "string" || !restDbUri.startsWith("postgres://authenticator:") || restDbUri.includes("?")) {
		throw new Error("The reviewed upstream PostgREST database URI changed; refusing to prepare it without connection keepalives");
	}
	compose.services.rest.environment.PGRST_DB_URI = `${restDbUri}?\${AIDR_POSTGREST_DB_URI_PARAMS:-${POSTGREST_DB_URI_PARAMS}}`;
	compose.services.auth.environment.GOTRUE_MAILER_TEMPLATES_RECOVERY = "http://dashboard:8080/auth-templates/recovery.html";
	compose.services.auth.environment.GOTRUE_MAILER_SUBJECTS_RECOVERY = "Reset your AIDR password";
	// Invites must link to /auth/callback?token_hash=...&type=invite; the default
	// GoTrue template delivers session tokens in the URL fragment, which the
	// dashboard rejects (login CSRF).
	compose.services.auth.environment.GOTRUE_MAILER_TEMPLATES_INVITE = "http://dashboard:8080/auth-templates/invite.html";
	compose.services.auth.environment.GOTRUE_MAILER_SUBJECTS_INVITE = "You have been invited to AIDR";
	compose.services.db.volumes = compose.services.db.volumes.map((v) => v.startsWith("./volumes/db/data:") ? "aidr-db:/var/lib/postgresql/data" : v);
	compose.services.storage.volumes = ["aidr-storage:/var/lib/storage"];
	compose.services.imgproxy.volumes = ["aidr-storage:/var/lib/storage:ro"];
	compose.volumes["aidr-db"] = {};
	compose.volumes["aidr-storage"] = {};
}
const healthApiOrigin = values.mode === "self-hosted" ? "http://api-gw:8000" : supabaseUrl;
const dashboardHealthPath = values.development ? "/livez" : "/readyz";
compose.services.dashboard = {
	image: `aidr-dashboard:${aidrVersion}`, build: "./dashboard", restart: "unless-stopped", ports: [`${loopbackBinding(dashboardUrl)}:${developmentHostPort(dashboardUrl, "8080")}:8080`], read_only: true,
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
		AIDR_LICENSE_HEALTH_FILE: "/run/aidr-health/license.json",
		...(!values.development ? { AIDR_PUBLIC_HTTPS_URL: dashboardUrl } : {}),
		AIDR_METRICS_TOKEN: "${AIDR_METRICS_TOKEN:?AIDR_METRICS_TOKEN is required}",
		AIDR_READINESS_REQUIRED_CHECKS: "database,storage,functions,signing,backup,queue,certificate",
	},
	volumes: [{ type: "bind", source: "./health", target: "/run/aidr-health", read_only: true }],
};
if (postureScanner) {
	// Merge the reviewed posture scanner stack with build contexts and mounts
	// rebased into the installation root. Volumes and networks become
	// project-scoped so two installations on one host never share scan state.
	const scannerCompose = parse(readFileSync(join(root, "docker-compose.posture-scanner.yml"), "utf8"));
	const rebase = [
		["./services/aig-bridge/aig_compat", `./${postureScannerDir}/bridge/aig_compat`],
		["./services/aig-bridge", `./${postureScannerDir}/bridge`],
		["./vendor/ai-infra-guard", `./${postureScannerDir}/vendor/ai-infra-guard`],
		["./packages/core/src/generated", `./${postureScannerDir}/generated`],
		["./deploy/onprem/egress/squid.conf", `./${postureScannerDir}/egress/squid.conf`],
		["${POSTURE_SCANNER_EGRESS_ALLOWLIST_PATH:-${AIG_EGRESS_ALLOWLIST_PATH:-./deploy/onprem/egress/allowlist.txt}}", `./${postureScannerDir}/egress/allowlist.txt`],
		["${POSTURE_SCANNER_SIGNING_PUBLIC_KEY_HOST_PATH:-${AIG_SIGNING_PUBLIC_KEY_HOST_PATH:?set POSTURE_SCANNER_SIGNING_PUBLIC_KEY_HOST_PATH}}", `./${postureScannerDir}/signing-public.pem`],
	];
	const rebased = (path) => {
		if (!path.startsWith(".") && !path.startsWith("${")) return path;
		for (const [from, to] of rebase) if (path === from || path.startsWith(`${from}/`) || path.startsWith(`${from}:`)) return to + path.slice(from.length);
		throw new Error(`Posture scanner Compose references an unreviewed host path: ${path}`);
	};
	const images = {
		"aig-server": `aidr-aig-server:${postureScanner.sourceVersion}`,
		"aig-agent": `aidr-aig-agent:${postureScanner.sourceVersion}`,
		"aig-bridge": `aidr-aig-bridge:${aidrVersion}`,
	};
	if (Object.keys(scannerCompose.services).sort().join(",") !== [...postureScannerServices].sort().join(",")) throw new Error("docker-compose.posture-scanner.yml services do not match the reviewed posture scanner service set");
	for (const [name, service] of Object.entries(scannerCompose.services)) {
		delete service.container_name;
		if (images[name]) service.image = images[name];
		if (service.build) service.build.context = rebased(service.build.context);
		service.volumes = (service.volumes ?? []).map((volume) => typeof volume === "string"
			? rebased(volume)
			: { ...volume, ...(volume.type === "bind" ? { source: rebased(volume.source) } : {}) });
		service.profiles = [...overlay["x-aidr-onprem"].posture_scanner.profiles];
		compose.services[name] = service;
	}
	compose.volumes ??= {};
	for (const [name, volume] of Object.entries(scannerCompose.volumes ?? {})) { const { name: _global, ...rest } = volume ?? {}; compose.volumes[name] = rest; }
	compose.networks ??= {};
	for (const [name, network] of Object.entries(scannerCompose.networks ?? {})) { const { name: _global, ...rest } = network ?? {}; compose.networks[name] = rest; }
}
if (privacyGateway) {
	const L = PRIVACY_GATEWAY_LAYOUT;
	const secretName = (ref) => `${PRIVACY_GATEWAY_SERVICE}-${ref}`;
	const secretRefs = [...privacyGateway.secretFiles.map(([ref]) => ref), L.tlsKeyRef];
	const publishHost = privacyGateway.bindAddress.includes(":") ? `[${privacyGateway.bindAddress}]` : privacyGateway.bindAddress;
	compose.services[PRIVACY_GATEWAY_SERVICE] = {
		image: `aidr-privacy-gateway:${aidrVersion}`, build: `./${PRIVACY_GATEWAY_SERVICE}/image`,
		// Opt-in: started only with --profile privacy-gateway, after the egress firewall is applied.
		profiles: [PRIVACY_GATEWAY_PROFILE],
		user: `${PRIVACY_GATEWAY_UID}:${PRIVACY_GATEWAY_UID}`, read_only: true, cap_drop: ["ALL"], security_opt: ["no-new-privileges:true"],
		tmpfs: ["/tmp:rw,noexec,nosuid,nodev,size=512m"],
		// The only listener is the mutually authenticated egress API.
		ports: [`${publishHost}:${L.port}:${L.port}`],
		environment: { AIDR_PRIVACY_CONFIG: L.config },
		// A dedicated network: no route to the database or any other AIDR service.
		networks: [PRIVACY_GATEWAY_SERVICE],
		healthcheck: { test: ["CMD", "/usr/local/bin/node", "/opt/aidr-private/healthcheck.mjs"], interval: "30s", timeout: "5s", retries: 3, start_period: "300s" },
		volumes: [
			{ type: "bind", source: `./${PRIVACY_GATEWAY_SERVICE}/service.json`, target: L.config, read_only: true },
			{ type: "bind", source: `./${PRIVACY_GATEWAY_SERVICE}/trust`, target: L.trust, read_only: true },
			{ type: "bind", source: `./${PRIVACY_GATEWAY_SERVICE}/tls`, target: L.tls, read_only: true },
			{ type: "bind", source: privacyGateway.modelsDirectory, target: L.models, read_only: true },
			{ type: "volume", source: "aidr-privacy-state", target: L.state },
		],
		secrets: secretRefs.map((ref) => ({ source: secretName(ref), target: `${L.secrets}/${ref}` })),
	};
	compose.secrets ??= {};
	for (const ref of secretRefs) compose.secrets[secretName(ref)] = { file: `./${PRIVACY_GATEWAY_SERVICE}/secrets/${ref}` };
	compose.volumes ??= {};
	compose.volumes["aidr-privacy-state"] = {};
	compose.networks ??= {};
	compose.networks[PRIVACY_GATEWAY_SERVICE] = {
		driver: "bridge",
		driver_opts: { "com.docker.network.bridge.enable_icc": "false" },
		ipam: { config: [{ subnet: privacyGateway.subnet }] },
	};
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
if (postureScanner) {
	// Build contexts only: skip paths the scanner .dockerignore already excludes,
	// release PDFs, and the bridge's test suite.
	const without = (names) => (path) => !names.includes(path.split(/[\\/]/).pop()) && !path.endsWith(".pdf");
	cpSync(join(root, "vendor/ai-infra-guard"), join(output, postureScannerDir, "vendor/ai-infra-guard"), { filter: without([".git", ".github", "img", "testcase", "node_modules", "__pycache__"]) });
	cpSync(join(root, "services/aig-bridge"), join(output, postureScannerDir, "bridge"), { filter: without(["tests", "__pycache__", ".pytest_cache"]) });
	for (const name of ["aig-data-manifest.json", "aig-cve-index.json", "aig-fingerprints.json", "aig-mcp-categories.json"]) {
		cpSync(join(root, "packages/core/src/generated", name), join(output, postureScannerDir, "generated", name));
	}
	cpSync(join(root, "deploy/onprem/egress"), join(output, postureScannerDir, "egress"));
	writeFileSync(join(output, postureScannerDir, "signing-public.pem"), postureScanner.publicKeyPem, { mode: 0o644, flag: "wx" });
}
if (privacyGateway) {
	const base = join(output, PRIVACY_GATEWAY_SERVICE);
	stagePrivacyGatewayImage(root, join(base, "image"));
	const publicFile = (relative, content) => {
		mkdirSync(dirname(join(base, relative)), { recursive: true });
		writeFileSync(join(base, relative), content, { mode: 0o644, flag: "wx" });
	};
	// Secret files stay owner-only; installation hands them to the container uid.
	mkdirSync(join(base, "secrets"), { mode: 0o700 });
	const secretFile = (ref, content) => writeFileSync(join(base, "secrets", ref), content, { mode: 0o600, flag: "wx" });
	publicFile("service.json", `${JSON.stringify(privacyGateway.config, null, 2)}\n`);
	publicFile("tls/server.pem", privacyGateway.tls.cert);
	publicFile("tls/client-ca.pem", privacyGateway.tls.clientCa);
	for (const [relative, source] of privacyGateway.trustFiles) publicFile(`trust/${relative}`, readFileSync(source));
	for (const [ref, source] of privacyGateway.secretFiles) secretFile(ref, readFileSync(source));
	secretFile(PRIVACY_GATEWAY_LAYOUT.tlsKeyRef, privacyGateway.tls.key);
	writeFileSync(join(base, "egress-firewall.sh"), renderPrivacyGatewayFirewall(privacyGateway), { mode: 0o700, flag: "wx" });
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
const artifacts = [...(privacyGateway ? ["image", "tls", "trust"].map((path) => `${PRIVACY_GATEWAY_SERVICE}/${path}`).flatMap((path) => inventory(join(output, path), path)) : []), ...(postureScanner ? ["bridge", "egress", "generated"].map((path) => `${postureScannerDir}/${path}`).flatMap((path) => inventory(join(output, path), path)) : []), ...inventory(join(output, "dashboard"), "dashboard"), ...inventory(join(output, "ingress"), "ingress"), ...inventory(join(output, "backup"), "backup"), ...inventory(join(output, "maintenance"), "maintenance"), ...inventory(join(output, "auth-templates"), "auth-templates"), ...inventory(join(output, "volumes/functions"), "volumes/functions")];
const source = existsSync(join(root, "release-source.json")) ? JSON.parse(readFileSync(join(root, "release-source.json"), "utf8")) : { commit: execFileSync("git", ["-C", root, "rev-parse", "HEAD"], { encoding: "utf8" }).trim(), dirty: !!execFileSync("git", ["-C", root, "status", "--porcelain"], { encoding: "utf8" }).trim() };
write("deployment.json", JSON.stringify({ schema_version: 1, project_name: compose.name, mode: values.mode, development: values.development, prepared_at: preparedAt.toISOString(), source_commit: source.commit, source_has_changes: source.dirty, upstream_sha: values.mode === "self-hosted" ? upstreamSha : null, dashboard_url: dashboardUrl, supabase_url: supabaseUrl, region: regionId, tenant_region: tenantRegionId, regions, resource_profile: profileName, dashboard_image: compose.services.dashboard.image, compliance_signing: { key_id: complianceKeyId, public_key_pem: compliancePublicKeyPem, public_key_sha256: createHash("sha256").update(complianceSigning.publicKey.export({ type: "spki", format: "der" })).digest("hex") }, posture_scanner: postureScanner ? { enabled: true, source_version: postureScanner.sourceVersion, source_commit: postureScanner.sourceCommit, bundle_id: postureScanner.bundleId, data_manifest_signed: postureScanner.signed, signing_key_id: postureScanner.keyId, signing_public_key_sha256: postureScanner.publicKeySha256, images: Object.fromEntries(postureScannerServices.map((name) => [name, compose.services[name].image])), task_backend: "sqlite", ha_required: false, egress: `aig-egress deny-by-default allowlist (${postureScannerDir}/egress/allowlist.txt)` } : { enabled: false }, privacy_gateway: privacyGateway ? { enabled: true, compose_profile: PRIVACY_GATEWAY_PROFILE, image: compose.services[PRIVACY_GATEWAY_SERVICE].image, interface: "explicit egress API: POST /v1/egress over mutual TLS; not transparent interception", listen: compose.services[PRIVACY_GATEWAY_SERVICE].ports[0], mtls: { required: true, server_certificate_sha256: privacyGateway.tlsSummary.serverFingerprint256, client_ca_sha256: privacyGateway.tlsSummary.clientCaFingerprint256, server_not_after: privacyGateway.tlsSummary.serverNotAfter }, destination: { kind: privacyGateway.config.destination.kind, origin: privacyGateway.config.destination.origin, model: privacyGateway.config.destination.model }, ner_manifest_sha256: privacyGateway.config.ner.manifestSha256, egress: { subnet: privacyGateway.subnet, allowed_cidrs: privacyGateway.egressCidrs, dns_cidrs: privacyGateway.dnsCidrs, enforcement: `prepared, not applied: run ${PRIVACY_GATEWAY_SERVICE}/egress-firewall.sh as root` } } : { enabled: false }, migrations, artifacts, note: "Prepared configuration, not a deployment acceptance record. Region and residency fields are operator declarations, not evidence of provider placement. The readiness, TLS renewal and backup timer units are prepared but not installed or enabled. TLS, authentication, backups and live smoke evidence required." }, null, 2));
console.log(`Prepared ${values.mode} installation at ${output}. Secrets written to private .env files; none printed.`);
