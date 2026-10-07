#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { deploymentCredentialFailures } from "./lib/deployment-credentials.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// --development acknowledges a loopback rehearsal: the evidence is then marked
// development-only. Without it, an online run refuses a development manifest so
// a rehearsal can never be filed as production deployment evidence.
const { values } = parseArgs({ options: { deployment: { type: "string", default: ".aidr-deploy" }, online: { type: "boolean", default: false }, development: { type: "boolean", default: false } } });
const dir = resolve(values.deployment);
const manifest = JSON.parse(readFileSync(join(dir, "deployment.json"), "utf8"));
const checks = []; const failures = []; const unverified = [];
const requiredComposeServices = ["studio", "api-gw", "auth", "rest", "realtime", "storage", "imgproxy", "meta", "functions", "db", "dashboard"];
function check(ok, label) { (ok ? checks : failures).push(label); console.log(`${ok ? "PASS" : "FAIL"} ${label}`); }
for (const entry of manifest.migrations ?? []) {
  const safe = /^\d{14}_[a-z0-9_]+\.sql$/.test(entry.name);
  check(safe && existsSync(join(dir, "migrations", entry.name)) && createHash("sha256").update(readFileSync(join(dir, "migrations", entry.name))).digest("hex") === entry.sha256, `migration ${safe ? entry.name : "invalid path"}`);
}
check(Number(process.versions.node.split(".")[0]) >= 24, "Node 24 or newer");
const env = Object.fromEntries(readFileSync(join(dir, ".env"), "utf8").split(/\r?\n/).filter((s) => /^[A-Z][A-Z0-9_]*=/.test(s)).map((s) => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=") + 1)]));
const functionEnv = Object.fromEntries(readFileSync(join(dir, ".env.functions"), "utf8").split(/\r?\n/).filter((s) => /^[A-Z][A-Z0-9_]*=/.test(s)).map((s) => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=") + 1)]));
if (!manifest.development) {
  let agentConfig;
  try { agentConfig = JSON.parse(readFileSync(join(dir, "agent-config.json"), "utf8")); } catch { agentConfig = null; }
  const keyFingerprint = (pem) => {
    try {
      if (typeof pem !== "string" || !pem.includes("-----BEGIN PUBLIC KEY-----") || pem.includes("PRIVATE KEY")) return null;
      const key = createPublicKey(pem);
      if (key.asymmetricKeyType !== "ed25519") return null;
      return createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
    } catch { return null; }
  };
  const integrityKeys = agentConfig?.integrity?.public_keys_pem;
  const licensingKeys = Array.isArray(agentConfig?.licensing?.public_keys_pem) ? agentConfig.licensing.public_keys_pem.map(keyFingerprint).filter(Boolean) : [];
  const integrityFingerprints = Array.isArray(integrityKeys) ? integrityKeys.map(keyFingerprint) : [];
  check(
    agentConfig?.mode === "managed" &&
      agentConfig?.integrity?.enabled === true &&
      agentConfig?.integrity?.verify_on_start === true &&
      integrityFingerprints.length > 0 &&
      integrityFingerprints.every(Boolean) &&
      integrityFingerprints.every((fingerprint) => !licensingKeys.includes(fingerprint)),
    "commercial artifact verification uses valid independent Ed25519 public keys",
  );
}
const ingressEnvPath = join(dir, ".env.ingress");
const ingressEnv = existsSync(ingressEnvPath)
  ? Object.fromEntries(readFileSync(ingressEnvPath, "utf8").split(/\r?\n/).filter((s) => /^[A-Z][A-Z0-9_]*=/.test(s)).map((s) => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=") + 1)]))
  : {};
check(existsSync(join(dir, "ingress", "device-start.mjs")) && existsSync(ingressEnvPath), "device-start ingress signer and private environment prepared");
check(existsSync(join(dir, "ingress", "aidr-tls-renew.service")) && existsSync(join(dir, "ingress", "aidr-tls-renew.timer")), "TLS renewal unit and timer prepared for the ingress host");
check(typeof functionEnv.AIDR_DEVICE_START_INGRESS_SECRET === "string" && functionEnv.AIDR_DEVICE_START_INGRESS_SECRET.length >= 32 && functionEnv.AIDR_DEVICE_START_INGRESS_SECRET === ingressEnv.AIDR_DEVICE_START_INGRESS_SECRET, "device-start Edge and ingress signing secrets match");
check(typeof ingressEnv.AIDR_DEVICE_START_PROXY_TOKEN === "string" && ingressEnv.AIDR_DEVICE_START_PROXY_TOKEN.length >= 32 && !ingressEnv.AIDR_DEVICE_START_PROXY_TOKEN.startsWith("REPLACE_") && ingressEnv.AIDR_DEVICE_START_PROXY_TOKEN !== ingressEnv.AIDR_DEVICE_START_INGRESS_SECRET, "device-start reverse-proxy token configured and independent from ingress signing secret");
let deviceUpstreamValid = false;
try {
  const upstream = new URL(ingressEnv.AIDR_DEVICE_START_UPSTREAM_URL);
  deviceUpstreamValid = upstream.pathname === "/functions/v1/device-start" && !upstream.username && !upstream.password && !upstream.search && !upstream.hash && (upstream.protocol === "https:" || (manifest.mode === "self-hosted" && ["127.0.0.1", "localhost", "[::1]"].includes(upstream.hostname) && upstream.protocol === "http:"));
} catch { /* recorded below */ }
check(deviceUpstreamValid, "device-start ingress upstream is a configured trusted endpoint");
if (manifest.mode === "cloud") {
  const configuredAnonKey = ingressEnv.AIDR_DEVICE_START_ANON_KEY;
  check(
    !!env.ANON_KEY && !env.ANON_KEY.startsWith("REPLACE_") &&
      typeof configuredAnonKey === "string" && configuredAnonKey === env.ANON_KEY,
    "cloud device-start ingress uses the selected project's configured anonymous API key",
  );
}
const credentialFailures = deploymentCredentialFailures(env);
check(credentialFailures.length === 0, "selected project's public and private keys configured");
if (credentialFailures.length) console.log(`FAIL missing, placeholder or shared vendor credentials: ${credentialFailures.join(", ")}`);
check(typeof functionEnv.AIDR_DELEGATION_ISSUER === "string" && functionEnv.AIDR_DELEGATION_ISSUER === manifest.supabase_url, "delegated credential issuer matches this control plane");
check(/^aidr-delegation-[a-f0-9]{12}$/.test(functionEnv.AIDR_DELEGATION_SIGNING_KEY_ID ?? ""), "delegated credential signing key id configured");
check(typeof functionEnv.AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64 === "string" && Buffer.from(functionEnv.AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64, "base64").length >= 48, "delegated credential private signing key configured");
check(typeof functionEnv.AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64 === "string" && Buffer.from(functionEnv.AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64, "base64").length >= 32, "delegated credential public verification key configured");
let delegationKeyPairValid = false;
try {
  const privateKey = createPrivateKey({ key: Buffer.from(functionEnv.AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64, "base64"), format: "der", type: "pkcs8" });
  const publicKey = createPublicKey({ key: Buffer.from(functionEnv.AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64, "base64"), format: "der", type: "spki" });
  const challenge = Buffer.from("aidr-delegation-key-health-v1", "utf8");
  delegationKeyPairValid = verify(null, challenge, publicKey, sign(null, challenge, privateKey));
} catch { /* recorded below without exposing key material */ }
check(delegationKeyPairValid, "delegated credential signing and verification keys match");
const base64Bytes = (value) => typeof value === "string" && /^[A-Za-z0-9+/]+={0,2}$/.test(value) ? Buffer.from(value, "base64").length : 0;
check(base64Bytes(functionEnv.AIDR_APPROVAL_SIGNING_WRAP_KEY_B64) === 32, "dashboard approval signing key wrap key configured (32 bytes)");
check(typeof functionEnv.AIDR_NOTIFICATION_ENCRYPTION_KEYS === "string" && functionEnv.AIDR_NOTIFICATION_ENCRYPTION_KEYS.split(",").length > 0 &&
  functionEnv.AIDR_NOTIFICATION_ENCRYPTION_KEYS.split(",").every((entry) => /^[a-z0-9][a-z0-9_-]{0,31}:/.test(entry) && base64Bytes(entry.slice(entry.indexOf(":") + 1)) === 32),
"alert channel encryption keyring configured");
check(typeof functionEnv.AIDR_NOTIFICATION_DISPATCH_TOKEN === "string" && functionEnv.AIDR_NOTIFICATION_DISPATCH_TOKEN.trim().length >= 32, "alert dispatcher token configured (drives agent-offline and governance alerts)");
// Compliance report signing is optional (reports then carry a sha256 digest
// only); when configured it must be a real Ed25519 key matching the public key
// recorded for auditors.
if (functionEnv.AIDR_COMPLIANCE_SIGNING_KEY_ID || functionEnv.AIDR_COMPLIANCE_SIGNING_PRIVATE_KEY_PKCS8_B64) {
  let complianceKeyValid = false;
  try {
    const privateKey = createPrivateKey({ key: Buffer.from(functionEnv.AIDR_COMPLIANCE_SIGNING_PRIVATE_KEY_PKCS8_B64 ?? "", "base64"), format: "der", type: "pkcs8" });
    const recorded = manifest.compliance_signing?.public_key_pem;
    const challenge = Buffer.from("aidr-compliance-key-health-v1", "utf8");
    complianceKeyValid = privateKey.asymmetricKeyType === "ed25519" &&
      /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(functionEnv.AIDR_COMPLIANCE_SIGNING_KEY_ID ?? "") &&
      (!recorded || (manifest.compliance_signing?.key_id === functionEnv.AIDR_COMPLIANCE_SIGNING_KEY_ID &&
        verify(null, challenge, createPublicKey(recorded), sign(null, challenge, privateKey))));
  } catch { /* recorded below without exposing key material */ }
  check(complianceKeyValid, "compliance report signing key is Ed25519 and matches the auditor public key");
} else {
  // Optional control, so not a failure; said out loud rather than passed.
  console.log("INFO compliance report signing key not configured: reports carry a sha256 digest but no Ed25519 signature");
}
const signupMode = manifest.mode === "cloud" ? env.AIDR_SIGNUP_MODE : "closed";
check(manifest.mode === "cloud" ? ["closed", "cloud"].includes(signupMode) : env.DISABLE_SIGNUP === "true", manifest.mode === "cloud" ? "cloud signup mode is explicit and valid" : "public signup disabled");
check(typeof env.S3_PROTOCOL_ACCESS_KEY_SECRET === "string" && env.S3_PROTOCOL_ACCESS_KEY_SECRET.length >= 32 && !credentialFailures.includes("S3_PROTOCOL_ACCESS_KEY_SECRET"), "S3 protocol credential is private and differs from the upstream demonstration secret");
// Failed SIEM deliveries and readiness evidence advance only while the shared maintenance
// worker is scheduled, so the doctor reports two separate facts: the unit templates travel
// with the kit, and the host actually schedules them. Only systemd can answer the second one, and only when
// this host exposes it; anywhere it cannot be determined the check is recorded as
// unverified instead of being reported as a pass.
const readMaintenanceUnit = (name) => {
	const relative = `maintenance/${name}`;
	const entries = Array.isArray(manifest.artifacts) ? manifest.artifacts.filter((artifact) => artifact?.path === relative) : [];
	const entry = entries.length === 1 ? entries[0] : null;
	const path = join(dir, "maintenance", name);
	if (!entry || !/^[a-f0-9]{64}$/.test(entry.sha256 ?? "") || !existsSync(path)) return "";
	const content = readFileSync(path);
	return createHash("sha256").update(content).digest("hex") === entry.sha256 ? content.toString("utf8") : "";
};
const siemServiceUnit = readMaintenanceUnit("aidr-siem-delivery.service");
const siemTimerUnit = readMaintenanceUnit("aidr-siem-delivery.timer");
check(siemTimerUnit.includes("Unit=aidr-siem-delivery.service") && /readiness-evidence-worker\.mjs/.test(siemServiceUnit), "shared readiness and SIEM timer present and wired to the maintenance worker");
// On Windows the timers are mirrored by Install-AidrMaintenanceTasks.ps1 as
// scheduled tasks under fixed names in the \AIDR\ folder. The installer leaves a
// declaration file; once it exists a missing or disabled task is a failure, not
// an unknown. Without it the operator may schedule the workers some other way,
// so an absent task stays UNVERIFIED instead of being guessed either way. The
// task XML is read rather than the CSV listing because its element names are
// not localized.
const windowsTaskPath = "\\AIDR\\";
const windowsMaintenanceDeclaration = join(dir, "windows-maintenance-tasks.json");
const windowsMaintenanceDeclared = existsSync(windowsMaintenanceDeclaration);
const xmlText = (value) => value.replace(/&quot;/g, "\"").replace(/&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
function windowsTaskState(name, worker) {
  const task = `${windowsTaskPath}${name}`;
  const schtasks = join(process.env.SystemRoot || "C:\\Windows", "System32", "schtasks.exe");
  const probe = spawnSync(schtasks, ["/Query", "/TN", task, "/XML"], { encoding: "utf8", timeout: 15000, windowsHide: true });
  if (probe.error) return { task, found: false, reason: `schtasks is not available on this host (${probe.error.code ?? "error"})` };
  const xml = probe.status === 0 ? String(probe.stdout ?? "") : "";
  if (!xml.includes("<Task")) return { task, found: false, reason: `scheduled task ${task} is not available (absent or unreadable)` };
  const settings = /<Settings>([\s\S]*?)<\/Settings>/.exec(xml)?.[1] ?? "";
  const triggers = /<Triggers>([\s\S]*?)<\/Triggers>/.exec(xml)?.[1] ?? "";
  const activeTrigger = [...triggers.matchAll(/<(\w+Trigger)>([\s\S]*?)<\/\1>/g)].some((match) => !/<Enabled>false<\/Enabled>/.test(match[2]));
  const command = xmlText(/<Command>([\s\S]*?)<\/Command>/.exec(xml)?.[1] ?? "").trim();
  const args = xmlText(/<Arguments>([\s\S]*?)<\/Arguments>/.exec(xml)?.[1] ?? "");
  const execCount = (xml.match(/<Exec>/g) ?? []).length;
  // The installer writes exactly these argument shapes; matching the whole
  // quoted path keeps C:\aidr from matching a task wired to C:\aidr-old.
  const expected = (name === "aidr-siem-delivery" ? `"${dir}\\maintenance\\${worker}"` : `\\scripts\\${worker}" "${dir}" --apply`).toLowerCase();
  const wired = execCount === 1 && /(^|[\\/"])node(\.exe)?"?$/i.test(command) && args.toLowerCase().includes(expected);
  const enabled = !/<Enabled>false<\/Enabled>/.test(settings) && activeTrigger;
  return { task, found: true, enabled, wired };
}
function windowsSchedulerCheck(name, worker, label, unverifiedLabel) {
  const state = windowsTaskState(name, worker);
  if (state.found) {
    const problem = !state.enabled ? "disabled or without an active trigger" : !state.wired ? "not wired to this deployment's maintenance worker" : "";
    check(!problem, `${label}${problem ? ` (${state.task} ${problem})` : ""}`);
  } else if (windowsMaintenanceDeclared) {
    check(false, `${label} (${state.reason}; declared by windows-maintenance-tasks.json)`);
  } else {
    const reason = `${state.reason}; no Windows maintenance declaration exists, so the host scheduler cannot inspect another scheduling method`;
    unverified.push({ check: unverifiedLabel, reason });
    console.log(`UNVERIFIED ${unverifiedLabel} (${reason})`);
  }
}
const siemSchedulerLabel = "shared readiness and SIEM timer is enabled in the host scheduler";
const siemScheduler = (() => {
  if (process.platform === "win32") return { windows: true };
  if (process.platform !== "linux") return { determinable: false, reason: `systemd timers are unavailable on ${process.platform}` };
  const probe = spawnSync("systemctl", ["is-enabled", "aidr-siem-delivery.timer"], { encoding: "utf8", timeout: 15000 });
  if (probe.error) return { determinable: false, reason: "systemctl is not available on this host" };
  return { determinable: true, enabled: probe.status === 0 };
})();
if (siemScheduler.windows) windowsSchedulerCheck("aidr-siem-delivery", "readiness-evidence-worker.mjs", siemSchedulerLabel, siemSchedulerLabel);
else if (siemScheduler.determinable) check(siemScheduler.enabled, siemSchedulerLabel);
else {
	unverified.push({ check: siemSchedulerLabel, reason: siemScheduler.reason });
	console.log(`UNVERIFIED ${siemSchedulerLabel} (${siemScheduler.reason})`);
}
for (const url of [manifest.dashboard_url, manifest.supabase_url]) {
  const parsed = new URL(url);
  check(parsed.protocol === "https:" || (manifest.development && ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname)), `HTTPS origin or isolated development: ${parsed.origin}`);
}
// Region and residency entries are operator declarations, not provider facts.
// A missing or explicitly false declaration fails; a true declaration is still
// not evidence of actual provider placement.
const regions = manifest.regions && typeof manifest.regions === "object" && !Array.isArray(manifest.regions) ? manifest.regions : {};
function declaredRegion(id) {
  if (typeof id !== "string" || id.length === 0) return null;
  const entry = regions[id];
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return null;
  const residency = entry.residency;
  if (!residency || typeof residency !== "object" || Array.isArray(residency) || residency.declared !== true || typeof residency.location !== "string" || residency.location.length === 0) return null;
  if (entry.supabase_url !== null && typeof entry.supabase_url !== "string") return null;
  return entry;
}
const deploymentRegion = declaredRegion(manifest.region);
check(!!deploymentRegion, deploymentRegion
  ? `operator-declared residency location: ${deploymentRegion.residency.location} (provider location not verified)`
  : "deployment region requires an explicit operator residency declaration");
check(!!declaredRegion(manifest.tenant_region) && manifest.tenant_region === manifest.region, "tenant declared region matches the deployment region");
check(!!deploymentRegion && (deploymentRegion.supabase_url === null || deploymentRegion.supabase_url === manifest.supabase_url), "declared region endpoint matches this deployment's public API origin");
check(!!deploymentRegion && !/^REPLACE/i.test(deploymentRegion.residency.location), "declared region residency location is not a placeholder");
const loopbackHosts = new Set(["localhost", "127.0.0.1", "[::1]"]);
const developmentEndpointsLoopback = !manifest.development || [manifest.dashboard_url, manifest.supabase_url].every((value) => {
	try { return loopbackHosts.has(new URL(value).hostname); } catch { return false; }
});
check(developmentEndpointsLoopback, "development mode uses loopback dashboard and Supabase endpoints");
// A `--development` manifest never configures a certificate and produces signing,
// backup and queue evidence only if the maintenance units happen to run, so its
// online result is a rehearsal. An online run must not file it as production
// evidence unless the operator explicitly asked for a development run, and a
// development run must not be pointed at a production manifest.
const developmentManifest = manifest.development !== false;
if (values.online || values.development) {
  check(typeof manifest.development === "boolean", "deployment manifest declares whether it is a development deployment");
  if (values.development) check(developmentManifest, "--development run targets a development manifest");
  else check(!developmentManifest, "production evidence requires a production manifest (development manifests need --development)");
}
// Nothing else in the repository verifies that the host armed the retention
// reaper, so an expired private export can silently outlive its retention
// window. Only the host's own scheduler can answer this: on a systemd host the
// timer must be installed and enabled, and where the scheduler cannot be read
// (non-systemd init, or Windows without the declared \AIDR\ scheduled tasks)
// the result is recorded as UNVERIFIED rather than assumed installed.
const retentionReaperTimer = "aidr-export-retention.timer";
if (process.platform === "win32") {
  windowsSchedulerCheck("aidr-export-retention", "deployment-maintenance.mjs", `retention reaper scheduled task installed and enabled: ${windowsTaskPath}aidr-export-retention`, `retention reaper timer not verified: ${retentionReaperTimer}`);
} else if (process.platform === "linux" && existsSync("/run/systemd/system")) {
  const probe = spawnSync("systemctl", ["is-enabled", retentionReaperTimer], { encoding: "utf8", timeout: 15000 });
  const state = (probe.stdout ?? "").trim().split(/\r?\n/)[0] ?? "";
  if (probe.error) {
    unverified.push({ check: `retention reaper timer state unreadable: ${retentionReaperTimer}`, reason: `systemctl ${probe.error.code ?? "unavailable"}` });
    console.log(`UNVERIFIED retention reaper timer state unreadable: ${retentionReaperTimer}`);
  } else {
    check(probe.status === 0 && /^enabled/.test(state), `retention reaper timer installed and enabled: ${retentionReaperTimer}${probe.status === 0 ? "" : ` (${state || "not enabled"})`}`);
  }
} else {
  unverified.push({ check: `retention reaper timer not verified: ${retentionReaperTimer}`, reason: `must be installed as a systemd timer or host scheduled task, which a ${process.platform} run cannot inspect` });
  console.log(`UNVERIFIED retention reaper timer not verified: ${retentionReaperTimer}`);
}
// Optional AI Security Posture scanner sidecar (prepared with
// --with-posture-scanner). Every check reads the prepared files only; secrets are
// compared, never printed. Installations prepared before the rename record the
// scanner under `aig`, stage it in `aig/` and use AIG_* settings; they are still
// checked.
const legacyPostureScanner = manifest.posture_scanner === undefined && manifest.aig !== undefined;
const postureScannerManifest = legacyPostureScanner ? manifest.aig : manifest.posture_scanner;
const postureScannerEnabled = postureScannerManifest?.enabled === true;
const postureScannerServices = ["aig-server", "aig-agent", "aig-bridge", "aig-egress"];
if (postureScannerEnabled) {
  const scannerDir = join(dir, legacyPostureScanner ? "aig" : "posture-scanner");
  const scannerEnv = (name) => env[`POSTURE_SCANNER_${name}`] || env[`AIG_${name}`];
  const privateSecret = (value) => typeof value === "string" && value.length >= 32 && !/^(REPLACE|replace-with)/.test(value);
  check(privateSecret(scannerEnv("AGENT_SHARED_SECRET")), "Posture scanner worker shared secret configured (at least 32 characters)");
  const bridgeAuthMode = env.BRIDGE_AUTH_MODE || "broker";
  check(
    bridgeAuthMode === "api_key"
      ? privateSecret(env.BRIDGE_API_KEY) && env.BRIDGE_API_KEY !== scannerEnv("AGENT_SHARED_SECRET")
      : bridgeAuthMode === "broker" && Buffer.byteLength(env.BRIDGE_JWT_SECRET ?? "", "utf8") >= 32 && !!env.BRIDGE_JWT_ISSUER && !!env.BRIDGE_JWT_AUDIENCE,
    `Posture scanner bridge authentication configured (${bridgeAuthMode === "api_key" ? "isolated API key independent from the worker secret" : "broker JWT secret, issuer and audience"})`,
  );
  let signingKeyFingerprint = null;
  try {
    const key = createPublicKey(readFileSync(join(scannerDir, legacyPostureScanner ? "aig-signing-public.pem" : "signing-public.pem"), "utf8"));
    if (key.asymmetricKeyType === "rsa" && (key.asymmetricKeyDetails?.modulusLength ?? 0) >= 2048) {
      signingKeyFingerprint = createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
    }
  } catch { /* recorded below */ }
  check(!!signingKeyFingerprint && signingKeyFingerprint === scannerEnv("TRUSTED_SIGNING_PUBLIC_KEY_SHA256") && signingKeyFingerprint === postureScannerManifest.signing_public_key_sha256, "Posture scanner data signing public key matches the pinned SPKI fingerprint");
  let scannerData = null;
  try { scannerData = JSON.parse(readFileSync(join(scannerDir, "generated", "aig-data-manifest.json"), "utf8")); } catch { /* recorded below */ }
  check(!!scannerData && scannerData.bundle_id === scannerEnv("EXPECTED_DATA_BUNDLE_ID") && scannerData.source?.commit === scannerEnv("EXPECTED_SOURCE_COMMIT"), "Posture scanner bundle and source commit pins match the staged data manifest");
  check(!!scannerData?.signature, "Posture scanner data manifest carries a release signature (an unsigned manifest keeps bridge readiness closed)");
  const taskBackend = env.BRIDGE_TASK_BACKEND || "sqlite";
  const haRequired = /^(1|true|yes|on)$/i.test(env.BRIDGE_HA_REQUIRED ?? "false");
  if (taskBackend === "postgres") {
    let dsnValid = false;
    try { dsnValid = ["postgres:", "postgresql:"].includes(new URL(env.BRIDGE_TASK_POSTGRES_DSN).protocol); } catch { /* recorded below */ }
    check(dsnValid, "Posture scanner bridge PostgreSQL task registry DSN configured for HA");
  } else {
    check(taskBackend === "sqlite" && !haRequired, "Posture scanner bridge task registry is single-host SQLite with HA not required");
  }
  const egressDir = join(scannerDir, "egress");
  const allowlistLines = existsSync(join(egressDir, "allowlist.txt"))
    ? readFileSync(join(egressDir, "allowlist.txt"), "utf8").split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#"))
    : null;
  const allowlistValid = Array.isArray(allowlistLines) && allowlistLines.every((line) => /^\.?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(line));
  const accessRules = existsSync(join(egressDir, "squid.conf"))
    ? readFileSync(join(egressDir, "squid.conf"), "utf8").split(/\r?\n/).map((line) => line.trim()).filter((line) => line.startsWith("http_access"))
    : [];
  const denyByDefault = accessRules.includes("http_access deny non_public_dst") && accessRules.at(-1) === "http_access deny all";
  check(env.BRIDGE_EGRESS_PROXY_URL === "http://aig-egress:3128" && denyByDefault && allowlistValid, "Posture scanner remote scans leave only through the deny-by-default egress gateway with a valid allowlist");
  if (allowlistValid) console.log(`INFO Posture scanner egress allowlist names ${allowlistLines.length} destination domain(s)${allowlistLines.length === 0 ? "; every remote scan is refused until one is added" : ""}`);
  let topologyIsolated = false;
  try {
    const requireCore = createRequire(join(root, "packages/core/package.json"));
    const { parse } = existsSync(join(root, "deploy/vendor/yaml.cjs")) ? requireCore(join(root, "deploy/vendor/yaml.cjs")) : requireCore("yaml");
    const compose = parse(readFileSync(join(dir, "compose.yml"), "utf8"));
    const networks = compose.networks ?? {};
    const serviceNetworks = (name) => { const value = compose.services?.[name]?.networks; return Array.isArray(value) ? value : Object.keys(value ?? {}); };
    const internal = (name) => networks[name]?.internal === true;
    const noMasquerade = (name) => String(networks[name]?.driver_opts?.["com.docker.network.bridge.enable_ip_masquerade"]) === "false";
    topologyIsolated = postureScannerServices.every((name) => compose.services?.[name])
      && ["aig-server", "aig-agent"].every((name) => serviceNetworks(name).length > 0 && serviceNetworks(name).every(internal) && !compose.services[name].ports)
      && !compose.services["aig-egress"].ports
      && serviceNetworks("aig-bridge").some(internal) && serviceNetworks("aig-bridge").every((name) => internal(name) || noMasquerade(name))
      && (compose.services["aig-bridge"].ports ?? []).every((port) => /^\$\{POSTURE_SCANNER_BIND_ADDRESS:-\$\{AIG_BIND_ADDRESS:-127\.0\.0\.1\}\}:|^\$\{AIG_BIND_ADDRESS:-127\.0\.0\.1\}:|^127\.0\.0\.1:/.test(String(port)));
  } catch { /* recorded below */ }
  check(topologyIsolated, "Posture scanner control network is internal and only the authenticated bridge publishes a loopback port");
  const scannerProfile = legacyPostureScanner ? "aig" : "posture-scanner";
  check((env.COMPOSE_PROFILES ?? "").split(",").map((value) => value.trim()).includes(scannerProfile), `Posture scanner Compose profile (${scannerProfile}) is active for this installation`);
  requiredComposeServices.push(...postureScannerServices);
}
if (manifest.mode === "self-hosted") {
  const config = spawnSync("docker", ["compose", "--project-directory", dir, "-f", join(dir, "compose.yml"), "config", "--quiet"], { encoding: "utf8", timeout: 15000 });
  check(config.status === 0, "Docker Compose configuration resolves");
  if (values.online) {
    const state = spawnSync("docker", ["compose", "--project-directory", dir, "-f", join(dir, "compose.yml"), "ps", "--all", "--format", "json"], { encoding: "utf8", timeout: 15000 });
    let services = [];
    try { services = state.stdout.trim().startsWith("[") ? JSON.parse(state.stdout) : state.stdout.trim().split(/\r?\n/).filter(Boolean).map((s) => JSON.parse(s)); } catch { /* recorded below */ }
    const serviceRows = new Map();
    for (const service of services) {
      if (!service?.Service) continue;
      serviceRows.set(service.Service, [...(serviceRows.get(service.Service) ?? []), service]);
    }
    const servicesHealthy = requiredComposeServices.every((name) => {
      const rows = serviceRows.get(name);
      return rows?.length > 0 && rows.every((service) => service.State === "running" && (!service.Health || service.Health === "healthy"));
    });
    check(state.status === 0 && servicesHealthy, "all required deployment services running and healthy");
  }
}
if (values.online && credentialFailures.length === 0) {
  if (manifest.mode === "cloud") {
    try {
      const response = await fetch(`${manifest.dashboard_url}/runtime-config.js`, { signal: AbortSignal.timeout(10000) });
      const script = response.headers.get("content-type")?.startsWith("application/javascript") && Number(response.headers.get("content-length") ?? 0) <= 16384 ? await response.text() : "";
      const prefix = "window.__AIDR_CONFIG__=";
      const runtimeConfig = script.startsWith(prefix) && script.endsWith(";") ? JSON.parse(script.slice(prefix.length, -1)) : null;
      check(response.ok && script.length <= 16384 && runtimeConfig?.signupMode === signupMode, "dashboard signup mode matches deployment configuration");
    } catch { check(false, "dashboard signup mode matches deployment configuration"); }
  }
  try {
    const response = await fetch(`${manifest.dashboard_url}/readyz`, { headers: { apikey: env.ANON_KEY }, signal: AbortSignal.timeout(10000) });
    const readiness = await response.json();
    const ready = response.ok && readiness?.status === "ready";
    // Name the failing readiness checks so the operator knows which evidence
    // source (signing, backup, queue, certificate, ...) to repair. Only short
    // known-shape names are echoed; anything else keeps the bare label.
    const reported = readiness?.checks && typeof readiness.checks === "object" && !Array.isArray(readiness.checks) ? Object.entries(readiness.checks) : [];
    const notOk = reported.filter(([name, state]) => /^[a-z][a-z0-9_]{0,31}$/.test(name) && state !== "ok").map(([name]) => name).slice(0, 16);
    check(ready, ready || notOk.length === 0 ? "dashboard readiness" : `dashboard readiness (not ok: ${notOk.join(", ")})`);
  } catch { check(false, "dashboard readiness"); }
  try { const response = await fetch(`${manifest.supabase_url}/auth/v1/health`, { headers: { apikey: env.ANON_KEY }, signal: AbortSignal.timeout(10000) }); check(response.ok, "authentication health"); }
  catch { check(false, "authentication health"); }
  try {
    const response = await fetch(`${manifest.supabase_url}/auth/v1/settings`, { headers: { apikey: env.ANON_KEY }, signal: AbortSignal.timeout(10000) });
    const settings = await response.json();
    check(response.ok && settings.disable_signup === (signupMode !== "cloud"), "authentication signup setting matches deployment mode");
  } catch { check(false, "authentication settings reachable"); }
}
if (unverified.length) console.log(`${unverified.length} check(s) UNVERIFIED on this host; none of them was reported as PASS`);
const passed = failures.length === 0 && unverified.length === 0;
writeFileSync(join(dir, "doctor-evidence.json"), JSON.stringify({ checked_at: new Date().toISOString(), passed, mode: manifest.mode, online: values.online, evidence_class: developmentManifest ? "development" : "production", checks, failures, unverified, scope: "Operational preflight only. Residency is an operator declaration, not verification of actual provider location. Unverified checks were not confirmed on this host. Customer login, host enforcement, backup restore, TLS routing and business acceptance are separate. Entries under unverified could not be determined on this host and are not evidence of success. No unverified check is recorded as passed." }, null, 2));
if (!passed) process.exitCode = 1;
