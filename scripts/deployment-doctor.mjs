#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: { deployment: { type: "string", default: ".aidr-deploy" }, online: { type: "boolean", default: false } } });
const dir = resolve(values.deployment);
const manifest = JSON.parse(readFileSync(join(dir, "deployment.json"), "utf8"));
const checks = []; const failures = []; const unverified = [];
function check(ok, label) { (ok ? checks : failures).push(label); console.log(`${ok ? "PASS" : "FAIL"} ${label}`); }
for (const entry of manifest.migrations ?? []) {
  const safe = /^\d{14}_[a-z0-9_]+\.sql$/.test(entry.name);
  check(safe && existsSync(join(dir, "migrations", entry.name)) && createHash("sha256").update(readFileSync(join(dir, "migrations", entry.name))).digest("hex") === entry.sha256, `migration ${safe ? entry.name : "invalid path"}`);
}
check(Number(process.versions.node.split(".")[0]) >= 24, "Node 24 or newer");
const env = Object.fromEntries(readFileSync(join(dir, ".env"), "utf8").split(/\r?\n/).filter((s) => /^[A-Z][A-Z0-9_]*=/.test(s)).map((s) => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=") + 1)]));
const functionEnv = Object.fromEntries(readFileSync(join(dir, ".env.functions"), "utf8").split(/\r?\n/).filter((s) => /^[A-Z][A-Z0-9_]*=/.test(s)).map((s) => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=") + 1)]));
const ingressEnvPath = join(dir, ".env.ingress");
const ingressEnv = existsSync(ingressEnvPath)
  ? Object.fromEntries(readFileSync(ingressEnvPath, "utf8").split(/\r?\n/).filter((s) => /^[A-Z][A-Z0-9_]*=/.test(s)).map((s) => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=") + 1)]))
  : {};
check(existsSync(join(dir, "ingress", "device-start.mjs")) && existsSync(ingressEnvPath), "device-start ingress signer and private environment prepared");
check(existsSync(join(dir, "ingress", "aidr-tls-renew.service")) && existsSync(join(dir, "ingress", "aidr-tls-renew.timer")), "TLS renewal unit and timer prepared for the ingress host");
check(typeof functionEnv.AIDR_DEVICE_START_INGRESS_SECRET === "string" && functionEnv.AIDR_DEVICE_START_INGRESS_SECRET.length >= 32 && functionEnv.AIDR_DEVICE_START_INGRESS_SECRET === ingressEnv.AIDR_DEVICE_START_INGRESS_SECRET, "device-start Edge and ingress signing secrets match");
check(typeof ingressEnv.AIDR_DEVICE_START_PROXY_TOKEN === "string" && ingressEnv.AIDR_DEVICE_START_PROXY_TOKEN.length >= 32 && !ingressEnv.AIDR_DEVICE_START_PROXY_TOKEN.startsWith("REPLACE_"), "device-start reverse-proxy token configured");
let deviceUpstreamValid = false;
try {
  const upstream = new URL(ingressEnv.AIDR_DEVICE_START_UPSTREAM_URL);
  deviceUpstreamValid = upstream.pathname === "/functions/v1/device-start" && !upstream.username && !upstream.password && !upstream.search && !upstream.hash && (upstream.protocol === "https:" || (manifest.mode === "self-hosted" && ["127.0.0.1", "localhost", "[::1]"].includes(upstream.hostname) && upstream.protocol === "http:"));
} catch { /* recorded below */ }
check(deviceUpstreamValid, "device-start ingress upstream is a configured trusted endpoint");
check(!!env.ANON_KEY && !!env.SERVICE_ROLE_KEY && !env.ANON_KEY.startsWith("REPLACE_") && !env.SERVICE_ROLE_KEY.startsWith("REPLACE_"), "selected project's public and private keys configured");
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
check(env.DISABLE_SIGNUP === "true", "public signup disabled");
const demoS3SecretHash = "7f59edafa4d502ca0156b8fddf28394634d77b1843838b5783a7c9c95fcbd32f";
check(typeof env.S3_PROTOCOL_ACCESS_KEY_SECRET === "string" && env.S3_PROTOCOL_ACCESS_KEY_SECRET.length >= 32 && createHash("sha256").update(env.S3_PROTOCOL_ACCESS_KEY_SECRET).digest("hex") !== demoS3SecretHash, "S3 protocol credential is private and differs from the upstream demonstration secret");
// Failed SIEM deliveries are retried only while a scheduler runs the drain worker, so
// the doctor reports two separate facts: the unit templates travel with the kit, and the
// host actually schedules them. Only systemd can answer the second one, and only when
// this host exposes it; anywhere it cannot be determined the check is recorded as
// unverified instead of being reported as a pass.
const kitRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const readSiemUnit = (name) => {
  const path = join(kitRoot, "deploy", "maintenance", name);
  return existsSync(path) ? readFileSync(path, "utf8") : "";
};
const siemServiceUnit = readSiemUnit("aidr-siem-delivery.service");
const siemTimerUnit = readSiemUnit("aidr-siem-delivery.timer");
check(siemTimerUnit.includes("Unit=aidr-siem-delivery.service") && /siem-delivery-worker\.mjs --max-items \d+/.test(siemServiceUnit), "SIEM delivery retry timer present and wired to the drain worker");
const siemScheduler = (() => {
  if (process.platform !== "linux") return { determinable: false, reason: `systemd timers are unavailable on ${process.platform}` };
  const probe = spawnSync("systemctl", ["is-enabled", "aidr-siem-delivery.timer"], { encoding: "utf8", timeout: 15000 });
  if (probe.error) return { determinable: false, reason: "systemctl is not available on this host" };
  return { determinable: true, enabled: probe.status === 0 };
})();
if (siemScheduler.determinable) check(siemScheduler.enabled, "SIEM delivery timer is enabled in the host scheduler");
else {
  unverified.push({ check: "SIEM delivery timer is enabled in the host scheduler", reason: siemScheduler.reason });
  console.log(`UNVERIFIED SIEM delivery timer is enabled in the host scheduler (${siemScheduler.reason})`);
}
for (const url of [manifest.dashboard_url, manifest.supabase_url]) {
  const parsed = new URL(url);
  check(parsed.protocol === "https:" || (manifest.development && ["localhost", "127.0.0.1"].includes(parsed.hostname)), `HTTPS origin or isolated development: ${parsed.origin}`);
}
// Region and residency entries are the operator's declarations. A missing
// declaration is a failure: the doctor cannot confirm that the tenant and the
// deployment were prepared for the same region, and it must not pass that.
const regions = manifest.regions && typeof manifest.regions === "object" && !Array.isArray(manifest.regions) ? manifest.regions : {};
function declaredRegion(id) {
  if (typeof id !== "string" || id.length === 0) return null;
  const entry = regions[id];
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return null;
  const residency = entry.residency;
  if (!residency || typeof residency !== "object" || Array.isArray(residency) || typeof residency.declared !== "boolean" || typeof residency.location !== "string" || residency.location.length === 0) return null;
  if (entry.supabase_url !== null && typeof entry.supabase_url !== "string") return null;
  return entry;
}
const deploymentRegion = declaredRegion(manifest.region);
check(!!deploymentRegion, "deployment manifest declares a known deployment region with residency information");
check(!!declaredRegion(manifest.tenant_region) && manifest.tenant_region === manifest.region, "tenant declared region matches the deployment region");
check(!!deploymentRegion && (deploymentRegion.supabase_url === null || deploymentRegion.supabase_url === manifest.supabase_url), "declared region endpoint matches this deployment's public API origin");
check(!!deploymentRegion && !/^REPLACE/i.test(deploymentRegion.residency.location), "declared region residency location is not a placeholder");
// Nothing else in the repository verifies that the host armed the retention
// reaper, so an expired private export can silently outlive its retention
// window. Only the host's own scheduler can answer this: on a systemd host the
// timer must be installed and enabled, and where the scheduler cannot be read
// (non-systemd init, including Windows where the operator may register a
// scheduled task under any name) the result is recorded as UNVERIFIED rather
// than assumed installed.
const retentionReaperTimer = "aidr-export-retention.timer";
if (process.platform === "linux" && existsSync("/run/systemd/system")) {
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
if (manifest.mode === "self-hosted") {
  const config = spawnSync("docker", ["compose", "--project-directory", dir, "-f", join(dir, "compose.yml"), "config", "--quiet"], { encoding: "utf8", timeout: 15000 });
  check(config.status === 0, "Docker Compose configuration resolves");
  if (values.online) {
    const state = spawnSync("docker", ["compose", "--project-directory", dir, "-f", join(dir, "compose.yml"), "ps", "--all", "--format", "json"], { encoding: "utf8", timeout: 15000 });
    let services = [];
    try { services = state.stdout.trim().startsWith("[") ? JSON.parse(state.stdout) : state.stdout.trim().split(/\r?\n/).filter(Boolean).map((s) => JSON.parse(s)); } catch { /* recorded below */ }
    check(state.status === 0 && services.length >= 10 && services.every((s) => s.State === "running" && (!s.Health || s.Health === "healthy")), "all required deployment services running and healthy");
  }
}
if (values.online) {
  for (const [url, label] of [[`${manifest.dashboard_url}/healthz`, "dashboard health"], [`${manifest.supabase_url}/auth/v1/health`, "authentication health"]]) {
    try { const response = await fetch(url, { headers: { apikey: env.ANON_KEY }, signal: AbortSignal.timeout(10000) }); check(response.ok, label); }
    catch { check(false, label); }
  }
  try {
    const response = await fetch(`${manifest.supabase_url}/auth/v1/settings`, { headers: { apikey: env.ANON_KEY }, signal: AbortSignal.timeout(10000) });
    const settings = await response.json();
    check(response.ok && settings.disable_signup === true, "authentication service confirms signup is disabled");
  } catch { check(false, "authentication settings reachable"); }
}
if (unverified.length) console.log(`${unverified.length} check(s) UNVERIFIED on this host; none of them was reported as PASS`);
writeFileSync(join(dir, "doctor-evidence.json"), JSON.stringify({ checked_at: new Date().toISOString(), passed: failures.length === 0, mode: manifest.mode, online: values.online, checks, failures, unverified, scope: "Operational preflight only. Unverified checks were not confirmed on this host. Customer login, host enforcement, backup restore, TLS routing and business acceptance are separate. Entries under unverified could not be determined on this host and are not evidence of success. No unverified check is recorded as passed." }, null, 2));
if (failures.length) process.exitCode = 1;
