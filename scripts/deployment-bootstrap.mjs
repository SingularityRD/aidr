#!/usr/bin/env node
// Deployment bootstrap CLI.
//
// Two operator actions live here and nowhere else: provisioning the first
// customer owner, and transferring that ownership to a second account. Neither
// is exposed as an Edge Function, an HTTP route, an MCP tool or any other
// agent-callable surface, and both require the deployment's service-role
// credential plus an accountable principal — an unauthenticated caller cannot
// reach either path.
import { closeSync, existsSync, fchmodSync, fsyncSync, lstatSync, linkSync, openSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { parseArgs } from "node:util";
import { renameWithRetry } from "./lib/atomic-write.mjs";
import { DEFAULT_PUBLIC_KEYS_PATH, verifyLicenseFile } from "./license-verify.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const { values } = parseArgs({ options: { deployment: { type: "string", default: ".aidr-deploy" }, email: { type: "string" }, name: { type: "string" }, seats: { type: "string" }, "license-expires-at": { type: "string" }, "license-reference": { type: "string" }, "license-file": { type: "string" }, "license-public-keys": { type: "string" }, "allow-custom-license-keys": { type: "boolean", default: false }, "unsigned-license-for-pilot": { type: "boolean", default: false }, resume: { type: "boolean", default: false }, "transfer-owner": { type: "string" }, "requested-by": { type: "string" } } });
const dir = resolve(values.deployment);
const manifest = JSON.parse(readFileSync(join(dir, "deployment.json"), "utf8"));
if (manifest.mode !== "self-hosted") throw new Error("Deployment bootstrap is only supported for self-hosted installations");
const env = Object.fromEntries(readFileSync(join(dir, ".env"), "utf8").split(/\r?\n/).filter((line) => /^[A-Z][A-Z0-9_]*=/.test(line)).map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]));
const base = new URL(manifest.supabase_url);
if (base.protocol !== "https:" && !(manifest.development && ["localhost", "127.0.0.1"].includes(base.hostname))) throw new Error("HTTPS required");
if (!env.SERVICE_ROLE_KEY || env.SERVICE_ROLE_KEY.startsWith("REPLACE_")) throw new Error("Configure the selected project's credentials first");
const receiptPath = join(dir, "bootstrap-receipt.json");
const transferReceiptPath = join(dir, "owner-transfer-receipt.json");

async function request(path, body, method = "POST", extraHeaders = {}) {
  const response = await fetch(new URL(path, base), { method, headers: { apikey: env.ANON_KEY, Authorization: `Bearer ${env.SERVICE_ROLE_KEY}`, "Content-Type": "application/json", ...extraHeaders }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new Error(`Provisioning failed at ${path.split("?")[0]} (HTTP ${response.status}); review service logs, then resume. No credentials printed.`);
  return response.json();
}

function preserveWindowsAcl(source, destination) {
  const script = `
$ErrorActionPreference = 'Stop'
$source = [System.IO.FileInfo]::new([Environment]::GetEnvironmentVariable('AIDR_BOOTSTRAP_ACL_SOURCE'))
$destination = [System.IO.FileInfo]::new([Environment]::GetEnvironmentVariable('AIDR_BOOTSTRAP_ACL_DESTINATION'))
$sourceAcl = $source.GetAccessControl()
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($sourceAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $currentUser) { throw 'Receipt is not owned by the current user' }
$destination.SetAccessControl($sourceAcl)
$destinationAcl = $destination.GetAccessControl()
$expected = $sourceAcl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
$actual = $destinationAcl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
if ($expected -ne $actual) { throw 'Receipt ACL was not preserved' }
`;
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], {
    env: { ...process.env, AIDR_BOOTSTRAP_ACL_SOURCE: source, AIDR_BOOTSTRAP_ACL_DESTINATION: destination },
    encoding: "utf8",
    timeout: 30_000,
    windowsHide: true,
  });
  if (result.error || result.status !== 0) throw new Error("Could not preserve bootstrap receipt ACL; the existing receipt was not replaced");
}

function writePrivateReceipt(path, receipt, { createOnly = false } = {}) {
  let existing = null;
  try {
    existing = lstatSync(path);
    if (existing.isSymbolicLink() || !existing.isFile()) throw new Error("Bootstrap receipt must be a regular file");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (createOnly && existing) throw new Error("Receipt already exists");
  if (process.platform !== "win32" && existing && typeof process.getuid === "function" && existing.uid !== process.getuid()) {
    throw new Error("Bootstrap receipt is not owned by the current user");
  }

  const mode = process.platform === "win32" || !existing ? 0o600 : existing.mode & 0o777;
  if (process.platform !== "win32" && (mode & 0o077) !== 0) throw new Error("Receipt permissions are not private");
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  let descriptor;
  let temporaryExists = false;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    temporaryExists = true;
    writeFileSync(descriptor, JSON.stringify(receipt, null, 2), "utf8");
    if (process.platform !== "win32") fchmodSync(descriptor, mode);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;

    if (existing && process.platform === "win32") preserveWindowsAcl(path, temporary);
    if (createOnly) {
      // Linking is an atomic create-if-absent on the same filesystem; never
      // replace a receipt created by a concurrent invocation.
      linkSync(temporary, path);
      try { unlinkSync(temporary); } catch {}
    } else {
      // The sibling temp keeps the replacement on one filesystem. A failed
      // rename leaves the previous receipt in place on both POSIX and Windows.
      renameWithRetry(temporary, path);
    }
    temporaryExists = false;
  } catch (error) {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch {}
    }
    if (temporaryExists) {
      try { unlinkSync(temporary); } catch {}
    }
    throw error;
  }
}

/**
 * Read one line of operator confirmation from stdin. Confirmation is never
 * accepted from command arguments: an argument is visible in shell history and
 * process listings, and it would let the transfer be driven without an
 * accountable operator actually confirming it.
 */
async function readConfirmation(expected) {
  if (process.stdin.isTTY) throw new Error(`Owner transfer is an operator action: pipe the confirmation on stdin from your terminal or secret manager (for example: printf '%s\\n' "${expected}" | node scripts/deployment-bootstrap.mjs --transfer-owner ...). Do not put the confirmation in command arguments.`);
  const chunks = []; let size = 0;
  for await (const chunk of process.stdin) { size += chunk.length; if (size > 1024) throw new Error("Confirmation input too large"); chunks.push(chunk); }
  const confirmation = Buffer.concat(chunks).toString("utf8").trim().toLowerCase();
  if (confirmation !== expected.toLowerCase()) throw new Error("Confirmation must repeat the new owner's email address");
}

async function findAccountByEmail(email) {
  for (let page = 1; page <= 100; page++) {
    const result = await request(`/auth/v1/admin/users?page=${page}&per_page=100`, undefined, "GET");
    const user = result.users?.find((candidate) => candidate.email?.toLowerCase() === email);
    if (user) return user;
    if ((result.users?.length ?? 0) < 100) break;
  }
  return null;
}

function selectedRows(result) {
  return Array.isArray(result) ? result : [];
}

async function membershipRow(tenantId, userId) {
  const rows = selectedRows(await request(`/rest/v1/team_members?tenant_id=eq.${tenantId}&user_id=eq.${userId}&select=user_id,role`, undefined, "GET"));
  return rows[0] ?? null;
}

async function ownerRows(tenantId) {
  return selectedRows(await request(`/rest/v1/team_members?tenant_id=eq.${tenantId}&role=eq.owner&select=user_id,role`, undefined, "GET"));
}

/**
 * Transfer ownership recorded by a completed bootstrap to a second account.
 *
 * The path refuses to run without the current owner: the completed bootstrap
 * receipt must name the principal, `--requested-by` must be that principal, that
 * principal must still hold `owner` in the tenant, and the receipt written
 * afterwards records both principals. The second owner is added before the
 * bootstrap principal is demoted, so the tenant is never left ownerless, and an
 * interrupted run is resumable from its own `in_progress` receipt.
 */
async function transferOwnership() {
  const requestedBy = values["requested-by"]?.trim().toLowerCase();
  const newOwnerEmail = values["transfer-owner"]?.trim().toLowerCase();
  if (!newOwnerEmail || !EMAIL.test(newOwnerEmail)) throw new Error("--transfer-owner must be a valid email address");
  if (!requestedBy || !UUID.test(requestedBy)) throw new Error("--requested-by must identify the accountable operator (the current owner's user id)");

  const bootstrap = existsSync(receiptPath) ? JSON.parse(readFileSync(receiptPath, "utf8")) : null;
  const tenantId = bootstrap?.tenant_id;
  const previousOwnerId = bootstrap?.user_id;
  const previousOwnerEmail = bootstrap?.email;
  if (bootstrap?.state !== "complete" || !UUID.test(String(tenantId ?? "")) || !UUID.test(String(previousOwnerId ?? "")) || !previousOwnerEmail) {
    throw new Error("Owner transfer requires the completed bootstrap receipt that records the current owner; run the bootstrap first");
  }
  if (requestedBy !== previousOwnerId) throw new Error("--requested-by must be the current owner recorded by the bootstrap receipt; ownership is transferred by its holder");
  await readConfirmation(newOwnerEmail);

  let receipt = null;
  if (existsSync(transferReceiptPath)) {
    receipt = JSON.parse(readFileSync(transferReceiptPath, "utf8"));
    if (receipt?.state !== "in_progress") throw new Error("An owner-transfer receipt already exists; ownership is never transferred twice by this command. Review owner-transfer-receipt.json.");
    if (receipt.tenant_id !== tenantId || receipt.previous_owner?.user_id !== previousOwnerId) throw new Error("The in-progress owner-transfer receipt does not match this deployment's current owner");
    if (receipt.new_owner?.email?.toLowerCase() !== newOwnerEmail) throw new Error("The in-progress owner-transfer receipt names a different new owner");
    receipt.last_resume_attempted_at = new Date().toISOString();
    writePrivateReceipt(transferReceiptPath, receipt);
  }

  const target = await findAccountByEmail(newOwnerEmail);
  if (!target?.id || !UUID.test(String(target.id))) throw new Error("The new owner must already have a confirmed account in this project; create or confirm it first, then run the transfer again");
  if (target.id === previousOwnerId) throw new Error("The new owner is already the current owner");
  if (receipt && receipt.new_owner?.user_id !== target.id) throw new Error("The in-progress owner-transfer receipt names a different new owner");

  const previousMembership = await membershipRow(tenantId, previousOwnerId);
  // A recorded `in_progress` receipt plus an already-demoted principal is an
  // interrupted run: the mutations are finished, only the receipt is open.
  const resuming = receipt !== null && previousMembership?.role === "admin";
  if (!resuming && previousMembership?.role !== "owner") throw new Error("The bootstrap principal is not the tenant's current owner; no transfer was performed");
  if (!resuming) {
    const owners = await ownerRows(tenantId);
    if (owners.length !== 1 || owners[0]?.user_id !== previousOwnerId) throw new Error("The tenant does not have exactly one owner; resolve the membership state before transferring ownership");
  }

  if (!receipt) {
    receipt = {
      bootstrap_id: bootstrap.bootstrap_id,
      tenant_id: tenantId,
      supabase_url: base.origin,
      state: "in_progress",
      started_at: new Date().toISOString(),
      authorized_by: requestedBy,
      previous_owner: { user_id: previousOwnerId, email: previousOwnerEmail, role_before: "owner", role_after: "admin" },
      new_owner: { user_id: target.id, email: newOwnerEmail, role: "owner" },
    };
    writePrivateReceipt(transferReceiptPath, receipt, { createOnly: true });
  }

  if (!resuming) {
    const added = selectedRows(await request("/rest/v1/team_members?on_conflict=team_id,user_id", { team_id: tenantId, tenant_id: tenantId, user_id: target.id, role: "owner" }, "POST", { Prefer: "resolution=merge-duplicates,return=representation" }));
    if (added.length !== 1 || added[0]?.user_id !== target.id || added[0]?.role !== "owner") throw new Error("The second owner membership was not confirmed; the transfer is incomplete");
    const ownersAfterAdd = await ownerRows(tenantId);
    if (ownersAfterAdd.length !== 2 || !ownersAfterAdd.some((row) => row.user_id === target.id) || !ownersAfterAdd.some((row) => row.user_id === previousOwnerId)) throw new Error("The tenant does not have two owners after the transfer step; the transfer is incomplete");

    const demoted = selectedRows(await request(`/rest/v1/team_members?tenant_id=eq.${tenantId}&user_id=eq.${previousOwnerId}&role=eq.owner`, { role: "admin" }, "PATCH", { Prefer: "return=representation" }));
    if (demoted.length !== 1 || demoted[0]?.role !== "admin") {
      // A conditional update matches nothing once the row is already demoted, so
      // the final membership - not the response - decides whether this is safe.
      const after = await membershipRow(tenantId, previousOwnerId);
      if (after?.role !== "admin") throw new Error("The previous owner was not demoted; the transfer is incomplete");
    }
  }

  const finalOwners = await ownerRows(tenantId);
  if (finalOwners.length !== 1 || finalOwners[0]?.user_id !== target.id) throw new Error("Ownership verification failed; the transfer is incomplete");
  const previousFinal = await membershipRow(tenantId, previousOwnerId);
  if (previousFinal?.role !== "admin") throw new Error("The previous owner's demotion was not confirmed; the transfer is incomplete");

  receipt.state = "complete";
  receipt.completed_at = new Date().toISOString();
  writePrivateReceipt(transferReceiptPath, receipt);
  console.log(`Ownership transferred from ${previousOwnerEmail} to ${newOwnerEmail} (tenant ${tenantId}). Private receipt saved; no password or token was printed.`);
}

/**
 * Resolve the licensed terms (seats, admission end, reference) before any API call.
 *
 * Production installs pass the vendor-signed `--license-file`; its seats, expiry
 * and license id become the admission terms and cannot be overridden by typed
 * flags. The database admission ends at `expires_at + grace_days`: after that,
 * managed features (seat admission, enrollment, managed delivery) stop, while
 * local detection on endpoints keeps enforcing. Typed terms remain only for a
 * pilot, behind `--unsigned-license-for-pilot`, and the receipt records them as
 * unsigned.
 */
function resolveLicenseTerms() {
  const typed = ["seats", "license-expires-at", "license-reference"].filter((flag) => values[flag] !== undefined).map((flag) => `--${flag}`);
  if (values["license-file"] !== undefined) {
    if (typed.length || values["unsigned-license-for-pilot"]) {
      throw new Error(`--license-file derives seats, expiry and reference from the signed license; remove ${[...typed, ...(values["unsigned-license-for-pilot"] ? ["--unsigned-license-for-pilot"] : [])].join(", ")}`);
    }
    const publicKeysPath = resolve(values["license-public-keys"] ?? DEFAULT_PUBLIC_KEYS_PATH);
    const trustRoot = publicKeysPath === resolve(DEFAULT_PUBLIC_KEYS_PATH) ? "shipped" : "override";
    // A registry override replaces the vendor trust root: whoever writes that
    // file can sign any seat count. Require an explicit acknowledgement and keep
    // the evidence (path, digest, warning) in the receipt.
    if (trustRoot === "override" && !values["allow-custom-license-keys"]) {
      throw new Error(`--license-public-keys replaces the vendor-published license trust root (${DEFAULT_PUBLIC_KEYS_PATH}); pass --allow-custom-license-keys to accept a custom registry. The receipt records the override.`);
    }
    if (trustRoot === "shipped" && values["allow-custom-license-keys"]) {
      throw new Error("--allow-custom-license-keys only applies together with a custom --license-public-keys registry");
    }
    let publicKeysSha256;
    try {
      publicKeysSha256 = createHash("sha256").update(readFileSync(publicKeysPath)).digest("hex");
    } catch {
      throw new Error(`License verification failed: license public-key registry ${publicKeysPath} is not readable`);
    }
    const trustRootWarning = trustRoot === "override"
      ? `License verified against the custom registry ${publicKeysPath} (sha256 ${publicKeysSha256}), not the shipped deploy/onprem/license-public-keys.json; the operator accepted it with --allow-custom-license-keys.`
      : null;
    let verified;
    try {
      verified = verifyLicenseFile(values["license-file"], { publicKeysPath });
    } catch (error) {
      throw new Error(`License verification failed: ${error.message}`);
    }
    const terms = verified.payload;
    if (verified.status === "not_yet_valid") throw new Error(`License ${terms.license_id} is not valid before ${terms.not_before}; bootstrap refused`);
    if (verified.status === "expired") throw new Error(`License ${terms.license_id} expired at ${terms.expires_at} and its grace period ended at ${verified.grace_ends_at}; obtain a renewed license`);
    if (verified.status === "grace") console.error(`WARNING: license ${terms.license_id} expired at ${terms.expires_at}; managed features stop at ${verified.grace_ends_at}. Local detection is not affected.`);
    if (trustRoot === "override") console.error(`WARNING: ${trustRootWarning} The receipt records this override.`);
    return {
      seats: terms.seats,
      admissionExpiresAtMs: Date.parse(verified.grace_ends_at),
      licenseReference: terms.license_id,
      defaultName: terms.customer,
      license: {
        source: "signed",
        license_id: terms.license_id,
        key_id: verified.key_id,
        customer: terms.customer,
        plan_id: terms.plan_id,
        features: terms.features,
        deployment: terms.deployment,
        seats: terms.seats,
        not_before: terms.not_before,
        expires_at: terms.expires_at,
        grace_days: terms.grace_days,
        managed_until: verified.grace_ends_at,
        document_sha256: verified.document_sha256,
        key_status: verified.key_status,
        trust_root: trustRoot,
        public_keys_sha256: publicKeysSha256,
        ...(trustRoot === "override" ? { public_keys_path: publicKeysPath, trust_root_warning: trustRootWarning } : {}),
      },
    };
  }
  if (values["license-public-keys"] !== undefined || values["allow-custom-license-keys"]) {
    throw new Error("--license-public-keys and --allow-custom-license-keys only apply together with --license-file");
  }
  if (!values["unsigned-license-for-pilot"]) {
    throw new Error("A vendor-signed --license-file is required. Typed --seats, --license-expires-at and --license-reference are accepted only for a pilot together with --unsigned-license-for-pilot");
  }
  const seats = Number(values.seats ?? "1");
  const admissionExpiresAtMs = Date.parse(values["license-expires-at"] ?? "");
  const licenseReference = values["license-reference"]?.trim() ?? "";
  if (!Number.isInteger(seats) || seats < 1 || seats > 100000) throw new Error("--seats must be 1..100000");
  if (!Number.isFinite(admissionExpiresAtMs) || admissionExpiresAtMs <= Date.now()
    || !licenseReference || licenseReference.length > 200 || /[\x00-\x1f\x7f]/.test(licenseReference)) {
    throw new Error("A future --license-expires-at and a 1..200 character --license-reference from the signed customer contract are required");
  }
  console.error([
    "",
    "!!! WARNING: UNSIGNED PILOT LICENSE !!!",
    "Seats, expiry and reference were typed on the command line and are NOT backed by a vendor-signed license.",
    "This is accepted only for a time-boxed pilot. Production and air-gapped installs must use --license-file.",
    "The bootstrap receipt records license.source = \"unsigned-pilot\".",
    "",
  ].join("\n"));
  return { seats, admissionExpiresAtMs, licenseReference, defaultName: undefined, license: { source: "unsigned-pilot" } };
}

async function bootstrap() {
const email = values.email?.trim().toLowerCase();
if (!email || !EMAIL.test(email)) throw new Error("Valid --email required");
const terms = resolveLicenseTerms();
const name = values.name?.trim() || terms.defaultName;
const seats = terms.seats;
if (!name || name.length > 120) throw new Error("Valid --name (1..120 characters) required");
const licenseReference = terms.licenseReference;
const licenseExpiresAt = new Date(terms.admissionExpiresAtMs).toISOString();
let receipt;
const receiptExists = existsSync(receiptPath);
if (receiptExists) {
  if (!values.resume) throw new Error("Bootstrap receipt exists. Use --resume with identical parameters; existing passwords are never reset.");
  receipt = JSON.parse(readFileSync(receiptPath, "utf8"));
  if (receipt.email !== email || receipt.name !== name || receipt.seats !== seats || receipt.supabase_url !== base.origin) throw new Error("Bootstrap resume parameters do not match");
  if ((receipt.license_expires_at && receipt.license_expires_at !== licenseExpiresAt)
    || (receipt.license_reference && receipt.license_reference !== licenseReference)
    || (receipt.license?.source && receipt.license.source !== terms.license.source)
    || (receipt.license?.document_sha256 && receipt.license.document_sha256 !== terms.license.document_sha256)) throw new Error("Bootstrap license terms do not match the saved receipt");
  receipt.license_expires_at = licenseExpiresAt;
  receipt.license_reference = licenseReference;
  receipt.license = terms.license;
} else {
  if (values.resume) throw new Error("No bootstrap receipt to resume");
  receipt = { bootstrap_id: randomUUID(), email, name, seats, license_expires_at: licenseExpiresAt, license_reference: licenseReference, license: terms.license, supabase_url: base.origin, state: "reserved" };
}
// Read and validate the only remaining operator input before recording a new
// receipt or making any API request. This keeps bad/empty passwords from
// partially configuring admission or stranding an unusable bootstrap receipt.
let password;
if (!receipt.user_id) {
  if (process.stdin.isTTY) throw new Error("Supply a 16..128 character password on stdin from your secret manager or a hidden prompt. Do not put passwords in command arguments.");
  const chunks = []; let size = 0;
  for await (const chunk of process.stdin) { size += chunk.length; if (size > 1024) throw new Error("Password input too large"); chunks.push(chunk); }
  password = Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
  if (password.length < 16 || password.length > 128 || /[\r\n\0]/.test(password)) throw new Error("Password must be 16..128 characters on one line");
}
writePrivateReceipt(receiptPath, receipt, { createOnly: !receiptExists });
const save = () => writePrivateReceipt(receiptPath, receipt);
await request("/rest/v1/rpc/configure_tenant_admission_mode", { p_mode: "onprem" });
if (values.resume && !receipt.user_id) {
  // Recover an interrupted successful account creation without changing accounts
  // that predate this operation. Bind to server-only app_metadata, never email alone.
  for (let page = 1; page <= 100; page++) {
    const result = await request(`/auth/v1/admin/users?page=${page}&per_page=100`, undefined, "GET");
    const user = result.users?.find((candidate) => candidate.email?.toLowerCase() === email && candidate.app_metadata?.aidr_bootstrap_id === receipt.bootstrap_id);
    if (user) { receipt.user_id = user.id; save(); break; }
    if ((result.users?.length ?? 0) < 100) break;
  }
}
if (!receipt.user_id) {
  const user = await request("/auth/v1/admin/users", { email, password, email_confirm: true, app_metadata: { aidr_bootstrap_id: receipt.bootstrap_id } });
  receipt.user_id = user.id; receipt.state = "account_created"; save();
}
const completed = await request("/rest/v1/rpc/bootstrap_customer", { p_user_id: receipt.user_id, p_bootstrap_id: receipt.bootstrap_id, p_name: name, p_seats: seats, p_license_expires_at: licenseExpiresAt, p_license_reference: licenseReference });
Object.assign(receipt, completed, { state: "complete", completed_at: new Date().toISOString() }); save();
console.log(`Customer owner and ${seats} agent seats provisioned (${terms.license.source === "signed" ? `license ${licenseReference}, managed features until ${licenseExpiresAt}` : "UNSIGNED pilot terms"}). Sign in at ${manifest.dashboard_url}/login. Private receipt saved; no password or token was printed.`);
}

if (values["transfer-owner"] !== undefined) await transferOwnership();
else await bootstrap();
