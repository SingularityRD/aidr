#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash, createHmac, randomUUID } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const PURPOSE = "aidr.saml.outage-recovery.v1";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX = /^[0-9a-f]{64}$/;
const PAYLOAD_FIELDS = ["purpose", "schema_version", "nonce", "tenant_id", "current_provider_id", "recovery_owner_id", "new_provider_id", "change_ref", "reason", "issued_at", "expires_at"];
const RECEIPT_FIELDS = ["tenant_id", "operator_id", "key_id", "payload_sha256", "mac_hex"];

function exactFields(value, fields, label) {
	if (!value || typeof value !== "object" || Array.isArray(value) ||
		Object.keys(value).length !== fields.length || fields.some((field) => !Object.hasOwn(value, field))) {
		throw new Error(`${label} has unexpected or missing fields`);
	}
}

function uuid(value, label) {
	if (typeof value !== "string" || !UUID.test(value)) throw new Error(`${label} must be a canonical lowercase UUID`);
	return value;
}

function boundedText(value, label, minimum, maximum) {
	if (typeof value !== "string" || value !== value.trim() || /[\u0000-\u001f\u007f-\u009f\ud800-\udfff]/u.test(value) ||
		[...value].length < minimum || [...value].length > maximum) {
		throw new Error(`${label} must be trimmed text of ${minimum} to ${maximum} characters without controls`);
	}
	return value;
}

function parseJson(text, label) {
	try { return JSON.parse(text); } catch { throw new Error(`${label} must contain valid JSON`); }
}

export function validatePayload(text, now = Math.floor(Date.now() / 1000)) {
	if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > 4096) throw new Error("Payload must contain at most 4096 UTF-8 bytes");
	const payload = parseJson(text, "Payload");
	exactFields(payload, PAYLOAD_FIELDS, "Payload");
	if (payload.purpose !== PURPOSE || payload.schema_version !== 1 || payload.new_provider_id !== null) {
		throw new Error("Payload purpose, version or recovery action is unsupported");
	}
	for (const field of ["nonce", "tenant_id", "current_provider_id", "recovery_owner_id"]) uuid(payload[field], field);
	boundedText(payload.change_ref, "change_ref", 1, 200);
	boundedText(payload.reason, "reason", 12, 500);
	if (!Number.isSafeInteger(payload.issued_at) || !Number.isSafeInteger(payload.expires_at) || payload.issued_at < 0 ||
		payload.expires_at <= payload.issued_at || payload.expires_at > payload.issued_at + 300 || payload.issued_at > now || payload.expires_at <= now) {
		throw new Error("Payload must be currently valid and expire within five minutes of issuance");
	}
	// Sign and submit exactly the reviewed bytes; reject whitespace, duplicate keys
	// and reordering rather than silently canonicalizing a changed file.
	const canonical = Object.fromEntries(PAYLOAD_FIELDS.map((field) => [field, payload[field]]));
	if (JSON.stringify(canonical) !== text) throw new Error("Payload bytes differ from the deterministic prepare output");
	return payload;
}

export function preparePayload(input, issuedAt = Math.floor(Date.now() / 1000)) {
	const payload = JSON.stringify({
		purpose: PURPOSE, schema_version: 1, nonce: input.nonce ?? randomUUID(),
		tenant_id: input.tenant_id?.toLowerCase(), current_provider_id: input.current_provider_id?.toLowerCase(),
		recovery_owner_id: input.recovery_owner_id?.toLowerCase(), new_provider_id: null,
		change_ref: input.change_ref, reason: input.reason, issued_at: issuedAt, expires_at: issuedAt + 300,
	});
	validatePayload(payload, issuedAt);
	return payload;
}

export function signPayload(text, key, now = Math.floor(Date.now() / 1000)) {
	const payload = validatePayload(text, now);
	exactFields(key, ["key_id", "tenant_id", "operator_id", "secret_hex"], "Custody key");
	for (const field of ["key_id", "tenant_id", "operator_id"]) uuid(key[field], field);
	if (key.tenant_id !== payload.tenant_id) throw new Error("Custody key belongs to another tenant");
	if (typeof key.secret_hex !== "string" || !HEX.test(key.secret_hex)) throw new Error("Custody key secret must be 32 bytes encoded as lowercase hex");
	return {
		tenant_id: key.tenant_id, operator_id: key.operator_id, key_id: key.key_id,
		payload_sha256: createHash("sha256").update(text, "utf8").digest("hex"),
		mac_hex: createHmac("sha256", Buffer.from(key.secret_hex, "hex")).update(text, "utf8").digest("hex"),
	};
}

export function prepareApprovals(text, receipts, now = Math.floor(Date.now() / 1000)) {
	const payload = validatePayload(text, now);
	if (!Array.isArray(receipts) || receipts.length !== 2) throw new Error("Exactly two independent approval receipts are required");
	const digest = createHash("sha256").update(text, "utf8").digest("hex");
	for (const receipt of receipts) {
		exactFields(receipt, RECEIPT_FIELDS, "Approval receipt");
		for (const field of ["tenant_id", "operator_id", "key_id"]) uuid(receipt[field], field);
		if (receipt.tenant_id !== payload.tenant_id || receipt.payload_sha256 !== digest) throw new Error("Approval receipt does not bind the reviewed payload");
		if (typeof receipt.mac_hex !== "string" || !HEX.test(receipt.mac_hex)) throw new Error("Approval MAC must be lowercase SHA-256 hex");
	}
	if (receipts[0].key_id === receipts[1].key_id || receipts[0].operator_id === receipts[1].operator_id) {
		throw new Error("Approvals must use distinct keys held by distinct operators");
	}
	// Only the database can authenticate MACs and enrolled operator identities.
	return receipts.map(({ key_id, mac_hex }) => ({ key_id, mac_hex }));
}

// Match the repository's private-file boundary: never accept inherited Windows
// read access as private merely because Node reports mode 0600.
const WINDOWS_PRIVATE_KEY_CHECK = `
$ErrorActionPreference = 'Stop'
$item = [System.IO.FileInfo]::new([Environment]::GetEnvironmentVariable('AIDR_SAML_CUSTODY_FILE'))
$acl = $item.GetAccessControl()
$owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $owner.Value) { throw 'Wrong owner' }
foreach ($entry in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
  if ($entry.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
      $entry.IdentityReference.Value -notin @($owner.Value, 'S-1-5-18', 'S-1-5-32-544')) { throw 'Non-private access' }
}
`;

export function readCustodyKey(path) {
	const absolute = resolve(path);
	const before = lstatSync(absolute);
	if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) throw new Error("Custody key must be a regular file without links");
	const handle = openSync(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
	try {
		const opened = fstatSync(handle);
		if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.nlink !== 1 || opened.size > 4096) {
			throw new Error("Custody key changed or exceeds the file size limit");
		}
		if (process.platform === "win32") {
			try {
				execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(WINDOWS_PRIVATE_KEY_CHECK, "utf16le").toString("base64")], {
					stdio: "ignore", windowsHide: true, timeout: 30_000, env: { ...process.env, AIDR_SAML_CUSTODY_FILE: absolute },
				});
			} catch { throw new Error("Custody key Windows ACL must allow only its owner, SYSTEM and Administrators"); }
		} else if (opened.uid !== process.getuid() || ![0o600, 0o400].includes(opened.mode & 0o777)) {
			throw new Error("Custody key must be owned by the current user with mode 0600 or 0400");
		}
		const after = lstatSync(absolute);
		if (after.isSymbolicLink() || after.dev !== opened.dev || after.ino !== opened.ino) throw new Error("Custody key changed during permission check");
		return parseJson(readFileSync(handle, "utf8"), "Custody key");
	} finally { closeSync(handle); }
}

function readPayload(path) {
	const bytes = readFileSync(path);
	if (bytes.length > 4096) throw new Error("Payload exceeds the file size limit");
	try { return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); }
	catch { throw new Error("Payload must be valid UTF-8"); }
}

export async function applyRecovery({ payload, receipts, supabaseUrl, serviceKey, development = false }, now = Math.floor(Date.now() / 1000)) {
	const approvals = prepareApprovals(payload, receipts, now);
	let endpoint;
	try { endpoint = new URL(supabaseUrl); } catch { throw new Error("An explicit Supabase HTTPS origin is required"); }
	if (endpoint.username || endpoint.password || endpoint.pathname !== "/" || endpoint.search || endpoint.hash ||
		(endpoint.protocol !== "https:" && !(development && endpoint.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(endpoint.hostname)))) {
		throw new Error("Supabase must be an HTTPS origin; explicit development permits only loopback HTTP");
	}
	if (typeof serviceKey !== "string" || !serviceKey || serviceKey !== serviceKey.trim() || /[\u0000-\u0020\u007f]/.test(serviceKey)) {
		throw new Error("SERVICE_ROLE_KEY environment credential is missing or malformed");
	}
	let response;
	try {
		response = await fetch(new URL("/rest/v1/rpc/recover_tenant_saml_outage", endpoint), {
			method: "POST", redirect: "error", signal: AbortSignal.timeout(30_000),
			headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, "Content-Type": "application/json" },
			body: JSON.stringify({ p_payload: payload, p_approvals: approvals }),
		});
	} catch { throw new Error("SAML recovery request did not return a response; reconcile the nonce before preparing another request"); }
	let result;
	try { result = await response.json(); } catch { throw new Error(`SAML recovery endpoint returned invalid JSON (${response.status}); reconcile the nonce`); }
	if (!response.ok) {
		const code = typeof result?.code === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(result.code) ? ` ${result.code}` : "";
		throw new Error(`SAML recovery rejected (${response.status}${code})`);
	}
	const reviewed = validatePayload(payload, now);
	try {
		exactFields(result, ["status", "method", "nonce", "tenant_id", "recovery_owner_id", "old_provider_id", "new_provider_id", "change_ref", "operator_ids", "audit_log_id", "applied_at"], "Recovery result");
	} catch { throw new Error("Recovery result has unexpected or missing fields; reconcile the nonce"); }
	if (result.status !== "recovered" || result.method !== "dual_operator_hmac" ||
		result.nonce !== reviewed.nonce || result.tenant_id !== reviewed.tenant_id ||
		result.recovery_owner_id !== reviewed.recovery_owner_id || result.old_provider_id !== reviewed.current_provider_id ||
		result.new_provider_id !== null || result.change_ref !== reviewed.change_ref ||
		!Array.isArray(result.operator_ids) || result.operator_ids.length !== 2 || new Set(result.operator_ids).size !== 2 ||
		receipts.some((receipt) => !result.operator_ids.includes(receipt.operator_id)) ||
		typeof result.audit_log_id !== "string" || !/^[1-9][0-9]{0,39}$/.test(result.audit_log_id) ||
		typeof result.applied_at !== "string" || !Number.isFinite(Date.parse(result.applied_at)) ||
		Date.parse(result.applied_at) < reviewed.issued_at * 1000 || Date.parse(result.applied_at) >= reviewed.expires_at * 1000) {
		throw new Error("SAML recovery response does not bind the reviewed request and independent operators; reconcile the nonce");
	}
	return result;
}

async function main() {
	const { values, positionals } = parseArgs({ allowPositionals: true, options: {
		tenant: { type: "string" }, "current-provider": { type: "string" }, "recovery-owner": { type: "string" },
		"change-ref": { type: "string" }, reason: { type: "string" }, out: { type: "string" },
		payload: { type: "string" }, "key-file": { type: "string" }, approval: { type: "string", multiple: true },
		"supabase-url": { type: "string" }, development: { type: "boolean" },
	} });
	const command = positionals[0];
	const allowed = {
		prepare: ["tenant", "current-provider", "recovery-owner", "change-ref", "reason", "out"],
		sign: ["payload", "key-file", "out"], apply: ["payload", "approval", "supabase-url", "development"],
	};
	if (positionals.length !== 1 || !allowed[command] || Object.keys(values).some((key) => !allowed[command].includes(key))) {
		throw new Error("Use prepare, sign or apply with the options documented in docs/operations/saml-outage-recovery.md");
	}
	if (command === "prepare") {
		if (!values.out) throw new Error("prepare requires --out");
		const text = preparePayload({ tenant_id: values.tenant, current_provider_id: values["current-provider"], recovery_owner_id: values["recovery-owner"], change_ref: values["change-ref"], reason: values.reason });
		writeFileSync(values.out, text, { flag: "wx", mode: 0o600 });
		console.log("Recovery payload prepared. Both operators must review this exact file before signing.");
	} else if (command === "sign") {
		if (!values.payload || !values["key-file"] || !values.out) throw new Error("sign requires --payload, --key-file and --out");
		const receipt = signPayload(readPayload(values.payload), readCustodyKey(values["key-file"]));
		writeFileSync(values.out, `${JSON.stringify(receipt, null, 2)}\n`, { flag: "wx", mode: 0o600 });
		console.log("Approval receipt written. Keep the custody key with its operator.");
	} else {
		if (!values.payload || !values["supabase-url"] || values.approval?.length !== 2) throw new Error("apply requires --payload, exactly two --approval files and --supabase-url");
		const result = await applyRecovery({ payload: readPayload(values.payload), receipts: values.approval.map((file) => parseJson(readFileSync(file, "utf8"), "Approval receipt")), supabaseUrl: values["supabase-url"], serviceKey: process.env.SERVICE_ROLE_KEY, development: values.development });
		console.log(JSON.stringify(result));
	}
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	main().catch((error) => { console.error(error instanceof Error ? error.message : "SAML recovery failed"); process.exitCode = 1; });
}
