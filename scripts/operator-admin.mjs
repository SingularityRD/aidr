#!/usr/bin/env node
// Platform-operator CLI for the `operator-admin` Edge Function.
//
//   node scripts/operator-admin.mjs <command> [options]
//
// Commands
//   mode <cloud|onprem|pilot>                  Fix the deployment admission mode (one-way).
//   legal --terms-version V --terms-url URL (--terms-sha256 HEX | --terms-file PATH)
//         --privacy-version V --privacy-url URL (--privacy-sha256 HEX | --privacy-file PATH)
//         --approval-reference REF [--verify-remote]
//                                              Record the approved Terms and Privacy documents.
//   grant --tenant ID --plan PLAN --seats N --expires-at ISO --reference REF [--owner ID]
//                                              Grant licensed admission to a tenant.
//   revoke --tenant ID --reason TEXT           Revoke a tenant's licensed admission.
//   tenants [--limit N] [--after ID] [--all]   List tenants (minimal fields, keyset paged).
//   usage --tenant ID                          Aggregate usage for one tenant.
//
// Every command accepts --dry-run, which prints the request body and sends nothing.
//
// Credentials come only from the environment, never from arguments:
//   AIDR_SUPABASE_URL (or SUPABASE_URL)       Project URL, https (http only for localhost).
//   SUPABASE_ANON_KEY                         Project anon key, sent as `apikey`.
//   Either
//     AIDR_OPERATOR_ACCESS_TOKEN              An AAL2 (MFA-verified) Supabase access token,
//   or
//     AIDR_OPERATOR_EMAIL, AIDR_OPERATOR_PASSWORD and AIDR_OPERATOR_TOTP_CODE
//     [AIDR_OPERATOR_TOTP_FACTOR_ID]          Sign in and step up with a TOTP factor.
//
// The CLI never prints a credential. Output is the function's JSON response;
// the exit code is 0 on success, 1 when the service refuses or fails, and 2 on
// a usage or local validation error.
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

export const FUNCTION_PATH = "/functions/v1/operator-admin";
const REQUEST_TIMEOUT_MS = 30_000;
const MAX_LIST_PAGES = 1_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[a-f0-9]{64}$/i;
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export class UsageError extends Error {}

const OPTIONS = {
	"dry-run": { type: "boolean", default: false },
	"terms-version": { type: "string" },
	"terms-url": { type: "string" },
	"terms-sha256": { type: "string" },
	"terms-file": { type: "string" },
	"privacy-version": { type: "string" },
	"privacy-url": { type: "string" },
	"privacy-sha256": { type: "string" },
	"privacy-file": { type: "string" },
	"approval-reference": { type: "string" },
	"verify-remote": { type: "boolean", default: false },
	tenant: { type: "string" },
	plan: { type: "string" },
	seats: { type: "string" },
	"expires-at": { type: "string" },
	reference: { type: "string" },
	owner: { type: "string" },
	reason: { type: "string" },
	limit: { type: "string" },
	after: { type: "string" },
	all: { type: "boolean", default: false },
	help: { type: "boolean", short: "h", default: false },
};

function required(values, name) {
	const value = values[name];
	if (typeof value !== "string" || !value.trim()) throw new UsageError(`--${name} is required`);
	return value.trim();
}

function tenantId(values, name = "tenant") {
	const value = required(values, name);
	if (!UUID.test(value)) throw new UsageError(`--${name} must be a UUID`);
	return value.toLowerCase();
}

function integer(value, name) {
	if (!/^\d+$/.test(value)) throw new UsageError(`--${name} must be a positive integer`);
	return Number(value);
}

export function sha256Hex(bytes) {
	return createHash("sha256").update(bytes).digest("hex");
}

/**
 * Resolve one legal document's digest from --X-sha256 and/or --X-file. When
 * both are given they must agree, so a typo in either is caught locally.
 */
async function documentDigest(values, prefix, io) {
	const declared = values[`${prefix}-sha256`]?.trim();
	const file = values[`${prefix}-file`];
	if (declared !== undefined && !SHA256.test(declared)) {
		throw new UsageError(`--${prefix}-sha256 must be 64 hex characters`);
	}
	let computed;
	if (file) computed = sha256Hex(await io.readFile(resolve(file)));
	if (declared && computed && declared.toLowerCase() !== computed) {
		throw new UsageError(`--${prefix}-sha256 does not match --${prefix}-file`);
	}
	const digest = (declared ?? computed)?.toLowerCase();
	if (!digest) throw new UsageError(`--${prefix}-sha256 or --${prefix}-file is required`);
	return digest;
}

/** Build the JSON body for one command; throws UsageError on invalid input. */
export async function buildRequestBody(command, positionals, values, io = { readFile }) {
	switch (command) {
		case "mode": {
			const mode = positionals[0];
			if (!["cloud", "onprem", "pilot"].includes(mode)) {
				throw new UsageError("mode requires one of: cloud, onprem, pilot");
			}
			return { action: "configure_admission_mode", mode };
		}
		case "legal": {
			const document = async (prefix) => ({
				version: required(values, `${prefix}-version`),
				url: required(values, `${prefix}-url`),
				sha256: await documentDigest(values, prefix, io),
			});
			return {
				action: "configure_legal_documents",
				terms: await document("terms"),
				privacy: await document("privacy"),
				approval_reference: required(values, "approval-reference"),
			};
		}
		case "grant": {
			const expiresAt = required(values, "expires-at");
			if (!Number.isFinite(Date.parse(expiresAt))) throw new UsageError("--expires-at must be an ISO-8601 timestamp");
			const body = {
				action: "grant_license",
				tenant_id: tenantId(values),
				plan_id: required(values, "plan"),
				seats: integer(required(values, "seats"), "seats"),
				expires_at: new Date(Date.parse(expiresAt)).toISOString(),
				reference: required(values, "reference"),
			};
			if (values.owner !== undefined) body.owner_user_id = tenantId(values, "owner");
			return body;
		}
		case "revoke":
			return { action: "revoke_license", tenant_id: tenantId(values), reason: required(values, "reason") };
		case "tenants": {
			const body = { action: "list_tenants" };
			if (values.limit !== undefined) body.limit = integer(values.limit, "limit");
			if (values.after !== undefined) body.after = tenantId(values, "after");
			return body;
		}
		case "usage":
			return { action: "tenant_usage", tenant_id: tenantId(values) };
		default:
			throw new UsageError(`unknown command: ${command ?? "(none)"}`);
	}
}

/** Project base URL from the environment; https is mandatory except on localhost. */
export function resolveProjectUrl(env) {
	const raw = env.AIDR_SUPABASE_URL || env.SUPABASE_URL;
	if (!raw) throw new UsageError("AIDR_SUPABASE_URL (or SUPABASE_URL) is required");
	let url;
	try {
		url = new URL(raw);
	} catch {
		throw new UsageError("AIDR_SUPABASE_URL is not a valid URL");
	}
	if (url.username || url.password) throw new UsageError("AIDR_SUPABASE_URL must not embed credentials");
	if (url.protocol !== "https:" && !(url.protocol === "http:" && LOCAL_HOSTS.has(url.hostname))) {
		throw new UsageError("AIDR_SUPABASE_URL must use https (http is allowed only for localhost)");
	}
	url.search = "";
	url.hash = "";
	return url;
}

function endpoint(base, path) {
	// A project URL may carry a path prefix (a self-hosted gateway); keep it.
	return new URL(`${base.pathname.replace(/\/+$/, "")}${path}`, base.origin);
}

async function postJson(fetchImpl, url, body, headers) {
	const response = await fetchImpl(url, {
		method: "POST",
		headers: { "Content-Type": "application/json", ...headers },
		body: JSON.stringify(body ?? {}),
		signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
	});
	let payload = null;
	try {
		payload = await response.json();
	} catch {
		payload = null;
	}
	return { status: response.status, ok: response.ok, payload };
}

/**
 * Obtain an AAL2 access token. A supplied token is used as-is (the function
 * enforces AAL2); otherwise the password grant is stepped up with TOTP.
 */
export async function obtainAccessToken(env, base, fetchImpl) {
	if (env.AIDR_OPERATOR_ACCESS_TOKEN) return env.AIDR_OPERATOR_ACCESS_TOKEN;
	const email = env.AIDR_OPERATOR_EMAIL;
	const password = env.AIDR_OPERATOR_PASSWORD;
	const code = env.AIDR_OPERATOR_TOTP_CODE;
	const anonKey = env.SUPABASE_ANON_KEY;
	if (!email || !password || !code) {
		throw new UsageError(
			"set AIDR_OPERATOR_ACCESS_TOKEN, or AIDR_OPERATOR_EMAIL + AIDR_OPERATOR_PASSWORD + AIDR_OPERATOR_TOTP_CODE",
		);
	}
	if (!anonKey) throw new UsageError("SUPABASE_ANON_KEY is required to sign in");
	if (!/^\d{6}$/.test(code)) throw new UsageError("AIDR_OPERATOR_TOTP_CODE must be a 6-digit code");

	const signIn = await postJson(fetchImpl, endpoint(base, "/auth/v1/token?grant_type=password"),
		{ email, password }, { apikey: anonKey });
	const aal1 = signIn.payload?.access_token;
	if (!signIn.ok || typeof aal1 !== "string") throw new Error(`sign-in failed (HTTP ${signIn.status})`);
	const bearer = { apikey: anonKey, Authorization: `Bearer ${aal1}` };

	let factorId = env.AIDR_OPERATOR_TOTP_FACTOR_ID;
	if (!factorId) {
		const factors = (signIn.payload?.user?.factors ?? [])
			.filter((factor) => factor?.factor_type === "totp" && factor?.status === "verified");
		if (factors.length !== 1) {
			throw new UsageError(
				factors.length === 0
					? "the operator account has no verified TOTP factor"
					: "several TOTP factors are verified; set AIDR_OPERATOR_TOTP_FACTOR_ID",
			);
		}
		factorId = factors[0].id;
	}
	if (typeof factorId !== "string" || !UUID.test(factorId)) throw new UsageError("invalid TOTP factor id");

	const challenge = await postJson(fetchImpl, endpoint(base, `/auth/v1/factors/${factorId}/challenge`), {}, bearer);
	const challengeId = challenge.payload?.id;
	if (!challenge.ok || typeof challengeId !== "string") throw new Error(`MFA challenge failed (HTTP ${challenge.status})`);
	const verify = await postJson(fetchImpl, endpoint(base, `/auth/v1/factors/${factorId}/verify`),
		{ challenge_id: challengeId, code }, bearer);
	const aal2 = verify.payload?.access_token;
	if (!verify.ok || typeof aal2 !== "string") throw new Error(`MFA verification failed (HTTP ${verify.status})`);
	return aal2;
}

/** Fetch each legal document and require its bytes to match the declared digest. */
export async function verifyRemoteDocuments(body, fetchImpl) {
	for (const key of ["terms", "privacy"]) {
		const document = body[key];
		const response = await fetchImpl(document.url, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
		if (!response.ok) throw new UsageError(`${key} document fetch failed (HTTP ${response.status})`);
		const digest = sha256Hex(Buffer.from(await response.arrayBuffer()));
		if (digest !== document.sha256) {
			throw new UsageError(`${key} document at ${document.url} does not match the declared sha256`);
		}
	}
}

export async function invokeOperatorAdmin(base, token, anonKey, body, fetchImpl) {
	const headers = { Authorization: `Bearer ${token}` };
	if (anonKey) headers.apikey = anonKey;
	return postJson(fetchImpl, endpoint(base, FUNCTION_PATH), body, headers);
}

const USAGE = `Usage: node scripts/operator-admin.mjs <mode|legal|grant|revoke|tenants|usage> [options]
See docs/operations/operator-admin.md for every option and the credential environment.`;

export async function run(argv, io = {}) {
	const env = io.env ?? process.env;
	const fetchImpl = io.fetch ?? globalThis.fetch;
	const out = io.stdout ?? ((line) => process.stdout.write(`${line}\n`));
	const err = io.stderr ?? ((line) => process.stderr.write(`${line}\n`));
	try {
		const { values, positionals } = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true });
		if (values.help || positionals.length === 0) {
			out(USAGE);
			return values.help ? 0 : 2;
		}
		const [command, ...rest] = positionals;
		if (values.all && command !== "tenants") throw new UsageError("--all applies only to tenants");
		const body = await buildRequestBody(command, rest, values, { readFile: io.readFile ?? readFile });
		if (values["dry-run"]) {
			out(JSON.stringify(body, null, 2));
			return 0;
		}
		const base = resolveProjectUrl(env);
		if (command === "legal" && values["verify-remote"]) await verifyRemoteDocuments(body, fetchImpl);
		const token = await obtainAccessToken(env, base, fetchImpl);

		if (command === "tenants" && values.all) {
			const tenants = [];
			let after = body.after ?? null;
			for (let page = 0; page < MAX_LIST_PAGES; page += 1) {
				const response = await invokeOperatorAdmin(base, token, env.SUPABASE_ANON_KEY,
					{ ...body, ...(after ? { after } : {}) }, fetchImpl);
				if (!response.ok) {
					out(JSON.stringify(response.payload ?? { error: `http_${response.status}` }, null, 2));
					return 1;
				}
				tenants.push(...(response.payload?.result?.tenants ?? []));
				after = response.payload?.result?.next_cursor ?? null;
				if (!after) {
					out(JSON.stringify({ ok: true, action: "list_tenants", result: { tenants, next_cursor: null } }, null, 2));
					return 0;
				}
			}
			throw new Error(`tenant listing exceeded ${MAX_LIST_PAGES} pages`);
		}

		const response = await invokeOperatorAdmin(base, token, env.SUPABASE_ANON_KEY, body, fetchImpl);
		out(JSON.stringify(response.payload ?? { error: `http_${response.status}` }, null, 2));
		return response.ok ? 0 : 1;
	} catch (error) {
		const usageFailure = error instanceof UsageError || error?.code?.startsWith?.("ERR_PARSE_ARGS");
		err(`operator-admin: ${error instanceof Error ? error.message : String(error)}`);
		return usageFailure ? 2 : 1;
	}
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	process.exitCode = await run(process.argv.slice(2));
}
