// Managed-mode dashboard approvals (docs/contracts/dashboard-approvals.md).
//
// Connector (tenant API key, scope `tenant` only; ingest-only keys refused):
//   POST /approval-requests                     file a pending approval for an
//        { iid, agent_runtime, action_id, artifact_digest, tool, threat_ids,
//          summary, expires_at }                ask verdict; idempotent on
//                                               (tenant, iid, action_id)
//        -> 201 { request_id, status, created }
//   GET  /approval-requests/{request_id}        poll
//        -> 200 { request_id, status, token?, key_id?, token_expires_at? }
//
// Dashboard (Supabase session; owner/admin; identity barrier; AAL2):
//   POST /approval-requests/{request_id}/decision   { decision, reason }
//   POST /approval-requests  { action: "decide", request_id, tenant_id, decision, reason }
//        -> 200 { ok, request_id, status, decided_at, key_id, token_expires_at }
//   POST /approval-requests  { action: "rotate_key", tenant_id }
//        -> 200 { ok, key_id, retired_key_id }
//
// The decision signs an Ed25519 token with the tenant approval signing key
// (sealed at rest, see _shared/approval-token.ts); the RPC re-checks role,
// request state and active key under row locks, refuses a token whose payload
// does not bind this exact request, and writes the audit rows. The agent never
// sees an approval surface: filing is done by the connector process, deciding
// by a human in the dashboard. Every failure is closed.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { authenticateTenantApiKey } from "../_shared/api-key-auth.ts";
import {
	APPROVAL_REQUEST_MAX_TTL_MS,
	APPROVAL_TOKEN_TTL_MS,
	type ApprovalDecision,
	type ApprovalTokenPayload,
	generateSealedApprovalKey,
	newApprovalNonce,
	parseWrapSecret,
	signApprovalToken,
	unsealApprovalKey,
	verifyApprovalToken,
} from "../_shared/approval-token.ts";
import { getBearerToken } from "../_shared/auth.ts";
import { ConfigurationError, configFailure, type EnvReader, loadConfig } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

const WRAP_ENV = "AIDR_APPROVAL_SIGNING_WRAP_KEY_B64";
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "AIDR_APPROVAL_SIGNING_WRAP_KEY_B64"] as const;
const MAX_BODY_BYTES = 8192;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CONTROL = /\p{Cc}/u;
const ACTION_ID = /^[A-Za-z0-9._:-]{8,128}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const THREAT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const RUNTIME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$/;
/** A client clock slightly ahead of ours is clamped, not refused. */
const EXPIRY_SKEW_MS = 5 * 60_000;
export const REASON_MAX = 500;

const readRuntimeEnv: EnvReader = (name) => {
	try {
		const value = Deno.env.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Node contract tests use process.env when Deno is unavailable.
	}
	return globalThis.process?.env?.[name];
};

type DatabaseClient = ReturnType<typeof createClient>;

export interface ApprovalRequestsDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => DatabaseClient;
	now?: () => number;
}

export interface CreateCommand {
	iid: string;
	agentRuntime: string;
	actionId: string;
	artifactDigest: string;
	tool: string;
	threatIds: string[];
	summary: string;
	expiresAtMs: number;
}

export type DashboardCommand =
	| { action: "decide"; requestId: string; tenantId: string | null; decision: ApprovalDecision; reason: string }
	| { action: "rotate_key"; tenantId: string };

type Route =
	| { kind: "create" }
	| { kind: "poll"; requestId: string }
	| { kind: "decision"; requestId: string }
	| { kind: "unknown" };

type ParseResult<T> = { ok: true; value: T } | { ok: false; error: string };

type RpcError = { code?: string; message?: string } | null;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function onlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
	return Object.keys(value).every((key) => allowed.includes(key));
}

function boundedText(value: unknown, max: number, min = 1): string | null {
	if (typeof value !== "string" || CONTROL.test(value)) return null;
	return value.length >= min && value.length <= max ? value : null;
}

export function routeFor(req: Request): Route {
	const segments = new URL(req.url).pathname.split("/").filter(Boolean);
	const index = segments.lastIndexOf("approval-requests");
	const rest = index < 0 ? [] : segments.slice(index + 1);
	if (req.method === "POST" && rest.length === 0) return { kind: "create" };
	if (req.method === "GET" && rest.length === 1 && UUID.test(rest[0])) {
		return { kind: "poll", requestId: rest[0].toLowerCase() };
	}
	if (req.method === "POST" && rest.length === 2 && UUID.test(rest[0]) && rest[1] === "decision") {
		return { kind: "decision", requestId: rest[0].toLowerCase() };
	}
	return { kind: "unknown" };
}

export function parseCreateBody(value: unknown, nowMs: number): ParseResult<CreateCommand> {
	if (
		!isRecord(value) ||
		!onlyKeys(value, [
			"iid", "agent_runtime", "action_id", "artifact_digest", "tool", "threat_ids", "summary", "expires_at",
		])
	) {
		return { ok: false, error: "invalid_request" };
	}
	const iid = typeof value.iid === "string" ? boundedText(value.iid.trim(), 128) : null;
	const agentRuntime = typeof value.agent_runtime === "string" && RUNTIME.test(value.agent_runtime)
		? value.agent_runtime.toLowerCase()
		: null;
	const actionId = typeof value.action_id === "string" && ACTION_ID.test(value.action_id) ? value.action_id : null;
	const artifactDigest = typeof value.artifact_digest === "string" && DIGEST.test(value.artifact_digest)
		? value.artifact_digest
		: null;
	const tool = boundedText(value.tool, 64);
	const summary = boundedText(value.summary, 512, 0);
	if (!iid || !agentRuntime || !actionId || !artifactDigest || !tool || summary === null) {
		return { ok: false, error: "invalid_request" };
	}
	if (
		!Array.isArray(value.threat_ids) ||
		value.threat_ids.length > 16 ||
		!value.threat_ids.every((id) => typeof id === "string" && THREAT_ID.test(id))
	) {
		return { ok: false, error: "invalid_threat_ids" };
	}
	const expires = typeof value.expires_at === "string" ? Date.parse(value.expires_at) : Number.NaN;
	if (!Number.isFinite(expires) || expires <= nowMs || expires > nowMs + APPROVAL_REQUEST_MAX_TTL_MS + EXPIRY_SKEW_MS) {
		return { ok: false, error: "invalid_expires_at" };
	}
	return {
		ok: true,
		value: {
			iid,
			agentRuntime,
			actionId,
			artifactDigest,
			tool,
			threatIds: [...new Set(value.threat_ids as string[])],
			summary,
			expiresAtMs: Math.min(expires, nowMs + APPROVAL_REQUEST_MAX_TTL_MS),
		},
	};
}

function parseDecisionFields(
	value: Record<string, unknown>,
): ParseResult<{ decision: ApprovalDecision; reason: string }> {
	if (value.decision !== "approve" && value.decision !== "deny") return { ok: false, error: "invalid_decision" };
	const reason = typeof value.reason === "string" ? boundedText(value.reason.trim(), REASON_MAX) : null;
	if (!reason) return { ok: false, error: "invalid_reason" };
	return { ok: true, value: { decision: value.decision, reason } };
}

export function parseDashboardBody(value: unknown, pathRequestId: string | null): ParseResult<DashboardCommand> {
	if (!isRecord(value)) return { ok: false, error: "invalid_request" };
	const tenantId = typeof value.tenant_id === "string" && UUID.test(value.tenant_id)
		? value.tenant_id.toLowerCase()
		: null;
	if (value.tenant_id !== undefined && !tenantId) return { ok: false, error: "invalid_request" };
	if (pathRequestId) {
		if (!onlyKeys(value, ["decision", "reason", "tenant_id"])) return { ok: false, error: "invalid_request" };
		const fields = parseDecisionFields(value);
		if (!fields.ok) return fields;
		return { ok: true, value: { action: "decide", requestId: pathRequestId, tenantId, ...fields.value } };
	}
	if (value.action === "decide") {
		if (!onlyKeys(value, ["action", "request_id", "tenant_id", "decision", "reason"]) || !tenantId ||
			typeof value.request_id !== "string" || !UUID.test(value.request_id)) {
			return { ok: false, error: "invalid_request" };
		}
		const fields = parseDecisionFields(value);
		if (!fields.ok) return fields;
		return {
			ok: true,
			value: { action: "decide", requestId: value.request_id.toLowerCase(), tenantId, ...fields.value },
		};
	}
	if (value.action === "rotate_key") {
		if (!onlyKeys(value, ["action", "tenant_id"]) || !tenantId) return { ok: false, error: "invalid_request" };
		return { ok: true, value: { action: "rotate_key", tenantId } };
	}
	return { ok: false, error: "invalid_action" };
}

type RequestRow = {
	id: string;
	tenant_id: string;
	iid: string;
	action_id: string;
	artifact_digest: string;
	tool: string;
	status: string;
	expires_at: string;
};

function validRequestRow(value: unknown, requestId: string): value is RequestRow {
	return isRecord(value) && value.id === requestId && typeof value.tenant_id === "string" &&
		UUID.test(value.tenant_id) && typeof value.iid === "string" && typeof value.action_id === "string" &&
		typeof value.artifact_digest === "string" && typeof value.tool === "string" &&
		typeof value.status === "string" && typeof value.expires_at === "string";
}

type StoredKey = {
	key_id: string;
	public_key_spki_b64: string;
	private_key_ciphertext_b64: string;
	private_key_nonce_b64: string;
	wrap_key_version: number;
};

function validStoredKey(value: unknown): value is StoredKey {
	return isRecord(value) && typeof value.key_id === "string" && typeof value.public_key_spki_b64 === "string" &&
		typeof value.private_key_ciphertext_b64 === "string" && typeof value.private_key_nonce_b64 === "string" &&
		Number.isSafeInteger(value.wrap_key_version);
}

async function readActiveKey(db: DatabaseClient, tenantId: string): Promise<{ ok: boolean; key: StoredKey | null }> {
	const { data, error } = await db
		.from("tenant_approval_signing_keys")
		.select("key_id,public_key_spki_b64,private_key_ciphertext_b64,private_key_nonce_b64,wrap_key_version")
		.eq("tenant_id", tenantId)
		.is("retired_at", null)
		.is("revoked_at", null)
		.maybeSingle();
	if (error) return { ok: false, key: null };
	if (data === null) return { ok: true, key: null };
	return validStoredKey(data) ? { ok: true, key: data } : { ok: false, key: null };
}

async function installKey(
	db: DatabaseClient,
	wrapSecret: Uint8Array,
	tenantId: string,
	actorUserId: string,
	rotate: boolean,
): Promise<{ ok: true; keyId: string; retiredKeyId: string | null } | { ok: false; error: RpcError }> {
	const sealed = await generateSealedApprovalKey(wrapSecret, tenantId);
	const { data, error } = await db.rpc("install_tenant_approval_signing_key", {
		p_tenant_id: tenantId,
		p_actor_user_id: actorUserId,
		p_key_id: sealed.keyId,
		p_public_key_spki_b64: sealed.publicKeySpkiB64,
		p_private_key_ciphertext_b64: sealed.privateKeyCiphertextB64,
		p_private_key_nonce_b64: sealed.privateKeyNonceB64,
		p_wrap_key_version: sealed.wrapKeyVersion,
		p_rotate: rotate,
	});
	if (error || !isRecord(data) || typeof data.key_id !== "string") {
		return { ok: false, error: (error as RpcError) ?? null };
	}
	return {
		ok: true,
		keyId: data.key_id,
		retiredKeyId: typeof data.retired_key_id === "string" ? data.retired_key_id : null,
	};
}

function rpcFailure(req: Request, error: RpcError, fallback: string, headers: Record<string, string> = {}): Response {
	switch (error?.code) {
		case "42501":
			return corsJson(req, 403, { error: "approval_forbidden" }, headers);
		case "P0002":
			return corsJson(req, 404, { error: "approval_request_not_found" }, headers);
		case "23505":
			return corsJson(req, 409, { error: "approval_request_conflict" }, headers);
		case "54000":
			return corsJson(req, 429, { error: "approval_request_quota" }, headers);
		case "55000":
			return corsJson(req, 409, { error: "approval_signing_key_changed", retryable: true }, headers);
		case "22023":
			return corsJson(req, 400, { error: "invalid_request" }, headers);
		default:
			return corsJson(req, 503, { error: fallback }, headers);
	}
}

async function handleCreate(
	req: Request,
	db: DatabaseClient,
	token: string,
	value: unknown,
	nowMs: number,
): Promise<Response> {
	const body = parseCreateBody(value, nowMs);
	if (!body.ok) return corsJson(req, 400, { error: body.error });
	const auth = await authenticateTenantApiKey(db, token, nowMs);
	if (!auth.ok) return corsJson(req, auth.status, { error: auth.error });
	const rate = await consumeTenantRateLimit(db, {
		tenantId: auth.tenantId,
		subject: auth.apiKeyId ?? auth.userId,
		endpoint: "approval-requests:create",
		perSubject: 120,
		perTenant: 2000,
		now: nowMs,
	});
	if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
	const { data, error } = await db.rpc("create_approval_request", {
		p_tenant_id: auth.tenantId,
		p_requester_user_id: auth.userId,
		p_api_key_id: auth.apiKeyId ?? null,
		p_bound_agent_id: auth.agentId ?? null,
		p_iid: body.value.iid,
		p_agent_runtime: body.value.agentRuntime,
		p_action_id: body.value.actionId,
		p_artifact_digest: body.value.artifactDigest,
		p_tool: body.value.tool,
		p_threat_ids: body.value.threatIds,
		p_summary: body.value.summary,
		p_expires_at: new Date(body.value.expiresAtMs).toISOString(),
	});
	if (error) return rpcFailure(req, error as RpcError, "approval_request_unavailable", rateLimitHeaders(rate));
	if (!isRecord(data) || typeof data.request_id !== "string" || !UUID.test(data.request_id) ||
		!["pending", "approved", "denied", "expired"].includes(String(data.status))) {
		return corsJson(req, 503, { error: "approval_request_unavailable" }, rateLimitHeaders(rate));
	}
	return corsJson(req, 201, {
		request_id: data.request_id,
		status: data.status,
		created: data.created === true,
	}, rateLimitHeaders(rate));
}

async function handlePoll(
	req: Request,
	db: DatabaseClient,
	token: string,
	requestId: string,
	nowMs: number,
): Promise<Response> {
	const auth = await authenticateTenantApiKey(db, token, nowMs);
	if (!auth.ok) return corsJson(req, auth.status, { error: auth.error });
	const rate = await consumeTenantRateLimit(db, {
		tenantId: auth.tenantId,
		subject: auth.apiKeyId ?? auth.userId,
		endpoint: "approval-requests:poll",
		perSubject: 1200,
		perTenant: 20000,
		now: nowMs,
	});
	if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
	const { data, error } = await db.rpc("read_approval_request_for_agent", {
		p_request_id: requestId,
		p_tenant_id: auth.tenantId,
		p_bound_agent_id: auth.agentId ?? null,
		p_requester_user_id: auth.userId,
	});
	if (error) return rpcFailure(req, error as RpcError, "approval_request_unavailable", rateLimitHeaders(rate));
	if (data === null) return corsJson(req, 404, { error: "approval_request_not_found" }, rateLimitHeaders(rate));
	if (!isRecord(data) || data.request_id !== requestId ||
		!["pending", "approved", "denied", "expired"].includes(String(data.status))) {
		return corsJson(req, 503, { error: "approval_request_unavailable" }, rateLimitHeaders(rate));
	}
	const decided = data.status === "approved" || data.status === "denied";
	if (decided && (typeof data.token !== "string" || typeof data.key_id !== "string")) {
		return corsJson(req, 503, { error: "approval_request_unavailable" }, rateLimitHeaders(rate));
	}
	return corsJson(req, 200, {
		request_id: requestId,
		status: data.status,
		...(decided
			? { token: data.token, key_id: data.key_id, token_expires_at: data.token_expires_at ?? null }
			: {}),
	}, rateLimitHeaders(rate));
}

async function handleDashboard(
	req: Request,
	db: DatabaseClient,
	token: string,
	wrapSecret: Uint8Array,
	command: DashboardCommand,
	nowMs: number,
): Promise<Response> {
	const { data: auth, error: authError } = await db.auth.getUser(token);
	if (authError || !auth.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
	const userId = auth.user.id;

	let tenantId: string;
	let request: RequestRow | null = null;
	if (command.action === "decide") {
		const { data, error } = await db
			.from("approval_requests")
			.select("id,tenant_id,iid,action_id,artifact_digest,tool,status,expires_at")
			.eq("id", command.requestId)
			.maybeSingle();
		if (error) return corsJson(req, 503, { error: "approval_request_unavailable" });
		// Another tenant's request is indistinguishable from a missing one.
		if (!data || (command.tenantId !== null && (data as { tenant_id?: unknown }).tenant_id !== command.tenantId)) {
			return corsJson(req, 404, { error: "approval_request_not_found" });
		}
		if (!validRequestRow(data, command.requestId)) return corsJson(req, 503, { error: "approval_request_unavailable" });
		request = data;
		tenantId = data.tenant_id.toLowerCase();
	} else {
		tenantId = command.tenantId;
	}

	const { data: member, error: memberError } = await db
		.from("tenant_members")
		.select("role,expires_at")
		.eq("tenant_id", tenantId)
		.eq("user_id", userId)
		.maybeSingle();
	if (memberError) return corsJson(req, 503, { error: "authorization_unavailable" });
	const role = String((member as { role?: unknown } | null)?.role ?? "");
	if (!membershipActive(member as { role?: string; expires_at?: string | null } | null, nowMs) ||
		!["owner", "admin", "member", "viewer"].includes(role)) {
		return command.action === "decide"
			? corsJson(req, 404, { error: "approval_request_not_found" })
			: corsJson(req, 403, { error: "approval_forbidden" });
	}
	const barrier = await checkIdentityBarrier(db, token, userId, tenantId);
	if (!barrier.ok) return corsJson(req, barrier.status, { error: barrier.error });
	if (role !== "owner" && role !== "admin") return corsJson(req, 403, { error: "approval_role_insufficient" });
	// Approving a blocked agent action is privileged: step-up is required even
	// when the tenant's general MFA policy is optional.
	const { data: assurance, error: assuranceError } = await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
	if (assuranceError || !assurance) return corsJson(req, 503, { error: "assurance_unavailable" });
	if (assurance.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" });

	const rate = await consumeTenantRateLimit(db, {
		tenantId,
		subject: userId,
		endpoint: `approval-requests:${command.action}`,
		perSubject: command.action === "decide" ? 60 : 5,
		perTenant: command.action === "decide" ? 600 : 20,
		now: nowMs,
	});
	if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
	const headers = rateLimitHeaders(rate);

	if (command.action === "rotate_key") {
		const installed = await installKey(db, wrapSecret, tenantId, userId, true);
		if (!installed.ok) return rpcFailure(req, installed.error, "approval_key_rotation_failed", headers);
		return corsJson(req, 200, { ok: true, key_id: installed.keyId, retired_key_id: installed.retiredKeyId }, headers);
	}

	const row = request as unknown as RequestRow;
	if (row.status !== "pending") {
		return corsJson(req, 409, { error: "approval_request_final", status: row.status }, headers);
	}
	if (!(Date.parse(row.expires_at) > nowMs)) {
		return corsJson(req, 409, { error: "approval_request_expired", status: "expired" }, headers);
	}

	let active = await readActiveKey(db, tenantId);
	if (!active.ok) return corsJson(req, 503, { error: "approval_signing_unavailable" }, headers);
	if (!active.key) {
		const installed = await installKey(db, wrapSecret, tenantId, userId, false);
		if (!installed.ok) return rpcFailure(req, installed.error, "approval_signing_unavailable", headers);
		active = await readActiveKey(db, tenantId);
		if (!active.ok || !active.key || active.key.key_id !== installed.keyId) {
			return corsJson(req, 503, { error: "approval_signing_unavailable" }, headers);
		}
	}
	const key = active.key as StoredKey;

	const issuedAt = new Date(nowMs);
	const expiresAt = new Date(nowMs + APPROVAL_TOKEN_TTL_MS);
	const payload: ApprovalTokenPayload = {
		v: 1,
		tenant_id: tenantId,
		iid: row.iid,
		action_id: row.action_id,
		artifact_digest: row.artifact_digest,
		tool: row.tool,
		decision: command.decision,
		approver_id: userId,
		issued_at: issuedAt.toISOString(),
		expires_at: expiresAt.toISOString(),
		nonce: newApprovalNonce(),
	};
	let signed: string;
	try {
		const privateKey = await unsealApprovalKey(wrapSecret, tenantId, key);
		signed = await signApprovalToken(payload, privateKey);
	} catch {
		// Wrong wrap secret, tampered ciphertext or a key bound to another tenant.
		return corsJson(req, 503, { error: "approval_signing_unavailable" }, headers);
	}
	// Self-check against the key that will be published before persisting.
	if (!(await verifyApprovalToken(signed, key.public_key_spki_b64))) {
		return corsJson(req, 503, { error: "approval_signing_unavailable" }, headers);
	}

	const { data, error } = await db.rpc("decide_approval_request", {
		p_request_id: row.id,
		p_tenant_id: tenantId,
		p_actor_user_id: userId,
		p_decision: command.decision,
		p_reason: command.reason,
		p_key_id: key.key_id,
		p_token: signed,
		p_token_nonce: payload.nonce,
		p_token_expires_at: payload.expires_at,
	});
	if (error) return rpcFailure(req, error as RpcError, "approval_decision_failed", headers);
	if (!isRecord(data) || data.request_id !== row.id) {
		return corsJson(req, 503, { error: "approval_decision_failed" }, headers);
	}
	if (data.outcome === "already_final") {
		return corsJson(req, 409, { error: "approval_request_final", status: data.status }, headers);
	}
	if (data.outcome === "expired") {
		return corsJson(req, 409, { error: "approval_request_expired", status: "expired" }, headers);
	}
	if (data.outcome !== "decided" || (data.status !== "approved" && data.status !== "denied")) {
		return corsJson(req, 503, { error: "approval_decision_failed" }, headers);
	}
	return corsJson(req, 200, {
		ok: true,
		request_id: row.id,
		status: data.status,
		decided_at: data.decided_at ?? issuedAt.toISOString(),
		key_id: key.key_id,
		token_expires_at: payload.expires_at,
	}, headers);
}

export function createApprovalRequestsHandler(deps: ApprovalRequestsDeps = {}) {
	const runtimeEnv = deps.env ?? readRuntimeEnv;
	const now = deps.now ?? Date.now;
	const makeClient = deps.client ?? ((url, key) => createClient(url, key, {
		auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
	}));

	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		const route = routeFor(req);
		if (route.kind === "unknown") {
			return req.method === "GET" || req.method === "POST"
				? corsJson(req, 404, { error: "not_found" })
				: corsJson(req, 405, { error: "method_not_allowed" });
		}
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) {
			return configFailure("approval-requests", config.error, (status, body) => corsJson(req, status, body));
		}
		const wrapSecret = parseWrapSecret(config.values[WRAP_ENV]);
		if (!wrapSecret) {
			return configFailure(
				"approval-requests",
				new ConfigurationError({ invalid: [WRAP_ENV] }),
				(status, body) => corsJson(req, status, body),
			);
		}
		const token = getBearerToken(req.headers.get("Authorization"));
		const missingApiKey = () => corsJson(req, 401, { error: "missing_api_key" });
		const missingSession = () => corsJson(req, 401, { error: "missing_access_token" });

		try {
			const db = () => makeClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY);
			if (route.kind === "poll") {
				return token ? await handlePoll(req, db(), token, route.requestId, now()) : missingApiKey();
			}
			const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
			if (route.kind === "decision") {
				if (!token) return missingSession();
				if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
				const command = parseDashboardBody(parsed.value, route.requestId);
				if (!command.ok) return corsJson(req, 400, { error: command.error });
				return await handleDashboard(req, db(), token, wrapSecret, command.value, now());
			}
			// POST /approval-requests: a body naming an `action` is a dashboard
			// session call; anything else is a connector filing a request (whose
			// strict body schema has no `action` key).
			if (parsed.ok && isRecord(parsed.value) && "action" in parsed.value) {
				if (!token) return missingSession();
				const command = parseDashboardBody(parsed.value, null);
				if (!command.ok) return corsJson(req, 400, { error: command.error });
				return await handleDashboard(req, db(), token, wrapSecret, command.value, now());
			}
			if (!token) return missingApiKey();
			if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
			return await handleCreate(req, db(), token, parsed.value, now());
		} catch {
			return corsJson(req, 503, { error: "approval_request_unavailable" });
		}
	};
}

const approvalRequests = createApprovalRequestsHandler();
Deno.serve(approvalRequests);
