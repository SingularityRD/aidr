// Supabase Edge Function: GET /v1/revocations and POST /v1/revocations
//
// Auth: Authorization: Bearer <api_key_plaintext>
//
// Returns a signed revocations payload used by commercial runtimes to:
// - revoke entitlement serials
// - revoke pack ids / versions
// - revoke artifact ids
// - revoke key ids
//
// POST actions: operator queue/rollback/cancel/list with an Auth access token,
// and agent poll/ack/result with an enrollment-issued, agent-bound API key.
// The command transport records agent-reported outcomes. Actual OS or provider
// containment requires a separately verified native consumer and field test.

import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import { authenticateTenantApiKeyBudgeted } from "../_shared/api-key-auth.ts";
import { getBearerToken as getAccessToken } from "../_shared/auth.ts";
import { configFailure, loadConfig, partialGroupError, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { canonicalJson } from "../_shared/policy-signature.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";
import { loadRevocationRows } from "./feed.ts";
import {
	commandSigningPayload,
	effectiveCommandState,
	isUuid,
	parseDeviceResult,
	parseQueueBody,
	parseRollbackBody,
	reverseCommandType,
	rpcStatus,
} from "./commands.ts";
import { deviceAttestationError } from "./attestation.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

const REVOCATION_SIGNING_KEY_ID = (Deno.env.get("AIDR_REVOCATION_SIGNING_KEY_ID") ?? "").trim();
const REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64 = (
	Deno.env.get("AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64") ?? ""
).trim();
const REVOCATION_EPOCH = Number(Deno.env.get("AIDR_REVOCATION_EPOCH") ?? "1");
const REVOCATION_TTL_HOURS = Number(Deno.env.get("AIDR_REVOCATION_TTL_HOURS") ?? "24");

function json(status: number, body: Record<string, unknown>, headers: Record<string, string> = {}) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers },
	});
}

function getBearerToken(req: Request): string | null {
	const header = req.headers.get("Authorization") ?? "";
	const m = header.match(/^Bearer\s+(.+)$/i);
	return m?.[1]?.trim() ? m[1].trim() : null;
}

async function sha256Hex(input: string): Promise<string> {
	const data = new TextEncoder().encode(input);
	const digest = await crypto.subtle.digest("SHA-256", data);
	const bytes = new Uint8Array(digest);
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

function bytesToBase64(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
}

async function revocationSigningKey(): Promise<CryptoKey | null> {
	if (!/^[A-Za-z0-9._:-]{1,128}$/.test(REVOCATION_SIGNING_KEY_ID) || !REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64) return null;
	try {
		const pkcs8 = Uint8Array.from(
			atob(REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64),
			(c) => c.charCodeAt(0),
		);
		return await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, [
			"sign",
		]);
	} catch {
		return null;
	}
}

async function signEd25519Detached(payloadJson: string, signingKey?: CryptoKey): Promise<string | null> {
	try {
		const key = signingKey ?? await revocationSigningKey();
		if (!key) return null;
		const sig = await crypto.subtle.sign("Ed25519", key, new TextEncoder().encode(payloadJson));
		return bytesToBase64(new Uint8Array(sig));
	} catch {
		return null;
	}
}

function addHoursIso(hours: number): string {
	const safe = Number.isFinite(hours) ? Math.max(0, hours) : 0;
	return new Date(Date.now() + safe * 60 * 60 * 1000).toISOString();
}

type ReadTable<Row extends Record<string, unknown>> = { Row: Row; Insert: never; Update: never; Relationships: [] };
type FleetCommandRow = {
	id: string; tenant_id: string; agent_id: string; actor_user_id: string; command_type: string;
	reason: string; rollback_of: string | null; state: string; attempts: number;
	created_at: string; expires_at: string; delivered_at: string | null;
	acknowledged_at: string | null; completed_at: string | null; result_code: string | null;
};
type RevocationsDatabase = {
	public: {
		Tables: {
			tenant_members: ReadTable<{ tenant_id: string; user_id: string; role: string; expires_at: string | null }>;
			tenants: ReadTable<{ id: string; status: string }>;
			api_keys: ReadTable<{ tenant_id: string; user_id: string; agent_id: string | null; revoked: boolean; key_hash: string; scope: string }>;
			agents: ReadTable<{ id: string; tenant_id: string; iid: string }>;
			fleet_response_commands: ReadTable<FleetCommandRow>;
			revocations: ReadTable<{ id: string; kind: string; value: string; tenant_id: string | null }>;
		};
		Views: Record<string, never>;
		Functions: {
			poll_bound_fleet_response_command: { Args: { p_key_hash: string; p_tenant_id: string; p_agent_id: string; p_installation_id: string }; Returns: { command: FleetCommandRow | null; tenant_id: string; agent_id: string; installation_id: string; key_hash: string } };
			record_fleet_response_command: { Args: { p_key_hash: string; p_tenant_id: string; p_agent_id: string; p_command_id: string; p_stage: string; p_outcome: string; p_result_code: string | null }; Returns: FleetCommandRow };
			cancel_fleet_response_command: { Args: { p_tenant_id: string; p_actor_user_id: string; p_command_id: string }; Returns: FleetCommandRow };
			queue_bounded_fleet_response_command: { Args: { p_tenant_id: string; p_actor_user_id: string; p_agent_id: string; p_command_type: string; p_reason: string; p_idempotency_key: string; p_ttl_seconds: number; p_rollback_of: string | null }; Returns: FleetCommandRow };
		};
		Enums: Record<string, never>;
		CompositeTypes: Record<string, never>;
	};
};
type DatabaseClient = SupabaseClient<RevocationsDatabase>;
type OperatorContext = { userId: string; tenantId: string };
type AgentContext = { tenantId: string; agentId: string; installationId: string; keyHash: string };

function commandError(req: Request, error: { code?: string }, fallback: string): Response {
	// 54000 is the bounded queue's depth rejection: the tenant has reached its
	// live-command ceiling and must let commands finish (or cancel them) before
	// queueing more. It is a quota answer, not a transport failure.
	if (error.code === "54000") {
		return corsJson(req, 429, { error: "tenant_queue_limit_reached" });
	}
	return corsJson(req, rpcStatus(error.code), {
		error: error.code === "PT409" || error.code === "23505"
			? "fleet_command_conflict"
			: error.code === "42501" ? "fleet_forbidden"
			: error.code === "22023" ? "invalid_fleet_command" : fallback,
	});
}

async function operatorContext(
	db: DatabaseClient,
	req: Request,
	tenantId: string,
	mutating: boolean,
): Promise<OperatorContext | Response> {
	const accessToken = getAccessToken(req.headers.get("Authorization"));
	if (!accessToken) return corsJson(req, 401, { error: "missing_access_token" });
	const { data: auth, error: authError } = await db.auth.getUser(accessToken);
	if (authError || !auth.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
	const barrier = await checkIdentityBarrier(db, accessToken, auth.user.id, tenantId);
	if (!barrier.ok) return corsJson(req, barrier.status, { error: barrier.error });
	const [{ data: member, error: memberError }, { data: tenant, error: tenantError }] =
		await Promise.all([
			db.from("tenant_members").select("role,expires_at").eq("tenant_id", tenantId)
				.eq("user_id", auth.user.id).maybeSingle(),
			db.from("tenants").select("status").eq("id", tenantId).maybeSingle(),
		]);
	if (memberError || tenantError) {
		return corsJson(req, 503, { error: "authorization_unavailable" });
	}
	if (!membershipActive(member) || tenant?.status !== "active" ||
		!["owner", "admin"].includes(String(member?.role ?? ""))) {
		return corsJson(req, 403, { error: "fleet_operator_forbidden" });
	}
	// A fleet-wide containment directive requires step-up assurance even when
	// the tenant has not enabled MFA as a general dashboard policy.
	if (mutating) {
		const { data: assurance, error: assuranceError } =
			await db.auth.mfa.getAuthenticatorAssuranceLevel(accessToken);
		if (assuranceError || !assurance) {
			return corsJson(req, 503, { error: "assurance_unavailable" });
		}
		if (assurance.currentLevel !== "aal2") {
			return corsJson(req, 403, { error: "mfa_required_for_fleet_response" });
		}
	}
	return { userId: auth.user.id, tenantId };
}

async function agentContext(db: DatabaseClient, req: Request): Promise<AgentContext | Response> {
	const token = getAccessToken(req.headers.get("Authorization"));
	if (!token) return corsJson(req, 401, { error: "missing_api_key" });
	const keyHash = await sha256Hex(token);
	// Fleet commands need a full, agent-bound tenant key: the shared guard admits
	// only `tenant` scope by default, so an ingest-only key never qualifies.
	const auth = await authenticateTenantApiKeyBudgeted(db, token, "fleet-response");
	if (!auth.ok) return corsJson(req, auth.status, { error: auth.error });
	if (!isUuid(auth.tenantId) || !isUuid(auth.agentId)) {
		return corsJson(req, 403, { error: "agent_bound_key_required" });
	}
	const { data: agent, error: agentError } = await db.from("agents").select("id,tenant_id,iid")
		.eq("tenant_id", auth.tenantId).eq("id", auth.agentId).maybeSingle();
	if (agentError) return corsJson(req, 503, { error: "authorization_unavailable" });
	if (!agent) return corsJson(req, 403, { error: "agent_access_denied" });
	if (typeof agent.iid !== "string" || agent.iid.trim().length === 0 || /[\u0000-\u001f\u007f\r\n]/.test(agent.iid)) {
		return corsJson(req, 503, { error: "device_attestation_unavailable" });
	}
	// Keep the presented hash: the RPC rechecks the retired hash's expiry under its row lock.
	return { tenantId: auth.tenantId, agentId: auth.agentId, installationId: agent.iid.trim(), keyHash };
}

export interface FleetCommandDeps {
	/** Overrides the service-role client; used by the contract suite. */
	db?: DatabaseClient;
}

/** Build the POST fleet-command handler. Exported so the contract suite can drive it. */
export function createFleetCommandHandler(deps: FleetCommandDeps = {}) {
	return async function handleFleetCommand(req: Request): Promise<Response> {
		// Preflight and origin policy are answered before any configuration or
		// database work, exactly as the module-level request path does.
		const preflight = handleCors(req);
		if (preflight) return preflight;
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) {
			return configFailure("revocations", config.error, (status, body) =>
				corsJson(req, status, body));
		}
		const db = deps.db ?? createClient<RevocationsDatabase>(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, {
			auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
		});
		return handleFleetCommandRequest(req, db);
	};
}

async function handleFleetCommandRequest(req: Request, db: DatabaseClient): Promise<Response> {
	const parsed = await readBoundedJson(req, 4096);
	if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
	const body = parsed.value;
	if (!body || typeof body !== "object" || Array.isArray(body)) {
		return corsJson(req, 400, { error: "invalid_request" });
	}
	const values = body as Record<string, unknown>;
	const action = values.action;
	if (typeof action !== "string") return corsJson(req, 400, { error: "invalid_action" });
	try {
		if (["poll", "ack", "result"].includes(action)) {
			const identity = await agentContext(db, req);
			if (identity instanceof Response) return identity;
			if (values.tenant_id !== undefined && values.tenant_id !== identity.tenantId) {
				return corsJson(req, 403, { error: "tenant_mismatch" });
			}
			const attestationError = deviceAttestationError(values.device_attestation, identity);
			if (attestationError) return corsJson(req, 403, { error: attestationError });
			const rate = await consumeTenantRateLimit(db, {
				tenantId: identity.tenantId,
				subject: identity.agentId,
				endpoint: "fleet-response-device",
				perSubject: 240,
				perTenant: 50_000,
			});
			if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
			if (action === "poll") {
				// Validate signing before leasing a command; no unsigned execution fallback.
				const signingKey = await revocationSigningKey();
				if (!signingKey) return corsJson(req, 503, { error: "fleet_command_signing_unavailable" });
				const { data, error } = await db.rpc("poll_bound_fleet_response_command", {
					p_key_hash: identity.keyHash,
					p_tenant_id: identity.tenantId,
					p_agent_id: identity.agentId,
					p_installation_id: identity.installationId,
				});
				if (error) return commandError(req, error, "fleet_poll_unavailable");
				if (!data || data.tenant_id !== identity.tenantId || data.agent_id !== identity.agentId ||
					data.installation_id !== identity.installationId || data.key_hash !== identity.keyHash) {
					return corsJson(req, 503, { error: "fleet_command_binding_unavailable" });
				}
				if (data.command === null) return corsJson(req, 200, { ok: true, command_signed: null });
				const payload = commandSigningPayload(data.command, identity, REVOCATION_SIGNING_KEY_ID);
				if (!payload) return corsJson(req, 503, { error: "fleet_command_binding_unavailable" });
				const sig = await signEd25519Detached(canonicalJson(payload), signingKey);
				if (!sig) return corsJson(req, 503, { error: "fleet_command_signing_unavailable" });
				return corsJson(req, 200, { ok: true, command_signed: {
					alg: "ed25519", key_id: REVOCATION_SIGNING_KEY_ID, sig_b64: sig, payload,
				} });
			}
			const result = parseDeviceResult(values);
			if (!result.ok) return corsJson(req, 400, { error: result.error });
			const { data, error } = await db.rpc("record_fleet_response_command", {
				p_key_hash: identity.keyHash,
				p_tenant_id: identity.tenantId,
				p_agent_id: identity.agentId,
				p_command_id: result.commandId,
				p_stage: result.stage,
				p_outcome: result.outcome,
				p_result_code: result.resultCode,
			});
			if (error) return commandError(req, error, "fleet_result_unavailable");
			const expected = action === "ack"
				? (result.outcome === "accepted" ? "acknowledged" : "failed")
				: result.outcome;
			if (data?.state !== expected) {
				return corsJson(req, 409, { error: "command_no_longer_actionable", state: data?.state });
			}
			return corsJson(req, 200, { ok: true, command_id: data.id, state: data.state });
		}

		if (!["queue", "rollback", "cancel", "list"].includes(action)) {
			return corsJson(req, 400, { error: "invalid_action" });
		}
		if (!isUuid(values.tenant_id)) return corsJson(req, 400, { error: "invalid_tenant_id" });
		const identity = await operatorContext(db, req, values.tenant_id, action !== "list");
		if (identity instanceof Response) return identity;
		const rate = await consumeTenantRateLimit(db, {
			tenantId: identity.tenantId,
			subject: identity.userId,
			endpoint: "fleet-response-operator",
			perSubject: 60,
			perTenant: 3000,
		});
		if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));

		if (action === "list") {
			if (values.command_id !== undefined && !isUuid(values.command_id)) {
				return corsJson(req, 400, { error: "invalid_command_id" });
			}
			let query = db.from("fleet_response_commands")
				.select("id,tenant_id,agent_id,actor_user_id,command_type,reason,rollback_of,state,attempts,created_at,expires_at,delivered_at,acknowledged_at,completed_at,result_code")
				.eq("tenant_id", identity.tenantId).order("created_at", { ascending: false })
				.order("id", { ascending: false }).limit(values.command_id ? 1 : 101);
			if (values.command_id) query = query.eq("id", values.command_id);
			const { data, error } = await query;
			if (error) return corsJson(req, 503, { error: "fleet_history_unavailable" });
			return corsJson(req, 200, {
				ok: true,
				commands: (values.command_id ? (data ?? []) : (data ?? []).slice(0, 100))
					.map((row) => ({ ...row, effective_state: effectiveCommandState(row) })),
				truncated: !values.command_id && (data ?? []).length > 100,
			});
		}
		if (action === "cancel") {
			if (!isUuid(values.command_id)) return corsJson(req, 400, { error: "invalid_command_id" });
			const { data, error } = await db.rpc("cancel_fleet_response_command", {
				p_tenant_id: identity.tenantId,
				p_actor_user_id: identity.userId,
				p_command_id: values.command_id,
			});
			if (error) return commandError(req, error, "fleet_cancel_unavailable");
			return corsJson(req, 200, { ok: true, command_id: data.id, state: data.state });
		}

		let agentId: string;
		let commandType: string;
		let reason: string;
		let idempotencyKey: string;
		let ttlSeconds: number;
		let rollbackOf: string | null = null;
		if (action === "queue") {
			const queue = parseQueueBody(values);
			if (!queue.ok) return corsJson(req, 400, { error: queue.error });
			({ agentId, commandType, reason, idempotencyKey, ttlSeconds } = queue);
		} else {
			const rollback = parseRollbackBody(values);
			if (!rollback.ok) return corsJson(req, 400, { error: rollback.error });
			const { data: original, error: originalError } = await db
				.from("fleet_response_commands").select("agent_id,command_type")
				.eq("tenant_id", identity.tenantId).eq("id", rollback.rollbackOf).maybeSingle();
			if (originalError) return corsJson(req, 503, { error: "rollback_lookup_unavailable" });
			if (!original) return corsJson(req, 404, { error: "rollback_source_not_found" });
			const reverse = reverseCommandType(original.command_type);
			if (!reverse) return corsJson(req, 400, { error: "command_not_reversible" });
			agentId = original.agent_id;
			commandType = reverse;
			reason = rollback.reason;
			idempotencyKey = rollback.idempotencyKey;
			ttlSeconds = rollback.ttlSeconds;
			rollbackOf = rollback.rollbackOf;
		}
		const { data, error } = await db.rpc("queue_bounded_fleet_response_command", {
			p_tenant_id: identity.tenantId,
			p_actor_user_id: identity.userId,
			p_agent_id: agentId,
			p_command_type: commandType,
			p_reason: reason,
			p_idempotency_key: idempotencyKey,
			p_ttl_seconds: ttlSeconds,
			p_rollback_of: rollbackOf,
		});
		if (error) return commandError(req, error, "fleet_queue_unavailable");
		return corsJson(req, 200, {
			ok: true,
			command: {
				id: data.id,
				agent_id: data.agent_id,
				command_type: data.command_type,
				state: data.state,
				expires_at: data.expires_at,
				rollback_of: data.rollback_of,
			},
		});
	} catch {
		return corsJson(req, 503, { error: "fleet_response_unavailable" });
	}
}

const fleetCommand = createFleetCommandHandler();

Deno.serve(async (req) => {
	// The fleet-command factory owns preflight, configuration ordering and the
	// POST method guard for its own request path.
	if (req.method === "POST" || req.method === "OPTIONS") return fleetCommand(req);
	const preflight = handleCors(req);
	if (preflight) return preflight;
	if (req.method !== "GET") {
		return json(405, { error: "method_not_allowed" });
	}

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("revocations", config.error, json);
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

	// An unsigned revocation feed is not a usable answer (a consumer cannot
	// distinguish "nothing revoked" from "signing is broken"), so a
	// HALF-configured key pair is a configuration error rather than a silent
	// `revocations_signed: null`.
	const signingProblem = partialGroupError({
		AIDR_REVOCATION_SIGNING_KEY_ID: REVOCATION_SIGNING_KEY_ID,
		AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64: REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64,
	});
	if (signingProblem) return configFailure("revocations", signingProblem, json);

	const apiKey = getBearerToken(req);
	if (!apiKey) {
		return json(401, { error: "missing_api_key" });
	}

	const supabase = createClient<RevocationsDatabase>(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	// Use the same bounded renewal overlap and admission check as the other
	// machine endpoints; the guard refuses non-`tenant` (ingest-only) keys.
	const auth = await authenticateTenantApiKeyBudgeted(supabase, apiKey, "revocations");
	if (!auth.ok) return json(auth.status, { error: auth.error });
	const { tenantId, userId } = auth;
	if (!isUuid(tenantId) || !isUuid(userId)) return json(403, { error: "agent_access_denied" });
	const agentId = typeof auth.agentId === "string" && isUuid(auth.agentId) ? auth.agentId.toLowerCase() : null;
	const rate = await consumeTenantRateLimit(supabase, {
		tenantId, subject: userId, endpoint: "revocations", perSubject: 300, perTenant: 10_000,
	});
	if (!rate.ok) return json(rate.status, { error: rate.error }, rateLimitHeaders(rate));

	const loaded = await loadRevocationRows(supabase.from("revocations"), tenantId);
	if (!loaded.ok) return json(503, { error: loaded.error });

	const artifacts: string[] = [];
	const packs: string[] = [];
	const keys: string[] = [];
	const entitlementSerials: string[] = [];

	for (const row of loaded.rows) {
		if (!row || typeof row.kind !== "string" || typeof row.value !== "string") continue;
		if (row.tenant_id && row.tenant_id !== tenantId) continue;
		const kind = row.kind.trim();
		const value = row.value.trim();
		if (!kind || !value) continue;
		if (kind === "artifact_id") artifacts.push(value);
		else if (kind === "pack_id") packs.push(value);
		else if (kind === "key_id") keys.push(value);
		else if (kind === "entitlement_serial") entitlementSerials.push(value);
	}

	// Schema 2 binds the signed list to this tenant (and agent, for agent-bound
	// keys); runtimes reject a list signed for anyone else, so one tenant's list
	// cannot be replayed to another tenant's runtime.
	const payload = {
		schema_version: 2,
		tenant_id: tenantId.toLowerCase(),
		agent_id: agentId,
		issued_at: new Date().toISOString(),
		expires_at: addHoursIso(REVOCATION_TTL_HOURS),
		revocation_epoch: Number.isFinite(REVOCATION_EPOCH) ? Math.max(1, Math.floor(REVOCATION_EPOCH)) : 1,
		revocations: {
			artifact_ids: artifacts,
			pack_ids: packs,
			key_ids: keys,
			entitlement_serials: entitlementSerials,
		},
	};

	const payloadJson = canonicalJson(payload);
	const sig = await signEd25519Detached(payloadJson);
	// Never answer 200 with an unsigned (null) feed: runtimes treat a missing list
	// like "nothing revoked". An unconfigured or broken signer is an outage.
	if (!sig) return json(503, { error: "revocation_signing_unavailable" });

	return json(200, {
		revocations_signed: {
			alg: "ed25519",
			key_id: REVOCATION_SIGNING_KEY_ID,
			sig_b64: sig,
			payload: JSON.parse(payloadJson),
		},
	});
});
