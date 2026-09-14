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

import { createClient } from "npm:@supabase/supabase-js@2";
import { getBearerToken as getAccessToken } from "../_shared/auth.ts";
import { configFailure, loadConfig, partialGroupError, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";
import { loadRevocationRows } from "./feed.ts";
import {
	deviceCommandView,
	effectiveCommandState,
	isUuid,
	parseDeviceResult,
	parseQueueBody,
	parseRollbackBody,
	reverseCommandType,
	rpcStatus,
} from "./commands.ts";

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

function json(status: number, body: Record<string, unknown>) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
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

function canonicalizeForSigning(value: unknown): unknown {
	if (Array.isArray(value)) return value.map((v) => canonicalizeForSigning(v));
	if (!value || typeof value !== "object") return value;
	const obj = value as Record<string, unknown>;
	const out: Record<string, unknown> = {};
	for (const key of Object.keys(obj).sort()) out[key] = canonicalizeForSigning(obj[key]);
	return out;
}

function canonicalJson(value: unknown): string {
	return JSON.stringify(canonicalizeForSigning(value));
}

function bytesToBase64(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
}

async function signEd25519Detached(payloadJson: string): Promise<string | null> {
	if (!REVOCATION_SIGNING_KEY_ID || !REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64) return null;
	try {
		const pkcs8 = Uint8Array.from(
			atob(REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64),
			(c) => c.charCodeAt(0),
		);
		const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, [
			"sign",
		]);
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

type DatabaseClient = ReturnType<typeof createClient>;
type OperatorContext = { userId: string; tenantId: string };
type AgentContext = { tenantId: string; agentId: string; keyHash: string };

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
	const { data: key, error: keyError } = await db.from("api_keys")
		.select("tenant_id,user_id,agent_id,revoked").eq("key_hash", keyHash).maybeSingle();
	if (keyError) return corsJson(req, 503, { error: "authorization_unavailable" });
	if (!key || key.revoked) return corsJson(req, 401, { error: "invalid_api_key" });
	if (!isUuid(key.tenant_id) || !isUuid(key.agent_id)) {
		return corsJson(req, 403, { error: "agent_bound_key_required" });
	}
	const [{ data: member, error: memberError }, { data: tenant, error: tenantError },
		{ data: agent, error: agentError }] = await Promise.all([
			db.from("tenant_members").select("role,expires_at")
				.eq("tenant_id", key.tenant_id).eq("user_id", key.user_id).maybeSingle(),
			db.from("tenants").select("status").eq("id", key.tenant_id).maybeSingle(),
			db.from("agents").select("id").eq("tenant_id", key.tenant_id)
				.eq("id", key.agent_id).maybeSingle(),
		]);
	if (memberError || tenantError || agentError) {
		return corsJson(req, 503, { error: "authorization_unavailable" });
	}
	if (!membershipActive(member) || tenant?.status !== "active" || !agent) {
		return corsJson(req, 403, { error: "agent_access_denied" });
	}
	return { tenantId: key.tenant_id, agentId: key.agent_id, keyHash };
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
		const db = deps.db ?? createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, {
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
			const rate = await consumeTenantRateLimit(db, {
				tenantId: identity.tenantId,
				subject: identity.agentId,
				endpoint: "fleet-response-device",
				perSubject: 240,
				perTenant: 50_000,
			});
			if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
			if (action === "poll") {
				const { data, error } = await db.rpc("poll_fleet_response_command", {
					p_key_hash: identity.keyHash,
					p_tenant_id: identity.tenantId,
					p_agent_id: identity.agentId,
				});
				if (error) return commandError(req, error, "fleet_poll_unavailable");
				return corsJson(req, 200, {
					ok: true,
					command: data ? deviceCommandView(data as Record<string, unknown>) : null,
				});
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

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	// api_key -> user_id (hash-only)
	const keyHash = await sha256Hex(apiKey);
	const { data: keyRow, error: keyErr } = await supabase
		.from("api_keys")
		.select("user_id, tenant_id, revoked")
		.eq("key_hash", keyHash)
		.maybeSingle();
	if (keyErr || !keyRow || keyRow.revoked) {
		return json(401, { error: "invalid_api_key" });
	}
	const tenantId = (keyRow.tenant_id as string | null) ?? (keyRow.user_id as string);

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

	const payload = {
		schema_version: 1,
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

	return json(200, {
		revocations_signed: sig
			? {
					alg: "ed25519",
					key_id: REVOCATION_SIGNING_KEY_ID,
					sig_b64: sig,
					payload: JSON.parse(payloadJson),
				}
			: null,
	});
});
