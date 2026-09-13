// Supabase Edge Function: POST /v1/enroll
//
// Auth: Authorization: Bearer <enrollment_token_plaintext>
// Body: { iid, agent_runtime, agent_runtime_version }
//
// Exchanges a one-time enrollment token for an API key and (optionally) returns a signed entitlement.
// This makes first-time setup easy while keeping API keys hash-only at rest.

import { createClient } from "npm:@supabase/supabase-js@2";
import { configFailure, loadConfig, partialGroupError, runtimeEnv } from "../_shared/config.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
import { entitlementWindow, validateEnrollmentBody } from "./contract.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

const ENTITLEMENT_SIGNING_KEY_ID = (Deno.env.get("AIDR_ENTITLEMENT_SIGNING_KEY_ID") ?? "").trim();
const ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64 = (
	Deno.env.get("AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64") ?? ""
).trim();
const PACK_MASTER_KEY_B64 = (Deno.env.get("AIDR_PACK_MASTER_KEY_B64") ?? "").trim();

const ENTITLEMENT_TTL_HOURS = Deno.env.get("AIDR_ENTITLEMENT_TTL_HOURS") ?? "168";
const ENTITLEMENT_GRACE_HOURS = Deno.env.get("AIDR_ENTITLEMENT_GRACE_HOURS") ?? "72";
const MAX_ENROLL_BODY_BYTES = 8 * 1024;

// Abuse throttling for enrollment token exchange.
const ENROLL_RATE_LIMIT_PER_MIN = Number(Deno.env.get("AIDR_ENROLL_RL_PER_MIN") ?? "30");

function json(status: number, body: Record<string, unknown>) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function getBearerToken(req: Request): string | null {
	const header = req.headers.get("Authorization") ?? "";
	const m = header.match(/^Bearer\s+(.+)$/i);
	const token = m?.[1]?.trim() ?? "";
	return token.length > 0 && token.length <= 512 ? token : null;
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

function base64Url(bytes: Uint8Array): string {
	const b64 = bytesToBase64(bytes);
	return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function randomApiKey(): string {
	const raw = new Uint8Array(32);
	crypto.getRandomValues(raw);
	return `aidr_live_${base64Url(raw)}`;
}

async function signEd25519Detached(payloadJson: string): Promise<string | null> {
	if (!ENTITLEMENT_SIGNING_KEY_ID || !ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64) return null;
	try {
		const pkcs8 = Uint8Array.from(
			atob(ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64),
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

async function deriveTenantPackKeyB64(userId: string): Promise<string | null> {
	if (!PACK_MASTER_KEY_B64) return null;
	try {
		const master = Uint8Array.from(atob(PACK_MASTER_KEY_B64), (c) => c.charCodeAt(0));
		const key = await crypto.subtle.importKey("raw", master, "HKDF", false, ["deriveBits"]);
		const bits = await crypto.subtle.deriveBits(
			{
				name: "HKDF",
				hash: "SHA-256",
				salt: new Uint8Array(),
				info: new TextEncoder().encode(`aidr:packkey:${userId}`),
			},
			key,
			256,
		);
		return bytesToBase64(new Uint8Array(bits));
	} catch {
		return null;
	}
}

async function rateLimitKey(
	supabase: ReturnType<typeof createClient>,
	key: string,
	limitPerMinute: number,
): Promise<boolean> {
	const nowMin = Math.floor(Date.now() / 60000);
	const { error: updErr } = await supabase.rpc("increment_rate_limit", {
		p_key: key,
		p_window_start: nowMin,
		p_delta: 1,
	});
	if (updErr) return false;

	const { data: after, error: countErr } = await supabase
		.from("rate_limits")
		.select("count")
		.eq("key", key)
		.eq("window_start", nowMin)
		.single();
	if (countErr) return false;
	const count = Number(after?.count ?? 0);
	return Number.isFinite(limitPerMinute) && limitPerMinute > 0 ? count <= limitPerMinute : true;
}

function buildPremiumModules(entRow: Record<string, unknown> | null): string[] {
	const out: string[] = [];
	if (entRow && entRow.premium_intel === true) out.push("premium_intel");
	if (entRow && entRow.premium_correlation === true) out.push("premium_correlation");
	if (entRow && entRow.premium_pkg_plugin === true) out.push("premium_pkg_plugin");
	return out;
}

Deno.serve(async (req) => {
	if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("enroll", config.error, json);
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

	// Signing is optional provisioning, but a HALF-configured key pair is a
	// misconfiguration: the operator believes the issued entitlement is signed
	// while the response would silently carry `entitlement_signed: null`.
	const signingProblem = partialGroupError({
		AIDR_ENTITLEMENT_SIGNING_KEY_ID: ENTITLEMENT_SIGNING_KEY_ID,
		AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64: ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64,
	});
	if (signingProblem) return configFailure("enroll", signingProblem, json);
	if (ENTITLEMENT_SIGNING_KEY_ID && !(await signEd25519Detached("aidr-signing-healthcheck"))) {
		return json(503, { error: "entitlement_signing_unavailable" });
	}
	if (!Number.isSafeInteger(ENROLL_RATE_LIMIT_PER_MIN)
		|| ENROLL_RATE_LIMIT_PER_MIN < 1 || ENROLL_RATE_LIMIT_PER_MIN > 10_000) {
		return json(503, { error: "enrollment_rate_limit_config_invalid" });
	}
	const window = entitlementWindow(new Date(), ENTITLEMENT_TTL_HOURS, ENTITLEMENT_GRACE_HOURS);
	if (!window) return json(503, { error: "entitlement_timing_unavailable" });

	const enrollToken = getBearerToken(req);
	if (!enrollToken) return json(401, { error: "missing_enrollment_token" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	// Basic throttling by token hash (best-effort).
	const tokenHash = await sha256Hex(enrollToken);
	const ok = await rateLimitKey(supabase, `enroll:${tokenHash.slice(0, 16)}`, ENROLL_RATE_LIMIT_PER_MIN);
	if (!ok) return json(429, { error: "rate_limited" });

	const parsed = await readBoundedJson(req, MAX_ENROLL_BODY_BYTES);
	if (!parsed.ok) return json(parsed.status, { error: parsed.error });
	const body = validateEnrollmentBody(parsed.value);
	if (!body) return json(400, { error: "invalid_enrollment_body" });
	const { iid } = body;

	// The RPC commits token consumption, tenant admission, seat allocation and
	// hash-only key insertion as one transaction. An RPC transport error may
	// hide a committed response, so the outcome is explicitly unknown there.
	const apiKey = randomApiKey();
	const keyHash = await sha256Hex(apiKey);
	const { data: exchangeData, error: exchangeErr } = await supabase.rpc("exchange_enrollment_token", {
		p_token_hash: tokenHash,
		p_iid: iid,
		p_agent_runtime: body.agent_runtime,
		p_agent_runtime_version: body.agent_runtime_version,
		p_key_hash: keyHash,
	});
	if (exchangeErr) return json(503, { error: "enrollment_exchange_failed", enrollment_outcome: "unknown" });
	const exchange = exchangeData && typeof exchangeData === "object" && !Array.isArray(exchangeData)
		? exchangeData as Record<string, unknown> : null;
	// A consumed token is indistinguishable from an invalid/expired token here.
	// If the prior HTTP response was lost, the key may already have committed.
	if (exchange?.status === "invalid_token") return json(401, {
		error: "invalid_or_expired_enrollment_token",
		enrollment_outcome: "unknown",
	});
	if (exchange?.status === "tenant_not_authorized") return json(403, { error: "tenant_not_authorized" });
	if (exchange?.status === "missing_entitlements") return json(503, { error: "missing_entitlements" });
	if (exchange?.status === "seat_exceeded") {
		return json(402, {
			error: "agent_limit_exceeded",
			allowed_agents: Number(exchange.allowed_agents ?? 0),
			current_agents: Number(exchange.current_agents ?? 0),
		});
	}
	if (exchange?.status !== "enrolled" || typeof exchange.user_id !== "string"
		|| typeof exchange.tenant_id !== "string" || typeof exchange.agent_id !== "string") {
		return json(503, { error: "enrollment_exchange_result_invalid", enrollment_outcome: "unknown" });
	}
	const userId = exchange.user_id;
	const tenantId = exchange.tenant_id;
	const agentId = exchange.agent_id;
	const includedAgents = Number(exchange.included_agents);
	const extraAgents = Number(exchange.extra_agents);
	const allowedAgents = Number(exchange.allowed_agents);
	const revocationEpoch = Number(exchange.revocation_epoch);
	if (![includedAgents, extraAgents, allowedAgents, revocationEpoch].every(Number.isFinite)) {
		return json(503, { error: "enrollment_exchange_result_invalid", enrollment_outcome: "committed" });
	}

	// 4) Return signed entitlement snapshot (same contract as ingest).
	const premiumModules = buildPremiumModules(exchange);
	const tenantPackKey = premiumModules.includes("premium_intel") ? await deriveTenantPackKeyB64(tenantId) : null;
	const entitlement = {
		schema_version: 2,
		tenant_id: tenantId,
		subscription_tier: extraAgents > 0 ? "pro" : "free",
		included_agents: includedAgents,
		extra_agents: extraAgents,
		allowed_agents: allowedAgents,
		premium_modules: premiumModules,
		pack_keys:
			tenantPackKey && premiumModules.includes("premium_intel")
				? [
						{
							alg: "aes-256-gcm",
							key_id: "aidr-pack-v1",
							key_b64: tenantPackKey,
							expires_at: window.graceUntil,
						},
					]
				: [],
		issued_at: window.issuedAt,
		expires_at: window.expiresAt,
		grace_until: window.graceUntil,
		serial: crypto.randomUUID(),
		revocation_epoch: Number.isFinite(revocationEpoch) ? Math.max(1, Math.floor(revocationEpoch)) : 1,
	};
	const entitlementJson = canonicalJson(entitlement);
	const sig = await signEd25519Detached(entitlementJson);
	if (ENTITLEMENT_SIGNING_KEY_ID && !sig) return json(503, {
		error: "enrollment_committed_entitlement_signing_failed",
		enrollment_outcome: "committed",
	});

	// Best-effort: persist the latest entitlement snapshot per (tenant_id, iid) for dashboard/debugging.
	try {
		const snapshot = JSON.parse(entitlementJson) as Record<string, unknown>;
		await supabase
			.from("entitlement_snapshots")
			.upsert(
				{
					user_id: userId,
					tenant_id: tenantId,
					iid,
					agent_id: agentId,
					entitlement: snapshot,
					sig_alg: sig ? "ed25519" : null,
					sig_key_id: sig ? ENTITLEMENT_SIGNING_KEY_ID : null,
					sig_b64: sig,
					issued_at: typeof snapshot.issued_at === "string" ? snapshot.issued_at : null,
					expires_at: typeof snapshot.expires_at === "string" ? snapshot.expires_at : null,
					grace_until: typeof snapshot.grace_until === "string" ? snapshot.grace_until : null,
				},
				{ onConflict: "tenant_id,iid" },
			);
	} catch {
		// Snapshot persistence is diagnostic-only; enrollment already succeeded.
	}

	// Best-effort audit log
	try {
		await supabase.from("admin_audit_logs").insert({
			actor_user_id: userId,
			tenant_id: tenantId,
			action: "enroll.consume_token",
			target_user_id: userId,
			detail: { iid },
		});
	} catch {
		// Post-commit audit transport failure must not hide the plaintext key.
	}

	return json(200, {
		ok: true,
		api_key: apiKey,
		allowed_agents: allowedAgents,
		entitlement_signed: sig
			? {
					alg: "ed25519",
					key_id: ENTITLEMENT_SIGNING_KEY_ID,
					sig_b64: sig,
					snapshot: JSON.parse(entitlementJson),
				}
			: null,
	});
});
