// Supabase Edge Function: POST /v1/enroll
//
// Auth: Authorization: Bearer <enrollment_token_plaintext | fleet_enrollment_key>
// Body: { iid, agent_runtime, agent_runtime_version }
//
// Exchanges a one-time enrollment token, or a multi-use fleet enrollment key
// (`aidr_fleet_`, see _shared/fleet-keys.ts), for a per-machine API key and
// (optionally) returns a signed entitlement. Both paths enforce tenant
// admission and seat allocation in one database transaction; API keys stay
// hash-only at rest.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { canonicalJson } from "../_shared/canonical-json.ts";
import { entitledPackKeys } from "../_shared/pack-keys.ts";
import { configFailure, loadConfig, partialGroupError, runtimeEnv } from "../_shared/config.ts";
import { capEntitlementTimes, parseActiveAdmission, parseEffectiveSeats } from "../_shared/effective-seats.ts";
import { fleetEnrollRateLimit, isFleetKeyBearer, isWellFormedFleetKey } from "../_shared/fleet-keys.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
import { entitlementWindow, validateEnrollmentBody } from "./contract.ts";
import { buildPremiumModules, tenantRuntimeCapabilities } from "../_shared/runtime-capabilities.ts";
import { signerHealthy } from "../_shared/signing-health.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

const ENTITLEMENT_SIGNING_KEY_ID = (Deno.env.get("AIDR_ENTITLEMENT_SIGNING_KEY_ID") ?? "").trim();
const ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64 = (
	Deno.env.get("AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64") ?? ""
).trim();
// Premium pack keys: same derivation and shared-key set as /v1/ingest (_shared/pack-keys.ts).
const PACK_MASTER_KEY_B64 = (Deno.env.get("AIDR_PACK_MASTER_KEY_B64") ?? "").trim();
const SHARED_PACK_KEYS = Deno.env.get("AIDR_SHARED_PACK_KEYS") ?? "";

const ENTITLEMENT_TTL_HOURS = Deno.env.get("AIDR_ENTITLEMENT_TTL_HOURS") ?? "168";
const ENTITLEMENT_GRACE_HOURS = Deno.env.get("AIDR_ENTITLEMENT_GRACE_HOURS") ?? "72";
const MAX_ENROLL_BODY_BYTES = 8 * 1024;

// Abuse throttling for enrollment token exchange.
const ENROLL_RATE_LIMIT_PER_MIN = Number(Deno.env.get("AIDR_ENROLL_RL_PER_MIN") ?? "30");
// Fleet keys get one bucket per key (not per creating admin), sized for a
// 500+ machine rollout; machines answered 429 retry after the window.
const FLEET_ENROLL_RATE_LIMIT_PER_MIN = fleetEnrollRateLimit(Deno.env.get("AIDR_ENROLL_FLEET_RL_PER_MIN"));
// Deployment-wide budget for bearer values that resolve to no enrollment token.
// It is checked before resolve_enrollment_token, so guessing cannot buy
// unbounded token lookups; a resolvable token never consumes it.
const ENROLL_UNRESOLVED_RATE_LIMIT_PER_MIN = Number(Deno.env.get("AIDR_ENROLL_UNRESOLVED_RL_PER_MIN") ?? "300");
const ENROLL_UNRESOLVED_RATE_KEY = "enroll:v1:unresolved";

function json(status: number, body: Record<string, unknown>) {
	// Every error before exchange is safe to retry. Branches that may have
	// committed explicitly override this; a consumed token never proves rollback.
	const responseBody = status >= 400 ? { enrollment_outcome: "not_committed", ...body } : body;
	return new Response(JSON.stringify(responseBody), {
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
	if (ENTITLEMENT_SIGNING_KEY_ID && !(await signerHealthy(
		`${ENTITLEMENT_SIGNING_KEY_ID}\n${ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64}`,
		async () => (await signEd25519Detached("aidr-signing-healthcheck")) !== null,
	))) {
		return json(503, { error: "entitlement_signing_unavailable" });
	}
	if (!Number.isSafeInteger(ENROLL_RATE_LIMIT_PER_MIN)
		|| ENROLL_RATE_LIMIT_PER_MIN < 1 || ENROLL_RATE_LIMIT_PER_MIN > 10_000) {
		return json(503, { error: "enrollment_rate_limit_config_invalid" });
	}
	if (!Number.isSafeInteger(ENROLL_UNRESOLVED_RATE_LIMIT_PER_MIN)
		|| ENROLL_UNRESOLVED_RATE_LIMIT_PER_MIN < 1 || ENROLL_UNRESOLVED_RATE_LIMIT_PER_MIN > 100_000) {
		return json(503, { error: "enrollment_rate_limit_config_invalid" });
	}
	if (FLEET_ENROLL_RATE_LIMIT_PER_MIN === null) {
		return json(503, { error: "enrollment_rate_limit_config_invalid" });
	}
	const window = entitlementWindow(new Date(), ENTITLEMENT_TTL_HOURS, ENTITLEMENT_GRACE_HOURS);
	if (!window) return json(503, { error: "entitlement_timing_unavailable" });

	const enrollToken = getBearerToken(req);
	if (!enrollToken) return json(401, { error: "missing_enrollment_token" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const tokenHash = await sha256Hex(enrollToken);
	const nowMin = Math.floor(Date.now() / 60000);
	// Fail closed: once this window's unresolved-token budget is spent, no
	// further bearer value is looked up until the window rolls over.
	const { data: unresolvedRow, error: unresolvedReadError } = await supabase.from("rate_limits").select("count")
		.eq("key", ENROLL_UNRESOLVED_RATE_KEY).eq("window_start", nowMin).maybeSingle();
	if (unresolvedReadError) return json(503, { error: "enrollment_rate_limit_unavailable" });
	const unresolvedCount = unresolvedRow == null ? 0 : Number((unresolvedRow as Record<string, unknown>).count);
	if (!Number.isSafeInteger(unresolvedCount) || unresolvedCount < 0) {
		return json(503, { error: "enrollment_rate_limit_unavailable" });
	}
	if (unresolvedCount >= ENROLL_UNRESOLVED_RATE_LIMIT_PER_MIN) return json(429, { error: "rate_limited" });
	// Resolve the token before selecting a rate-limit bucket. Never let an
	// attacker choose an arbitrary bucket with an unverified bearer value. A
	// malformed fleet key is charged to the unresolved budget without a lookup.
	const fleet = isFleetKeyBearer(enrollToken);
	const { data: resolvedToken, error: resolveError } = fleet
		? isWellFormedFleetKey(enrollToken)
			? await supabase.rpc("resolve_fleet_enrollment_key", { p_key_hash: tokenHash })
			: { data: null, error: null }
		: await supabase.rpc("resolve_enrollment_token", { p_token_hash: tokenHash });
	const resolved = resolvedToken && typeof resolvedToken === "object" && !Array.isArray(resolvedToken)
		? resolvedToken as Record<string, unknown> : null;
	if (resolveError || !resolved || typeof resolved.tenant_id !== "string" || typeof resolved.user_id !== "string"
		|| (fleet && typeof resolved.key_id !== "string")) {
		if (resolveError) return json(503, { error: "enrollment_authorization_unavailable" });
		const { error: unresolvedUpdateError } = await supabase.rpc("increment_rate_limit", {
			p_key: ENROLL_UNRESOLVED_RATE_KEY, p_window_start: nowMin, p_delta: 1,
		});
		if (unresolvedUpdateError) return json(503, { error: "enrollment_rate_limit_unavailable" });
		return json(401, {
			error: "invalid_or_expired_enrollment_token", enrollment_outcome: "unknown",
		});
	}
	const rateKey = fleet
		? `enroll:fleet:${resolved.key_id}`
		: `enroll:${resolved.tenant_id}:${resolved.user_id}`;
	const rateLimit = fleet ? FLEET_ENROLL_RATE_LIMIT_PER_MIN : ENROLL_RATE_LIMIT_PER_MIN;
	const { error: rateUpdateError } = await supabase.rpc("increment_rate_limit", {
		p_key: rateKey, p_window_start: nowMin, p_delta: 1,
	});
	if (rateUpdateError) return json(503, { error: "enrollment_rate_limit_unavailable" });
	const { data: rateCount, error: rateReadError } = await supabase.from("rate_limits").select("count")
		.eq("key", rateKey).eq("window_start", nowMin).single();
	if (rateReadError) return json(503, { error: "enrollment_rate_limit_unavailable" });
	const count = Number(rateCount?.count);
	if (!Number.isSafeInteger(count) || count < 1) {
		return json(503, { error: "enrollment_rate_limit_unavailable" });
	}
	if (count > rateLimit) {
		return json(429, fleet ? { error: "rate_limited", retry_after_seconds: 60 - (Math.floor(Date.now() / 1000) % 60) }
			: { error: "rate_limited" });
	}

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
	const runtime = {
		p_iid: iid,
		p_agent_runtime: body.agent_runtime,
		p_agent_runtime_version: body.agent_runtime_version,
		p_key_hash: keyHash,
	};
	const { data: exchangeData, error: exchangeErr } = fleet
		? await supabase.rpc("exchange_fleet_enrollment_key", { p_fleet_key_hash: tokenHash, ...runtime })
		: await supabase.rpc("exchange_enrollment_token", { p_token_hash: tokenHash, ...runtime });
	if (exchangeErr?.code === "42501") return json(403, { error: "tenant_not_admitted" });
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
	// The fleet key's own seat cap is spent; the tenant may still have seats.
	if (exchange?.status === "fleet_key_exhausted") {
		return json(409, {
			error: "fleet_key_exhausted",
			seat_cap: Number(exchange.seat_cap ?? 0),
			enrolled_count: Number(exchange.enrolled_count ?? 0),
		});
	}
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
	const storedExtraAgents = Number(exchange.extra_agents);
	const registeredAllowed = Number(exchange.allowed_agents);
	const revocationEpoch = Number(exchange.revocation_epoch);
	if (![includedAgents, storedExtraAgents, registeredAllowed, revocationEpoch]
		.every((value) => Number.isSafeInteger(value) && value >= 0)) {
		return json(503, { error: "enrollment_exchange_result_invalid", enrollment_outcome: "committed" });
	}
	// Reconcile the committed registration against the provider's current term.
	// A missed webhook cannot mint a paid offline entitlement past that date.
	const { data: effectiveRows, error: effectiveErr } = await supabase.rpc(
		"effective_tenant_seats", { p_tenant_id: tenantId },
	);
	const effective = effectiveErr ? null : parseEffectiveSeats(effectiveRows);
	if (!effective || registeredAllowed < includedAgents ||
		registeredAllowed > includedAgents + effective.extraAgents) {
		return json(503, { error: "enrollment_committed_entitlement_unavailable", enrollment_outcome: "committed" });
	}
	const { data: admissionData, error: admissionError } = await supabase.rpc(
		"get_tenant_admission", { p_tenant_id: tenantId, p_user_id: userId },
	);
	const admission = admissionError ? null : parseActiveAdmission(admissionData);
	if (!admission || registeredAllowed > admission.allowedAgents) {
		return json(503, { error: "enrollment_committed_admission_unavailable", enrollment_outcome: "committed" });
	}
	const allowedAgents = registeredAllowed;
	const extraAgents = allowedAgents - includedAgents;
	const providerUntil = extraAgents > 0 ? effective.providerValidUntilMs : null;
	const cappedWindow = capEntitlementTimes(
		window.expiresAt, window.graceUntil,
		admission.validUntilMs === null ? providerUntil
			: providerUntil === null ? admission.validUntilMs
				: Math.min(providerUntil, admission.validUntilMs),
	);
	if (!cappedWindow) {
		return json(503, { error: "enrollment_committed_entitlement_unavailable", enrollment_outcome: "committed" });
	}

	// 4) Return signed entitlement snapshot (same contract as ingest).
	const capabilities = ENTITLEMENT_SIGNING_KEY_ID ? tenantRuntimeCapabilities(
		tenantId, Deno.env.get("AIDR_RUNTIME_CAPABILITIES_BY_TENANT"), admissionData,
	) : [];
	const premiumModules = buildPremiumModules(exchange, capabilities);
	const packKeys = premiumModules.includes("premium_intel")
		? await entitledPackKeys({ masterB64: PACK_MASTER_KEY_B64, sharedKeys: SHARED_PACK_KEYS, tenantId })
		: [];
	const entitlement = {
		schema_version: 2,
		tenant_id: tenantId,
		subscription_tier: extraAgents > 0 ? "pro" : "free",
		included_agents: includedAgents,
		extra_agents: extraAgents,
		allowed_agents: allowedAgents,
		premium_modules: premiumModules,
		pack_keys: premiumModules.includes("premium_intel")
			? packKeys.map((key) => ({
					alg: "aes-256-gcm",
					key_id: key.key_id,
					key_b64: key.key_b64,
					expires_at: cappedWindow.graceUntil,
				}))
			: [],
		issued_at: window.issuedAt,
		expires_at: cappedWindow.expiresAt,
		grace_until: cappedWindow.graceUntil,
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

	// Best-effort audit log. A fleet enrollment was already audited inside
	// exchange_fleet_enrollment_key, in the same transaction as the key.
	if (!fleet) {
		try {
			await supabase.from("admin_audit_logs").insert({
				actor_user_id: userId,
				tenant_id: tenantId,
				action: "enroll.consume_token",
				target_user_id: userId,
				detail: { iid, runtime_capabilities: capabilities },
			});
		} catch {
			// Post-commit audit transport failure must not hide the plaintext key.
		}
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
