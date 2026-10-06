// Supabase Edge Function: POST /v1/ingest
//
// Auth: Authorization: Bearer <api_key_plaintext>
// Body: { iid, agent_runtime, agent_runtime_version, aidr_version, events: [...] }
//
// This function:
// - maps api_key -> user_id (via stored sha256 hash)
// - upserts agent by (user_id, iid)
// - enforces agent-seat limit: included_agents + extra_agents
// - idempotently inserts stable event identities for the dashboard

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { capEntitlementTimes, parseActiveAdmission, parseEffectiveSeats } from "../_shared/effective-seats.ts";
import { authenticateTenantApiKey } from "../_shared/api-key-auth.ts";
import { configFailure, loadConfig, partialGroupError, runtimeEnv } from "../_shared/config.ts";
import {
	consumeTenantRateLimit,
	rateLimitHeaders,
	readBoundedJson,
} from "../_shared/request-limits.ts";
import { normalizeIngestEvents } from "./events.ts";
import { buildPremiumModules, tenantRuntimeCapabilities } from "../_shared/runtime-capabilities.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 5 * 1024 * 1024;

// Commercial v1: signed entitlements (Ed25519).
// Key material should be provided via environment variables in the Edge Functions runtime.
const ENTITLEMENT_SIGNING_KEY_ID = (Deno.env.get("AIDR_ENTITLEMENT_SIGNING_KEY_ID") ?? "").trim();
const ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64 = (
	Deno.env.get("AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64") ?? ""
).trim();

// Premium pack encryption: master key used to derive per-tenant pack keys (HKDF-SHA256).
// This secret MUST be kept server-side; clients only receive derived, time-bound keys via entitlements.
const PACK_MASTER_KEY_B64 = (Deno.env.get("AIDR_PACK_MASTER_KEY_B64") ?? "").trim();

// Default: 7d online entitlement TTL, followed by 72h offline grace.
// Keep these limits aligned with /v1/enroll: malformed settings must not mint
// snapshots whose lifetime silently collapses or stretches indefinitely.
const ENTITLEMENT_TTL_HOURS_RAW = Deno.env.get("AIDR_ENTITLEMENT_TTL_HOURS") ?? "168";
const ENTITLEMENT_GRACE_HOURS_RAW = Deno.env.get("AIDR_ENTITLEMENT_GRACE_HOURS") ?? "72";

function parseBoundedHours(raw: string, min: number, max: number): number | null {
	if (!/^\d+$/.test(raw)) return null;
	const hours = Number(raw);
	return Number.isSafeInteger(hours) && hours >= min && hours <= max ? hours : null;
}

function entitlementTiming(): { ttlHours: number; graceHours: number } | null {
	const ttlHours = parseBoundedHours(ENTITLEMENT_TTL_HOURS_RAW, 1, 720);
	const graceHours = parseBoundedHours(ENTITLEMENT_GRACE_HOURS_RAW, 0, 168);
	return ttlHours === null || graceHours === null ? null : { ttlHours, graceHours };
}

function json(
	status: number,
	body: Record<string, unknown>,
	headers: Record<string, string> = {},
) {
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

type IngestBody = {
	iid?: string;
	agent_runtime?: string;
	agent_runtime_version?: string;
	aidr_version?: string;
	events?: unknown;
};

function canonicalizeForSigning(value: unknown): unknown {
	if (Array.isArray(value)) return value.map((v) => canonicalizeForSigning(v));
	if (!value || typeof value !== "object") return value;
	const obj = value as Record<string, unknown>;
	const out: Record<string, unknown> = {};
	for (const key of Object.keys(obj).sort()) {
		out[key] = canonicalizeForSigning(obj[key]);
	}
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

function buildEntitlementSnapshot(params: {
	tenantId: string;
	includedAgents: number;
	extraAgents: number;
	allowedAgents: number;
	premiumModules: string[];
	tenantPackKey: string | null;
	revocationEpoch: number;
	timing: { ttlHours: number; graceHours: number };
	providerValidUntilMs?: number | null;
}) {
	const issuedAt = new Date();
	const normalExpiresAt = new Date(issuedAt.getTime() + params.timing.ttlHours * 3_600_000);
	const normalGraceUntil = new Date(normalExpiresAt.getTime() + params.timing.graceHours * 3_600_000);
	const capped = capEntitlementTimes(
		normalExpiresAt.toISOString(), normalGraceUntil.toISOString(),
		params.providerValidUntilMs ?? null, issuedAt.getTime(),
	);
	if (!capped) return null;
	return {
		schema_version: 2,
		tenant_id: params.tenantId,
		subscription_tier: params.extraAgents > 0 ? "pro" : "free",
		included_agents: params.includedAgents,
		extra_agents: params.extraAgents,
		allowed_agents: params.allowedAgents,
		premium_modules: params.premiumModules,
		pack_keys:
			params.tenantPackKey && params.premiumModules.includes("premium_intel")
				? [
						{
							alg: "aes-256-gcm",
							key_id: "aidr-pack-v1",
							key_b64: params.tenantPackKey,
							// A pack key never outlives its signed entitlement. It remains
							// usable during the explicitly configured offline grace window.
							expires_at: capped.graceUntil,
						},
					]
				: [],
		issued_at: issuedAt.toISOString(),
		expires_at: capped.expiresAt,
		grace_until: capped.graceUntil,
		serial: crypto.randomUUID(),
		revocation_epoch: params.revocationEpoch,
	};
}

Deno.serve(async (req) => {
	if (req.method !== "POST") {
		return json(405, { error: "method_not_allowed" });
	}

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("ingest", config.error, json);
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

	// Signing is optional provisioning, but a HALF-configured key pair is a
	// misconfiguration: the operator believes entitlements are signed while the
	// function would silently answer with `entitlement_signed: null`.
	const signingProblem = partialGroupError({
		AIDR_ENTITLEMENT_SIGNING_KEY_ID: ENTITLEMENT_SIGNING_KEY_ID,
		AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64: ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64,
	});
	if (signingProblem) return configFailure("ingest", signingProblem, json);
	if (ENTITLEMENT_SIGNING_KEY_ID && !(await signEd25519Detached("aidr-signing-healthcheck"))) {
		return json(503, { error: "entitlement_signing_unavailable", retryable: true });
	}
	const timing = entitlementTiming();
	if (!timing) return json(503, { error: "entitlement_timing_unavailable" });

	const apiKey = getBearerToken(req);
	if (!apiKey) {
		return json(401, { error: "missing_api_key" });
	}
	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});
	const tenantAuth = await authenticateTenantApiKey(supabase, apiKey);
	if (!tenantAuth.ok) return json(tenantAuth.status, { error: tenantAuth.error });

	const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
	if (!parsed.ok) return json(parsed.status, { error: parsed.error });
	if (!parsed.value || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
		return json(400, { error: "invalid_json" });
	}
	const body = parsed.value as IngestBody;

	const iid = typeof body.iid === "string" ? body.iid.trim() : "";
	if (!iid || iid.length > 128) {
		return json(400, { error: "missing_iid" });
	}
	if (
		[body.agent_runtime, body.agent_runtime_version, body.aidr_version].some(
			(value) => typeof value === "string" && value.length > 128,
		)
	) {
		return json(400, { error: "invalid_agent_metadata" });
	}

	const normalizedEvents = normalizeIngestEvents(body.events);
	if (!normalizedEvents.ok) {
		return json(normalizedEvents.status, {
			error: normalizedEvents.error,
			...(normalizedEvents.detail ? { detail: normalizedEvents.detail } : {}),
		});
	}
	const events = normalizedEvents.events;
	if (events.length === 0) {
		// Allow heartbeat-style calls to update last_seen.
	}

	const rate = await consumeTenantRateLimit(supabase, {
		tenantId: tenantAuth.tenantId,
		subject: tenantAuth.userId,
		endpoint: "ingest",
		perSubject: 1_200,
		perTenant: 50_000,
		cost: Math.max(1, events.length),
	});
	if (!rate.ok) return json(rate.status, { error: rate.error }, rateLimitHeaders(rate));

	// Shared auth supplies the binding for either the active key or a valid overlap key.
	const userId = tenantAuth.userId;
	const tenantId = tenantAuth.tenantId;
	if (tenantAuth.agentId) {
		const { data: bound, error: boundError } = await supabase
			.from("agents")
			.select("iid")
			.eq("id", tenantAuth.agentId)
			.eq("tenant_id", tenantId)
			.maybeSingle();
		if (boundError || !bound || bound.iid !== iid)
			return json(403, { error: "agent_key_mismatch" });
	}

	// 2) load the explicit entitlement row. An absent row is not a free grant.
	const { data: ent, error: entErr } = await supabase
		.from("entitlements")
		.select(
			"included_agents, extra_agents, premium_intel, premium_correlation, premium_pkg_plugin, revocation_epoch",
		)
		.eq("tenant_id", tenantId)
		.maybeSingle();
	if (entErr) return json(503, { error: "entitlements_unavailable", retryable: true });
	if (!ent) return json(403, { error: "entitlement_not_provisioned" });

	const includedAgents = Number(ent.included_agents);
	const storedExtraAgents = Number(ent.extra_agents);
	const revocationEpoch = Number((ent as unknown as Record<string, unknown>).revocation_epoch);
	if (!Number.isSafeInteger(includedAgents) || includedAgents < 0 ||
		!Number.isSafeInteger(storedExtraAgents) || storedExtraAgents < 0 ||
		!Number.isSafeInteger(revocationEpoch) || revocationEpoch < 0) {
		return json(503, { error: "entitlements_unavailable", retryable: true });
	}

	// 3) Register/touch the agent and enforce the seat limit atomically. The
	// database function locks the tenant entitlement and agent namespace so two
	// first-seen requests cannot oversubscribe the tenant.
	const { data: registrationRows, error: registrationErr } = await supabase.rpc(
		"register_agent_for_ingest",
		{
			p_user_id: userId,
			p_tenant_id: tenantId,
			p_iid: iid,
			p_agent_runtime: typeof body.agent_runtime === "string" ? body.agent_runtime : null,
			p_agent_runtime_version:
				typeof body.agent_runtime_version === "string" ? body.agent_runtime_version : null,
		},
	);
	if (registrationErr) {
		if (registrationErr.code === "42501") return json(403, { error: "tenant_not_admitted" });
		// Never expose raw Postgres/Supabase errors to an untrusted ingest client.
		return json(503, { error: "agent_registration_unavailable", retryable: true });
	}
	const registration = (Array.isArray(registrationRows) ? registrationRows[0] : null) as Record<
		string,
		unknown
	> | null;
	const agentId = typeof registration?.agent_id === "string" ? registration.agent_id : null;
	if (!registration) {
		return json(500, { error: "agent_registration_failed" });
	}
	// Stored extra_agents is only a billing projection. Re-read authoritative
	// provider term after registration, then never sign more seats than its cap.
	const { data: effectiveRows, error: effectiveErr } = await supabase.rpc(
		"effective_tenant_seats", { p_tenant_id: tenantId },
	);
	const effective = effectiveErr ? null : parseEffectiveSeats(effectiveRows);
	const registeredAllowed = Number(registration.allowed_agents);
	if (!effective || !Number.isSafeInteger(registeredAllowed) || registeredAllowed < includedAgents) {
		return json(503, { error: "entitlements_unavailable", retryable: true });
	}
	const { data: admissionData, error: admissionError } = await supabase.rpc(
		"get_tenant_admission", { p_tenant_id: tenantId, p_user_id: userId },
	);
	if (admissionError) return json(503, { error: "admission_unavailable", retryable: true });
	if (admissionData && typeof admissionData === "object" && !Array.isArray(admissionData)
		&& ["expired", "revoked", "none", "not_entitled", "unconfigured"].includes(String((admissionData as Record<string, unknown>).status))) {
		return json(403, { error: "tenant_not_admitted" });
	}
	const admission = parseActiveAdmission(admissionData);
	if (!admission) return json(503, { error: "admission_unavailable", retryable: true });
	const capabilities = ENTITLEMENT_SIGNING_KEY_ID ? tenantRuntimeCapabilities(
		tenantId, Deno.env.get("AIDR_RUNTIME_CAPABILITIES_BY_TENANT"), admissionData,
	) : [];
	const premiumModules = buildPremiumModules(ent as unknown as Record<string, unknown>, capabilities);
	const allowedAgents = Math.min(includedAgents + effective.extraAgents, registeredAllowed, admission.allowedAgents);
	const extraAgents = allowedAgents - includedAgents;
	const providerUntil = extraAgents > 0 ? effective.providerValidUntilMs : null;
	const providerValidUntilMs = admission.validUntilMs === null ? providerUntil
		: providerUntil === null ? admission.validUntilMs
			: Math.min(providerUntil, admission.validUntilMs);
	if (registration.seat_exceeded !== true && registeredAllowed > allowedAgents) {
		// The provider term or seat count changed between registration and this
		// read. Retry registration under the new cap before acknowledging events.
		return json(503, { error: "entitlements_changed", retryable: true });
	}
	if (registration.seat_exceeded === true) {
		const current = Number(registration.current_agents ?? 0);
		const tenantPackKey = premiumModules.includes("premium_intel")
			? await deriveTenantPackKeyB64(tenantId)
			: null;
		const entitlement = buildEntitlementSnapshot({
			tenantId, includedAgents, extraAgents, allowedAgents, premiumModules,
			tenantPackKey, revocationEpoch, timing, providerValidUntilMs,
		});
		if (!entitlement) return json(503, { error: "entitlements_unavailable", retryable: true });
		const entitlementJson = canonicalJson(entitlement);
		const sig = await signEd25519Detached(entitlementJson);
		if (ENTITLEMENT_SIGNING_KEY_ID && !sig) return json(503, { error: "entitlement_signing_unavailable", retryable: true });
		return json(402, {
			error: "agent_limit_exceeded",
			allowed_agents: Number(registration.allowed_agents ?? allowedAgents),
			current_agents: current,
			entitlement: JSON.parse(entitlementJson),
			entitlement_signed: sig
				? {
						alg: "ed25519",
						key_id: ENTITLEMENT_SIGNING_KEY_ID,
						sig_b64: sig,
						snapshot: JSON.parse(entitlementJson),
					}
				: null,
			entitlement_sig_alg: sig ? "ed25519" : null,
			entitlement_key_id: sig ? ENTITLEMENT_SIGNING_KEY_ID : null,
			entitlement_sig: sig,
		});
	}
	if (!agentId) {
		return json(500, { error: "agent_registration_failed" });
	}

	// 4) Insert events idempotently. A database failure is retryable and must be
	// visible to the durable client queue; returning ok here would lose events.
	if (events.length > 0 && agentId) {
		const rows = events.map((evt) => ({
			user_id: userId,
			tenant_id: tenantId,
			agent_id: agentId,
			event_id: evt.event_id,
			type: typeof evt.type === "string" ? (evt.type as string) : "runtime_verdict",
			payload: evt,
		}));

		const { error: evtErr } = await supabase
			.from("events")
			.upsert(rows, { onConflict: "tenant_id,event_id", ignoreDuplicates: true });
		if (evtErr) {
			// The write-boundary guard can reject a seat reduction or revoked
			// admission after registration. Retrying that durable batch forever
			// cannot restore authorization; never acknowledge it as inserted.
			if (evtErr.code === "42501") return json(403, { error: "agent_not_authorized" });
			// Detection stays local/fail-open, while telemetry delivery remains explicitly unavailable.
			return json(503, { error: "events_insert_failed", retryable: true });
		}
	}

	const tenantPackKey = premiumModules.includes("premium_intel")
		? await deriveTenantPackKeyB64(tenantId)
		: null;

	const entitlement = buildEntitlementSnapshot({
		tenantId, includedAgents, extraAgents, allowedAgents, premiumModules,
		tenantPackKey, revocationEpoch, timing, providerValidUntilMs,
	});
	if (!entitlement) return json(503, { error: "entitlements_unavailable", retryable: true });
	const entitlementJson = canonicalJson(entitlement);
	const sig = await signEd25519Detached(entitlementJson);
	if (ENTITLEMENT_SIGNING_KEY_ID && !sig) return json(503, { error: "entitlement_signing_unavailable", retryable: true });

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
		// Fail-open: snapshot storage must never block ingest.
	}

	return json(200, {
		ok: true,
		acknowledged_event_ids: events.map((event) => event.event_id),
		agent_id: agentId,
		allowed_agents: allowedAgents,
		entitlement: JSON.parse(entitlementJson),
		entitlement_signed: sig
			? {
					alg: "ed25519",
					key_id: ENTITLEMENT_SIGNING_KEY_ID,
					sig_b64: sig,
					snapshot: JSON.parse(entitlementJson),
				}
			: null,
		entitlement_sig_alg: sig ? "ed25519" : null,
		entitlement_key_id: sig ? ENTITLEMENT_SIGNING_KEY_ID : null,
		entitlement_sig: sig,
	}, rateLimitHeaders(rate));
});
