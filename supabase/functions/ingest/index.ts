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
//
// Browser Guard installs use agent_runtime "browser_guard" and send counts-only
// "privacy_scan", "shadow_ai_usage" and "aup_acknowledgement" events
// (docs/contracts/privacy-telemetry.md). Each install is a protected agent seat
// like any other runtime; events.ts projects the events.
//
// Browser Guard should authenticate with an `ingest:browser_guard` key, not a
// tenant key: its credential sits in browser management policy where any user
// of the profile can read it. That key may only send those event types as
// the browser_guard runtime, is rate limited per key, registers at most its
// `install_limit` installations, and never receives the signed entitlement
// (which can carry the tenant pack key).
//
// Plan gating: an `ingest:browser_guard` key requires the tenant plan feature
// `browser_privacy_guard` (Team and up), and AI Security Posture findings
// (infra_scan_finding, mcp_inventory_finding, agent_posture_finding) require
// `ai_security_posture` (Business and up). Verdict and runtime events from
// connectors are never plan-gated.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { type ApprovalPublicKey, loadApprovalPublicKeys } from "../_shared/approval-token.ts";
import { capEntitlementTimes, parseActiveAdmission, parseEffectiveSeats } from "../_shared/effective-seats.ts";
import {
	apiKeyRateSubject,
	authenticateTenantApiKeyBudgeted,
	BROWSER_GUARD_INGEST_SCOPE,
} from "../_shared/api-key-auth.ts";
import { canonicalJson } from "../_shared/canonical-json.ts";
import { entitledPackKeys } from "../_shared/pack-keys.ts";
import { configFailure, loadConfig, partialGroupError, runtimeEnv } from "../_shared/config.ts";
import {
	consumeTenantRateLimit,
	rateLimitHeaders,
	readBoundedJson,
} from "../_shared/request-limits.ts";
import { normalizeIngestEvents } from "./events.ts";
import { partitionPostureEvents } from "./posture.ts";
import { requireFeature } from "../_shared/plan-entitlements.ts";
import { signerHealthy } from "../_shared/signing-health.ts";
import { buildPremiumModules, tenantRuntimeCapabilities } from "../_shared/runtime-capabilities.ts";
import {
	type TenantSlotRejection,
	tenantSlotGate,
	tenantSlotResponse,
	withTenantSlot,
} from "../_shared/tenant-concurrency.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 5 * 1024 * 1024;

const BROWSER_GUARD_RUNTIME = "browser_guard";
// Fair-share admission against the leases shared with policy (AIDR_TENANT_INFLIGHT_*).
const admitTenantRequest = tenantSlotGate(runtimeEnv);
// Counts-only Browser Guard events (docs/contracts/privacy-telemetry.md).
const BROWSER_GUARD_EVENT_TYPES: ReadonlySet<string> = new Set([
	"privacy_scan",
	"shadow_ai_usage",
	"aup_acknowledgement",
]);
const TENANT_INGEST_EVENTS_PER_MIN = 50_000;
// Events per minute one `ingest:browser_guard` key may deliver across all of
// its installations. A malformed value fails closed (rate_limit_unavailable).
const BROWSER_KEY_EVENTS_PER_MIN_RAW = (Deno.env.get("AIDR_BROWSER_KEY_INGEST_RL_PER_MIN") ?? "6000").trim();

function browserKeyEventsPerMinute(): number {
	if (!/^\d{1,6}$/.test(BROWSER_KEY_EVENTS_PER_MIN_RAW)) return Number.NaN;
	const value = Number(BROWSER_KEY_EVENTS_PER_MIN_RAW);
	return value >= 1 && value <= TENANT_INGEST_EVENTS_PER_MIN ? value : Number.NaN;
}

// Commercial v1: signed entitlements (Ed25519).
// Key material should be provided via environment variables in the Edge Functions runtime.
const ENTITLEMENT_SIGNING_KEY_ID = (Deno.env.get("AIDR_ENTITLEMENT_SIGNING_KEY_ID") ?? "").trim();
const ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64 = (
	Deno.env.get("AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64") ?? ""
).trim();

// Premium pack keys (see _shared/pack-keys.ts): the master key derives each
// tenant's pack key (HKDF-SHA256) and AIDR_SHARED_PACK_KEYS holds the keys of
// shared/vendor packs. Both stay server-side; clients only receive the keys
// they are entitled to, time-bound, inside the signed entitlement.
const PACK_MASTER_KEY_B64 = (Deno.env.get("AIDR_PACK_MASTER_KEY_B64") ?? "").trim();
const SHARED_PACK_KEYS = Deno.env.get("AIDR_SHARED_PACK_KEYS") ?? "";

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

/** A plan refusal body; an unreadable entitlement is retryable, a missing feature is not. */
function planRefusal(status: 402 | 503, body: Record<string, unknown>): Record<string, unknown> {
	return status === 503 ? { ...body, retryable: true } : body;
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

function bytesToBase64(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
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
	packKeys: Array<{ key_id: string; key_b64: string }>;
	revocationEpoch: number;
	timing: { ttlHours: number; graceHours: number };
	providerValidUntilMs?: number | null;
	approvalPublicKeys?: ApprovalPublicKey[];
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
		// A pack key never outlives its signed entitlement. It remains usable
		// during the explicitly configured offline grace window.
		pack_keys: params.premiumModules.includes("premium_intel")
			? params.packKeys.map((key) => ({
					alg: "aes-256-gcm",
					key_id: key.key_id,
					key_b64: key.key_b64,
					expires_at: capped.graceUntil,
				}))
			: [],
		issued_at: issuedAt.toISOString(),
		expires_at: capped.expiresAt,
		grace_until: capped.graceUntil,
		serial: crypto.randomUUID(),
		revocation_epoch: params.revocationEpoch,
		// Dashboard approval verification keys (docs/contracts/dashboard-approvals.md).
		// Added only once the tenant has a signing key, so tenants that never use
		// dashboard approvals keep the exact snapshot shape older connectors verify.
		...(params.approvalPublicKeys && params.approvalPublicKeys.length > 0
			? { approval_public_keys: params.approvalPublicKeys }
			: {}),
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
	if (ENTITLEMENT_SIGNING_KEY_ID && !(await signerHealthy(
		`${ENTITLEMENT_SIGNING_KEY_ID}\n${ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64}`,
		async () => (await signEd25519Detached("aidr-signing-healthcheck")) !== null,
	))) {
		return json(503, { error: "entitlement_signing_unavailable", retryable: true });
	}
	const timing = entitlementTiming();
	if (!timing) return json(503, { error: "entitlement_timing_unavailable" });

	const apiKey = getBearerToken(req);
	if (!apiKey) {
		return json(401, { error: "missing_api_key" });
	}
	const supabase = serviceClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
	// Fair-share admission (../_shared/tenant-concurrency.ts): the key lookup and
	// everything after it, including the registration and seat locks that pin
	// pooled database connections, run inside one of the tenant's in-flight leases.
	return withTenantSlot(admitTenantRequest, supabase, apiKey,
		() => ingestForTenant(req, supabase, apiKey, timing), overloaded);
});

function serviceClient(url: string, serviceRoleKey: string) {
	return createClient(url, serviceRoleKey, { auth: { persistSession: false } });
}

function overloaded(rejection: TenantSlotRejection): Response {
	const answer = tenantSlotResponse(rejection);
	return json(answer.status, answer.body, answer.headers);
}

async function ingestForTenant(
	req: Request,
	supabase: ReturnType<typeof serviceClient>,
	apiKey: string,
	timing: { ttlHours: number; graceHours: number },
): Promise<Response> {
	const tenantAuth = await authenticateTenantApiKeyBudgeted(supabase, apiKey, "ingest", Date.now(), {
		allowedScopes: ["tenant", BROWSER_GUARD_INGEST_SCOPE],
	});
	if (!tenantAuth.ok) return json(tenantAuth.status, { error: tenantAuth.error });
	const browserKey = tenantAuth.scope === BROWSER_GUARD_INGEST_SCOPE;
	const browserKeyId = browserKey ? tenantAuth.apiKeyId ?? "" : "";
	if (browserKey && !browserKeyId) return json(403, { error: "api_key_scope_denied" });

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
	if (browserKey && body.agent_runtime !== BROWSER_GUARD_RUNTIME) {
		return json(403, { error: "api_key_scope_denied" });
	}

	const normalizedEvents = normalizeIngestEvents(body.events);
	if (!normalizedEvents.ok) {
		return json(normalizedEvents.status, {
			error: normalizedEvents.error,
			...(normalizedEvents.detail ? { detail: normalizedEvents.detail } : {}),
		});
	}
	// An empty batch is a heartbeat that only updates last_seen.
	let events = normalizedEvents.events;
	if (browserKey && events.some((event) => !BROWSER_GUARD_EVENT_TYPES.has(String(event.type)))) {
		return json(403, { error: "event_type_not_permitted" });
	}

	// Plan feature gates (../_shared/plan-entitlements.ts), after the key has
	// bound the tenant and before any budget, seat or row is spent. The plan is
	// resolved only for a Browser Guard key or a batch carrying posture
	// findings: verdict and runtime ingest never reads or depends on a plan.
	// Both gates fail closed (402 plan_feature_required, 503 unavailable).
	let postureRejection: { eventIds: string[]; reason: Record<string, unknown> } | null = null;
	if (browserKey) {
		const decision = await requireFeature(supabase, tenantAuth.tenantId, "browser_privacy_guard");
		if (!decision.ok) return json(decision.status, planRefusal(decision.status, decision.body));
	} else {
		const { posture, other } = partitionPostureEvents(events);
		if (posture.length > 0) {
			const decision = await requireFeature(supabase, tenantAuth.tenantId, "ai_security_posture");
			if (!decision.ok) {
				// A posture-only upload is refused outright. In a mixed batch the
				// connector's verdicts still land; the posture findings are not
				// written, not acknowledged, and named with the plan reason.
				if (other.length === 0) return json(decision.status, planRefusal(decision.status, decision.body));
				events = other;
				postureRejection = {
					eventIds: posture.map((event) => event.event_id),
					reason: planRefusal(decision.status, decision.body),
				};
			}
		}
	}
	const rejectedEvents = postureRejection
		? { rejected_event_ids: postureRejection.eventIds, rejected_reason: postureRejection.reason }
		: {};

	// An ingest key is budgeted as one subject however many installs share it.
	const rate = await consumeTenantRateLimit(supabase, {
		tenantId: tenantAuth.tenantId,
		subject: browserKey ? `api_key:${browserKeyId}` : apiKeyRateSubject(tenantAuth),
		endpoint: browserKey ? "ingest:browser_guard" : "ingest",
		perSubject: browserKey ? browserKeyEventsPerMinute() : 1_200,
		perTenant: TENANT_INGEST_EVENTS_PER_MIN,
		cost: Math.max(1, events.length),
	});
	if (!rate.ok) return json(rate.status, { error: rate.error }, rateLimitHeaders(rate));

	// Shared auth supplies the binding for either the active key or a valid overlap key.
	const tenantId = tenantAuth.tenantId;
	// A tenant-owned device key (fleet enrollment) carries no person. Its
	// events keep the agent's recorded enrolling user as attribution, which the
	// events write guard binds to the agent; authority came from the fleet key.
	const fleetDevice = tenantAuth.userId === null;
	let userId = tenantAuth.userId ?? "";
	if (fleetDevice && (!tenantAuth.agentId || !tenantAuth.apiKeyId)) {
		return json(403, { error: "agent_key_mismatch" });
	}
	if (tenantAuth.agentId) {
		const { data: bound, error: boundError } = await supabase
			.from("agents")
			.select("iid,user_id")
			.eq("id", tenantAuth.agentId)
			.eq("tenant_id", tenantId)
			.maybeSingle();
		if (boundError || !bound || bound.iid !== iid)
			return json(403, { error: "agent_key_mismatch" });
		if (fleetDevice) {
			const attributed = (bound as { user_id?: unknown }).user_id;
			if (typeof attributed !== "string" || !attributed) return json(403, { error: "agent_key_mismatch" });
			userId = attributed;
		}
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
	// An ingest key registers through its own RPC, which also enforces the
	// runtime, the key's installation cap and the key-to-install binding.
	const runtimeVersion =
		typeof body.agent_runtime_version === "string" ? body.agent_runtime_version : null;
	const { data: registrationRows, error: registrationErr } = browserKey
		? await supabase.rpc("register_browser_guard_agent_for_ingest", {
			p_api_key_id: browserKeyId,
			p_iid: iid,
			p_agent_runtime_version: runtimeVersion,
		})
		: await supabase.rpc("register_agent_for_ingest", {
			p_user_id: userId,
			p_tenant_id: tenantId,
			p_iid: iid,
			p_agent_runtime: typeof body.agent_runtime === "string" ? body.agent_runtime : null,
			p_agent_runtime_version: runtimeVersion,
		});
	if (registrationErr) {
		if (registrationErr.code === "42501") {
			const reason = String(registrationErr.message ?? "");
			if (browserKey && reason.includes("agent_runtime_mismatch")) {
				return json(403, { error: "agent_runtime_mismatch" });
			}
			if (browserKey && reason.includes("api_key_scope_denied")) {
				return json(403, { error: "api_key_scope_denied" });
			}
			return json(403, { error: "tenant_not_admitted" });
		}
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
	if (browserKey && registration.install_limit_exceeded === true) {
		return json(403, {
			error: "install_limit_exceeded",
			install_limit: tenantAuth.installLimit,
		});
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
	const { data: admissionData, error: admissionError } = fleetDevice
		? await supabase.rpc("get_fleet_device_admission", { p_api_key_id: tenantAuth.apiKeyId })
		: await supabase.rpc("get_tenant_admission", { p_tenant_id: tenantId, p_user_id: userId });
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
		// Over the seat limit: report the counts only. A signed snapshot or a
		// derived pack key here would let one unbound API key collect
		// entitlements for unlimited agents (matches /enroll's seat_exceeded).
		return json(402, {
			error: "agent_limit_exceeded",
			allowed_agents: Number(registration.allowed_agents ?? allowedAgents),
			current_agents: Number(registration.current_agents ?? 0),
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

	if (browserKey) {
		// Delivery acknowledgement only: an ingest key never receives the signed
		// entitlement, which can carry the tenant's premium pack key.
		return json(200, {
			ok: true,
			acknowledged_event_ids: events.map((event) => event.event_id),
			agent_id: agentId,
			...rejectedEvents,
		}, rateLimitHeaders(rate));
	}

	const packKeys = premiumModules.includes("premium_intel")
		? await entitledPackKeys({ masterB64: PACK_MASTER_KEY_B64, sharedKeys: SHARED_PACK_KEYS, tenantId })
		: [];

	const entitlement = buildEntitlementSnapshot({
		tenantId, includedAgents, extraAgents, allowedAgents, premiumModules,
		packKeys, revocationEpoch, timing, providerValidUntilMs,
		approvalPublicKeys: await loadApprovalPublicKeys(supabase, tenantId, Date.now()),
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
		...rejectedEvents,
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
}
