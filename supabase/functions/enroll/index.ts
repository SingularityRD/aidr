// Supabase Edge Function: POST /v1/enroll
//
// Auth: Authorization: Bearer <enrollment_token_plaintext>
// Body: { iid, agent_runtime, agent_runtime_version }
//
// Exchanges a one-time enrollment token for an API key and (optionally) returns a signed entitlement.
// This makes first-time setup easy while keeping API keys hash-only at rest.

import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const ENTITLEMENT_SIGNING_KEY_ID = (Deno.env.get("AIDR_ENTITLEMENT_SIGNING_KEY_ID") ?? "").trim();
const ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64 = (
	Deno.env.get("AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64") ?? ""
).trim();
const PACK_MASTER_KEY_B64 = (Deno.env.get("AIDR_PACK_MASTER_KEY_B64") ?? "").trim();

const ENTITLEMENT_TTL_HOURS = Number(Deno.env.get("AIDR_ENTITLEMENT_TTL_HOURS") ?? "168");
const ENTITLEMENT_GRACE_HOURS = Number(Deno.env.get("AIDR_ENTITLEMENT_GRACE_HOURS") ?? "72");

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

function addHoursIso(hours: number): string {
	const safe = Number.isFinite(hours) ? Math.max(0, hours) : 0;
	return new Date(Date.now() + safe * 60 * 60 * 1000).toISOString();
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

type EnrollBody = {
	iid?: string;
	agent_runtime?: string;
	agent_runtime_version?: string;
};

function buildPremiumModules(entRow: Record<string, unknown> | null): string[] {
	const out: string[] = [];
	if (entRow && entRow.premium_intel === true) out.push("premium_intel");
	if (entRow && entRow.premium_correlation === true) out.push("premium_correlation");
	if (entRow && entRow.premium_pkg_plugin === true) out.push("premium_pkg_plugin");
	return out;
}

Deno.serve(async (req) => {
	if (req.method !== "POST") return json(405, { error: "method_not_allowed" });
	if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
		return json(500, { error: "misconfigured_supabase_env" });
	}

	const enrollToken = getBearerToken(req);
	if (!enrollToken) return json(401, { error: "missing_enrollment_token" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	// Basic throttling by token hash (best-effort).
	const tokenHash = await sha256Hex(enrollToken);
	const ok = await rateLimitKey(supabase, `enroll:${tokenHash.slice(0, 16)}`, ENROLL_RATE_LIMIT_PER_MIN);
	if (!ok) return json(429, { error: "rate_limited" });

	let body: EnrollBody = {};
	try {
		body = (await req.json()) as EnrollBody;
	} catch {
		body = {};
	}
	const iid = typeof body.iid === "string" ? body.iid.trim() : "";
	if (!iid) return json(400, { error: "missing_iid" });

	// 1) Validate and consume the enrollment token atomically. The RPC updates
	// only an unused, unexpired row and returns its owner, so concurrent
	// exchanges cannot both mint API keys from the same token.
	const { data: consumedRows, error: consumeErr } = await supabase.rpc("consume_enrollment_token", {
		p_token_hash: tokenHash,
	});
	if (consumeErr) return json(500, { error: "enrollment_token_store_unavailable" });
	const tokRow = Array.isArray(consumedRows) ? consumedRows[0] : null;
	if (!tokRow || typeof tokRow.user_id !== "string") {
		return json(401, { error: "invalid_or_expired_enrollment_token" });
	}

	const userId = tokRow.user_id as string;
	const tenantId = (typeof tokRow.tenant_id === "string" ? tokRow.tenant_id : null) ?? userId;

	// 2) Load the tenant entitlement. Agent registration below performs the
	// actual seat check under a transaction/advisory lock.
	const { data: entRow, error: entErr } = await supabase
		.from("entitlements")
		.select("included_agents,extra_agents,premium_intel,premium_correlation,premium_pkg_plugin,revocation_epoch")
		.eq("tenant_id", tenantId)
		.maybeSingle();
	if (entErr || !entRow) return json(500, { error: "missing_entitlements" });

	const includedAgents = Number(entRow.included_agents ?? 1);
	const extraAgents = Number(entRow.extra_agents ?? 0);
	const allowedAgents = Math.max(0, includedAgents) + Math.max(0, extraAgents);
	const revocationEpoch = Number(entRow.revocation_epoch ?? 1);

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
	if (registrationErr) return json(500, { error: "agent_registration_failed" });
	const registration = (Array.isArray(registrationRows) ? registrationRows[0] : null) as Record<
		string,
		unknown
	> | null;
	if (!registration || registration.seat_exceeded === true || typeof registration.agent_id !== "string") {
		return json(402, {
			error: "agent_limit_exceeded",
			allowed_agents: Number(registration?.allowed_agents ?? allowedAgents),
			current_agents: Number(registration?.current_agents ?? allowedAgents),
		});
	}
	const agentId = registration.agent_id;

	// 3) Issue API key (hash-only at rest).
	let apiKey = "";
	let keyHash = "";
	let inserted = false;
	for (let i = 0; i < 5; i++) {
		apiKey = randomApiKey();
		keyHash = await sha256Hex(apiKey);
		const { error } = await supabase.from("api_keys").insert({
			user_id: userId,
			tenant_id: tenantId,
			label: `enroll:${iid}`,
			key_hash: keyHash,
		});
		if (!error) {
			inserted = true;
			break;
		}
	}
	if (!inserted) return json(500, { error: "api_key_issue_failed" });

	// 4) Return signed entitlement snapshot (same contract as ingest).
	const premiumModules = buildPremiumModules(entRow as Record<string, unknown>);
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
							expires_at: addHoursIso(ENTITLEMENT_GRACE_HOURS),
						},
					]
				: [],
		issued_at: new Date().toISOString(),
		expires_at: addHoursIso(ENTITLEMENT_TTL_HOURS),
		grace_until: addHoursIso(ENTITLEMENT_GRACE_HOURS),
		serial: crypto.randomUUID(),
		revocation_epoch: Number.isFinite(revocationEpoch) ? Math.max(1, Math.floor(revocationEpoch)) : 1,
	};
	const entitlementJson = canonicalJson(entitlement);
	const sig = await signEd25519Detached(entitlementJson);

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
	await supabase.from("admin_audit_logs").insert({
		actor_user_id: userId,
		tenant_id: tenantId,
		action: "enroll.consume_token",
		target_user_id: userId,
		detail: { iid },
	});

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
