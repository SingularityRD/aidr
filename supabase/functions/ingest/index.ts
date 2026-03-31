// Supabase Edge Function: POST /v1/ingest
//
// Auth: Authorization: Bearer <api_key_plaintext>
// Body: { iid, agent_runtime, agent_runtime_version, aidr_version, events: [...] }
//
// This function:
// - maps api_key -> user_id (via stored sha256 hash)
// - upserts agent by (user_id, iid)
// - enforces agent-seat limit: included_agents + extra_agents
// - inserts events for dashboard

import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

// Commercial v1: signed entitlements (Ed25519).
// Key material should be provided via environment variables in the Edge Functions runtime.
const ENTITLEMENT_SIGNING_KEY_ID = (Deno.env.get("AIDR_ENTITLEMENT_SIGNING_KEY_ID") ?? "").trim();
const ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64 = (
	Deno.env.get("AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64") ?? ""
).trim();

// Premium pack encryption: master key used to derive per-tenant pack keys (HKDF-SHA256).
// This secret MUST be kept server-side; clients only receive derived, time-bound keys via entitlements.
const PACK_MASTER_KEY_B64 = (Deno.env.get("AIDR_PACK_MASTER_KEY_B64") ?? "").trim();

// Default: 7d entitlement TTL + 72h offline grace.
const ENTITLEMENT_TTL_HOURS = Number(Deno.env.get("AIDR_ENTITLEMENT_TTL_HOURS") ?? "168");
const ENTITLEMENT_GRACE_HOURS = Number(Deno.env.get("AIDR_ENTITLEMENT_GRACE_HOURS") ?? "72");

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

function addHoursIso(hours: number): string {
	const safe = Number.isFinite(hours) ? Math.max(0, hours) : 0;
	return new Date(Date.now() + safe * 60 * 60 * 1000).toISOString();
}

function buildPremiumModules(entRow: Record<string, unknown> | null): string[] {
	const out: string[] = [];
	if (entRow && entRow.premium_intel === true) out.push("premium_intel");
	if (entRow && entRow.premium_correlation === true) out.push("premium_correlation");
	if (entRow && entRow.premium_pkg_plugin === true) out.push("premium_pkg_plugin");
	return out;
}

Deno.serve(async (req) => {
	if (req.method !== "POST") {
		return json(405, { error: "method_not_allowed" });
	}

	if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
		return json(500, { error: "misconfigured_supabase_env" });
	}

	const apiKey = getBearerToken(req);
	if (!apiKey) {
		return json(401, { error: "missing_api_key" });
	}

	let body: IngestBody;
	try {
		body = (await req.json()) as IngestBody;
	} catch {
		return json(400, { error: "invalid_json" });
	}

	const iid = typeof body.iid === "string" ? body.iid.trim() : "";
	if (!iid) {
		return json(400, { error: "missing_iid" });
	}

	const events = Array.isArray(body.events) ? (body.events as Record<string, unknown>[]) : [];
	if (events.length === 0) {
		// Allow heartbeat-style calls to update last_seen.
	}

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	// 1) api_key -> user_id
	const keyHash = await sha256Hex(apiKey);
	const { data: keyRow, error: keyErr } = await supabase
		.from("api_keys")
		.select("user_id, revoked")
		.eq("key_hash", keyHash)
		.maybeSingle();

	if (keyErr || !keyRow || keyRow.revoked) {
		return json(401, { error: "invalid_api_key" });
	}

	const userId = keyRow.user_id as string;

	// 2) load entitlements (default row is created by trigger; still fail-open)
	const { data: ent, error: entErr } = await supabase
		.from("entitlements")
		.select(
			"included_agents, extra_agents, premium_intel, premium_correlation, premium_pkg_plugin, revocation_epoch",
		)
		.eq("user_id", userId)
		.maybeSingle();

	const includedAgents = entErr || !ent ? 1 : Number(ent.included_agents ?? 1);
	const extraAgents = entErr || !ent ? 0 : Number(ent.extra_agents ?? 0);
	const allowedAgents = Math.max(0, includedAgents + extraAgents);
	const premiumModules = buildPremiumModules((ent as unknown as Record<string, unknown>) ?? null);
	const revocationEpoch =
		entErr || !ent ? 1 : Number((ent as unknown as Record<string, unknown>).revocation_epoch ?? 1);

	// 3) upsert agent with seat enforcement on first-seen
	const { data: existingAgent, error: existingErr } = await supabase
		.from("agents")
		.select("id")
		.eq("user_id", userId)
		.eq("iid", iid)
		.maybeSingle();

	if (existingErr) {
		return json(500, { error: "db_error", detail: String(existingErr.message ?? existingErr) });
	}

	let agentId: string | null = existingAgent?.id ?? null;

	if (!agentId) {
		const { count, error: countErr } = await supabase
			.from("agents")
			.select("*", { count: "exact", head: true })
			.eq("user_id", userId);

		const current = countErr ? 0 : Number(count ?? 0);
		if (allowedAgents > 0 && current >= allowedAgents) {
			const tenantPackKey = premiumModules.includes("premium_intel")
				? await deriveTenantPackKeyB64(userId)
				: null;

			const entitlement = {
				schema_version: 2,
				tenant_id: userId,
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
				revocation_epoch: revocationEpoch,
			};
			const entitlementJson = canonicalJson(entitlement);
			const sig = await signEd25519Detached(entitlementJson);

			return json(402, {
				error: "agent_limit_exceeded",
				allowed_agents: allowedAgents,
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

		const { data: inserted, error: insErr } = await supabase
			.from("agents")
			.insert({
				user_id: userId,
				iid,
				agent_runtime: typeof body.agent_runtime === "string" ? body.agent_runtime : null,
				agent_runtime_version:
					typeof body.agent_runtime_version === "string" ? body.agent_runtime_version : null,
				last_seen: new Date().toISOString(),
			})
			.select("id")
			.single();

		if (insErr) {
			return json(500, { error: "db_error", detail: String(insErr.message ?? insErr) });
		}

		agentId = inserted.id as string;
	} else {
		// Touch last_seen and update runtime metadata
		await supabase
			.from("agents")
			.update({
				agent_runtime: typeof body.agent_runtime === "string" ? body.agent_runtime : undefined,
				agent_runtime_version:
					typeof body.agent_runtime_version === "string" ? body.agent_runtime_version : undefined,
				last_seen: new Date().toISOString(),
			})
			.eq("id", agentId);
	}

	// 4) Insert events (best-effort)
	if (events.length > 0 && agentId) {
		const rows = events.slice(0, 200).map((evt) => ({
			user_id: userId,
			agent_id: agentId,
			type: typeof evt.type === "string" ? (evt.type as string) : "runtime_verdict",
			payload: evt,
		}));

		const { error: evtErr } = await supabase.from("events").insert(rows);
		if (evtErr) {
			// Fail-open for agent; telemetry failure shouldn't break ingestion heartbeat
			return json(200, { ok: true, warnings: ["events_insert_failed"] });
		}
	}

	const tenantPackKey = premiumModules.includes("premium_intel")
		? await deriveTenantPackKeyB64(userId)
		: null;

	const entitlement = {
		schema_version: 2,
		tenant_id: userId,
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
		revocation_epoch: revocationEpoch,
	};
	const entitlementJson = canonicalJson(entitlement);
	const sig = await signEd25519Detached(entitlementJson);

	// Best-effort: persist the latest entitlement snapshot per (user_id, iid) for dashboard/debugging.
	try {
		const snapshot = JSON.parse(entitlementJson) as Record<string, unknown>;
		await supabase
			.from("entitlement_snapshots")
			.upsert(
				{
					user_id: userId,
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
				{ onConflict: "user_id,iid" },
			);
	} catch {
		// Fail-open: snapshot storage must never block ingest.
	}

	return json(200, {
		ok: true,
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
	});
});

