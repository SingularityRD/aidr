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
		.select("included_agents, extra_agents")
		.eq("user_id", userId)
		.maybeSingle();

	const includedAgents = entErr || !ent ? 1 : Number(ent.included_agents ?? 1);
	const extraAgents = entErr || !ent ? 0 : Number(ent.extra_agents ?? 0);
	const allowedAgents = Math.max(0, includedAgents + extraAgents);

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
			return json(402, {
				error: "agent_limit_exceeded",
				allowed_agents: allowedAgents,
				current_agents: current,
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

	return json(200, { ok: true, agent_id: agentId });
});

