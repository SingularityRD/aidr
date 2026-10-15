// Supabase Edge Function: POST /v1/connector-heartbeat
//
// Auth: Authorization: Bearer <tenant API key> (the device's enrolled key).
//
// `aidr heartbeat` measures every agent host on a device and reports one
// state per connector (protected / hook_missing / hook_disabled /
// hook_untrusted / hook_broken). The measurement happens on the device, from
// outside the hook, because a removed or untrusted hook never runs and so
// cannot report that it stopped. record_connector_heartbeat
// (20261014000205) stores the latest state, refreshes agents.last_seen and
// raises `agent.unprotected` when a protected connector stops being
// protected. The body carries enums and counts only.

import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import { authenticateTenantApiKeyBudgeted } from "../_shared/api-key-auth.ts";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const ENDPOINT = "connector-heartbeat";
const MAX_BODY_BYTES = 4096;
const IID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const HEARTBEAT_CONNECTORS = ["claude-code", "cursor", "vscode", "openclaw", "opencode", "codex"] as const;
export const HEARTBEAT_STATES = ["protected", "hook_missing", "hook_disabled", "hook_untrusted", "hook_broken"] as const;
export const HEARTBEAT_ENFORCEMENT = ["machine_policy", "user_config", "none"] as const;

export interface ConnectorReport {
	connector: (typeof HEARTBEAT_CONNECTORS)[number];
	state: (typeof HEARTBEAT_STATES)[number];
	enforcement: (typeof HEARTBEAT_ENFORCEMENT)[number];
	protection_locked: boolean;
	disable_attempts: number;
	host_version?: string;
}

function oneOf<T extends readonly string[]>(list: T, value: unknown): value is T[number] {
	return typeof value === "string" && (list as readonly string[]).includes(value);
}

/** Strict allow-list parse of the request body; null when anything is off. */
export function parseHeartbeat(value: unknown): { iid: string; reports: ConnectorReport[] } | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const body = value as Record<string, unknown>;
	if (Object.keys(body).some((key) => key !== "iid" && key !== "connectors")) return null;
	if (typeof body.iid !== "string" || !IID.test(body.iid)) return null;
	if (!Array.isArray(body.connectors) || body.connectors.length < 1 || body.connectors.length > HEARTBEAT_CONNECTORS.length) {
		return null;
	}
	const seen = new Set<string>();
	const reports: ConnectorReport[] = [];
	for (const entry of body.connectors) {
		if (!entry || typeof entry !== "object" || Array.isArray(entry)) return null;
		const item = entry as Record<string, unknown>;
		const allowed = ["connector", "state", "enforcement", "protection_locked", "disable_attempts", "host_version"];
		if (Object.keys(item).some((key) => !allowed.includes(key))) return null;
		if (!oneOf(HEARTBEAT_CONNECTORS, item.connector) || seen.has(item.connector)) return null;
		if (!oneOf(HEARTBEAT_STATES, item.state)) return null;
		const enforcement = item.enforcement ?? "user_config";
		if (!oneOf(HEARTBEAT_ENFORCEMENT, enforcement)) return null;
		const locked = item.protection_locked ?? false;
		if (typeof locked !== "boolean") return null;
		const attempts = item.disable_attempts ?? 0;
		if (typeof attempts !== "number" || !Number.isSafeInteger(attempts) || attempts < 0 || attempts > 1_000_000) return null;
		if (item.host_version !== undefined && (typeof item.host_version !== "string" || !VERSION.test(item.host_version))) {
			return null;
		}
		seen.add(item.connector);
		reports.push({
			connector: item.connector,
			state: item.state,
			enforcement,
			protection_locked: locked,
			disable_attempts: attempts,
			...(typeof item.host_version === "string" ? { host_version: item.host_version } : {}),
		});
	}
	return { iid: body.iid, reports };
}

const json = (status: number, body: Record<string, unknown>, headers: Record<string, string> = {}) =>
	new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers },
	});

export interface ConnectorHeartbeatDeps {
	/** Overrides the service-role client; used by the contract suite. */
	db?: SupabaseClient;
}

type AgentRow = { id: string; iid: string; retired_at?: string | null };

export function createConnectorHeartbeatHandler(deps: ConnectorHeartbeatDeps = {}) {
	return async function handle(req: Request): Promise<Response> {
		if (req.method !== "POST") return json(405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) return configFailure(ENDPOINT, config.error, json);
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return json(401, { error: "missing_api_key" });
		try {
			const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
			if (!parsed.ok) return json(parsed.status, { error: parsed.error });
			const heartbeat = parseHeartbeat(parsed.value);
			if (!heartbeat) return json(400, { error: "invalid_heartbeat" });
			const db = deps.db ?? createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, {
				auth: { persistSession: false },
			});
			const auth = await authenticateTenantApiKeyBudgeted(db, token, ENDPOINT);
			if (!auth.ok) return json(auth.status, { error: auth.error });
			const rate = await consumeTenantRateLimit(db, {
				tenantId: auth.tenantId,
				subject: auth.userId,
				endpoint: ENDPOINT,
				perSubject: 120,
				perTenant: 20_000,
			});
			if (!rate.ok) return json(rate.status, { error: rate.error }, rateLimitHeaders(rate));

			// An agent-bound key reports only for its own agent; an unbound tenant
			// key names the agent by its installation id. Heartbeats never create
			// an agent: enrollment and seat admission stay with ingest/enroll.
			const bound = typeof auth.agentId === "string" && UUID.test(auth.agentId) ? auth.agentId : null;
			const lookup = bound
				? await db.from("agents").select("id,iid,retired_at").eq("tenant_id", auth.tenantId).eq("id", bound).maybeSingle()
				: await db.from("agents").select("id,iid,retired_at").eq("tenant_id", auth.tenantId).eq("iid", heartbeat.iid).maybeSingle();
			if (lookup.error) return json(503, { error: "heartbeat_unavailable" });
			const agent = lookup.data as AgentRow | null;
			if (!agent) return json(404, { error: "agent_not_enrolled" });
			if (agent.iid !== heartbeat.iid) return json(403, { error: "agent_key_mismatch" });
			// A retired agent is no longer part of the fleet: an unbound tenant key
			// must not refresh its last_seen or report it as protected (SEC-6).
			if (agent.retired_at !== undefined && agent.retired_at !== null) return json(409, { error: "agent_retired" });

			const recorded = await db.rpc("record_connector_heartbeat", {
				p_tenant_id: auth.tenantId,
				p_agent_id: agent.id,
				p_reports: heartbeat.reports,
			});
			if (recorded.error) return json(503, { error: "heartbeat_unavailable" });
			const result = (recorded.data ?? {}) as { recorded?: unknown; alerts?: unknown };
			return json(200, {
				ok: true,
				recorded: typeof result.recorded === "number" ? result.recorded : heartbeat.reports.length,
			}, rateLimitHeaders(rate));
		} catch {
			return json(503, { error: "heartbeat_unavailable" });
		}
	};
}

Deno.serve(createConnectorHeartbeatHandler());
