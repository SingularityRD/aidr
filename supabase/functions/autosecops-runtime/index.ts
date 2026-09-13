// Supabase Edge Function: AIDR -> AutoSecOps runtime visibility bridge.
//
// The browser never receives the AutoSecOps credential. A Supabase access
// token authenticates the caller; this function verifies team membership,
// resolves the server-side AutoSecOps team mapping, and forwards only the
// bounded read-only runtime queries needed by the AIDR dashboard.

import { createClient } from "npm:@supabase/supabase-js@2";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import {
	ConfigurationError,
	configFailure,
	isConfiguredValue,
	loadConfig,
	partialGroupError,
	runtimeEnv,
} from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

const AUTOSECOPS_RUNTIME_URL = (Deno.env.get("AUTOSECOPS_RUNTIME_URL") ?? "").trim();
const AUTOSECOPS_RUNTIME_TOKEN = (Deno.env.get("AUTOSECOPS_RUNTIME_TOKEN") ?? "").trim();
const AUTOSECOPS_AIDR_TEAM_ID = (Deno.env.get("AUTOSECOPS_AIDR_TEAM_ID") ?? "").trim();
const AUTOSECOPS_TEAM_ID = (Deno.env.get("AUTOSECOPS_TEAM_ID") ?? "").trim();
const AUTOSECOPS_TEAM_MAP = (Deno.env.get("AUTOSECOPS_RUNTIME_TEAM_MAP") ?? "").trim();

type Action = "health" | "fleet" | "performance";
type RequestBody = {
	action?: unknown;
	team_id?: unknown;
	query?: unknown;
};

function getBearerToken(req: Request): string | null {
	const header = req.headers.get("Authorization") ?? "";
	const match = header.match(/^Bearer\s+(.+)$/i);
	return match?.[1]?.trim() ? match[1].trim() : null;
}

function isAutoSecOpsTeamId(value: string): boolean {
	const parsed = Number(value);
	return /^[1-9][0-9]{0,19}$/.test(value) && Number.isSafeInteger(parsed) && parsed > 0;
}

function isAidrTeamId(value: string): boolean {
	return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function parseTeamMap(): Record<string, string> | null {
	if (!AUTOSECOPS_TEAM_MAP) return {};
	try {
		const parsed: unknown = JSON.parse(AUTOSECOPS_TEAM_MAP);
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
		const out: Record<string, string> = {};
		for (const [key, value] of Object.entries(parsed)) {
			if (!isAidrTeamId(key) && !/^[0-9a-f-]{36}$/i.test(key)) return null;
			if (typeof value !== "string" || !isAutoSecOpsTeamId(value)) return null;
			out[key] = value;
		}
		return out;
	} catch {
		return null;
	}
}

function configured(): boolean {
	if (!AUTOSECOPS_RUNTIME_URL || !AUTOSECOPS_RUNTIME_TOKEN) return false;
	try {
		const url = new URL(AUTOSECOPS_RUNTIME_URL);
		if (url.protocol !== "https:") return false;
		if (url.username || url.password || url.search || url.hash) return false;
	} catch {
		return false;
	}
	const singleTenantMapping =
		isAidrTeamId(AUTOSECOPS_AIDR_TEAM_ID) && isAutoSecOpsTeamId(AUTOSECOPS_TEAM_ID);
	return singleTenantMapping || Boolean(AUTOSECOPS_TEAM_MAP);
}

/**
 * Distinguish "this deployment does not use the AutoSecOps bridge" from "the
 * bridge credentials are misconfigured".
 *
 * - Nothing set: the integration is optional and simply off. The handler
 *   answers `integration_not_configured` (503), unchanged.
 * - Half set: the operator believes the bridge is on, so name the missing
 *   variable instead of silently answering "not configured".
 * - URL present but unusable (not a bare https origin): a configuration error,
 *   reported as `invalid` rather than an opaque downstream failure.
 */
function integrationConfigProblem(): ConfigurationError | null {
	const partial = partialGroupError({
		AUTOSECOPS_RUNTIME_URL,
		AUTOSECOPS_RUNTIME_TOKEN,
	});
	if (partial) return partial;
	if (!isConfiguredValue(AUTOSECOPS_RUNTIME_URL)) return null;

	try {
		const url = new URL(AUTOSECOPS_RUNTIME_URL);
		const usable =
			url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash;
		return usable ? null : new ConfigurationError({ invalid: ["AUTOSECOPS_RUNTIME_URL"] });
	} catch {
		return new ConfigurationError({ invalid: ["AUTOSECOPS_RUNTIME_URL"] });
	}
}

function parseQuery(action: Action, value: unknown): Record<string, unknown> {
	if (action !== "fleet") return {};
	if (value === undefined) return { limit: 100 };
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new Error("invalid_query");
	}
	const input = value as Record<string, unknown>;
	const allowed = new Set(["agent_id", "runtime", "state", "limit", "cursor"]);
	const output: Record<string, unknown> = {};
	for (const [key, item] of Object.entries(input)) {
		if (!allowed.has(key)) throw new Error("invalid_query");
		if (["agent_id", "runtime", "state", "cursor"].includes(key)) {
			if (typeof item !== "string" || item.length > 256 || /[\u0000\r\n]/.test(item)) {
				throw new Error("invalid_query");
			}
			output[key] = item;
			continue;
		}
		if (!Number.isInteger(item) || Number(item) < 1 || Number(item) > 100) {
			throw new Error("invalid_query");
		}
		output[key] = Number(item);
	}
	if (!Object.hasOwn(output, "limit")) output.limit = 100;
	return output;
}

async function authenticatedUser(
	req: Request,
	supabaseUrl: string,
	serviceRoleKey: string,
) {
	const token = getBearerToken(req);
	if (!token) throw new Error("missing_access_token");
	const supabase = createClient(supabaseUrl, serviceRoleKey, {
		auth: { persistSession: false },
	});
	const { data, error } = await supabase.auth.getUser(token);
	if (error || !data?.user?.id) throw new Error("invalid_access_token");
	const identity = await checkIdentityBarrier(supabase, token, data.user.id);
	if (!identity.ok) throw new Error(identity.error);
	return { supabase, userId: data.user.id, token };
}

async function resolveAidrTeam(
	supabase: ReturnType<typeof createClient>,
	userId: string,
	requestedTeam: string | undefined,
): Promise<string> {
	let aidrTeamId = requestedTeam?.trim() ?? "";
	if (aidrTeamId) {
		if (!isAidrTeamId(aidrTeamId)) throw new Error("invalid_team_id");
		const { data, error } = await supabase
			.from("team_members")
			.select("team_id")
			.eq("team_id", aidrTeamId)
			.eq("user_id", userId)
			.maybeSingle();
		if (error) throw new Error("team_membership_unavailable");
		if (!data?.team_id) throw new Error("team_membership_required");
	} else {
		const { data, error } = await supabase
			.from("team_members")
			.select("team_id")
			.eq("user_id", userId)
			.limit(2);
		if (error) throw new Error("team_membership_unavailable");
		const teams = (data ?? []).map((row) => String(row.team_id)).filter(isAidrTeamId);
		if (teams.length > 1) throw new Error("team_selection_required");
		aidrTeamId = teams[0] ?? userId;
	}
	return aidrTeamId;
}

function resolveAutoSecOpsTeam(aidrTeamId: string): string | null {
	const map = parseTeamMap();
	if (map === null) return null;
	const mapped = map?.[aidrTeamId];
	if (mapped) return mapped;
	if (AUTOSECOPS_AIDR_TEAM_ID === aidrTeamId && isAutoSecOpsTeamId(AUTOSECOPS_TEAM_ID)) {
		return AUTOSECOPS_TEAM_ID;
	}
	return null;
}

function errorStatus(error: Error): number {
	switch (error.message) {
		case "missing_access_token":
		case "invalid_access_token":
		case "session_revoked":
			return 401;
		case "mfa_required":
		case "team_membership_required":
			return 403;
		case "team_selection_required":
		case "invalid_team_id":
		case "invalid_query":
			return 400;
		case "team_membership_unavailable":
		case "identity_state_unavailable":
		case "identity_policy_unavailable":
		case "identity_barrier_unavailable":
		case "assurance_unavailable":
		case "integration_not_configured":
			return 503;
		default:
			return 500;
	}
}

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;
	if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) {
		return configFailure("autosecops-runtime", config.error, (status, body) =>
			corsJson(req, status, body),
		);
	}
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

	const integrationProblem = integrationConfigProblem();
	if (integrationProblem) {
		return configFailure("autosecops-runtime", integrationProblem, (status, body) =>
			corsJson(req, status, body),
		);
	}

	try {
		if (!configured()) throw new Error("integration_not_configured");
		const body = (await req.json()) as RequestBody;
		const action = typeof body.action === "string" ? body.action : "";
		if (action !== "health" && action !== "fleet" && action !== "performance") {
			throw new Error("invalid_query");
		}
		const { supabase, userId, token } = await authenticatedUser(req, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
		const aidrTeamId = await resolveAidrTeam(
			supabase,
			userId,
			typeof body.team_id === "string" ? body.team_id : undefined,
		);
		const tenantIdentity = await checkIdentityBarrier(supabase, token, userId, aidrTeamId);
		if (!tenantIdentity.ok) throw new Error(tenantIdentity.error);
		const autoSecOpsTeamId = resolveAutoSecOpsTeam(aidrTeamId);
		if (!autoSecOpsTeamId) throw new Error("integration_not_configured");
		const query = parseQuery(action, body.query);
		const path = action === "health" ? "health" : action === "fleet" ? "fleet" : "performance";
		const payload: Record<string, unknown> = {
			scope: { tenant_id: `team:${autoSecOpsTeamId}`, team_id: autoSecOpsTeamId },
		};
		if (action === "health") payload.query = {};
		if (action === "fleet") payload.query = query;

		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), 5000);
		let response: Response;
		try {
			response = await fetch(`${AUTOSECOPS_RUNTIME_URL}/api/v1/aidr/runtime/${path}`, {
				method: "POST",
				redirect: "error",
				signal: controller.signal,
				headers: {
					Accept: "application/json",
					"Content-Type": "application/json",
					Authorization: `Bearer ${AUTOSECOPS_RUNTIME_TOKEN}`,
					"X-Request-ID": crypto.randomUUID(),
				},
				body: JSON.stringify(payload),
			});
		} finally {
			clearTimeout(timeout);
		}
		if (!response.ok) {
			return corsJson(req, 502, { error: "autosecops_unavailable", provider: "autosecops" });
		}
		let data: unknown;
		try {
			data = await response.json();
		} catch {
			return corsJson(req, 502, { error: "autosecops_invalid_response", provider: "autosecops" });
		}
		if (!data || typeof data !== "object" || Array.isArray(data)) {
			return corsJson(req, 502, { error: "autosecops_invalid_response", provider: "autosecops" });
		}
		return corsJson(req, 200, {
			ok: true,
			provider: "autosecops",
			action,
			team_id: autoSecOpsTeamId,
			data,
		});
	} catch (cause) {
		const error = cause instanceof Error ? cause : new Error("integration_failed");
		const status = error.name === "AbortError" ? 504 : errorStatus(error);
		return corsJson(req, status, { error: status === 500 ? "integration_failed" : error.message });
	}
});
