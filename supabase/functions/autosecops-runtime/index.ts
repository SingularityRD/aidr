// Supabase Edge Function: AIDR -> AutoSecOps runtime visibility bridge.
//
// The browser never receives the AutoSecOps credential. A Supabase access
// token authenticates the caller; this function verifies team membership,
// resolves the server-side AutoSecOps team mapping, and forwards only the
// bounded read-only runtime queries needed by the AIDR dashboard.
//
// The handler is built by `createAutoSecOpsRuntimeHandler` so the repository's
// contract suite can drive the real request path with an injected client,
// fetcher and environment. `Deno.serve` at the bottom wires the production
// defaults. There is exactly one implementation of each guard: an injected
// dependency changes where a value comes from, never whether it is checked.

import { createClient } from "npm:@supabase/supabase-js@2";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import {
	ConfigurationError,
	configFailure,
	isConfiguredValue,
	loadConfig,
	partialGroupError,
	type EnvReader,
} from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";

/**
 * Runtime environment reader.
 *
 * Deno's `Deno.env` is the production source. The repository's contract suite
 * runs this same handler under Node, where `Deno` does not exist, so the reader
 * falls back to `process.env` instead of the handler carrying a test-only
 * branch. A per-request read also means a rotated credential or a corrected URL
 * takes effect without a redeploy.
 */
const runtimeEnv: EnvReader = (name) => {
	try {
		const value = Deno.env.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Not running under Deno; fall through to process.env.
	}
	return globalThis.process?.env?.[name];
};

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

const AUTO_SECOPS_ENV_NAMES = [
	"AUTOSECOPS_RUNTIME_URL",
	"AUTOSECOPS_RUNTIME_TOKEN",
	"AUTOSECOPS_AIDR_TEAM_ID",
	"AUTOSECOPS_TEAM_ID",
	"AUTOSECOPS_RUNTIME_TEAM_MAP",
] as const;

type Action = "health" | "fleet" | "performance";
type RequestBody = {
	action?: unknown;
	team_id?: unknown;
	query?: unknown;
};

export interface AutoSecOpsRuntimeDeps {
	/** Environment reader. Defaults to the runtime env with a Node fallback. */
	env?: EnvReader;
	/** Service-role client factory. Defaults to `createClient`. */
	client?: (url: string, key: string) => ReturnType<typeof createClient>;
	/** Outbound fetch. Defaults to the global `fetch`. */
	fetcher?: typeof fetch;
	/** Clock, in epoch milliseconds. Defaults to `Date.now`. */
	now?: () => number;
}

function getBearerToken(req: Request): string | null {
	const header = req.headers.get("Authorization") ?? "";
	const match = header.match(/^Bearer\s+(.+)$/i);
	return match?.[1]?.trim() ? match[1].trim() : null;
}

export function isAutoSecOpsTeamId(value: string): boolean {
	const parsed = Number(value);
	return /^[1-9][0-9]{0,19}$/.test(value) && Number.isSafeInteger(parsed) && parsed > 0;
}

export function isAidrTeamId(value: string): boolean {
	return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function parseTeamMap(raw: string): Record<string, string> | null {
	if (!raw) return {};
	try {
		const parsed: unknown = JSON.parse(raw);
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

export function parseQuery(action: Action, value: unknown): Record<string, unknown> {
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

export function errorStatus(error: Error): number {
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

export function createAutoSecOpsRuntimeHandler(deps: AutoSecOpsRuntimeDeps = {}) {
	const env: EnvReader = deps.env ?? runtimeEnv;
	const doFetch = deps.fetcher ?? fetch;
	const now = deps.now ?? Date.now;

	/**
	 * Build the privileged service-role client.
	 *
	 * `createClient` is referenced only here; `handle` binds this builder to
	 * `makeClient` *after* the request-time configuration guard, so a
	 * misconfigured deployment never constructs a client. `deps.client` exists so
	 * the contract suite can drive the real request path without a network or a
	 * Deno runtime.
	 */
	const buildClient =
		deps.client ??
		((url: string, key: string) => createClient(url, key, { auth: { persistSession: false } }));
	const injectedClient = deps.client;

	const readEnv = (name: (typeof AUTO_SECOPS_ENV_NAMES)[number]): string =>
		(env(name) ?? "").trim();

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
	function integrationConfigProblem(url: string, token: string): ConfigurationError | null {
		const partial = partialGroupError({
			AUTOSECOPS_RUNTIME_URL: url,
			AUTOSECOPS_RUNTIME_TOKEN: token,
		});
		if (partial) return partial;
		if (!isConfiguredValue(url)) return null;

		try {
			const parsed = new URL(url);
			const usable =
				parsed.protocol === "https:" &&
				!parsed.username &&
				!parsed.password &&
				!parsed.search &&
				!parsed.hash;
			return usable ? null : new ConfigurationError({ invalid: ["AUTOSECOPS_RUNTIME_URL"] });
		} catch {
			return new ConfigurationError({ invalid: ["AUTOSECOPS_RUNTIME_URL"] });
		}
	}

	/**
	 * Configuration is validated per request, before any authentication, client
	 * construction or database work, so a missing variable answers with an
	 * explicit 500 that names it instead of failing later with an empty
	 * credential (AIDR-011).
	 */
	return async function handle(req: Request): Promise<Response> {
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
		// Bound only now, after the guard, so a misconfigured deployment never
		// reaches the privileged client at all.
		const makeClient = injectedClient ?? buildClient;

		// Bridge configuration is read per request so a rotated credential or a
		// corrected URL takes effect without redeploying the function.
		const runtimeUrl = readEnv("AUTOSECOPS_RUNTIME_URL");
		const runtimeToken = readEnv("AUTOSECOPS_RUNTIME_TOKEN");
		const aidrTeamIdSetting = readEnv("AUTOSECOPS_AIDR_TEAM_ID");
		const autoSecOpsTeamIdSetting = readEnv("AUTOSECOPS_TEAM_ID");
		const teamMapRaw = readEnv("AUTOSECOPS_RUNTIME_TEAM_MAP");

		const integrationProblem = integrationConfigProblem(runtimeUrl, runtimeToken);
		if (integrationProblem) {
			return configFailure("autosecops-runtime", integrationProblem, (status, body) =>
				corsJson(req, status, body),
			);
		}

		function configured(): boolean {
			if (!runtimeUrl || !runtimeToken) return false;
			try {
				const parsed = new URL(runtimeUrl);
				if (parsed.protocol !== "https:") return false;
				if (parsed.username || parsed.password || parsed.search || parsed.hash) return false;
			} catch {
				return false;
			}
			const singleTenantMapping =
				isAidrTeamId(aidrTeamIdSetting) && isAutoSecOpsTeamId(autoSecOpsTeamIdSetting);
			return singleTenantMapping || Boolean(teamMapRaw);
		}

		function resolveAutoSecOpsTeam(aidrTeamId: string): string | null {
			const map = parseTeamMap(teamMapRaw);
			if (map === null) return null;
			const mapped = map[aidrTeamId];
			if (mapped) return mapped;
			if (aidrTeamIdSetting === aidrTeamId && isAutoSecOpsTeamId(autoSecOpsTeamIdSetting)) {
				return autoSecOpsTeamIdSetting;
			}
			return null;
		}

		try {
			if (!configured()) throw new Error("integration_not_configured");
			const body = (await req.json()) as unknown;
			if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("invalid_query");
			const request = body as RequestBody;
			const action = typeof request.action === "string" ? request.action : "";
			if (action !== "health" && action !== "fleet" && action !== "performance") {
				throw new Error("invalid_query");
			}
			const token = getBearerToken(req);
			if (!token) throw new Error("missing_access_token");
			const supabase = makeClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
			const { data, error } = await supabase.auth.getUser(token);
			if (error || !data?.user?.id) throw new Error("invalid_access_token");
			const identity = await checkIdentityBarrier(supabase, token, data.user.id);
			if (!identity.ok) throw new Error(identity.error);
			const userId = data.user.id;
			// Team resolution stays in the request path, after the configuration
			// guard, because it is the first database work the request performs.
			let aidrTeamId = typeof request.team_id === "string" ? request.team_id.trim() : "";
			if (aidrTeamId) {
				if (!isAidrTeamId(aidrTeamId)) throw new Error("invalid_team_id");
				const { data: memberRow, error: memberError } = await supabase
					.from("team_members")
					.select("team_id")
					.eq("team_id", aidrTeamId)
					.eq("user_id", userId)
					.maybeSingle();
				if (memberError) throw new Error("team_membership_unavailable");
				if (!memberRow?.team_id) throw new Error("team_membership_required");
			} else {
				const { data: memberRows, error: memberError } = await supabase
					.from("team_members")
					.select("team_id")
					.eq("user_id", userId)
					.limit(2);
				if (memberError) throw new Error("team_membership_unavailable");
				const teams = (memberRows ?? []).map((row) => String(row.team_id)).filter(isAidrTeamId);
				if (teams.length > 1) throw new Error("team_selection_required");
				aidrTeamId = teams[0] ?? userId;
			}
			const tenantIdentity = await checkIdentityBarrier(supabase, token, userId, aidrTeamId);
			if (!tenantIdentity.ok) throw new Error(tenantIdentity.error);
			const autoSecOpsTeamId = resolveAutoSecOpsTeam(aidrTeamId);
			if (!autoSecOpsTeamId) throw new Error("integration_not_configured");
			const query = parseQuery(action, request.query);
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
				response = await doFetch(`${runtimeUrl}/api/v1/aidr/runtime/${path}`, {
					method: "POST",
					redirect: "error",
					signal: controller.signal,
					headers: {
						Accept: "application/json",
						"Content-Type": "application/json",
						// The provider credential never reaches the browser: it is attached
						// here, in the server-side leg only.
						Authorization: `Bearer ${runtimeToken}`,
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
			let providerData: unknown;
			try {
				providerData = await response.json();
			} catch {
				return corsJson(req, 502, { error: "autosecops_invalid_response", provider: "autosecops" });
			}
			if (!providerData || typeof providerData !== "object" || Array.isArray(providerData)) {
				return corsJson(req, 502, { error: "autosecops_invalid_response", provider: "autosecops" });
			}
			return corsJson(req, 200, {
				ok: true,
				provider: "autosecops",
				action,
				team_id: autoSecOpsTeamId,
				data: providerData,
			});
		} catch (cause) {
			const failure = cause instanceof Error ? cause : new Error("integration_failed");
			const status = failure.name === "AbortError" ? 504 : errorStatus(failure);
			return corsJson(req, status, {
				error: status === 500 ? "integration_failed" : failure.message,
			});
		}
	};
}

Deno.serve(createAutoSecOpsRuntimeHandler());
