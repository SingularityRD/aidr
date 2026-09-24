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

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
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
import { readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

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
	return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[name];
};

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_REQUEST_BODY_BYTES = 16 * 1024;
const MAX_PROVIDER_BODY_BYTES = 256 * 1024;

const AUTO_SECOPS_ENV_NAMES = [
	"AUTOSECOPS_RUNTIME_URL",
	"AUTOSECOPS_RUNTIME_TOKEN",
	"AUTOSECOPS_AIDR_TEAM_ID",
	"AUTOSECOPS_TEAM_ID",
	"AUTOSECOPS_RUNTIME_TEAM_MAP",
] as const;

type Action = "health" | "fleet";
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

function record(value: unknown): Record<string, unknown> | null {
	return value && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: null;
}

function scoped(value: Record<string, unknown>, teamId: string): boolean {
	return (!Object.hasOwn(value, "team_id") || value.team_id === teamId) &&
		(!Object.hasOwn(value, "tenant_id") || value.tenant_id === `team:${teamId}`);
}

function boundedString(value: unknown, limit: number): value is string {
	return typeof value === "string" && value.length > 0 && value.length <= limit &&
		!/[\u0000-\u001f\u007f]/.test(value);
}

function strings(
	input: Record<string, unknown>,
	limits: Record<string, number>,
	required: readonly string[],
): Record<string, string> | null {
	const output: Record<string, string> = {};
	for (const [key, limit] of Object.entries(limits)) {
		const value = input[key];
		if (value === undefined || value === null) {
			if (required.includes(key)) return null;
			continue;
		}
		if (!boundedString(value, limit)) return null;
		output[key] = value;
	}
	return output;
}

function providerData(action: Action, value: unknown, teamId: string): Record<string, unknown> | null {
	const root = record(value);
	if (!root || !scoped(root, teamId)) return null;
	if (action === "health") {
		const snapshot = record(root.snapshot);
		if (!snapshot || !scoped(snapshot, teamId)) return null;
		const fields = strings(snapshot, { state: 32 }, ["state"]);
		if (!fields) return null;
		const clean: Record<string, unknown> = { ...fields };
		for (const key of ["active_agents", "open_degradations"]) {
			const count = snapshot[key];
			if (count === undefined || count === null) continue;
			if (!Number.isSafeInteger(count) || Number(count) < 0 || Number(count) > 1_000_000_000) return null;
			clean[key] = count;
		}
		if (snapshot.components !== undefined && snapshot.components !== null) {
			if (!Array.isArray(snapshot.components) || snapshot.components.length > 32) return null;
			const components: Record<string, string>[] = [];
			for (const item of snapshot.components) {
				const component = record(item);
				if (!component) return null;
				const fields = strings(component, { name: 128, state: 32 }, ["name", "state"]);
				if (!fields) return null;
				components.push(fields);
			}
			clean.components = components;
		}
		return { snapshot: clean };
	}
	const response = record(root.response);
	if (!response || !scoped(response, teamId) || !Array.isArray(response.items) || response.items.length > 100) return null;
	const items: Record<string, string>[] = [];
	const limits = {
		agent_id: 128, agent_name: 128, runtime: 64, instance_id: 128,
		connector: 64, connector_version: 64, state: 32, health: 32, last_event_at: 64,
	};
	for (const item of response.items) {
		const agent = record(item);
		if (!agent || !scoped(agent, teamId)) return null;
		const fields = strings(agent, limits, ["agent_id"]);
		if (!fields) return null;
		items.push(fields);
	}
	return { response: { items } };
}

export function errorStatus(error: Error): number {
	switch (error.message) {
		case "missing_access_token":
		case "invalid_access_token":
		case "session_revoked":
			return 401;
		case "mfa_required":
		case "team_membership_required":
		case "tenant_inactive":
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
				parsed.pathname === "/" &&
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
			const parsedBody = await readBoundedJson(req, MAX_REQUEST_BODY_BYTES);
			if (!parsedBody.ok) {
				if (parsedBody.status === 413) return corsJson(req, 413, { error: "invalid_query" });
				throw new Error("invalid_query");
			}
			const body = parsedBody.value;
			if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("invalid_query");
			const request = body as RequestBody;
			const action = typeof request.action === "string" ? request.action : "";
			if (action !== "health" && action !== "fleet") {
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
					.from("tenant_members")
					.select("tenant_id,role,expires_at")
					.eq("tenant_id", aidrTeamId)
					.eq("user_id", userId)
					.maybeSingle();
				if (memberError) throw new Error("team_membership_unavailable");
				if (!membershipActive(memberRow, now())) throw new Error("team_membership_required");
			} else {
				const activeAfter = new Date(now()).toISOString();
				const { data: memberRows, error: memberError } = await supabase
					.from("tenant_members")
					.select("tenant_id,role,expires_at")
					.eq("user_id", userId)
					.or(`expires_at.is.null,expires_at.gt.${activeAfter}`)
					.limit(2);
				if (memberError) throw new Error("team_membership_unavailable");
				const teams = ((memberRows ?? []) as Array<{ tenant_id: unknown; role?: string; expires_at?: string | null }>)
					.filter((row) => membershipActive(row, now()))
					.map((row) => String(row.tenant_id))
					.filter(isAidrTeamId);
				if (teams.length > 1) throw new Error("team_selection_required");
				aidrTeamId = teams[0] ?? "";
				if (!aidrTeamId) throw new Error("team_membership_required");
			}
			const { data: tenant, error: tenantError } = await supabase
				.from("tenants")
				.select("status")
				.eq("id", aidrTeamId)
				.maybeSingle();
			if (tenantError) throw new Error("team_membership_unavailable");
			if ((tenant as { status?: unknown } | null)?.status !== "active") throw new Error("tenant_inactive");
			const tenantIdentity = await checkIdentityBarrier(supabase, token, userId, aidrTeamId);
			if (!tenantIdentity.ok) throw new Error(tenantIdentity.error);
			const autoSecOpsTeamId = resolveAutoSecOpsTeam(aidrTeamId);
			if (!autoSecOpsTeamId) throw new Error("integration_not_configured");
			const query = parseQuery(action, request.query);
			const path = action;
			const payload: Record<string, unknown> = {
				scope: { tenant_id: `team:${autoSecOpsTeamId}`, team_id: autoSecOpsTeamId },
			};
			if (action === "health") payload.query = {};
			if (action === "fleet") payload.query = query;

			const controller = new AbortController();
			const timeout = setTimeout(() => controller.abort(), 5000);
			let response: Response;
			try {
				response = await doFetch(`${new URL(runtimeUrl).origin}/api/v1/aidr/runtime/${path}`, {
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
			const parsedProvider = await readBoundedJson(response, MAX_PROVIDER_BODY_BYTES);
			if (!parsedProvider.ok) {
				return corsJson(req, 502, { error: "autosecops_invalid_response", provider: "autosecops" });
			}
			const filteredData = providerData(action, parsedProvider.value, autoSecOpsTeamId);
			if (!filteredData) {
				return corsJson(req, 502, { error: "autosecops_invalid_response", provider: "autosecops" });
			}
			return corsJson(req, 200, {
				ok: true,
				provider: "autosecops",
				action,
				team_id: autoSecOpsTeamId,
				data: filteredData,
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
