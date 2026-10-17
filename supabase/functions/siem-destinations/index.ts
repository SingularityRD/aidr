// Tenant SIEM forwarding destinations for the dashboard (SIEM page).
//
// GET   Header X-AIDR-Tenant-ID. Owners and administrators list destinations
//       (metadata, a non-secret target hint, backlog and dead-letter counts)
//       and the most recent dead letters.
// POST  { tenant_id, action: "create", provider, format, name, config, filters, enabled? }
//       { tenant_id, action: "update", destination_id, name?, enabled?, format?, filters?, config? }
//       { tenant_id, action: "delete", destination_id }
//       { tenant_id, action: "test", destination_id }
//       { tenant_id, action: "requeue", destination_id }
//       owner/admin at AAL2, BUSINESS plan (siem_export), rate limited,
//       audited by the RPCs.
//
// Connection settings are write-only: `config` is validated, sealed with
// AIDR_NOTIFICATION_ENCRYPTION_KEYS bound to (tenant, destination, provider)
// and never echoed back. A test send enqueues a content-free outbox row and
// forwards it immediately through the same path the scheduled forwarder uses,
// so the dashboard shows the collector's real answer.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, type EnvReader, loadConfig, readConfigValue } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { denoDnsResolver, type DnsResolver, type NotificationKeyring, parseKeyring } from "../_shared/notification-targets.ts";
import { type PlanEntitlementDb, requireFeature } from "../_shared/plan-entitlements.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";
import {
	encryptSiemConfig,
	formatAllowed,
	parseSiemConfig,
	SIEM_FORMATS,
	SIEM_PROVIDERS,
	type SiemFormat,
	type SiemProvider,
	siemTargetHint,
} from "../_shared/siem-config.ts";
import { runSiemForwarding, SiemForwardError } from "../_shared/siem-forwarding.ts";
import { denoSocketTransport, type SocketTransport } from "../_shared/socket-transport.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 96 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CONTROL = /\p{Cc}/u;
export const MAX_DESTINATIONS = 10;
const NAME_MAX = 80;
const SEVERITIES = ["info", "warning", "high", "critical"] as const;
const DECISIONS = ["allow", "ask", "deny"] as const;

const readRuntimeEnv: EnvReader = (name) => {
	try {
		const value = Deno.env.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Node contract tests use process.env when Deno is unavailable.
	}
	return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[name];
};

type DatabaseClient = ReturnType<typeof createClient<any, "public">>;

export interface SiemDestinationsDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => DatabaseClient;
	now?: () => number;
	random?: () => number;
	resolveDns?: DnsResolver;
	transport?: SocketTransport;
	newId?: () => string;
}

export interface SiemFilters {
	incidents: boolean;
	decisions: Array<(typeof DECISIONS)[number]>;
	browser: boolean;
	/** Administrative actions and sign-ins (public.admin_audit_logs). Optional: absent means off on create, unchanged on update. */
	admin_audit?: boolean;
	min_severity: (typeof SEVERITIES)[number];
}

export type SiemCommand =
	| { action: "create"; tenantId: string; provider: SiemProvider; format: SiemFormat; name: string; config: unknown; filters: SiemFilters; enabled: boolean }
	| { action: "update"; tenantId: string; destinationId: string; name?: string; enabled?: boolean; format?: SiemFormat; filters?: SiemFilters; config?: unknown }
	| { action: "delete"; tenantId: string; destinationId: string }
	| { action: "test"; tenantId: string; destinationId: string }
	| { action: "requeue"; tenantId: string; destinationId: string };

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function onlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
	return Object.keys(value).every((key) => allowed.includes(key));
}

function normalizeName(value: unknown): string | null {
	if (typeof value !== "string" || CONTROL.test(value)) return null;
	const trimmed = value.trim();
	return trimmed.length >= 1 && trimmed.length <= NAME_MAX ? trimmed : null;
}

const FILTER_KEYS = ["incidents", "decisions", "browser", "min_severity"] as const;

/** Mirrors app.siem_filters_valid: four required keys (+ optional admin_audit), decisions unique, at least one event selected. */
export function parseSiemFilters(value: unknown): SiemFilters | null {
	if (!isRecord(value) || !FILTER_KEYS.every((key) => key in value) || !onlyKeys(value, [...FILTER_KEYS, "admin_audit"])) {
		return null;
	}
	if (typeof value.incidents !== "boolean" || typeof value.browser !== "boolean") return null;
	if (value.admin_audit !== undefined && typeof value.admin_audit !== "boolean") return null;
	if (!SEVERITIES.includes(value.min_severity as SiemFilters["min_severity"])) return null;
	if (!Array.isArray(value.decisions) || value.decisions.length > 3 ||
		!value.decisions.every((item) => DECISIONS.includes(item as SiemFilters["decisions"][number])) ||
		new Set(value.decisions).size !== value.decisions.length) {
		return null;
	}
	if (!value.incidents && !value.browser && value.admin_audit !== true && value.decisions.length === 0) return null;
	return value as unknown as SiemFilters;
}

export function parseSiemCommand(value: unknown): { ok: true; command: SiemCommand } | { ok: false; error: string } {
	if (!isRecord(value) || typeof value.tenant_id !== "string" || !UUID.test(value.tenant_id)) {
		return { ok: false, error: "invalid_request" };
	}
	const tenantId = value.tenant_id.toLowerCase();
	if (value.action === "create") {
		if (!onlyKeys(value, ["action", "tenant_id", "provider", "format", "name", "config", "filters", "enabled"])) {
			return { ok: false, error: "invalid_request" };
		}
		if (!SIEM_PROVIDERS.includes(value.provider as SiemProvider)) return { ok: false, error: "invalid_provider" };
		const format = (value.format ?? "json") as SiemFormat;
		if (!SIEM_FORMATS.includes(format) || !formatAllowed(value.provider as SiemProvider, format)) {
			return { ok: false, error: "invalid_format" };
		}
		const name = normalizeName(value.name);
		if (!name) return { ok: false, error: "invalid_destination_name" };
		const filters = parseSiemFilters(value.filters);
		if (!filters) return { ok: false, error: "invalid_filters" };
		if (value.enabled !== undefined && typeof value.enabled !== "boolean") return { ok: false, error: "invalid_request" };
		if (value.config === undefined) return { ok: false, error: "invalid_config" };
		return {
			ok: true,
			command: {
				action: "create",
				tenantId,
				provider: value.provider as SiemProvider,
				format,
				name,
				config: value.config,
				filters,
				enabled: value.enabled !== false,
			},
		};
	}
	if (!["update", "delete", "test", "requeue"].includes(value.action as string)) return { ok: false, error: "invalid_action" };
	if (typeof value.destination_id !== "string" || !UUID.test(value.destination_id)) return { ok: false, error: "invalid_request" };
	const destinationId = value.destination_id.toLowerCase();
	if (value.action !== "update") {
		if (!onlyKeys(value, ["action", "tenant_id", "destination_id"])) return { ok: false, error: "invalid_request" };
		const action = value.action as "delete" | "test" | "requeue";
		return { ok: true, command: { action, tenantId, destinationId } as SiemCommand };
	}
	if (!onlyKeys(value, ["action", "tenant_id", "destination_id", "name", "enabled", "format", "filters", "config"])) {
		return { ok: false, error: "invalid_request" };
	}
	const command: Extract<SiemCommand, { action: "update" }> = { action: "update", tenantId, destinationId };
	if (value.name !== undefined) {
		const name = normalizeName(value.name);
		if (!name) return { ok: false, error: "invalid_destination_name" };
		command.name = name;
	}
	if (value.enabled !== undefined) {
		if (typeof value.enabled !== "boolean") return { ok: false, error: "invalid_request" };
		command.enabled = value.enabled;
	}
	if (value.format !== undefined) {
		if (!SIEM_FORMATS.includes(value.format as SiemFormat)) return { ok: false, error: "invalid_format" };
		command.format = value.format as SiemFormat;
	}
	if (value.filters !== undefined) {
		const filters = parseSiemFilters(value.filters);
		if (!filters) return { ok: false, error: "invalid_filters" };
		command.filters = filters;
	}
	if (value.config !== undefined) command.config = value.config;
	if (Object.keys(command).length === 3) return { ok: false, error: "no_changes" };
	return { ok: true, command };
}

function rpcFailure(req: Request, error: { code?: string } | null, headers: Record<string, string>): Response {
	switch (error?.code) {
		case "42501":
			return corsJson(req, 403, { error: "siem_destinations_forbidden" }, headers);
		case "22023":
		case "23514":
			return corsJson(req, 400, { error: "invalid_siem_destination" }, headers);
		case "P0002":
			return corsJson(req, 404, { error: "siem_destination_not_found" }, headers);
		case "23505":
			return corsJson(req, 409, { error: "siem_destination_name_conflict" }, headers);
		case "54000":
			return corsJson(req, 409, { error: "siem_destination_limit" }, headers);
		case "55000":
			return corsJson(req, 409, { error: "workspace_not_active" }, headers);
		default:
			return corsJson(req, 503, { error: "siem_destinations_unavailable" }, headers);
	}
}

function validView(value: unknown): value is Record<string, unknown> {
	return isRecord(value) && typeof value.id === "string" && UUID.test(value.id) &&
		SIEM_PROVIDERS.includes(value.provider as SiemProvider) && typeof value.name === "string" &&
		typeof value.target_hint === "string" && typeof value.enabled === "boolean" && isRecord(value.filters) &&
		!("config_ciphertext" in value);
}

/** Destination view without write-only fields, whatever the RPC returned. */
function destinationView(value: Record<string, unknown>) {
	const {
		id, provider, format, name, target_hint, enabled, filters, created_by, created_at, updated_at,
		last_delivery_at, last_delivery_status, last_error, consecutive_failures, dropped_events, pending, dead,
	} = value;
	return {
		id, provider, format, name, target_hint, enabled, filters, created_by, created_at, updated_at,
		last_delivery_at, last_delivery_status, last_error, consecutive_failures, dropped_events, pending, dead,
	};
}

/** Tenant-wide count of rows that could not be queued (app.siem_enqueue_failure_summary). */
function enqueueFailures(value: unknown): { count: number; last_failed_at: string | null } {
	if (!isRecord(value)) return { count: 0, last_failed_at: null };
	return {
		count: Number.isSafeInteger(value.count) && (value.count as number) >= 0 ? (value.count as number) : 0,
		last_failed_at: typeof value.last_failed_at === "string" ? value.last_failed_at : null,
	};
}

export function createSiemDestinationsHandler(deps: SiemDestinationsDeps = {}) {
	const runtimeEnv = deps.env ?? readRuntimeEnv;
	const now = deps.now ?? Date.now;
	const newId = deps.newId ?? (() => crypto.randomUUID());
	const makeClient = deps.client ?? ((url, key) => createClient(url, key, {
		auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
	}));

	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "GET" && req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) return configFailure("siem-destinations", config.error, (status, body) => corsJson(req, status, body));

		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });

		let command: SiemCommand | null = null;
		let tenantId: string;
		if (req.method === "GET") {
			const header = (req.headers.get("X-AIDR-Tenant-ID") ?? "").trim();
			if (!UUID.test(header)) return corsJson(req, 400, { error: "invalid_request" });
			tenantId = header.toLowerCase();
		} else {
			const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
			if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
			const result = parseSiemCommand(parsed.value);
			if (!result.ok) return corsJson(req, 400, { error: result.error });
			command = result.command;
			tenantId = command.tenantId;
		}

		const keyring: NotificationKeyring | null = await parseKeyring(readConfigValue(runtimeEnv, "AIDR_NOTIFICATION_ENCRYPTION_KEYS"));
		const allowPrivate = readConfigValue(runtimeEnv, "AIDR_SIEM_ALLOW_PRIVATE_NETWORKS").trim().toLowerCase() === "true";

		try {
			const db = makeClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY);
			const { data: auth, error: authError } = await db.auth.getUser(token);
			if (authError || !auth.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
			const userId = auth.user.id;
			const barrier = await checkIdentityBarrier(db, token, userId, tenantId);
			if (!barrier.ok) return corsJson(req, barrier.status, { error: barrier.error });

			const [{ data: member, error: memberError }, { data: tenant, error: tenantError }] = await Promise.all([
				db.from("tenant_members").select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle(),
				db.from("tenants").select("id,status").eq("id", tenantId).maybeSingle(),
			]);
			if (memberError || tenantError) return corsJson(req, 503, { error: "authorization_unavailable" });
			const role = String((member as { role?: unknown } | null)?.role ?? "");
			if (!membershipActive(member as { role?: string; expires_at?: string | null } | null, now()) ||
				!["owner", "admin"].includes(role)) {
				return corsJson(req, 403, { error: "siem_destinations_forbidden" });
			}
			const status = (tenant as { status?: unknown } | null)?.status;
			if (!tenant || status === "closed" || status === "closing") {
				return corsJson(req, 403, { error: "siem_destinations_forbidden" });
			}
			// Central SIEM forwarding is part of the BUSINESS siem_export feature.
			const plan = await requireFeature(db as unknown as PlanEntitlementDb, tenantId, "siem_export");
			if (!plan.ok) return corsJson(req, plan.status, plan.body);

			if (!command) {
				const { data, error } = await db.rpc("list_siem_destinations", { p_tenant_id: tenantId });
				if (error || !isRecord(data) || !Array.isArray(data.destinations) || !Array.isArray(data.dead_letters) ||
					!data.destinations.every(validView)) {
					return corsJson(req, 503, { error: "siem_destinations_unavailable" });
				}
				return corsJson(req, 200, {
					ok: true,
					configured: keyring !== null,
					private_networks_allowed: allowPrivate,
					permissions: { can_manage: status === "active", requires_aal2: true },
					limits: { max_destinations: MAX_DESTINATIONS },
					destinations: (data.destinations as Record<string, unknown>[]).map(destinationView),
					dead_letters: data.dead_letters,
					enqueue_failures: enqueueFailures(data.enqueue_failures),
				});
			}

			if (status !== "active") return corsJson(req, 409, { error: "workspace_not_active" });
			// Forwarding destinations are privileged configuration: require step-up.
			const { data: assurance, error: assuranceError } = await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
			if (assuranceError || !assurance) return corsJson(req, 503, { error: "assurance_unavailable" });
			if (assurance.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" });

			const testing = command.action === "test";
			const rate = await consumeTenantRateLimit(db, {
				tenantId,
				subject: userId,
				endpoint: testing ? "siem-destinations:test" : "siem-destinations",
				perSubject: testing ? 5 : 20,
				perTenant: testing ? 20 : 100,
			});
			if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
			const headers = rateLimitHeaders(rate);
			const actor = { p_tenant_id: tenantId, p_actor_user_id: userId };

			if (command.action === "delete" || command.action === "requeue") {
				const { data, error } = command.action === "delete"
					? await db.rpc("delete_siem_destination", { ...actor, p_destination_id: command.destinationId })
					: await db.rpc("requeue_siem_dead_letters", { ...actor, p_destination_id: command.destinationId, p_limit: 50_000 });
				if (error) return rpcFailure(req, error, headers);
				if (!isRecord(data)) return corsJson(req, 503, { error: "siem_destinations_unavailable" }, headers);
				return command.action === "delete"
					? corsJson(req, 200, { ok: true, deleted: command.destinationId }, headers)
					: corsJson(req, 200, { ok: true, requeued: Number.isSafeInteger(data.requeued) ? data.requeued : 0 }, headers);
			}

			if (command.action === "test") {
				if (!keyring) return corsJson(req, 503, { error: "siem_not_configured" }, headers);
				const { data, error } = await db.rpc("enqueue_siem_test", { ...actor, p_destination_id: command.destinationId });
				if (error) return rpcFailure(req, error, headers);
				const deliveryId = isRecord(data) ? data.delivery_id : null;
				if (typeof deliveryId !== "string" || !/^[0-9]{1,19}$/.test(deliveryId)) {
					return corsJson(req, 503, { error: "siem_destinations_unavailable" }, headers);
				}
				const summary = await runSiemForwarding(db as never, {
					keyring,
					transport: deps.transport ?? denoSocketTransport,
					resolveDns: deps.resolveDns ?? denoDnsResolver,
					allowPrivateNetworks: allowPrivate,
					entitled: async () => "ok",
					now,
					random: deps.random ?? Math.random,
					deliveryId,
				});
				const result = summary.results[0];
				return corsJson(req, 200, {
					ok: true,
					delivery: {
						id: deliveryId,
						status: result ? (result.outcome === "delivered" ? "delivered" : "dead") : "pending",
						error: result?.error ?? null,
						status_code: result?.statusCode ?? null,
					},
				}, headers);
			}

			// create / update: seal any new configuration with the destination binding.
			let destinationId: string;
			let provider: SiemProvider;
			if (command.action === "create") {
				destinationId = newId().toLowerCase();
				provider = command.provider;
			} else {
				destinationId = command.destinationId;
				const { data: existing, error: existingError } = await db.from("siem_destinations")
					.select("id,provider").eq("id", destinationId).eq("tenant_id", tenantId).maybeSingle();
				if (existingError) return corsJson(req, 503, { error: "siem_destinations_unavailable" }, headers);
				if (!existing) return corsJson(req, 404, { error: "siem_destination_not_found" }, headers);
				provider = (existing as { provider: SiemProvider }).provider;
				if (!SIEM_PROVIDERS.includes(provider)) return corsJson(req, 503, { error: "siem_destinations_unavailable" }, headers);
				if (command.format && !formatAllowed(provider, command.format)) return corsJson(req, 400, { error: "invalid_format" }, headers);
			}

			let sealed: { ciphertext: string; keyId: string; hint: string } | null = null;
			if (command.config !== undefined) {
				if (!keyring) return corsJson(req, 503, { error: "siem_not_configured" }, headers);
				const parsed = parseSiemConfig(provider, command.config);
				if (!parsed.ok) return corsJson(req, 400, { error: parsed.error }, headers);
				// A private collector needs the operator's deployment-wide permission first.
				if ("allow_private_network" in parsed.config && parsed.config.allow_private_network && !allowPrivate) {
					return corsJson(req, 400, { error: "private_network_not_allowed" }, headers);
				}
				const encrypted = await encryptSiemConfig(keyring, { tenantId, destinationId, provider }, parsed.config);
				sealed = { ...encrypted, hint: siemTargetHint(parsed.config) };
			}

			const { data, error } = command.action === "create"
				? await db.rpc("create_siem_destination", {
					...actor,
					p_destination_id: destinationId,
					p_provider: provider,
					p_format: command.format,
					p_name: command.name,
					p_config_ciphertext: sealed?.ciphertext,
					p_config_key_id: sealed?.keyId,
					p_target_hint: sealed?.hint,
					p_filters: command.filters,
					p_enabled: command.enabled,
				})
				: await db.rpc("update_siem_destination", {
					...actor,
					p_destination_id: destinationId,
					p_expected_provider: provider,
					p_name: command.name ?? null,
					p_enabled: command.enabled ?? null,
					p_format: command.format ?? null,
					p_filters: command.filters ?? null,
					p_config_ciphertext: sealed?.ciphertext ?? null,
					p_config_key_id: sealed?.keyId ?? null,
					p_target_hint: sealed?.hint ?? null,
				});
			if (error) return rpcFailure(req, error, headers);
			if (!validView(data)) return corsJson(req, 503, { error: "siem_destinations_unavailable" }, headers);
			return corsJson(req, 200, {
				ok: true,
				destination: destinationView(data),
				...(Array.isArray(data.changed) ? { changed: data.changed } : {}),
			}, headers);
		} catch (error) {
			if (error instanceof SiemForwardError) return corsJson(req, 503, { error: "siem_delivery_unavailable" });
			return corsJson(req, 503, { error: "siem_destinations_unavailable" });
		}
	};
}

const siemDestinations = createSiemDestinationsHandler();
Deno.serve(siemDestinations);
