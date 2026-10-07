// Tenant alert channels for the dashboard (Settings → Notifications).
//
// GET   Header X-AIDR-Tenant-ID. Owners and administrators list channels
//       (metadata and a non-secret target hint only) and recent deliveries.
// POST  { tenant_id, action: "create", type, name, target, filters, enabled? }
//       { tenant_id, action: "update", channel_id, name?, enabled?, filters?, target? }
//       { tenant_id, action: "delete", channel_id }
//       { tenant_id, action: "test", channel_id }
//       owner/admin at AAL2, rate limited, audited by the RPCs.
//
// Destinations are write-only: `target` is validated (https, provider host
// allow-list, no private/metadata addresses), encrypted with
// AIDR_NOTIFICATION_ENCRYPTION_KEYS bound to (tenant, channel, type), and never
// echoed back. A test send enqueues a content-free outbox row and delivers it
// immediately through the same dispatcher path the scheduled worker uses.
//
// Authorization is re-derived on the server for every request and repeated in
// the service-role RPCs under row locks. Every failure is closed.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, type EnvReader, loadConfig, readConfigValue } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { createMailer, type Mailer } from "../_shared/mailer.ts";
import { DispatchError, runNotificationDispatch } from "../_shared/notification-delivery.ts";
import {
	CHANNEL_TYPES,
	type ChannelType,
	denoDnsResolver,
	type DnsResolver,
	encryptTarget,
	type NotificationKeyring,
	parseKeyring,
	parseTarget,
	targetHint,
} from "../_shared/notification-targets.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 8192;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CONTROL = /\p{Cc}/u;
export const MAX_CHANNELS = 20;
export const CHANNEL_NAME_MAX = 80;
/** Always required (the original filter object). */
export const FILTER_KEYS = [
	"incident_created",
	"incident_min_severity",
	"runtime_deny_critical",
	"approval_requested",
	"privacy_blocked_spike",
	"privacy_spike_threshold",
	"privacy_spike_window_minutes",
] as const;
/**
 * Agent-offline and governance filters (migration 20260928000001). Optional:
 * absent means "off" on create and "unchanged" on update.
 */
export const EXTENDED_FILTER_KEYS = [
	"agent_offline",
	"agent_offline_minutes",
	"governance_review_overdue",
	"governance_intake_requested",
	"governance_change_pending",
	"governance_exception_expiring",
	"governance_exception_days",
	"governance_digest",
] as const;
export const AGENT_OFFLINE_MINUTES = Object.freeze({ min: 5, max: 10_080 });
export const EXCEPTION_DAYS = Object.freeze({ min: 1, max: 90 });

const readRuntimeEnv: EnvReader = (name) => {
	try {
		const value = Deno.env.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Node contract tests use process.env when Deno is unavailable.
	}
	return globalThis.process?.env?.[name];
};

type DatabaseClient = ReturnType<typeof createClient>;

export interface NotificationChannelsDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => DatabaseClient;
	now?: () => number;
	random?: () => number;
	fetch?: typeof fetch;
	resolveDns?: DnsResolver;
	mailer?: Mailer;
	newId?: () => string;
}

export interface ChannelFilters {
	incident_created: boolean;
	incident_min_severity: "info" | "warning" | "high" | "critical";
	runtime_deny_critical: boolean;
	approval_requested: boolean;
	privacy_blocked_spike: boolean;
	privacy_spike_threshold: number;
	privacy_spike_window_minutes: number;
	agent_offline?: boolean;
	agent_offline_minutes?: number;
	governance_review_overdue?: boolean;
	governance_intake_requested?: boolean;
	governance_change_pending?: boolean;
	governance_exception_expiring?: boolean;
	governance_exception_days?: number;
	governance_digest?: boolean;
}

export type ChannelCommand =
	| {
			action: "create";
			tenantId: string;
			type: ChannelType;
			name: string;
			target: unknown;
			filters: ChannelFilters;
			enabled: boolean;
	  }
	| {
			action: "update";
			tenantId: string;
			channelId: string;
			name?: string;
			enabled?: boolean;
			filters?: ChannelFilters;
			target?: unknown;
	  }
	| { action: "delete" | "test"; tenantId: string; channelId: string };

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function onlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
	return Object.keys(value).every((key) => allowed.includes(key));
}

export function normalizeChannelName(value: unknown): string | null {
	if (typeof value !== "string" || CONTROL.test(value)) return null;
	const trimmed = value.trim();
	return trimmed.length >= 1 && trimmed.length <= CHANNEL_NAME_MAX ? trimmed : null;
}

function boundedInteger(value: unknown, bounds: { min: number; max: number }): boolean {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= bounds.min && value <= bounds.max;
}

/**
 * Mirrors app.notification_filters_valid: the original keys are all required,
 * the extended keys are optional, anything else is refused.
 */
export function parseFilters(value: unknown): ChannelFilters | null {
	if (!isRecord(value) || !FILTER_KEYS.every((key) => key in value) ||
		!onlyKeys(value, [...FILTER_KEYS, ...EXTENDED_FILTER_KEYS])) {
		return null;
	}
	const extendedBools = [
		"agent_offline",
		"governance_review_overdue",
		"governance_intake_requested",
		"governance_change_pending",
		"governance_exception_expiring",
		"governance_digest",
	] as const;
	if (!extendedBools.every((key) => value[key] === undefined || typeof value[key] === "boolean")) return null;
	if (value.agent_offline_minutes !== undefined && !boundedInteger(value.agent_offline_minutes, AGENT_OFFLINE_MINUTES)) {
		return null;
	}
	if (value.governance_exception_days !== undefined && !boundedInteger(value.governance_exception_days, EXCEPTION_DAYS)) {
		return null;
	}
	const bools = ["incident_created", "runtime_deny_critical", "approval_requested", "privacy_blocked_spike"] as const;
	if (!bools.every((key) => typeof value[key] === "boolean")) return null;
	if (!["info", "warning", "high", "critical"].includes(value.incident_min_severity as string)) return null;
	const threshold = value.privacy_spike_threshold;
	const window = value.privacy_spike_window_minutes;
	if (typeof threshold !== "number" || !Number.isSafeInteger(threshold) || threshold < 1 || threshold > 10_000) {
		return null;
	}
	if (typeof window !== "number" || !Number.isSafeInteger(window) || window < 5 || window > 1440) return null;
	if (!bools.some((key) => value[key] === true) && !extendedBools.some((key) => value[key] === true)) return null;
	return value as unknown as ChannelFilters;
}

export function parseChannelCommand(value: unknown): { ok: true; command: ChannelCommand } | { ok: false; error: string } {
	if (!isRecord(value) || typeof value.tenant_id !== "string" || !UUID.test(value.tenant_id)) {
		return { ok: false, error: "invalid_request" };
	}
	const tenantId = value.tenant_id.toLowerCase();
	if (value.action === "create") {
		if (!onlyKeys(value, ["action", "tenant_id", "type", "name", "target", "filters", "enabled"])) {
			return { ok: false, error: "invalid_request" };
		}
		if (!CHANNEL_TYPES.includes(value.type as ChannelType)) return { ok: false, error: "invalid_channel_type" };
		const name = normalizeChannelName(value.name);
		if (name === null) return { ok: false, error: "invalid_channel_name" };
		const filters = parseFilters(value.filters);
		if (!filters) return { ok: false, error: "invalid_filters" };
		if (value.enabled !== undefined && typeof value.enabled !== "boolean") return { ok: false, error: "invalid_request" };
		if (value.target === undefined) return { ok: false, error: "invalid_target" };
		return {
			ok: true,
			command: {
				action: "create",
				tenantId,
				type: value.type as ChannelType,
				name,
				target: value.target,
				filters,
				enabled: value.enabled !== false,
			},
		};
	}
	if (typeof value.channel_id !== "string" || !UUID.test(value.channel_id)) {
		return { ok: false, error: value.action === "update" || value.action === "delete" || value.action === "test" ? "invalid_request" : "invalid_action" };
	}
	const channelId = value.channel_id.toLowerCase();
	if (value.action === "update") {
		if (!onlyKeys(value, ["action", "tenant_id", "channel_id", "name", "enabled", "filters", "target"])) {
			return { ok: false, error: "invalid_request" };
		}
		if (value.name === undefined && value.enabled === undefined && value.filters === undefined && value.target === undefined) {
			return { ok: false, error: "no_changes" };
		}
		const command: ChannelCommand = { action: "update", tenantId, channelId };
		if (value.name !== undefined) {
			const name = normalizeChannelName(value.name);
			if (name === null) return { ok: false, error: "invalid_channel_name" };
			command.name = name;
		}
		if (value.enabled !== undefined) {
			if (typeof value.enabled !== "boolean") return { ok: false, error: "invalid_request" };
			command.enabled = value.enabled;
		}
		if (value.filters !== undefined) {
			const filters = parseFilters(value.filters);
			if (!filters) return { ok: false, error: "invalid_filters" };
			command.filters = filters;
		}
		if (value.target !== undefined) command.target = value.target;
		return { ok: true, command };
	}
	if (value.action === "delete" || value.action === "test") {
		if (!onlyKeys(value, ["action", "tenant_id", "channel_id"])) return { ok: false, error: "invalid_request" };
		return { ok: true, command: { action: value.action, tenantId, channelId } };
	}
	return { ok: false, error: "invalid_action" };
}

function rpcFailure(req: Request, error: { code?: string } | null, headers: Record<string, string>): Response {
	switch (error?.code) {
		case "42501":
			return corsJson(req, 403, { error: "notification_channels_forbidden" }, headers);
		case "22023":
			return corsJson(req, 400, { error: "invalid_notification_channel" }, headers);
		case "P0002":
			return corsJson(req, 404, { error: "notification_channel_not_found" }, headers);
		case "23505":
			return corsJson(req, 409, { error: "notification_channel_name_conflict" }, headers);
		case "54000":
			return corsJson(req, 409, { error: "notification_channel_limit" }, headers);
		case "55000":
			return corsJson(req, 409, { error: "workspace_not_active" }, headers);
		default:
			return corsJson(req, 503, { error: "notification_channels_unavailable" }, headers);
	}
}

function validChannelView(value: unknown): value is Record<string, unknown> {
	return isRecord(value) && typeof value.id === "string" && UUID.test(value.id) &&
		CHANNEL_TYPES.includes(value.type as ChannelType) && typeof value.name === "string" &&
		typeof value.target_hint === "string" && typeof value.enabled === "boolean" && isRecord(value.filters) &&
		!("target_ciphertext" in value);
}

/** Channel view without write-only fields, whatever the RPC returned. */
function channelView(value: Record<string, unknown>) {
	const {
		id, type, name, target_hint, enabled, filters, created_by, created_at, updated_at,
		last_delivery_at, last_delivery_status, last_error, consecutive_failures,
	} = value;
	return {
		id, type, name, target_hint, enabled, filters, created_by, created_at, updated_at,
		last_delivery_at, last_delivery_status, last_error, consecutive_failures,
	};
}

export function createNotificationChannelsHandler(deps: NotificationChannelsDeps = {}) {
	const runtimeEnv = deps.env ?? readRuntimeEnv;
	const now = deps.now ?? Date.now;
	const random = deps.random ?? Math.random;
	const newId = deps.newId ?? (() => crypto.randomUUID());
	const makeClient = deps.client ?? ((url, key) => createClient(url, key, {
		auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
	}));

	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "GET" && req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) {
			return configFailure("notification-channels", config.error, (status, body) => corsJson(req, status, body));
		}

		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });

		let command: ChannelCommand | null = null;
		let tenantId: string;
		if (req.method === "GET") {
			const header = (req.headers.get("X-AIDR-Tenant-ID") ?? "").trim();
			if (!UUID.test(header)) return corsJson(req, 400, { error: "invalid_request" });
			tenantId = header.toLowerCase();
		} else {
			const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
			if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
			const result = parseChannelCommand(parsed.value);
			if (!result.ok) return corsJson(req, 400, { error: result.error });
			command = result.command;
			tenantId = command.tenantId;
		}

		const keyring: NotificationKeyring | null = await parseKeyring(
			readConfigValue(runtimeEnv, "AIDR_NOTIFICATION_ENCRYPTION_KEYS"),
		);
		const mailer = deps.mailer ?? createMailer(runtimeEnv);

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
				return corsJson(req, 403, { error: "notification_channels_forbidden" });
			}
			const status = (tenant as { status?: unknown } | null)?.status;
			if (!tenant || status === "closed" || status === "closing") {
				return corsJson(req, 403, { error: "notification_channels_forbidden" });
			}

			if (!command) {
				const { data, error } = await db.rpc("list_notification_channels", { p_tenant_id: tenantId });
				if (error || !isRecord(data) || !Array.isArray(data.channels) || !Array.isArray(data.recent_deliveries) ||
					!data.channels.every(validChannelView)) {
					return corsJson(req, 503, { error: "notification_channels_unavailable" });
				}
				return corsJson(req, 200, {
					ok: true,
					configured: keyring !== null,
					mail_configured: mailer.provider !== "none",
					permissions: { can_manage: status === "active", requires_aal2: true },
					limits: { max_channels: MAX_CHANNELS },
					channels: (data.channels as Record<string, unknown>[]).map(channelView),
					recent_deliveries: data.recent_deliveries,
				});
			}

			if (status !== "active") return corsJson(req, 409, { error: "workspace_not_active" });
			// Alert destinations are privileged configuration: require step-up even
			// when the tenant's general MFA policy is optional.
			const { data: assurance, error: assuranceError } = await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
			if (assuranceError || !assurance) return corsJson(req, 503, { error: "assurance_unavailable" });
			if (assurance.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" });

			const testing = command.action === "test";
			const rate = await consumeTenantRateLimit(db, {
				tenantId,
				subject: userId,
				endpoint: testing ? "notification-channels:test" : "notification-channels",
				perSubject: testing ? 5 : 20,
				perTenant: testing ? 20 : 100,
			});
			if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
			const headers = rateLimitHeaders(rate);

			if (command.action === "delete") {
				const { data, error } = await db.rpc("delete_notification_channel", {
					p_tenant_id: tenantId,
					p_actor_user_id: userId,
					p_channel_id: command.channelId,
				});
				if (error) return rpcFailure(req, error, headers);
				if (!isRecord(data) || data.deleted !== true) {
					return corsJson(req, 503, { error: "notification_channels_unavailable" }, headers);
				}
				return corsJson(req, 200, { ok: true, deleted: command.channelId }, headers);
			}

			if (command.action === "test") {
				if (!keyring) return corsJson(req, 503, { error: "notifications_not_configured" }, headers);
				const { data, error } = await db.rpc("enqueue_notification_test", {
					p_tenant_id: tenantId,
					p_actor_user_id: userId,
					p_channel_id: command.channelId,
				});
				if (error) return rpcFailure(req, error, headers);
				const deliveryId = isRecord(data) ? data.delivery_id : null;
				if (typeof deliveryId !== "string" || !UUID.test(deliveryId)) {
					return corsJson(req, 503, { error: "notification_channels_unavailable" }, headers);
				}
				const summary = await runNotificationDispatch(db as never, {
					keyring,
					dashboardUrl: readConfigValue(runtimeEnv, "AIDR_DASHBOARD_URL"),
					fetch: deps.fetch ?? fetch,
					resolveDns: deps.resolveDns ?? denoDnsResolver,
					mailer,
					now,
					random,
					deliveryId,
				});
				const result = summary.results[0];
				return corsJson(req, 200, {
					ok: true,
					delivery: {
						id: deliveryId,
						status: result?.status ?? "pending",
						error: result?.error ?? null,
						status_code: result?.statusCode ?? null,
					},
				}, headers);
			}

			// create / update: encrypt any new destination with the channel binding.
			let channelId: string;
			let type: ChannelType;
			if (command.action === "create") {
				channelId = newId().toLowerCase();
				type = command.type;
			} else {
				channelId = command.channelId;
				const { data: existing, error: existingError } = await db.from("notification_channels")
					.select("id,type").eq("id", channelId).eq("tenant_id", tenantId).maybeSingle();
				if (existingError) return corsJson(req, 503, { error: "notification_channels_unavailable" }, headers);
				if (!existing) return corsJson(req, 404, { error: "notification_channel_not_found" }, headers);
				type = (existing as { type: ChannelType }).type;
				if (!CHANNEL_TYPES.includes(type)) {
					return corsJson(req, 503, { error: "notification_channels_unavailable" }, headers);
				}
			}

			let sealed: { ciphertext: string; keyId: string; hint: string } | null = null;
			const rawTarget = command.target;
			if (rawTarget !== undefined) {
				if (!keyring) return corsJson(req, 503, { error: "notifications_not_configured" }, headers);
				const target = parseTarget(type, rawTarget);
				if (!target.ok) return corsJson(req, 400, { error: target.error }, headers);
				const encrypted = await encryptTarget(keyring, { tenantId, channelId, type }, target.target);
				sealed = { ...encrypted, hint: await targetHint(target.target) };
			}

			const { data, error } = command.action === "create"
				? await db.rpc("create_notification_channel", {
					p_tenant_id: tenantId,
					p_actor_user_id: userId,
					p_channel_id: channelId,
					p_type: type,
					p_name: command.name,
					p_target_ciphertext: sealed?.ciphertext,
					p_target_key_id: sealed?.keyId,
					p_target_hint: sealed?.hint,
					p_filters: command.filters,
					p_enabled: command.enabled,
				})
				: await db.rpc("update_notification_channel", {
					p_tenant_id: tenantId,
					p_actor_user_id: userId,
					p_channel_id: channelId,
					p_expected_type: type,
					p_name: command.name ?? null,
					p_enabled: command.enabled ?? null,
					p_filters: command.filters ?? null,
					p_target_ciphertext: sealed?.ciphertext ?? null,
					p_target_key_id: sealed?.keyId ?? null,
					p_target_hint: sealed?.hint ?? null,
				});
			if (error) return rpcFailure(req, error, headers);
			if (!validChannelView(data)) return corsJson(req, 503, { error: "notification_channels_unavailable" }, headers);
			return corsJson(req, 200, {
				ok: true,
				channel: channelView(data),
				...(Array.isArray(data.changed) ? { changed: data.changed } : {}),
			}, headers);
		} catch (error) {
			if (error instanceof DispatchError) {
				return corsJson(req, 503, { error: "notification_delivery_unavailable" });
			}
			return corsJson(req, 503, { error: "notification_channels_unavailable" });
		}
	};
}

const notificationChannels = createNotificationChannelsHandler();
Deno.serve(notificationChannels);
