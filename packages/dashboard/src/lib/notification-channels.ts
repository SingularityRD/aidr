import { supabase } from "./supabase";

/**
 * Client for the `notification-channels` Edge Function (Settings →
 * Notifications). Every answer is validated. Destinations are write-only: the
 * service never returns a webhook URL, secret or recipient list, only a
 * non-secret `targetHint`.
 */

const CHANNEL_TYPES = ["slack", "teams", "webhook", "email"] as const;
export type ChannelType = (typeof CHANNEL_TYPES)[number];
export const SEVERITIES = ["info", "warning", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export interface NotificationFilters {
	incidentCreated: boolean;
	incidentMinSeverity: Severity;
	runtimeDenyCritical: boolean;
	approvalRequested: boolean;
	privacyBlockedSpike: boolean;
	privacySpikeThreshold: number;
	privacySpikeWindowMinutes: number;
}

export const DEFAULT_FILTERS: NotificationFilters = Object.freeze({
	incidentCreated: true,
	incidentMinSeverity: "high",
	runtimeDenyCritical: true,
	approvalRequested: false,
	privacyBlockedSpike: false,
	privacySpikeThreshold: 10,
	privacySpikeWindowMinutes: 15,
});

export const SPIKE_BOUNDS = Object.freeze({
	threshold: { min: 1, max: 10_000 },
	windowMinutes: { min: 5, max: 1440 },
});

export interface NotificationChannel {
	id: string;
	type: ChannelType;
	name: string;
	targetHint: string;
	enabled: boolean;
	filters: NotificationFilters;
	createdAt: string | null;
	lastDeliveryAt: string | null;
	lastDeliveryStatus: string | null;
	lastError: string | null;
	consecutiveFailures: number;
}

export interface NotificationDelivery {
	id: string;
	channelId: string;
	eventType: string;
	status: string;
	attempts: number;
	lastError: string | null;
	lastStatusCode: number | null;
	createdAt: string;
}

export interface NotificationSettings {
	configured: boolean;
	mailConfigured: boolean;
	canManage: boolean;
	maxChannels: number;
	channels: NotificationChannel[];
	recentDeliveries: NotificationDelivery[];
}

export type ChannelTarget =
	| { url: string }
	| { url: string; secret: string }
	| { recipients: string[] };

export interface TestResult {
	status: "delivered" | "pending" | "dead" | "lease_lost";
	error: string | null;
	statusCode: number | null;
}

export type NotificationResult<T> = { ok: true; value: T } | { ok: false; error: string };

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

const nullableString = (value: unknown) => (typeof value === "string" ? value : null);

/** The service's machine-readable error code, if the failed response carried one. */
async function errorCode(error: unknown): Promise<string | null> {
	const context = (error as { context?: unknown } | null | undefined)?.context;
	if (!(context instanceof Response)) return null;
	try {
		const body: unknown = await context.clone().json();
		return isRecord(body) &&
			typeof body.error === "string" &&
			/^[a-z][a-z0-9_]{0,63}$/.test(body.error)
			? body.error
			: null;
	} catch {
		return null;
	}
}

function readFilters(value: unknown): NotificationFilters | null {
	if (!isRecord(value)) return null;
	const {
		incident_created,
		incident_min_severity,
		runtime_deny_critical,
		approval_requested,
		privacy_blocked_spike,
		privacy_spike_threshold,
		privacy_spike_window_minutes,
	} = value;
	if (
		typeof incident_created !== "boolean" ||
		!SEVERITIES.includes(incident_min_severity as Severity) ||
		typeof runtime_deny_critical !== "boolean" ||
		typeof approval_requested !== "boolean" ||
		typeof privacy_blocked_spike !== "boolean" ||
		!Number.isSafeInteger(privacy_spike_threshold) ||
		!Number.isSafeInteger(privacy_spike_window_minutes)
	)
		return null;
	return {
		incidentCreated: incident_created,
		incidentMinSeverity: incident_min_severity as Severity,
		runtimeDenyCritical: runtime_deny_critical,
		approvalRequested: approval_requested,
		privacyBlockedSpike: privacy_blocked_spike,
		privacySpikeThreshold: privacy_spike_threshold as number,
		privacySpikeWindowMinutes: privacy_spike_window_minutes as number,
	};
}

function filtersBody(filters: NotificationFilters) {
	return {
		incident_created: filters.incidentCreated,
		incident_min_severity: filters.incidentMinSeverity,
		runtime_deny_critical: filters.runtimeDenyCritical,
		approval_requested: filters.approvalRequested,
		privacy_blocked_spike: filters.privacyBlockedSpike,
		privacy_spike_threshold: filters.privacySpikeThreshold,
		privacy_spike_window_minutes: filters.privacySpikeWindowMinutes,
	};
}

function readChannel(value: unknown): NotificationChannel | null {
	if (!isRecord(value)) return null;
	const filters = readFilters(value.filters);
	if (
		!filters ||
		typeof value.id !== "string" ||
		!CHANNEL_TYPES.includes(value.type as ChannelType) ||
		typeof value.name !== "string" ||
		typeof value.target_hint !== "string" ||
		typeof value.enabled !== "boolean"
	)
		return null;
	return {
		id: value.id,
		type: value.type as ChannelType,
		name: value.name,
		targetHint: value.target_hint,
		enabled: value.enabled,
		filters,
		createdAt: nullableString(value.created_at),
		lastDeliveryAt: nullableString(value.last_delivery_at),
		lastDeliveryStatus: nullableString(value.last_delivery_status),
		lastError: nullableString(value.last_error),
		consecutiveFailures: Number.isSafeInteger(value.consecutive_failures)
			? (value.consecutive_failures as number)
			: 0,
	};
}

function readDelivery(value: unknown): NotificationDelivery | null {
	if (
		!isRecord(value) ||
		typeof value.id !== "string" ||
		typeof value.channel_id !== "string" ||
		typeof value.event_type !== "string" ||
		typeof value.status !== "string" ||
		!Number.isSafeInteger(value.attempts) ||
		typeof value.created_at !== "string"
	)
		return null;
	return {
		id: value.id,
		channelId: value.channel_id,
		eventType: value.event_type,
		status: value.status,
		attempts: value.attempts as number,
		lastError: nullableString(value.last_error),
		lastStatusCode: Number.isSafeInteger(value.last_status_code)
			? (value.last_status_code as number)
			: null,
		createdAt: value.created_at,
	};
}

function allOrNothing<T>(values: unknown, read: (value: unknown) => T | null): T[] | null {
	if (!Array.isArray(values)) return null;
	const rows = values.map(read);
	return rows.every((row): row is T => row !== null) ? rows : null;
}

export async function loadNotificationSettings(
	tenantId: string,
): Promise<NotificationResult<NotificationSettings>> {
	try {
		const { data, error } = await supabase.functions.invoke("notification-channels", {
			method: "GET",
			headers: { "X-AIDR-Tenant-ID": tenantId },
		});
		if (error)
			return { ok: false, error: (await errorCode(error)) ?? "notification_channels_unavailable" };
		if (
			!isRecord(data) ||
			data.ok !== true ||
			!isRecord(data.permissions) ||
			!isRecord(data.limits)
		) {
			return { ok: false, error: "notification_channels_unavailable" };
		}
		const channels = allOrNothing(data.channels, readChannel);
		const recentDeliveries = allOrNothing(data.recent_deliveries, readDelivery);
		if (
			!channels ||
			!recentDeliveries ||
			typeof data.configured !== "boolean" ||
			typeof data.mail_configured !== "boolean" ||
			typeof data.permissions.can_manage !== "boolean" ||
			!Number.isSafeInteger(data.limits.max_channels)
		)
			return { ok: false, error: "notification_channels_unavailable" };
		return {
			ok: true,
			value: {
				configured: data.configured,
				mailConfigured: data.mail_configured,
				canManage: data.permissions.can_manage,
				maxChannels: data.limits.max_channels as number,
				channels,
				recentDeliveries,
			},
		};
	} catch {
		return { ok: false, error: "notification_channels_unavailable" };
	}
}

async function mutate(
	body: Record<string, unknown>,
	fallback: string,
): Promise<NotificationResult<Record<string, unknown>>> {
	try {
		const { data, error } = await supabase.functions.invoke("notification-channels", {
			method: "POST",
			body,
		});
		if (error) return { ok: false, error: (await errorCode(error)) ?? fallback };
		return isRecord(data) && data.ok === true
			? { ok: true, value: data }
			: { ok: false, error: fallback };
	} catch {
		return { ok: false, error: fallback };
	}
}

function channelResult(
	result: NotificationResult<Record<string, unknown>>,
	fallback: string,
): NotificationResult<NotificationChannel> {
	if (!result.ok) return result;
	const channel = readChannel(result.value.channel);
	return channel ? { ok: true, value: channel } : { ok: false, error: fallback };
}

export async function createNotificationChannel(
	tenantId: string,
	input: {
		type: ChannelType;
		name: string;
		target: ChannelTarget;
		filters: NotificationFilters;
		enabled?: boolean;
	},
): Promise<NotificationResult<NotificationChannel>> {
	const result = await mutate(
		{
			tenant_id: tenantId,
			action: "create",
			type: input.type,
			name: input.name,
			target: input.target,
			filters: filtersBody(input.filters),
			...(input.enabled === false ? { enabled: false } : {}),
		},
		"notification_channel_create_failed",
	);
	return channelResult(result, "notification_channel_create_failed");
}

export async function updateNotificationChannel(
	tenantId: string,
	channelId: string,
	changes: {
		name?: string;
		enabled?: boolean;
		filters?: NotificationFilters;
		target?: ChannelTarget;
	},
): Promise<NotificationResult<NotificationChannel>> {
	const result = await mutate(
		{
			tenant_id: tenantId,
			action: "update",
			channel_id: channelId,
			...(changes.name !== undefined ? { name: changes.name } : {}),
			...(changes.enabled !== undefined ? { enabled: changes.enabled } : {}),
			...(changes.filters !== undefined ? { filters: filtersBody(changes.filters) } : {}),
			...(changes.target !== undefined ? { target: changes.target } : {}),
		},
		"notification_channel_update_failed",
	);
	return channelResult(result, "notification_channel_update_failed");
}

export async function deleteNotificationChannel(
	tenantId: string,
	channelId: string,
): Promise<NotificationResult<string>> {
	const result = await mutate(
		{ tenant_id: tenantId, action: "delete", channel_id: channelId },
		"notification_channel_delete_failed",
	);
	if (!result.ok) return result;
	return result.value.deleted === channelId
		? { ok: true, value: channelId }
		: { ok: false, error: "notification_channel_delete_failed" };
}

export async function testNotificationChannel(
	tenantId: string,
	channelId: string,
): Promise<NotificationResult<TestResult>> {
	const result = await mutate(
		{ tenant_id: tenantId, action: "test", channel_id: channelId },
		"notification_test_failed",
	);
	if (!result.ok) return result;
	const delivery = result.value.delivery;
	if (
		!isRecord(delivery) ||
		!["delivered", "pending", "dead", "lease_lost"].includes(String(delivery.status))
	)
		return { ok: false, error: "notification_test_failed" };
	return {
		ok: true,
		value: {
			status: delivery.status as TestResult["status"],
			error: nullableString(delivery.error),
			statusCode: Number.isSafeInteger(delivery.status_code)
				? (delivery.status_code as number)
				: null,
		},
	};
}

/**
 * A fresh signing secret for a generic webhook, generated in the browser so the
 * operator can copy it into the receiver before saving. The service stores it
 * encrypted and never returns it.
 */
export function generateWebhookSecret(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(32));
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return `whsec_${btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}`;
}

/** Split an operator-entered recipient list on commas, semicolons and whitespace. */
export function parseRecipients(value: string): string[] {
	return [
		...new Set(
			value
				.split(/[\s,;]+/)
				.map((item) => item.trim().toLowerCase())
				.filter(Boolean),
		),
	];
}
