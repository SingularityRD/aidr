import { supabase } from "./supabase";

/**
 * Client for the `siem-destinations` Edge Function (SIEM page, central
 * forwarding). Every answer is validated. Connection settings are write-only:
 * the service never returns a token, key, secret or CA, only a non-secret
 * `targetHint` (provider route and host:port).
 */

const SIEM_PROVIDERS = ["syslog", "splunk_hec", "elastic", "sentinel", "webhook"] as const;
export type SiemProvider = (typeof SIEM_PROVIDERS)[number];
const SIEM_FORMATS = ["json", "cef", "leef"] as const;
export type SiemFormat = (typeof SIEM_FORMATS)[number];
export const SIEM_SEVERITIES = ["info", "warning", "high", "critical"] as const;
export type SiemSeverity = (typeof SIEM_SEVERITIES)[number];
export const SIEM_DECISIONS = ["deny", "ask", "allow"] as const;
export type SiemDecision = (typeof SIEM_DECISIONS)[number];

export interface SiemFilters {
	incidents: boolean;
	decisions: SiemDecision[];
	browser: boolean;
	minSeverity: SiemSeverity;
}

export const DEFAULT_SIEM_FILTERS: SiemFilters = Object.freeze({
	incidents: true,
	decisions: ["deny", "ask"],
	browser: false,
	minSeverity: "info",
}) as SiemFilters;

export interface SiemDestination {
	id: string;
	provider: SiemProvider;
	format: SiemFormat;
	name: string;
	targetHint: string;
	enabled: boolean;
	filters: SiemFilters;
	lastDeliveryAt: string | null;
	lastDeliveryStatus: string | null;
	lastError: string | null;
	consecutiveFailures: number;
	droppedEvents: number;
	pending: number;
	dead: number;
}

interface SiemDeadLetter {
	id: string;
	destinationId: string;
	kind: string;
	type: string | null;
	decision: string | null;
	severity: string | null;
	attempts: number;
	lastError: string | null;
	lastStatusCode: number | null;
	deadAt: string | null;
}

export interface SiemSettings {
	configured: boolean;
	privateNetworksAllowed: boolean;
	canManage: boolean;
	maxDestinations: number;
	destinations: SiemDestination[];
	deadLetters: SiemDeadLetter[];
}

export type SiemResult<T> = { ok: true; value: T } | { ok: false; error: string };

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

const nullableString = (value: unknown) => (typeof value === "string" ? value : null);
const count = (value: unknown) => (Number.isSafeInteger(value) ? (value as number) : 0);

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

function readFilters(value: unknown): SiemFilters | null {
	if (!isRecord(value)) return null;
	const { incidents, decisions, browser, min_severity } = value;
	if (
		typeof incidents !== "boolean" ||
		typeof browser !== "boolean" ||
		!SIEM_SEVERITIES.includes(min_severity as SiemSeverity) ||
		!Array.isArray(decisions) ||
		!decisions.every((item) => SIEM_DECISIONS.includes(item as SiemDecision))
	)
		return null;
	return {
		incidents,
		browser,
		decisions: decisions as SiemDecision[],
		minSeverity: min_severity as SiemSeverity,
	};
}

function readDestination(value: unknown): SiemDestination | null {
	if (!isRecord(value)) return null;
	const filters = readFilters(value.filters);
	if (
		!filters ||
		typeof value.id !== "string" ||
		!SIEM_PROVIDERS.includes(value.provider as SiemProvider) ||
		!SIEM_FORMATS.includes(value.format as SiemFormat) ||
		typeof value.name !== "string" ||
		typeof value.target_hint !== "string" ||
		typeof value.enabled !== "boolean"
	)
		return null;
	return {
		id: value.id,
		provider: value.provider as SiemProvider,
		format: value.format as SiemFormat,
		name: value.name,
		targetHint: value.target_hint,
		enabled: value.enabled,
		filters,
		lastDeliveryAt: nullableString(value.last_delivery_at),
		lastDeliveryStatus: nullableString(value.last_delivery_status),
		lastError: nullableString(value.last_error),
		consecutiveFailures: count(value.consecutive_failures),
		droppedEvents: count(value.dropped_events),
		pending: count(value.pending),
		dead: count(value.dead),
	};
}

function readDeadLetter(value: unknown): SiemDeadLetter | null {
	if (
		!isRecord(value) ||
		typeof value.id !== "string" ||
		typeof value.destination_id !== "string" ||
		typeof value.kind !== "string"
	)
		return null;
	return {
		id: value.id,
		destinationId: value.destination_id,
		kind: value.kind,
		type: nullableString(value.type),
		decision: nullableString(value.decision),
		severity: nullableString(value.severity),
		attempts: count(value.attempts),
		lastError: nullableString(value.last_error),
		lastStatusCode: Number.isSafeInteger(value.last_status_code)
			? (value.last_status_code as number)
			: null,
		deadAt: nullableString(value.dead_at),
	};
}

function allOrNothing<T>(values: unknown, read: (value: unknown) => T | null): T[] | null {
	if (!Array.isArray(values)) return null;
	const rows = values.map(read);
	return rows.every((row): row is T => row !== null) ? rows : null;
}

export async function loadSiemSettings(tenantId: string): Promise<SiemResult<SiemSettings>> {
	try {
		const { data, error } = await supabase.functions.invoke("siem-destinations", {
			method: "GET",
			headers: { "X-AIDR-Tenant-ID": tenantId },
		});
		if (error)
			return { ok: false, error: (await errorCode(error)) ?? "siem_destinations_unavailable" };
		if (
			!isRecord(data) ||
			data.ok !== true ||
			!isRecord(data.permissions) ||
			!isRecord(data.limits)
		)
			return { ok: false, error: "siem_destinations_unavailable" };
		const destinations = allOrNothing(data.destinations, readDestination);
		const deadLetters = allOrNothing(data.dead_letters, readDeadLetter);
		if (!destinations || !deadLetters || typeof data.configured !== "boolean")
			return { ok: false, error: "siem_destinations_unavailable" };
		return {
			ok: true,
			value: {
				configured: data.configured,
				privateNetworksAllowed: data.private_networks_allowed === true,
				canManage: data.permissions.can_manage === true,
				maxDestinations: count(data.limits.max_destinations),
				destinations,
				deadLetters,
			},
		};
	} catch {
		return { ok: false, error: "siem_destinations_unavailable" };
	}
}

async function mutate(
	body: Record<string, unknown>,
	fallback: string,
): Promise<SiemResult<Record<string, unknown>>> {
	try {
		const { data, error } = await supabase.functions.invoke("siem-destinations", {
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

function filtersBody(filters: SiemFilters) {
	return {
		incidents: filters.incidents,
		decisions: [...new Set(filters.decisions)],
		browser: filters.browser,
		min_severity: filters.minSeverity,
	};
}

export async function createSiemDestination(
	tenantId: string,
	input: {
		provider: SiemProvider;
		format: SiemFormat;
		name: string;
		config: Record<string, unknown>;
		filters: SiemFilters;
	},
): Promise<SiemResult<SiemDestination>> {
	const result = await mutate(
		{
			tenant_id: tenantId,
			action: "create",
			provider: input.provider,
			format: input.format,
			name: input.name,
			config: input.config,
			filters: filtersBody(input.filters),
		},
		"siem_destination_create_failed",
	);
	if (!result.ok) return result;
	const destination = readDestination(result.value.destination);
	return destination
		? { ok: true, value: destination }
		: { ok: false, error: "siem_destination_create_failed" };
}

export async function updateSiemDestination(
	tenantId: string,
	destinationId: string,
	changes: { enabled?: boolean; format?: SiemFormat; filters?: SiemFilters },
): Promise<SiemResult<SiemDestination>> {
	const result = await mutate(
		{
			tenant_id: tenantId,
			action: "update",
			destination_id: destinationId,
			...(changes.enabled !== undefined ? { enabled: changes.enabled } : {}),
			...(changes.format !== undefined ? { format: changes.format } : {}),
			...(changes.filters !== undefined ? { filters: filtersBody(changes.filters) } : {}),
		},
		"siem_destination_update_failed",
	);
	if (!result.ok) return result;
	const destination = readDestination(result.value.destination);
	return destination
		? { ok: true, value: destination }
		: { ok: false, error: "siem_destination_update_failed" };
}

export async function siemDestinationAction(
	tenantId: string,
	destinationId: string,
	action: "delete" | "test" | "requeue",
): Promise<SiemResult<{ status?: string; error?: string | null; requeued?: number }>> {
	const result = await mutate(
		{ tenant_id: tenantId, action, destination_id: destinationId },
		`siem_${action}_failed`,
	);
	if (!result.ok) return result;
	if (action === "test") {
		const delivery = result.value.delivery;
		if (!isRecord(delivery) || typeof delivery.status !== "string")
			return { ok: false, error: "siem_test_failed" };
		return { ok: true, value: { status: delivery.status, error: nullableString(delivery.error) } };
	}
	if (action === "requeue") return { ok: true, value: { requeued: count(result.value.requeued) } };
	return { ok: true, value: {} };
}
