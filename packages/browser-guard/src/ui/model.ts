/**
 * Pure view-model helpers shared by the popup and the options page.
 * Nothing here touches the DOM or extension APIs.
 */

import { ADAPTERS, adapterForUrl } from "../sites/index.js";
import {
	ENTITY_TYPES,
	type EntityType,
	type GuardMode,
	type GuardPolicy,
	type GuardStats,
	type LiteralRule,
	type SiteId,
	type TelemetryConfig,
} from "../types.js";
import { msg } from "./i18n.js";

export const GUARD_MODES: readonly GuardMode[] = ["auto", "confirm", "block", "monitor"];

/** Policy keys the UI edits; a key present in `policy.managedKeys` renders read-only. */
export type ManagedKey =
	| "mode"
	| "enabledEntities"
	| "literals"
	| "disabledSites"
	| "maskPaste"
	| "restoreResponses"
	| "useNativeHost"
	| "language"
	| "telemetry";

export function isLocked(policy: GuardPolicy, key: ManagedKey): boolean {
	return policy.managedKeys.includes(key);
}

export type SupportedSiteId = Exclude<SiteId, "other">;

export interface SiteInfo {
	readonly id: SupportedSiteId;
	readonly label: string;
	readonly hosts: readonly string[];
}

/**
 * AI chat products Browser Guard protects, derived from the site adapters so the
 * UI lists exactly the hosts the content script runs on.
 */
export const SUPPORTED_SITES: readonly SiteInfo[] = ADAPTERS.filter(
	(adapter): adapter is typeof adapter & { id: SupportedSiteId } => adapter.id !== "other",
).map((adapter) => ({ id: adapter.id, label: adapter.label, hosts: adapter.hosts }));

export function siteLabel(id: SiteId | null | undefined): string | null {
	return SUPPORTED_SITES.find((site) => site.id === id)?.label ?? null;
}

export function isSupportedSite(id: unknown): id is SupportedSiteId {
	return SUPPORTED_SITES.some((site) => site.id === id);
}

/**
 * Maps a tab URL to a supported site, or null. Uses the same exact-host
 * resolver as the content script, so the popup never claims protection on a
 * page the guard does not run on.
 */
export function siteForUrl(url: string | undefined): SupportedSiteId | null {
	if (!url) return null;
	const id = adapterForUrl(url).id;
	return isSupportedSite(id) ? id : null;
}

export type EntityGroupId =
	| "identity"
	| "contact"
	| "financial"
	| "technical"
	| "organization"
	| "other";

export interface EntityGroup {
	readonly id: EntityGroupId;
	readonly labelKey: string;
	readonly types: readonly EntityType[];
}

export const ENTITY_GROUPS: readonly EntityGroup[] = [
	{
		id: "identity",
		labelKey: msg("group_identity"),
		types: ["PERSON", "TC_KIMLIK", "US_SSN", "PASSPORT", "NATIONAL_ID", "DATE_OF_BIRTH", "TAX_ID"],
	},
	{
		id: "contact",
		labelKey: msg("group_contact"),
		types: ["EMAIL", "PHONE", "ADDRESS", "LOCATION"],
	},
	{
		id: "financial",
		labelKey: msg("group_financial"),
		types: ["IBAN", "CREDIT_CARD", "BANK_ACCOUNT"],
	},
	{
		id: "technical",
		labelKey: msg("group_technical"),
		types: ["SECRET", "PRIVATE_KEY", "IP_ADDRESS", "MAC_ADDRESS", "USERNAME"],
	},
	{ id: "organization", labelKey: msg("group_organization"), types: ["INTERNAL", "CLASSIFIED"] },
	{ id: "other", labelKey: msg("group_other"), types: ["HEALTH_ID", "LICENSE_PLATE"] },
];

/** Returns the enabled list with `type` toggled, in canonical ENTITY_TYPES order. */
export function toggleEntity(
	enabled: readonly EntityType[],
	type: EntityType,
	on: boolean,
): EntityType[] {
	const set = new Set(enabled);
	if (on) set.add(type);
	else set.delete(type);
	return ENTITY_TYPES.filter((candidate) => set.has(candidate));
}

export function toggleSite(
	disabled: readonly SiteId[],
	site: SupportedSiteId,
	enabled: boolean,
): SiteId[] {
	const rest = disabled.filter((candidate) => candidate !== site);
	return enabled ? rest : [...rest, site];
}

export type ProtectionStatus =
	| { readonly kind: "loading" }
	| { readonly kind: "unsupported" }
	| { readonly kind: "blocked"; readonly site: SupportedSiteId }
	| { readonly kind: "disabled-policy"; readonly site: SupportedSiteId }
	| { readonly kind: "disabled-user"; readonly site: SupportedSiteId }
	| { readonly kind: "paused"; readonly site: SupportedSiteId; readonly until: number }
	| { readonly kind: "monitoring"; readonly site: SupportedSiteId }
	| { readonly kind: "protected"; readonly site: SupportedSiteId };

/**
 * Protection status for the current tab. Order matters: an organisation block
 * wins over everything, then per-site disablement, then a user pause.
 */
export function protectionStatus(
	policy: GuardPolicy,
	stats: GuardStats,
	urlSite: SupportedSiteId | null,
	now: number,
): ProtectionStatus {
	const site = isSupportedSite(stats.site) ? stats.site : urlSite;
	if (!site) return { kind: "unsupported" };
	if (policy.blockedSites.includes(site)) return { kind: "blocked", site };
	if (policy.disabledSites.includes(site)) {
		return isLocked(policy, "disabledSites")
			? { kind: "disabled-policy", site }
			: { kind: "disabled-user", site };
	}
	if (stats.pausedUntil !== null && stats.pausedUntil > now) {
		return { kind: "paused", site, until: stats.pausedUntil };
	}
	if (policy.mode === "monitor") return { kind: "monitoring", site };
	return { kind: "protected", site };
}

export interface EntityCount {
	readonly type: EntityType;
	readonly count: number;
}

/** Entity types with a positive count, highest first (ties in canonical order). */
export function topEntityTypes(
	byType: Readonly<Partial<Record<EntityType, number>>>,
	limit = 5,
): EntityCount[] {
	return ENTITY_TYPES.map((type) => ({ type, count: byType[type] ?? 0 }))
		.filter((entry) => Number.isFinite(entry.count) && entry.count > 0)
		.sort((a, b) => b.count - a.count)
		.slice(0, limit);
}

export const LITERAL_MIN_LENGTH = 2;
export const LITERAL_MAX_LENGTH = 256;
export const LITERAL_MAX_COUNT = 1024;

export type LiteralError = "too_short" | "too_long" | "multiline" | "duplicate" | "limit";

export type LiteralValidation =
	| { readonly ok: true; readonly rule: LiteralRule }
	| { readonly ok: false; readonly error: LiteralError };

export const LITERAL_ERROR_KEYS: Readonly<Record<LiteralError, string>> = {
	too_short: msg("literal_error_too_short"),
	too_long: msg("literal_error_too_long"),
	multiline: msg("literal_error_multiline"),
	duplicate: msg("literal_error_duplicate"),
	limit: msg("literal_error_limit"),
};

/**
 * Validates a custom term before it is added. Lengths count UTF-16 code units,
 * the same unit the background policy validator uses, so a term accepted here
 * is never rejected when it is saved.
 */
export function validateLiteral(
	rawValue: string,
	type: EntityType,
	existing: readonly LiteralRule[],
): LiteralValidation {
	const value = rawValue.trim();
	if (existing.length >= LITERAL_MAX_COUNT) return { ok: false, error: "limit" };
	if (/[\r\n]/.test(value)) return { ok: false, error: "multiline" };
	if (value.length < LITERAL_MIN_LENGTH) return { ok: false, error: "too_short" };
	if (value.length > LITERAL_MAX_LENGTH) return { ok: false, error: "too_long" };
	const folded = value.toLocaleLowerCase();
	if (existing.some((rule) => rule.value.trim().toLocaleLowerCase() === folded)) {
		return { ok: false, error: "duplicate" };
	}
	return { ok: true, rule: { value, type } };
}

export function removeLiteral(existing: readonly LiteralRule[], index: number): LiteralRule[] {
	return existing.filter((_rule, position) => position !== index);
}

export type TelemetryError = "url_invalid" | "url_insecure" | "key_missing" | "key_invalid";

export type TelemetryValidation =
	| { readonly ok: true; readonly config: TelemetryConfig }
	| { readonly ok: false; readonly error: TelemetryError };

export const TELEMETRY_ERROR_KEYS: Readonly<Record<TelemetryError, string>> = {
	url_invalid: msg("telemetry_error_url_invalid"),
	url_insecure: msg("telemetry_error_url_insecure"),
	key_missing: msg("telemetry_error_key_missing"),
	key_invalid: msg("telemetry_error_key_invalid"),
};

export const API_KEY_MIN_LENGTH = 8;
export const API_KEY_MAX_LENGTH = 512;
const API_KEY_PATTERN = /^[\x21-\x7e]+$/;
const MAX_URL_LENGTH = 2048;
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1"]);

/**
 * Validates the organisation connection form with the same rules the
 * background policy applies: HTTPS (plain HTTP only for a localhost control
 * plane in development), no credentials, query or fragment in the URL, and a
 * printable-ASCII API key of 8..512 characters. An empty key keeps the saved key.
 */
export function validateTelemetry(
	rawUrl: string,
	rawKey: string,
	current: TelemetryConfig | null,
): TelemetryValidation {
	const trimmed = rawUrl.trim();
	let parsed: URL;
	try {
		if (trimmed.length === 0 || trimmed.length > MAX_URL_LENGTH) throw new Error("length");
		parsed = new URL(trimmed);
	} catch {
		return { ok: false, error: "url_invalid" };
	}
	if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
		return { ok: false, error: "url_invalid" };
	}
	if (parsed.username || parsed.password || parsed.search || parsed.hash) {
		return { ok: false, error: "url_invalid" };
	}
	if (parsed.protocol === "http:" && !LOOPBACK_HOSTS.has(parsed.hostname)) {
		return { ok: false, error: "url_insecure" };
	}
	const apiKey = rawKey.trim() || current?.apiKey || "";
	if (!apiKey) return { ok: false, error: "key_missing" };
	if (
		apiKey.length < API_KEY_MIN_LENGTH ||
		apiKey.length > API_KEY_MAX_LENGTH ||
		!API_KEY_PATTERN.test(apiKey)
	) {
		return { ok: false, error: "key_invalid" };
	}
	const controlPlaneUrl = `${parsed.origin}${parsed.pathname.replace(/\/+$/, "")}`;
	return { ok: true, config: { controlPlaneUrl, apiKey } };
}

function isStringArray(value: unknown): value is string[] {
	return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

/** Structural check on a GET_POLICY response before the UI trusts it. */
export function isGuardPolicy(value: unknown): value is GuardPolicy {
	if (typeof value !== "object" || value === null) return false;
	const policy = value as Partial<Record<keyof GuardPolicy, unknown>>;
	return (
		typeof policy.mode === "string" &&
		GUARD_MODES.includes(policy.mode as GuardMode) &&
		isStringArray(policy.enabledEntities) &&
		isStringArray(policy.managedKeys) &&
		isStringArray(policy.blockedSites) &&
		isStringArray(policy.disabledSites) &&
		isStringArray(policy.neverRestore) &&
		Array.isArray(policy.literals) &&
		policy.literals.every(
			(rule) =>
				typeof rule === "object" &&
				rule !== null &&
				typeof (rule as LiteralRule).value === "string" &&
				typeof (rule as LiteralRule).type === "string",
		) &&
		typeof policy.maskPaste === "boolean" &&
		typeof policy.restoreResponses === "boolean" &&
		typeof policy.allowUserPause === "boolean" &&
		(policy.language === "auto" || policy.language === "en" || policy.language === "tr") &&
		typeof policy.policyId === "string" &&
		(policy.telemetry === null ||
			(typeof policy.telemetry === "object" &&
				typeof (policy.telemetry as TelemetryConfig).controlPlaneUrl === "string"))
	);
}

/** Structural check on a GET_STATS response. */
export function isGuardStats(value: unknown): value is GuardStats {
	if (typeof value !== "object" || value === null) return false;
	const stats = value as Partial<Record<keyof GuardStats, unknown>>;
	return (
		typeof stats.protectedPrompts === "number" &&
		typeof stats.maskedItems === "number" &&
		typeof stats.blockedSends === "number" &&
		typeof stats.byType === "object" &&
		stats.byType !== null &&
		(stats.pausedUntil === null || typeof stats.pausedUntil === "number") &&
		(stats.nativeHost === "connected" ||
			stats.nativeHost === "unavailable" ||
			stats.nativeHost === "disabled")
	);
}

/**
 * A failed background request. `code` is the worker's stable error code
 * (e.g. LOCKED_KEYS, PAUSE_DISABLED) or NO_RESPONSE / BAD_RESPONSE.
 */
export class GuardRequestError extends Error {
	constructor(
		readonly code: string,
		readonly keys: readonly string[] = [],
	) {
		super(`Background request failed: ${code}`);
		this.name = "GuardRequestError";
	}
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

/**
 * Checks a background reply. Every reply is `{ ok: true, ... }` or
 * `{ ok: false, error }`; anything else (including no reply) is a failure, so
 * the UI never reports a change as saved when the worker did not confirm it.
 */
export function expectOk(response: unknown): Record<string, unknown> {
	if (!isRecord(response)) throw new GuardRequestError("NO_RESPONSE");
	if (response.ok === false) {
		const code = typeof response.error === "string" ? response.error : "UNKNOWN";
		throw new GuardRequestError(code, isStringArray(response.keys) ? response.keys : []);
	}
	if (response.ok !== true) throw new GuardRequestError("BAD_RESPONSE");
	return response;
}

/** Extracts the policy from a GET_POLICY / SET_USER_SETTINGS reply. */
export function policyFromResponse(response: unknown): GuardPolicy {
	const policy = expectOk(response).policy;
	if (!isGuardPolicy(policy)) throw new GuardRequestError("BAD_RESPONSE");
	return policy;
}

/** Extracts the stats from a GET_STATS reply. */
export function statsFromResponse(response: unknown): GuardStats {
	const stats = expectOk(response).stats;
	if (!isGuardStats(stats)) throw new GuardRequestError("BAD_RESPONSE");
	return stats;
}

/** Message key explaining a failed request to the user. */
export function errorKeyFor(error: unknown): string {
	if (error instanceof GuardRequestError) {
		if (error.code === "LOCKED_KEYS") return msg("error_locked");
		if (error.code === "PAUSE_DISABLED") return msg("error_pause_disabled");
		if (error.code === "INVALID_SETTINGS") return msg("error_invalid");
	}
	return msg("error_save");
}
