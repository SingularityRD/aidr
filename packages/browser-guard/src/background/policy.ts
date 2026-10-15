/**
 * Effective Browser Guard policy: administrator-managed policy (chrome.storage.managed)
 * merged over user settings (chrome.storage.local) merged over the built-in default.
 *
 * Validation is strict but never throws. An unknown key is ignored. A managed value of the
 * wrong shape fails safe instead of falling back to the built-in default (several defaults
 * are the permissive choice): a list keeps its valid entries, any other protection key takes
 * its strictest value (see FAIL_SAFE), and the key is locked and listed in
 * `policy.policyErrors` so the popup, the options page and telemetry can report it. Warnings
 * and error codes name keys only, never values (an apiKey must not reach a log line).
 */
import { WORKSPACE_ID_PATTERN } from "../sites/accounts.js";
import { AI_SERVICE_ID_PATTERN, AI_SERVICES } from "../sites/catalog.js";
import { CUSTOM_SITE_LIMITS, SELECTOR_FORBIDDEN } from "../sites/custom.js";
import {
	ACCOUNT_SITE_IDS,
	type AcceptableUseNotice,
	type AccountSiteId,
	type CustomSiteConfig,
	type DashboardPolicyTrust,
	ENTITY_TYPES,
	type EntityType,
	type ExactDataSet,
	type GuardMode,
	type GuardPolicy,
	type LiteralRule,
	type ShadowAiMode,
	type ShadowAiPolicy,
	type SiteId,
	type TelemetryConfig,
	type UserSettings,
	type WorkAccountAction,
	type WorkAccountPolicy,
	type WorkAccountSiteRule,
} from "../types.js";
import { SITE_HOSTS, SITE_PATHS } from "./dnr.js";
import { sha256Hex } from "./sha256.js";

const MIB = 1024 * 1024;

export const GUARD_MODES: readonly GuardMode[] = Object.freeze([
	"auto",
	"confirm",
	"block",
	"monitor",
]);

/** Every SiteId (kept local so the background does not depend on the site adapters). */
export const SITE_ID_LIST: readonly SiteId[] = Object.freeze([
	"chatgpt",
	"gemini",
	"claude",
	"copilot",
	"perplexity",
	"deepseek",
	"mistral",
	"grok",
	"custom",
	"other",
]);

const POLICY_LIMITS = Object.freeze({
	maxLiterals: 1024,
	literalMinChars: 2,
	literalMaxChars: 256,
	maxExactDataSets: 16,
	maxFingerprintsTotal: 100_000,
	maxFileBytes: 50 * MIB,
	maxUrlChars: 2048,
	apiKeyMinChars: 8,
	apiKeyMaxChars: 512,
});

/** Identifier syntax shared with the telemetry contract (`policy_id`). */
export const POLICY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DATASET_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const HEX64_PATTERN = /^[0-9a-fA-F]{64}$/;
const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;
const API_KEY_PATTERN = /^[\x21-\x7e]+$/;

/** Entity types that are noisy on chat pages and therefore off by default. */
const NOISY_BY_DEFAULT: readonly EntityType[] = ["USERNAME", "LOCATION"];

export const DEFAULT_POLICY: GuardPolicy = deepFreeze({
	version: 1,
	mode: "auto",
	enabledEntities: ENTITY_TYPES.filter((t) => !NOISY_BY_DEFAULT.includes(t)),
	neverRestore: ["SECRET", "PRIVATE_KEY"],
	literals: [],
	exactData: [],
	detectSignals: true,
	signalAction: "warn",
	blockedSites: [],
	disabledSites: [],
	customSites: [],
	shadowAi: { mode: "off", sanctioned: [], blocked: [] },
	allowUserPause: true,
	allowSendAnyway: true,
	maskPaste: true,
	fileHandling: "scan",
	documentHandling: "mask",
	maxFileBytes: 5 * MIB,
	restoreResponses: true,
	useNativeHost: false,
	requireNativeNer: false,
	uninspectedImages: "warn",
	telemetry: null,
	language: "auto",
	managedKeys: [],
	policyErrors: [],
	policyId: "aidr-browser-guard-default",
	acceptableUse: null,
	dashboardPolicy: null,
	workAccounts: null,
} satisfies GuardPolicy);

type Validator = (raw: unknown) => { ok: true; value: unknown } | { ok: false };

const valid = (value: unknown) => ({ ok: true as const, value });
const invalid = { ok: false as const };

function oneOf<T extends string>(values: readonly T[]): Validator {
	return (raw) => (typeof raw === "string" && values.includes(raw as T) ? valid(raw) : invalid);
}

const bool: Validator = (raw) => (typeof raw === "boolean" ? valid(raw) : invalid);

function isPlainObject(raw: unknown): raw is Record<string, unknown> {
	if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return false;
	const proto = Object.getPrototypeOf(raw);
	return proto === Object.prototype || proto === null;
}

function hasExactKeys(raw: Record<string, unknown>, keys: readonly string[]): boolean {
	const own = Object.keys(raw);
	return own.length === keys.length && own.every((k) => keys.includes(k));
}

function isEntityType(raw: unknown): raw is EntityType {
	return typeof raw === "string" && (ENTITY_TYPES as readonly string[]).includes(raw);
}

function enumList<T extends string>(values: readonly T[], maxItems: number): Validator {
	return (raw) => {
		if (!Array.isArray(raw) || raw.length > maxItems) return invalid;
		if (!raw.every((v) => typeof v === "string" && values.includes(v as T))) return invalid;
		return valid([...new Set(raw as T[])]);
	};
}

const entityList = enumList(ENTITY_TYPES, ENTITY_TYPES.length * 4);
const siteList = enumList(SITE_ID_LIST, SITE_ID_LIST.length * 4);

/** One `{ value, type }` literal rule, or null when it is malformed or out of bounds. */
function literalRule(item: unknown): LiteralRule | null {
	if (!isPlainObject(item) || !hasExactKeys(item, ["value", "type"])) return null;
	const { value, type } = item;
	if (typeof value !== "string" || !isEntityType(type)) return null;
	if (value.length < POLICY_LIMITS.literalMinChars) return null;
	if (value.length > POLICY_LIMITS.literalMaxChars) return null;
	if (value.trim().length < POLICY_LIMITS.literalMinChars) return null;
	return { value, type };
}

const literals: Validator = (raw) => {
	if (!Array.isArray(raw) || raw.length > POLICY_LIMITS.maxLiterals) return invalid;
	const out: LiteralRule[] = [];
	const seen = new Set<string>();
	for (const item of raw) {
		const rule = literalRule(item);
		if (!rule) return invalid;
		const key = `${rule.type}\u0000${rule.value}`;
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(rule);
	}
	return valid(out);
};

/**
 * The value the deployment examples (`deploy/browser-guard/*.example.*`) carry in
 * `exactData[].keyB64`. It is deliberately not base64, so it can never act as an HMAC
 * key; a managed policy that still holds it (or any other `REPLACE_WITH_` value) has its
 * `exactData` refused with a warning naming the cause. The examples once shipped a real
 * 32-byte key; it was retired as compromised and is refused too (see below).
 */
export const EXACT_DATA_PLACEHOLDER_KEY = "REPLACE_WITH_DATASET_KEY_FROM_FINGERPRINT_DATASET";
const PLACEHOLDER_PATTERN = /^\s*REPLACE_WITH_/i;
const isPlaceholderDataset = (item: unknown): boolean =>
	isPlainObject(item) &&
	(PLACEHOLDER_PATTERN.test(String(item.keyB64)) ||
		(Array.isArray(item.fingerprints) &&
			item.fingerprints.some((fp) => PLACEHOLDER_PATTERN.test(String(fp)))));

/**
 * The retired example dataset: the deployment examples once shipped a real 32-byte HMAC key
 * (dataset `crm-customers-example`). It is public, so it is treated as compromised: a managed
 * policy that still uses it has its `exactData` refused with a warning naming it. Only the
 * SHA-256 of the base64 value is kept here (the value itself must not reappear in the
 * repository), together with the example's fingerprints (HMAC digests, not secrets).
 */
const RETIRED_EXAMPLE_DIGESTS: ReadonlySet<string> = new Set([
	"6ebab6aa4ce1a68f67f8812933df26731a3696b9b23e2948e7165e8c3a5dc541",
]);
const RETIRED_EXAMPLE_FINGERPRINTS: ReadonlySet<string> = new Set([
	"7284cb51429e3ff4e4d9b0cc1cee1276631d01aacc98cd83b3f39847a747fa36",
	"dace37df0e61d972ce461b5887cc8ef241df0749dd737adc7de1b118305d89b2",
	"fd5d74d29c57fd1c18a6d23aa82f83ea8211081ed570ae9ac60b90f7e4b71180",
]);
const isRetiredExampleDataset = (item: unknown): boolean =>
	isPlainObject(item) &&
	((typeof item.keyB64 === "string" &&
		item.keyB64.length <= 1024 &&
		RETIRED_EXAMPLE_DIGESTS.has(sha256Hex(item.keyB64.trim()))) ||
		(Array.isArray(item.fingerprints) &&
			item.fingerprints.some((fp) =>
				RETIRED_EXAMPLE_FINGERPRINTS.has(String(fp).trim().toLowerCase()),
			)));

/**
 * Lowest estimated entropy (bits) a dataset may declare for its weakest value. Below this, an
 * endpoint holding the dataset key could enumerate the value space offline (a 7-digit customer
 * number is about 23 bits, a TCKN about 30): such columns must be combined into composite values
 * (name + number) or left to the built-in rules. Mirrors MIN_ENTROPY_BITS in
 * scripts/fingerprint-dataset.mjs (asserted by build-tools.test.ts).
 */
export const EXACT_DATA_MIN_ENTROPY_BITS = 64;
const MAX_ENTROPY_BITS = 4096;

const isFingerprint = (raw: unknown): boolean => typeof raw === "string" && HEX64_PATTERN.test(raw);

/** A dataset's fields once its shape is valid; fingerprints are checked by the caller. */
function datasetFields(
	item: unknown,
): (Omit<ExactDataSet, "fingerprints"> & { fingerprints: unknown[] }) | null {
	if (
		!isPlainObject(item) ||
		!hasExactKeys(item, ["datasetId", "keySource", "minEntropyBits", "fingerprints", "type"])
	)
		return null;
	const { datasetId, keySource, minEntropyBits, fingerprints, type } = item;
	if (typeof datasetId !== "string" || !DATASET_ID_PATTERN.test(datasetId)) return null;
	if (keySource !== "native-host" || !isEntityType(type) || !Array.isArray(fingerprints))
		return null;
	if (
		!Number.isSafeInteger(minEntropyBits) ||
		(minEntropyBits as number) < EXACT_DATA_MIN_ENTROPY_BITS ||
		(minEntropyBits as number) > MAX_ENTROPY_BITS
	)
		return null;
	return { datasetId, keySource, minEntropyBits: minEntropyBits as number, fingerprints, type };
}

const exactData: Validator = (raw) => {
	if (!Array.isArray(raw) || raw.length > POLICY_LIMITS.maxExactDataSets) return invalid;
	const out: ExactDataSet[] = [];
	const ids = new Set<string>();
	let total = 0;
	for (const item of raw) {
		const fields = datasetFields(item);
		if (!fields || ids.has(fields.datasetId)) return invalid;
		// Bound the total before checking every fingerprint.
		total += fields.fingerprints.length;
		if (total > POLICY_LIMITS.maxFingerprintsTotal) return invalid;
		if (!fields.fingerprints.every(isFingerprint)) return invalid;
		ids.add(fields.datasetId);
		const fingerprints = (fields.fingerprints as string[]).map((f) => f.toLowerCase());
		out.push({ ...fields, fingerprints: [...new Set(fingerprints)] });
	}
	return valid(out);
};

const maxFileBytes: Validator = (raw) =>
	Number.isSafeInteger(raw) && (raw as number) >= 1 && (raw as number) <= POLICY_LIMITS.maxFileBytes
		? valid(raw)
		: invalid;

const policyId: Validator = (raw) =>
	typeof raw === "string" && POLICY_ID_PATTERN.test(raw) ? valid(raw) : invalid;

/** Acceptable-use notice identifier, shared with the acknowledgement telemetry contract. */
export const NOTICE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
export const NOTICE_LIMITS = Object.freeze({
	versionMax: 999_999,
	titleMaxChars: 120,
	textMaxChars: 4000,
	urlMaxChars: 2048,
});
/** Control characters other than tab, line feed and carriage return. */
const NOTICE_CONTROL = /[^\P{Cc}\t\n\r]/u;
const NOTICE_KEYS = ["id", "version", "title", "text", "url"];

/** https only, no credentials; returns the normalised href or null. */
function noticeUrl(raw: unknown): string | null {
	if (typeof raw !== "string" || raw.length === 0 || raw.length > NOTICE_LIMITS.urlMaxChars)
		return null;
	try {
		const url = new URL(raw);
		if (url.protocol !== "https:" || url.username || url.password) return null;
		return url.href;
	} catch {
		return null;
	}
}

function noticeText(raw: unknown, max: number): string | null {
	if (typeof raw !== "string" || NOTICE_CONTROL.test(raw)) return null;
	const trimmed = raw.trim();
	return trimmed.length === 0 || trimmed.length > max ? null : trimmed;
}

/** The `acceptableUse` managed key: a whole notice or nothing. */
export function validateAcceptableUseNotice(raw: unknown): AcceptableUseNotice | null {
	if (!isPlainObject(raw) || !Object.keys(raw).every((key) => NOTICE_KEYS.includes(key)))
		return null;
	const { id, version } = raw;
	if (typeof id !== "string" || !NOTICE_ID_PATTERN.test(id)) return null;
	if (!Number.isSafeInteger(version) || (version as number) < 1) return null;
	if ((version as number) > NOTICE_LIMITS.versionMax) return null;
	const title = noticeText(raw.title, NOTICE_LIMITS.titleMaxChars);
	const text = noticeText(raw.text, NOTICE_LIMITS.textMaxChars);
	if (title === null || text === null) return null;
	if (raw.url === undefined) return { id, version: version as number, title, text };
	const url = noticeUrl(raw.url);
	return url === null ? null : { id, version: version as number, title, text, url };
}

const acceptableUse: Validator = (raw) => {
	const notice = validateAcceptableUseNotice(raw);
	return notice ? valid(notice) : invalid;
};

/**
 * Control-plane base URL: https only, except plain http to localhost/127.0.0.1 for
 * local development. No credentials, query or fragment. Returns the normalised URL
 * without a trailing slash, or null.
 */
export function normalizeControlPlaneUrl(raw: unknown): string | null {
	if (typeof raw !== "string" || raw.length === 0 || raw.length > POLICY_LIMITS.maxUrlChars)
		return null;
	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		return null;
	}
	if (url.username || url.password || url.search || url.hash) return null;
	const devHost = url.hostname === "localhost" || url.hostname === "127.0.0.1";
	if (url.protocol !== "https:" && !(url.protocol === "http:" && devHost)) return null;
	return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

const isApiKey = (raw: unknown): raw is string =>
	typeof raw === "string" &&
	raw.length >= POLICY_LIMITS.apiKeyMinChars &&
	raw.length <= POLICY_LIMITS.apiKeyMaxChars &&
	API_KEY_PATTERN.test(raw);

function telemetryValidator(allowNull: boolean): Validator {
	return (raw) => {
		if (raw === null) return allowNull ? valid(null) : invalid;
		if (!isPlainObject(raw) || !hasExactKeys(raw, ["controlPlaneUrl", "apiKey"])) return invalid;
		const controlPlaneUrl = normalizeControlPlaneUrl(raw.controlPlaneUrl);
		const { apiKey } = raw;
		if (!controlPlaneUrl || !isApiKey(apiKey)) return invalid;
		return valid({ controlPlaneUrl, apiKey } satisfies TelemetryConfig);
	};
}

const CUSTOM_SITE_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;
/** Exact DNS hostname: lowercase labels, at least one dot (matches the build's host shape). */
const HOSTNAME_PATTERN =
	/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
/** Labels must not carry control characters. */
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;
/** Hosts a built-in site runs on, shared hosts (Microsoft 365) included. */
const BUILT_IN_HOSTS: ReadonlySet<string> = new Set([
	...Object.values(SITE_HOSTS).flat(),
	...Object.values(SITE_PATHS)
		.flat()
		.map((p) => p.host),
]);

/**
 * Normalises one configured custom-site host: a bare hostname or an `https://host[/]`
 * origin. Anything with another scheme, a port, credentials, a path, a query, a
 * wildcard, a single label or an IP-looking tail is rejected (null).
 */
export function normalizeCustomHost(raw: unknown): string | null {
	if (typeof raw !== "string" || raw.length === 0 || raw.length > 300) return null;
	let host = raw.trim().toLowerCase();
	if (host.includes("://")) {
		let url: URL;
		try {
			url = new URL(host);
		} catch {
			return null;
		}
		if (url.protocol !== "https:" || url.port || url.username || url.password) return null;
		if (url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) return null;
		if (!/^https:\/\/[^/?#]+\/?$/.test(host)) return null;
		host = url.hostname;
	}
	if (!HOSTNAME_PATTERN.test(host) || /^[0-9.]+$/.test(host)) return null;
	return host;
}

function selectorList(raw: unknown): string[] | null {
	if (raw === undefined) return [];
	if (!Array.isArray(raw) || raw.length > CUSTOM_SITE_LIMITS.maxSelectorsPerList) return null;
	const out: string[] = [];
	for (const item of raw) {
		if (typeof item !== "string" || item.trim().length === 0) return null;
		if (item.length > CUSTOM_SITE_LIMITS.maxSelectorChars || SELECTOR_FORBIDDEN.test(item))
			return null;
		if (!out.includes(item)) out.push(item);
	}
	return out;
}

const CUSTOM_SITE_KEYS = [
	"id",
	"label",
	"hosts",
	"editorSelectors",
	"sendButtonSelectors",
	"responseSelectors",
] as const;

/** One custom site (see CustomSiteConfig), or null when any field is malformed. */
function customSite(item: unknown): CustomSiteConfig | null {
	if (!isPlainObject(item)) return null;
	if (Object.keys(item).some((k) => !(CUSTOM_SITE_KEYS as readonly string[]).includes(k)))
		return null;
	const { id, label } = item;
	if (typeof id !== "string" || !CUSTOM_SITE_ID_PATTERN.test(id)) return null;
	if (typeof label !== "string" || CONTROL_CHARS.test(label)) return null;
	const trimmedLabel = label.trim();
	if (trimmedLabel.length === 0 || trimmedLabel.length > CUSTOM_SITE_LIMITS.maxLabelChars)
		return null;
	if (!Array.isArray(item.hosts) || item.hosts.length === 0) return null;
	if (item.hosts.length > CUSTOM_SITE_LIMITS.maxHostsPerSite) return null;
	const hosts: string[] = [];
	for (const raw of item.hosts) {
		const host = normalizeCustomHost(raw);
		// A built-in site keeps its own adapter; configuring it again is a policy error.
		if (!host || BUILT_IN_HOSTS.has(host)) return null;
		if (!hosts.includes(host)) hosts.push(host);
	}
	const editorSelectors = selectorList(item.editorSelectors);
	const sendButtonSelectors = selectorList(item.sendButtonSelectors);
	const responseSelectors = selectorList(item.responseSelectors);
	if (!editorSelectors || !sendButtonSelectors || !responseSelectors) return null;
	return {
		id,
		label: trimmedLabel,
		hosts,
		editorSelectors,
		sendButtonSelectors,
		responseSelectors,
	};
}

/** At most 20 sites, unique ids, no host configured twice; any bad entry rejects the key. */
const customSites: Validator = (raw) => {
	if (!Array.isArray(raw) || raw.length > CUSTOM_SITE_LIMITS.maxSites) return invalid;
	const out: CustomSiteConfig[] = [];
	const ids = new Set<string>();
	const hosts = new Set<string>();
	for (const item of raw) {
		const site = customSite(item);
		if (!site || ids.has(site.id) || site.hosts.some((h) => hosts.has(h))) return invalid;
		ids.add(site.id);
		for (const host of site.hosts) hosts.add(host);
		out.push(site);
	}
	return valid(out);
};

export const SHADOW_AI_MODES: readonly ShadowAiMode[] = Object.freeze([
	"off",
	"monitor",
	"block-unsanctioned",
]);

/**
 * Service id list. Well-formed ids this build's catalog does not know are kept (a newer
 * policy must not switch enforcement off); they simply match no service.
 */
function serviceIdList(raw: unknown): string[] | null {
	if (raw === undefined) return [];
	if (!Array.isArray(raw) || raw.length > AI_SERVICES.length * 4) return null;
	if (!raw.every((id) => typeof id === "string" && AI_SERVICE_ID_PATTERN.test(id))) return null;
	return [...new Set(raw as string[])];
}

const shadowAi: Validator = (raw) => {
	if (!isPlainObject(raw)) return invalid;
	if (Object.keys(raw).some((k) => !["mode", "sanctioned", "blocked"].includes(k))) return invalid;
	if (!SHADOW_AI_MODES.includes(raw.mode as ShadowAiMode)) return invalid;
	const sanctioned = serviceIdList(raw.sanctioned);
	const blocked = serviceIdList(raw.blocked);
	if (!sanctioned || !blocked) return invalid;
	return valid({ mode: raw.mode as ShadowAiMode, sanctioned, blocked } satisfies ShadowAiPolicy);
};

/** Ed25519 SubjectPublicKeyInfo DER prefix (RFC 8410); the raw key is the 32 bytes after it. */
const ED25519_SPKI_PREFIX = [
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const PEM_PATTERN =
	/^-----BEGIN PUBLIC KEY-----\s*([A-Za-z0-9+/=\s]{1,200})-----END PUBLIC KEY-----\s*$/;
const TENANT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const DASHBOARD_POLICY_MAX_KEYS = 4;

/** DER bytes of an Ed25519 SPKI PEM public key, or null for anything else. */
export function ed25519SpkiFromPem(raw: unknown): Uint8Array<ArrayBuffer> | null {
	if (typeof raw !== "string" || raw.length > 512) return null;
	const match = PEM_PATTERN.exec(raw.trim());
	if (!match) return null;
	const b64 = (match[1] ?? "").replace(/\s+/g, "");
	if (b64.length % 4 !== 0 || !BASE64_PATTERN.test(b64)) return null;
	let der: Uint8Array<ArrayBuffer>;
	try {
		der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
	} catch {
		return null;
	}
	if (der.length !== ED25519_SPKI_PREFIX.length + 32) return null;
	return ED25519_SPKI_PREFIX.every((byte, i) => der[i] === byte) ? der : null;
}

/** `dashboardPolicy`: 1-4 Ed25519 SPKI PEM keys and an optional tenant pin (managed only). */
const dashboardPolicy: Validator = (raw) => {
	if (!isPlainObject(raw)) return invalid;
	if (Object.keys(raw).some((k) => k !== "publicKeysPem" && k !== "tenantId")) return invalid;
	const { publicKeysPem, tenantId } = raw;
	if (!Array.isArray(publicKeysPem) || publicKeysPem.length < 1) return invalid;
	if (publicKeysPem.length > DASHBOARD_POLICY_MAX_KEYS) return invalid;
	if (!publicKeysPem.every((pem) => ed25519SpkiFromPem(pem) !== null)) return invalid;
	if (tenantId !== undefined && (typeof tenantId !== "string" || !TENANT_ID_PATTERN.test(tenantId)))
		return invalid;
	return valid({
		publicKeysPem: [...new Set((publicKeysPem as string[]).map((pem) => pem.trim()))],
		tenantId: (tenantId as string | undefined) ?? null,
	} satisfies DashboardPolicyTrust);
};

export const WORK_ACCOUNT_ACTIONS: readonly WorkAccountAction[] = Object.freeze([
	"warn",
	"block",
	"mask-only",
]);
export const WORK_ACCOUNT_LIMITS = Object.freeze({ maxIdsPerSite: 64, maxDomainsPerSite: 64 });
const WORK_ACCOUNT_KEYS = ["action", "unverified", "sites"];
const WORK_ACCOUNT_RULE_KEYS = ["workspaceIds", "emailDomains"];

const workspaceIdEntry = (item: unknown): string | null =>
	typeof item === "string" && WORKSPACE_ID_PATTERN.test(item) ? item.toLowerCase() : null;

/** An email domain: a bare hostname (an `@` prefix is tolerated), lowercase. */
const emailDomainEntry = (item: unknown): string | null => {
	if (typeof item !== "string") return null;
	const domain = item.trim().toLowerCase().replace(/^@/, "");
	return HOSTNAME_PATTERN.test(domain) && !/^[0-9.]+$/.test(domain) ? domain : null;
};

/** One site's rule; `strict` refuses any bad entry, otherwise bad entries are dropped. */
function workAccountRule(raw: unknown, strict: boolean): WorkAccountSiteRule | null {
	if (!isPlainObject(raw)) return strict ? null : { workspaceIds: [], emailDomains: [] };
	if (strict && Object.keys(raw).some((k) => !WORK_ACCOUNT_RULE_KEYS.includes(k))) return null;
	const lists = [
		[raw.workspaceIds, WORK_ACCOUNT_LIMITS.maxIdsPerSite, workspaceIdEntry],
		[raw.emailDomains, WORK_ACCOUNT_LIMITS.maxDomainsPerSite, emailDomainEntry],
	] as const;
	const out: string[][] = [];
	for (const [list, max, entry] of lists) {
		if (list === undefined) {
			out.push([]);
			continue;
		}
		if (strict && (!Array.isArray(list) || list.length > max || !list.every((v) => entry(v))))
			return null;
		out.push(validEntries(list, max, entry));
	}
	return { workspaceIds: out[0] ?? [], emailDomains: out[1] ?? [] };
}

/**
 * Rules of the sites listed in `raw.sites`; `strict` refuses an unknown site or a bad rule,
 * otherwise every known site is kept with its valid identifiers.
 */
function workAccountSites(
	raw: unknown,
	strict: boolean,
): Partial<Record<AccountSiteId, WorkAccountSiteRule>> | null {
	if (!isPlainObject(raw)) return strict ? null : {};
	const out: Partial<Record<AccountSiteId, WorkAccountSiteRule>> = {};
	for (const [site, value] of Object.entries(raw)) {
		if (!(ACCOUNT_SITE_IDS as readonly string[]).includes(site)) {
			if (strict) return null;
			continue;
		}
		const rule = workAccountRule(value, strict);
		if (!rule) return null;
		out[site as AccountSiteId] = rule;
	}
	return out;
}

/** `workAccounts`: personal vs company AI accounts (managed only). */
const workAccounts: Validator = (raw) => {
	if (!isPlainObject(raw) || Object.keys(raw).some((k) => !WORK_ACCOUNT_KEYS.includes(k)))
		return invalid;
	if (!WORK_ACCOUNT_ACTIONS.includes(raw.action as WorkAccountAction)) return invalid;
	const unverified = raw.unverified ?? "enforce";
	if (unverified !== "enforce" && unverified !== "allow") return invalid;
	const sites = workAccountSites(raw.sites, true);
	if (!sites || Object.keys(sites).length === 0) return invalid;
	return valid({
		action: raw.action as WorkAccountAction,
		unverified,
		sites,
	} satisfies WorkAccountPolicy);
};

/**
 * An invalid `workAccounts` keeps every known site with its valid identifiers and takes the
 * strictest settings: `block`, unverified accounts enforced. With no usable site it stays off
 * (there is nothing to check), and the key is still reported in `policyErrors`.
 */
function failSafeWorkAccounts(raw: unknown): WorkAccountPolicy | null {
	const sites = workAccountSites(isPlainObject(raw) ? raw.sites : undefined, false) ?? {};
	if (Object.keys(sites).length === 0) return null;
	return { action: "block", unverified: "enforce", sites };
}

type ManagedKey = Exclude<keyof GuardPolicy, "version" | "managedKeys" | "policyErrors">;

const MANAGED_VALIDATORS: Readonly<Record<ManagedKey, Validator>> = {
	mode: oneOf(GUARD_MODES),
	enabledEntities: entityList,
	neverRestore: entityList,
	literals,
	exactData,
	detectSignals: bool,
	signalAction: oneOf(["off", "warn", "block"]),
	blockedSites: siteList,
	disabledSites: siteList,
	customSites,
	shadowAi,
	allowUserPause: bool,
	allowSendAnyway: bool,
	maskPaste: bool,
	fileHandling: oneOf(["scan", "block", "allow"]),
	documentHandling: oneOf(["mask", "block", "allow"]),
	maxFileBytes,
	restoreResponses: bool,
	useNativeHost: bool,
	requireNativeNer: bool,
	uninspectedImages: oneOf(["warn", "block"]),
	telemetry: telemetryValidator(false),
	language: oneOf(["auto", "en", "tr"]),
	policyId,
	acceptableUse,
	dashboardPolicy,
	workAccounts,
};

/** The valid entries of a list (at most `max`, duplicates dropped); [] for a non-list. */
function validEntries<T>(raw: unknown, max: number, entry: (item: unknown) => T | null): T[] {
	if (!Array.isArray(raw)) return [];
	const out: T[] = [];
	const seen = new Set<string>();
	for (const item of raw) {
		if (out.length >= max) break;
		const value = entry(item);
		if (value === null) continue;
		const key = JSON.stringify(value);
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(value);
	}
	return out;
}

const enumEntry =
	<T extends string>(values: readonly T[]) =>
	(item: unknown): T | null =>
		typeof item === "string" && values.includes(item as T) ? (item as T) : null;

const serviceIdEntry = (item: unknown): string | null =>
	typeof item === "string" && AI_SERVICE_ID_PATTERN.test(item) ? item : null;

/** Valid datasets of an invalid `exactData` list, within the per-policy limits. */
function validDatasets(raw: unknown): ExactDataSet[] {
	const out: ExactDataSet[] = [];
	if (!Array.isArray(raw)) return out;
	let total = 0;
	for (const item of raw) {
		if (out.length >= POLICY_LIMITS.maxExactDataSets) break;
		const fields = datasetFields(item);
		if (!fields || out.some((d) => d.datasetId === fields.datasetId)) continue;
		if (total + fields.fingerprints.length > POLICY_LIMITS.maxFingerprintsTotal) continue;
		if (!fields.fingerprints.every(isFingerprint)) continue;
		total += fields.fingerprints.length;
		const fingerprints = (fields.fingerprints as string[]).map((f) => f.toLowerCase());
		out.push({ ...fields, fingerprints: [...new Set(fingerprints)] });
	}
	return out;
}

/** Valid sites of an invalid `customSites` list (duplicate ids and hosts dropped). */
function validCustomSites(raw: unknown): CustomSiteConfig[] {
	const out: CustomSiteConfig[] = [];
	if (!Array.isArray(raw)) return out;
	for (const item of raw) {
		if (out.length >= CUSTOM_SITE_LIMITS.maxSites) break;
		const site = customSite(item);
		if (!site || out.some((s) => s.id === site.id || s.hosts.some((h) => site.hosts.includes(h))))
			continue;
		out.push(site);
	}
	return out;
}

const SERVICE_LIST_MAX = AI_SERVICES.length * 4;

/**
 * An invalid `shadowAi` keeps its valid service ids; a missing or unknown mode becomes
 * `block-unsanctioned` (the strictest one: only sanctioned services stay reachable).
 */
function failSafeShadowAi(raw: unknown): ShadowAiPolicy {
	const r = isPlainObject(raw) ? raw : {};
	return {
		mode: SHADOW_AI_MODES.includes(r.mode as ShadowAiMode)
			? (r.mode as ShadowAiMode)
			: "block-unsanctioned",
		sanctioned: validEntries(r.sanctioned, SERVICE_LIST_MAX, serviceIdEntry),
		blocked: validEntries(r.blocked, SERVICE_LIST_MAX, serviceIdEntry),
	};
}

/**
 * What an invalid managed value becomes (fail safe, never the permissive built-in default):
 * lists keep their valid entries (a typo in one site id must not drop the whole block list),
 * other protection keys take their strictest value. A REG_SZ "false" where a boolean is
 * expected therefore turns pause and send-original off, and a mistyped mode blocks.
 * Keys without an entry here have no safe value to invent (telemetry endpoint, language,
 * policy id, notice, dashboard trust anchor, file size limit): they keep the built-in value.
 * Every invalid key is still reported in `policyErrors`.
 */
const FAIL_SAFE: Readonly<Partial<Record<ManagedKey, (raw: unknown) => unknown>>> = {
	mode: () => "block",
	enabledEntities: () => [...ENTITY_TYPES],
	neverRestore: () => [...ENTITY_TYPES],
	literals: (raw) => validEntries(raw, POLICY_LIMITS.maxLiterals, literalRule),
	exactData: validDatasets,
	detectSignals: () => true,
	signalAction: () => "block",
	blockedSites: (raw) => validEntries(raw, SITE_ID_LIST.length, enumEntry(SITE_ID_LIST)),
	disabledSites: (raw) => validEntries(raw, SITE_ID_LIST.length, enumEntry(SITE_ID_LIST)),
	customSites: validCustomSites,
	shadowAi: failSafeShadowAi,
	allowUserPause: () => false,
	allowSendAnyway: () => false,
	maskPaste: () => true,
	fileHandling: () => "block",
	documentHandling: () => "block",
	restoreResponses: () => false,
	useNativeHost: () => true,
	requireNativeNer: () => true,
	uninspectedImages: () => "block",
	workAccounts: failSafeWorkAccounts,
};

/**
 * Not user settings, but they let a user send data unmasked (pause, "send original"). Under
 * any managed policy they are off unless the administrator sets them explicitly.
 */
export const MANAGED_OFF_BY_DEFAULT_KEYS = Object.freeze([
	"allowUserPause",
	"allowSendAnyway",
] as const);

/** `policyErrors` code for a managed policy that is not an object or could not be read. */
export const POLICY_ERROR_WHOLE = "*";

const USER_VALIDATORS: Readonly<Record<keyof UserSettings, Validator>> = {
	mode: MANAGED_VALIDATORS.mode,
	enabledEntities: entityList,
	literals,
	disabledSites: siteList,
	maskPaste: bool,
	restoreResponses: bool,
	// Adds detection only (NER on top of the rules), so it is not a protection-reducing key.
	useNativeHost: bool,
	uninspectedImages: MANAGED_VALIDATORS.uninspectedImages,
	language: MANAGED_VALIDATORS.language,
	telemetry: telemetryValidator(true),
};

/**
 * Managed-only switch (not part of GuardPolicy): `true` lets users keep changing the
 * protection settings the administrator did not set. Absent or `false` locks them.
 */
export const ALLOW_USER_OVERRIDES_KEY = "allowUserOverrides";

/** Keys an administrator may set in chrome.storage.managed (static/managed_schema.json). */
export const MANAGED_POLICY_KEYS: readonly (ManagedKey | typeof ALLOW_USER_OVERRIDES_KEY)[] =
	Object.freeze([...(Object.keys(MANAGED_VALIDATORS) as ManagedKey[]), ALLOW_USER_OVERRIDES_KEY]);

/**
 * User settings that can weaken protection (fewer entity types, fewer literals, paste
 * unmasked, originals restored into the page, sites switched off, a weaker mode). While any
 * managed policy is present they are locked to the managed or built-in value unless the
 * administrator sets `allowUserOverrides: true`.
 */
export const PROTECTION_SETTING_KEYS: readonly (keyof UserSettings)[] = Object.freeze([
	"mode",
	"enabledEntities",
	"literals",
	"maskPaste",
	"restoreResponses",
	"disabledSites",
	"uninspectedImages",
]);

/**
 * Built-in values that differ when a managed (enterprise) policy is present and the
 * administrator did not set the key: an uninspected picture is blocked, not only warned about.
 */
export const MANAGED_DEFAULTS: Readonly<Partial<Record<keyof UserSettings, unknown>>> =
	Object.freeze({ uninspectedImages: "block" });

/** Keys a user may change (options page / popup). */
export const USER_SETTING_KEYS: readonly (keyof UserSettings)[] = Object.freeze(
	Object.keys(USER_VALIDATORS) as (keyof UserSettings)[],
);

export interface UserSettingsValidation {
	readonly settings: Partial<UserSettings>;
	readonly unknownKeys: readonly string[];
	readonly invalidKeys: readonly string[];
}

/** Validates user settings key by key; unknown and invalid keys are reported and dropped. */
export function validateUserSettings(raw: unknown): UserSettingsValidation {
	const settings: Record<string, unknown> = {};
	const unknownKeys: string[] = [];
	const invalidKeys: string[] = [];
	if (raw === undefined || raw === null) return { settings, unknownKeys, invalidKeys };
	if (!isPlainObject(raw)) return { settings, unknownKeys, invalidKeys: ["*"] };
	for (const [key, value] of Object.entries(raw)) {
		const validator = Object.hasOwn(USER_VALIDATORS, key)
			? USER_VALIDATORS[key as keyof UserSettings]
			: undefined;
		if (!validator) {
			unknownKeys.push(key);
			continue;
		}
		const result = validator(value);
		if (result.ok) settings[key] = result.value;
		else invalidKeys.push(key);
	}
	return { settings: settings as Partial<UserSettings>, unknownKeys, invalidKeys };
}

export interface PolicyEvaluation {
	readonly policy: GuardPolicy;
	/** Human-readable, value-free notes about ignored input. */
	readonly warnings: readonly string[];
}

export interface EvaluateOptions {
	/**
	 * chrome.storage.managed could not be read. The administrator's intent is unknown, so it
	 * is treated as a managed policy without valid keys: protection keys locked, pause and
	 * send-original off, and a whole-policy error reported.
	 */
	readonly managedUnavailable?: boolean;
}

/**
 * Merges managed over user over default and reports everything that was ignored.
 * Never throws.
 *
 * Locking: every key the administrator sets is locked. When ANY managed policy is present
 * (a non-empty managed object, even one whose keys are all invalid: admin intent that failed
 * validation must not unlock the user), the protection-reducing user settings
 * (`PROTECTION_SETTING_KEYS`) are locked too, at the managed or built-in value, unless the
 * managed policy sets `allowUserOverrides: true`. With overrides allowed, a managed `mode`
 * still locks `disabledSites` (a user must not be able to switch off an
 * administrator-mandated mode per site). Under any managed policy `allowUserPause` and
 * `allowSendAnyway` are false unless the administrator sets them (MANAGED_OFF_BY_DEFAULT_KEYS).
 */
export function evaluatePolicy(
	managed: unknown,
	user: unknown,
	options: EvaluateOptions = {},
): PolicyEvaluation {
	const warnings: string[] = [];
	const merged: Record<string, unknown> = { ...DEFAULT_POLICY };
	const managedKeys: string[] = [];
	const policyErrors: string[] = [];

	const userResult = validateUserSettings(options.managedUnavailable ? undefined : user);
	for (const key of userResult.unknownKeys) warnings.push(`user: unknown key "${key}" ignored`);
	for (const key of userResult.invalidKeys)
		warnings.push(`user: invalid value for "${key}" ignored`);
	Object.assign(merged, userResult.settings);

	const sink: ManagedSink = { managedKeys, policyErrors, warnings };
	const admin = options.managedUnavailable
		? managedUnavailable(sink)
		: mergeManaged(managed, merged, sink);

	if (managedKeys.includes("mode") && !managedKeys.includes("disabledSites")) {
		if ((merged.disabledSites as readonly SiteId[]).length > 0)
			warnings.push('user: "disabledSites" ignored because "mode" is managed');
		merged.disabledSites = [];
		managedKeys.push("disabledSites");
	}

	if (admin.present && !admin.allowUserOverrides)
		lockProtectionKeys(merged, managedKeys, userResult.settings, warnings);

	if (admin.present) switchOffUnlessManaged(merged, managedKeys);
	// With user overrides allowed, a managed install still starts from the managed defaults.
	if (admin.present)
		for (const [key, value] of Object.entries(MANAGED_DEFAULTS))
			if (!managedKeys.includes(key) && !Object.hasOwn(userResult.settings, key))
				merged[key] = value;

	if (merged.requireNativeNer === true)
		requireNativeHost(merged, managedKeys, warnings, '"requireNativeNer" is true');
	// Dataset keys come only from the native host (see ExactDataSet).
	if ((merged.exactData as readonly ExactDataSet[]).length > 0)
		requireNativeHost(
			merged,
			managedKeys,
			warnings,
			'"exactData" needs the native host for its keys',
		);

	merged.version = 1;
	merged.managedKeys = managedKeys;
	merged.policyErrors = policyErrors;
	return { policy: deepFreeze(merged as unknown as GuardPolicy), warnings };
}

/**
 * Why a managed `exactData` value is refused outright: the retired example key, an example
 * placeholder, a dataset that carries its HMAC key in browser policy (readable by every user in
 * chrome://policy, the registry or policies.json, which lets them enumerate the values), or a
 * dataset whose values are too guessable to protect with a keyed hash.
 */
function exactDataRefusal(value: unknown): string | null {
	if (!Array.isArray(value)) return null;
	if (value.some(isRetiredExampleDataset))
		return 'managed: "exactData" uses the retired example dataset key (crm-customers-example), which was published in the deployment examples and is compromised; ignored. Build each dataset with fingerprint-dataset.mjs and a fresh key';
	if (value.some(isPlaceholderDataset))
		return 'managed: "exactData" still holds the example placeholder key; ignored. Build each dataset with fingerprint-dataset.mjs';
	if (value.some((item) => isPlainObject(item) && Object.hasOwn(item, "keyB64")))
		return 'managed: "exactData" carries its HMAC key ("keyB64") in browser policy, which every user can read (chrome://policy, registry, policies.json); ignored. Rebuild each dataset with fingerprint-dataset.mjs --secret-file and install the secret in the native host configuration';
	if (
		value.some(
			(item) =>
				isPlainObject(item) &&
				typeof item.minEntropyBits === "number" &&
				item.minEntropyBits < EXACT_DATA_MIN_ENTROPY_BITS,
		)
	)
		return `managed: "exactData" has a dataset whose values are below ${EXACT_DATA_MIN_ENTROPY_BITS} bits of estimated entropy and could be enumerated from its fingerprints; ignored. Use composite values (for example name + customer number)`;
	return null;
}

interface ManagedSink {
	readonly managedKeys: string[];
	readonly policyErrors: string[];
	readonly warnings: string[];
}

interface ManagedPresence {
	readonly present: boolean;
	readonly allowUserOverrides: boolean;
}

/** Unreadable managed storage: unknown administrator intent, so it locks like a policy. */
function managedUnavailable({ policyErrors, warnings }: ManagedSink): ManagedPresence {
	warnings.push("managed: policy storage unavailable; user settings suspended");
	policyErrors.push(POLICY_ERROR_WHOLE);
	return { present: true, allowUserOverrides: false };
}

/** Pause and send-original are off under a managed policy unless the administrator set them. */
function switchOffUnlessManaged(merged: Record<string, unknown>, managedKeys: string[]): void {
	for (const key of MANAGED_OFF_BY_DEFAULT_KEYS) {
		if (managedKeys.includes(key)) continue;
		merged[key] = false;
		managedKeys.push(key);
	}
}

/**
 * Validates managed keys into `merged` / `managedKeys`. Reports whether a managed policy
 * is present (fail closed: a value that is not an object, or an object whose keys are all
 * invalid, is still administrator intent) and the `allowUserOverrides` switch. An invalid
 * value fails safe (FAIL_SAFE) and is recorded in `policyErrors`.
 */
function mergeManaged(
	managed: unknown,
	merged: Record<string, unknown>,
	sink: ManagedSink,
): ManagedPresence {
	if (managed === undefined || managed === null)
		return { present: false, allowUserOverrides: false };
	if (!isPlainObject(managed)) {
		sink.warnings.push("managed: policy is not an object; ignored");
		sink.policyErrors.push(POLICY_ERROR_WHOLE);
		return { present: true, allowUserOverrides: false };
	}
	let allowUserOverrides = false;
	for (const [key, value] of Object.entries(managed)) {
		if (key !== ALLOW_USER_OVERRIDES_KEY) {
			mergeManagedKey(key, value, merged, sink);
		} else if (typeof value === "boolean") {
			// Managed-only switch; never merged into the policy.
			allowUserOverrides = value;
		} else {
			// An invalid switch keeps the lock.
			sink.warnings.push(`managed: invalid value for "${key}" ignored`);
			sink.policyErrors.push(key);
		}
	}
	return { present: Object.keys(managed).length > 0, allowUserOverrides };
}

/** One managed key: the validated value, else its fail-safe value (reported either way). */
function mergeManagedKey(
	key: string,
	value: unknown,
	merged: Record<string, unknown>,
	{ managedKeys, policyErrors, warnings }: ManagedSink,
): void {
	const validator = Object.hasOwn(MANAGED_VALIDATORS, key)
		? MANAGED_VALIDATORS[key as ManagedKey]
		: undefined;
	if (!validator) {
		warnings.push(`managed: unknown key "${key}" ignored`);
		return;
	}
	const refusal = key === "exactData" ? exactDataRefusal(value) : null;
	if (refusal) {
		warnings.push(refusal);
		policyErrors.push(key);
		return;
	}
	const result = validator(value);
	if (result.ok) {
		merged[key] = result.value;
		managedKeys.push(key);
		return;
	}
	policyErrors.push(key);
	const failSafe = FAIL_SAFE[key as ManagedKey];
	if (!failSafe) {
		warnings.push(`managed: invalid value for "${key}" ignored`);
		return;
	}
	warnings.push(`managed: invalid value for "${key}"; fail-safe value applied`);
	merged[key] = failSafe(value);
	managedKeys.push(key);
}

/**
 * `requireNativeNer` (managed only) needs the native host: `useNativeHost` is forced on and
 * locked, whatever the managed or user value was, so neither side can switch the required
 * check off by disabling the bridge.
 */
function requireNativeHost(
	merged: Record<string, unknown>,
	managedKeys: string[],
	warnings: string[],
	reason: string,
): void {
	if (merged.useNativeHost !== true)
		warnings.push(`"useNativeHost" forced on because managed ${reason}`);
	merged.useNativeHost = true;
	if (!managedKeys.includes("useNativeHost")) managedKeys.push("useNativeHost");
}

/** Locks every protection key the managed policy did not set at its built-in default. */
function lockProtectionKeys(
	merged: Record<string, unknown>,
	managedKeys: string[],
	user: Partial<UserSettings>,
	warnings: string[],
): void {
	for (const key of PROTECTION_SETTING_KEYS) {
		if (managedKeys.includes(key)) continue;
		if (Object.hasOwn(user, key))
			warnings.push(`user: "${key}" ignored because a managed policy locks user overrides`);
		merged[key] = Object.hasOwn(MANAGED_DEFAULTS, key)
			? MANAGED_DEFAULTS[key]
			: DEFAULT_POLICY[key];
		managedKeys.push(key);
	}
}

/** Contract entry point (see src/types.ts): managed keys override user settings. */
export function mergePolicy(
	managed: unknown,
	user: Partial<UserSettings> | undefined,
): GuardPolicy {
	return evaluatePolicy(managed, user).policy;
}

function deepFreeze<T>(value: T): T {
	if (value && typeof value === "object" && !Object.isFrozen(value)) {
		Object.freeze(value);
		for (const v of Object.values(value)) deepFreeze(v);
	}
	return value;
}
