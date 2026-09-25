/**
 * Effective Browser Guard policy: administrator-managed policy (chrome.storage.managed)
 * merged over user settings (chrome.storage.local) merged over the built-in default.
 *
 * Validation is strict but never throws: an unknown key or a value of the wrong
 * shape is ignored as a whole (mirroring how Chrome drops a managed policy that
 * does not match static/managed_schema.json) and reported in a warning list.
 * Warnings name keys only, never values (an apiKey must not reach a log line).
 */
import {
	ENTITY_TYPES,
	type EntityType,
	type ExactDataSet,
	type GuardMode,
	type GuardPolicy,
	type LiteralRule,
	type SiteId,
	type TelemetryConfig,
	type UserSettings,
} from "../types.js";

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
	allowUserPause: true,
	allowSendAnyway: true,
	maskPaste: true,
	fileHandling: "scan",
	documentHandling: "mask",
	maxFileBytes: 5 * MIB,
	restoreResponses: true,
	useNativeHost: false,
	telemetry: null,
	language: "auto",
	managedKeys: [],
	policyId: "aidr-browser-guard-default",
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

const isDatasetKey = (raw: unknown): raw is string =>
	typeof raw === "string" &&
	raw.length >= 16 &&
	raw.length <= 1024 &&
	raw.length % 4 === 0 &&
	BASE64_PATTERN.test(raw);

const isFingerprint = (raw: unknown): boolean => typeof raw === "string" && HEX64_PATTERN.test(raw);

/** A dataset's fields once its shape is valid; fingerprints are checked by the caller. */
function datasetFields(
	item: unknown,
): (Omit<ExactDataSet, "fingerprints"> & { fingerprints: unknown[] }) | null {
	if (!isPlainObject(item) || !hasExactKeys(item, ["datasetId", "keyB64", "fingerprints", "type"]))
		return null;
	const { datasetId, keyB64, fingerprints, type } = item;
	if (typeof datasetId !== "string" || !DATASET_ID_PATTERN.test(datasetId)) return null;
	if (!isDatasetKey(keyB64) || !isEntityType(type) || !Array.isArray(fingerprints)) return null;
	return { datasetId, keyB64, fingerprints, type };
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

type ManagedKey = Exclude<keyof GuardPolicy, "version" | "managedKeys">;

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
	allowUserPause: bool,
	allowSendAnyway: bool,
	maskPaste: bool,
	fileHandling: oneOf(["scan", "block", "allow"]),
	documentHandling: oneOf(["mask", "block", "allow"]),
	maxFileBytes,
	restoreResponses: bool,
	useNativeHost: bool,
	telemetry: telemetryValidator(false),
	language: oneOf(["auto", "en", "tr"]),
	policyId,
};

const USER_VALIDATORS: Readonly<Record<keyof UserSettings, Validator>> = {
	mode: MANAGED_VALIDATORS.mode,
	enabledEntities: entityList,
	literals,
	disabledSites: siteList,
	maskPaste: bool,
	restoreResponses: bool,
	// Adds detection only (NER on top of the rules), so it is not a protection-reducing key.
	useNativeHost: bool,
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
]);

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
 * administrator-mandated mode per site).
 */
export function evaluatePolicy(managed: unknown, user: unknown): PolicyEvaluation {
	const warnings: string[] = [];
	const merged: Record<string, unknown> = { ...DEFAULT_POLICY };
	const managedKeys: string[] = [];

	const userResult = validateUserSettings(user);
	for (const key of userResult.unknownKeys) warnings.push(`user: unknown key "${key}" ignored`);
	for (const key of userResult.invalidKeys)
		warnings.push(`user: invalid value for "${key}" ignored`);
	Object.assign(merged, userResult.settings);

	const admin = mergeManaged(managed, merged, managedKeys, warnings);

	if (managedKeys.includes("mode") && !managedKeys.includes("disabledSites")) {
		if ((merged.disabledSites as readonly SiteId[]).length > 0)
			warnings.push('user: "disabledSites" ignored because "mode" is managed');
		merged.disabledSites = [];
		managedKeys.push("disabledSites");
	}

	if (admin.present && !admin.allowUserOverrides)
		lockProtectionKeys(merged, managedKeys, userResult.settings, warnings);

	merged.version = 1;
	merged.managedKeys = managedKeys;
	return { policy: deepFreeze(merged as unknown as GuardPolicy), warnings };
}

/**
 * Validates managed keys into `merged` / `managedKeys`. Reports whether a managed policy
 * is present (fail closed: a value that is not an object, or an object whose keys are all
 * invalid, is still administrator intent) and the `allowUserOverrides` switch.
 */
function mergeManaged(
	managed: unknown,
	merged: Record<string, unknown>,
	managedKeys: string[],
	warnings: string[],
): { readonly present: boolean; readonly allowUserOverrides: boolean } {
	if (managed === undefined || managed === null)
		return { present: false, allowUserOverrides: false };
	if (!isPlainObject(managed)) {
		warnings.push("managed: policy is not an object; ignored");
		return { present: true, allowUserOverrides: false };
	}
	let allowUserOverrides = false;
	for (const [key, value] of Object.entries(managed)) {
		if (key === ALLOW_USER_OVERRIDES_KEY) {
			// Managed-only switch; never merged into the policy.
			if (typeof value === "boolean") allowUserOverrides = value;
			else warnings.push(`managed: invalid value for "${key}" ignored`);
			continue;
		}
		const validator = Object.hasOwn(MANAGED_VALIDATORS, key)
			? MANAGED_VALIDATORS[key as ManagedKey]
			: undefined;
		if (!validator) {
			warnings.push(`managed: unknown key "${key}" ignored`);
			continue;
		}
		const result = validator(value);
		if (!result.ok) {
			warnings.push(`managed: invalid value for "${key}" ignored`);
			continue;
		}
		merged[key] = result.value;
		managedKeys.push(key);
	}
	return { present: Object.keys(managed).length > 0, allowUserOverrides };
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
		merged[key] = DEFAULT_POLICY[key];
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
