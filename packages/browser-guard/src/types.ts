/**
 * Shared contracts for Singularity AIDR Browser Guard.
 *
 * Every module in this package codes against these types so that the engine,
 * site adapters, content script, background worker and UI can be developed and
 * tested independently. Change a contract here first, then its implementations.
 *
 * Module ownership (one file tree per owner):
 *   src/engine/detect.ts      detection + signals + exact-data-match  -> DetectionEngine
 *   src/engine/vault.ts       reversible pseudonymisation             -> PlaceholderVault
 *   src/engine/files.ts       file / paste document sanitisation      -> sanitizeFile
 *   src/sites/*.ts            per-site adapters + generic fallback    -> SiteAdapter
 *   src/dom/editor.ts         read/rewrite textarea/ProseMirror/Quill -> EditorAccess
 *   src/content/*.ts          interception, bubble UI, unmask observer
 *   src/background/*.ts       policy, telemetry, audit, native host
 *   src/ui/*.ts               popup + options pages
 */

/** Entity types. Mirrors packages/privacy/src/types.ts ENTITY_TYPES (same order). */
export const ENTITY_TYPES = [
	"PERSON",
	"EMAIL",
	"PHONE",
	"TC_KIMLIK",
	"IBAN",
	"CREDIT_CARD",
	"ADDRESS",
	"US_SSN",
	"DATE_OF_BIRTH",
	"PASSPORT",
	"NATIONAL_ID",
	"TAX_ID",
	"BANK_ACCOUNT",
	"IP_ADDRESS",
	"MAC_ADDRESS",
	"SECRET",
	"PRIVATE_KEY",
	"INTERNAL",
	"CLASSIFIED",
	"LOCATION",
	"USERNAME",
	"HEALTH_ID",
	"LICENSE_PLATE",
] as const;
export type EntityType = (typeof ENTITY_TYPES)[number];

/** Short placeholder prefixes used by the vault, e.g. `[EMAIL_1]`, `[TCKN_2]`. */
export const PLACEHOLDER_PREFIX: Readonly<Record<EntityType, string>> = {
	PERSON: "PERSON",
	EMAIL: "EMAIL",
	PHONE: "PHONE",
	TC_KIMLIK: "TCKN",
	IBAN: "IBAN",
	CREDIT_CARD: "CARD",
	ADDRESS: "ADDRESS",
	US_SSN: "SSN",
	DATE_OF_BIRTH: "DOB",
	PASSPORT: "PASSPORT",
	NATIONAL_ID: "NATIONAL_ID",
	TAX_ID: "TAX_ID",
	BANK_ACCOUNT: "ACCOUNT",
	IP_ADDRESS: "IP",
	MAC_ADDRESS: "MAC",
	SECRET: "SECRET",
	PRIVATE_KEY: "PRIVATE_KEY",
	INTERNAL: "INTERNAL",
	CLASSIFIED: "CLASSIFIED",
	LOCATION: "LOCATION",
	USERNAME: "USERNAME",
	HEALTH_ID: "HEALTH_ID",
	LICENSE_PLATE: "PLATE",
};

/** A detected sensitive span in UTF-16 offsets of the scanned text. */
export interface Finding {
	readonly type: EntityType;
	readonly start: number;
	readonly end: number;
	/** 0..1 heuristic score; not a calibrated probability. */
	readonly score: number;
	/** Where the finding came from. */
	readonly source: "rule" | "literal" | "exact-data" | "native-ner";
}

/** Non-entity risk signals (prompt injection, source code...). Codes only. */
export type SignalCode =
	| "INSTRUCTION_OVERRIDE"
	| "PROMPT_EXTRACTION"
	| "ROLE_DELIMITER"
	| "ROLE_SPOOF"
	| "ACTIVE_CONTENT"
	| "SOURCE_CODE_HINT"
	| "EXACT_DATA_MATCH";

export interface ScanResult {
	readonly findings: readonly Finding[];
	readonly signals: readonly SignalCode[];
	/** Counts per entity type (what telemetry may send). */
	readonly counts: Readonly<Partial<Record<EntityType, number>>>;
	/** True when the scan could not complete (limit/timeout); callers fail closed per policy. */
	readonly incomplete: boolean;
	readonly elapsedMs: number;
}

export interface LiteralRule {
	readonly value: string;
	readonly type: EntityType;
}

/**
 * Exact-data-match dataset shipped by an administrator: HMAC-SHA256 fingerprints only, built by
 * scripts/fingerprint-dataset.mjs. Managed policy carries no key: `keySource: "native-host"` means
 * the per-dataset key is derived by the AIDR Privacy native host from a secret in its own
 * configuration, and the background worker fills in `keyB64` at runtime (never persisted, never
 * shown in the options page). A dataset in policy that carries `keyB64` is refused.
 */
export interface ExactDataSet {
	readonly datasetId: string;
	/** Where the dataset key comes from; the only accepted source is the native host. */
	readonly keySource?: "native-host";
	/**
	 * Lowest estimated entropy (bits) of any fingerprinted value, recorded by the dataset tool.
	 * The policy refuses a dataset below EXACT_DATA_MIN_ENTROPY_BITS.
	 */
	readonly minEntropyBits?: number;
	/** Runtime only: base64 per-dataset key from the native host. Absent: the dataset cannot be checked (scans are incomplete). */
	readonly keyB64?: string;
	/** hex HMAC-SHA256 of normalised token sequences (see engine/detect.ts for the normalisation). */
	readonly fingerprints: readonly string[];
	readonly type: EntityType;
}

export interface DetectionOptions {
	readonly enabledEntities: readonly EntityType[];
	readonly literals: readonly LiteralRule[];
	readonly exactData: readonly ExactDataSet[];
	readonly detectSignals: boolean;
	readonly maxInputChars: number;
	readonly maxScanMs: number;
}

export interface DetectionEngine {
	scan(text: string): Promise<ScanResult>;
}

/** Reversible pseudonymisation vault (one per tab/conversation). */
export interface MaskResult {
	readonly masked: string;
	/** Placeholders introduced by this call, in order of appearance. */
	readonly placeholders: readonly string[];
	readonly counts: Readonly<Partial<Record<EntityType, number>>>;
}

export interface PlaceholderVault {
	mask(text: string, findings: readonly Finding[]): MaskResult;
	/** Restores every known placeholder; unknown/secret-locked placeholders stay as-is. */
	unmask(text: string): string;
	/** Placeholder -> original, for UI tooltips. Never serialise to storage.local or network. */
	lookup(placeholder: string): string | undefined;
	size(): number;
	clear(): void;
	/** Serialise for chrome.storage.session (memory-only) persistence across worker restarts. */
	exportSession(): VaultSnapshot;
}

export interface VaultSnapshot {
	readonly version: 1;
	readonly createdAt: number;
	readonly entries: ReadonlyArray<{
		readonly placeholder: string;
		readonly value: string;
		readonly type: EntityType;
	}>;
}

/** Guard modes. */
export type GuardMode = "auto" | "confirm" | "block" | "monitor";

export type SiteId =
	| "chatgpt"
	| "gemini"
	| "claude"
	| "copilot"
	| "perplexity"
	| "deepseek"
	| "mistral"
	| "grok"
	/** A company-internal AI portal configured by the administrator (`customSites`). */
	| "custom"
	| "other";

/**
 * Company-internal AI chat portal configured by the administrator (managed key
 * `customSites`). Masking runs there once the browser granted the extension access to
 * its hosts; the content script is then registered dynamically (chrome.scripting).
 */
export interface CustomSiteConfig {
	/** `^[a-z0-9][a-z0-9-]{0,31}$`, unique within the policy. */
	readonly id: string;
	readonly label: string;
	/** Exact lowercase HTTPS hostnames (no scheme, port, path or wildcard). */
	readonly hosts: readonly string[];
	readonly editorSelectors: readonly string[];
	readonly sendButtonSelectors: readonly string[];
	readonly responseSelectors: readonly string[];
}

/** Shadow AI category of a catalogued generative-AI service (src/sites/catalog.ts). */
export type AiServiceCategory =
	| "chat"
	| "coding"
	| "image"
	| "meeting"
	| "writing"
	| "search"
	| "agent";

/**
 * Shadow AI discovery and control (managed key `shadowAi`). Service ids come from the
 * catalog in src/sites/catalog.ts.
 *   off                 visits are not counted (default)
 *   monitor             visits to catalogued services are counted (per service, per day)
 *   block-unsanctioned  counted, and every catalogued service not in `sanctioned` is blocked
 * Ids in `blocked` are blocked in every mode; a service in both `sanctioned` and `blocked`
 * is blocked (deny wins).
 */
export type ShadowAiMode = "off" | "monitor" | "block-unsanctioned";

export interface ShadowAiPolicy {
	readonly mode: ShadowAiMode;
	readonly sanctioned: readonly string[];
	readonly blocked: readonly string[];
}

/**
 * Sites where Browser Guard can tell a company workspace from a personal account
 * (src/sites/accounts.ts). Other sites expose no usable signal and are never account-checked.
 */
export const ACCOUNT_SITE_IDS = ["chatgpt", "claude", "gemini", "copilot"] as const;
export type AccountSiteId = (typeof ACCOUNT_SITE_IDS)[number];

/**
 * What the guard does on a configured site when the signed-in account is not confirmed as one
 * of the organisation's (managed key `workAccounts`):
 *   warn       the first send on the page asks the user to confirm (Continue / Cancel); uploads
 *              show a warning; masking runs as usual
 *   block      prompt sends and file uploads are refused
 *   mask-only  sends are allowed, but only masked: monitor mode, a user pause, a site the user
 *              disabled and "Send original" do not apply there
 */
export type WorkAccountAction = "warn" | "block" | "mask-only";

/** Organisation identifiers accepted on one site; both empty = any recognised work account. */
export interface WorkAccountSiteRule {
	/** ChatGPT workspace account ids, Claude organisation UUIDs (compared case-insensitively). */
	readonly workspaceIds: readonly string[];
	/** Email domains of the signed-in account; subdomains of a listed domain match too. */
	readonly emailDomains: readonly string[];
}

/** Managed key `workAccounts` (managed only). */
export interface WorkAccountPolicy {
	readonly action: WorkAccountAction;
	/**
	 * `enforce` (default): an account the page does not identify is treated like a personal
	 * one (fail closed). `allow`: only an account positively recognised as personal or as
	 * another organisation's gets the action.
	 */
	readonly unverified: "enforce" | "allow";
	/** Only the sites listed here are account-checked. */
	readonly sites: Readonly<Partial<Record<AccountSiteId, WorkAccountSiteRule>>>;
}

/**
 * Result of the account check (telemetry `account_type`, an enum only):
 *   company     an allowed workspace / email domain (or any work account when the site lists none)
 *   personal    a recognised personal / consumer account
 *   other       an identified account that is not on the allowed list
 *   unverified  the page exposed no usable account signal
 */
export const ACCOUNT_TYPES = ["company", "personal", "other", "unverified"] as const;
export type AccountType = (typeof ACCOUNT_TYPES)[number];

export interface SiteAdapter {
	readonly id: SiteId;
	readonly label: string;
	readonly hosts: readonly string[];
	/** CSS selectors for the prompt editor, most specific first. */
	readonly editorSelectors: readonly string[];
	readonly sendButtonSelectors: readonly string[];
	/** Containers holding assistant responses (for local unmasking). */
	readonly responseSelectors: readonly string[];
	/** Containers holding the user's own sent messages (also unmasked locally). */
	readonly userMessageSelectors: readonly string[];
	readonly fileInputSelectors: readonly string[];
}

export type EditorKind = "textarea" | "prosemirror" | "quill" | "contenteditable";

export interface EditorAccess {
	readonly element: HTMLElement;
	readonly kind: EditorKind;
	read(): string;
	/** Replace the whole editor content so the site's framework state observes it. */
	write(text: string): Promise<void>;
}

/**
 * The editor a send gesture belongs to, resolved from where the gesture happened (the
 * clicked button, the submitted form, the key target), never from focus.
 */
export interface EditorMatch {
	/**
	 * The editor; null when several editors in the same container hold text, so which one
	 * the site sends is ambiguous (the guard then refuses the send).
	 */
	readonly editor: EditorAccess | null;
	/**
	 * The smallest container (element, shadow root or document) above the anchor in which
	 * an editor was found; the editor itself when the anchor is inside an editor.
	 */
	readonly container: Node;
}

/** Effective policy after merging managed (admin) over user settings. */
export interface GuardPolicy {
	readonly version: 1;
	readonly mode: GuardMode;
	readonly enabledEntities: readonly EntityType[];
	/** Entity types that are masked but never restored in the page (e.g. SECRET). */
	readonly neverRestore: readonly EntityType[];
	readonly literals: readonly LiteralRule[];
	readonly exactData: readonly ExactDataSet[];
	readonly detectSignals: boolean;
	/** Signal handling: warn shows coaching; block stops the send. */
	readonly signalAction: "off" | "warn" | "block";
	readonly blockedSites: readonly SiteId[];
	readonly disabledSites: readonly SiteId[];
	/** Administrator-configured internal AI portals (managed only). */
	readonly customSites: readonly CustomSiteConfig[];
	/** Shadow AI discovery and control (managed only). */
	readonly shadowAi: ShadowAiPolicy;
	readonly allowUserPause: boolean;
	readonly allowSendAnyway: boolean;
	readonly maskPaste: boolean;
	readonly fileHandling: "scan" | "block" | "allow";
	/**
	 * Office (DOCX/XLSX/PPTX), OpenDocument (ODT/ODS/ODP/ODG), legacy Office (DOC/XLS/PPT) and
	 * PDF uploads when `fileHandling` is "scan" (managed-only): "mask" masks OOXML/OpenDocument
	 * text in place and scans PDFs and legacy Office files (blocking those with findings, as they
	 * cannot be rewritten; a legacy file that could not be fully read passes only as unscanned:
	 * warning, blocked in block mode); "block" rejects every
	 * such document; "allow" skips parsing and treats them like other binary files (unscanned
	 * warning; blocked in block mode). Absent means "mask".
	 */
	readonly documentHandling: "mask" | "block" | "allow";
	readonly maxFileBytes: number;
	readonly restoreResponses: boolean;
	readonly useNativeHost: boolean;
	/**
	 * Managed-only: native NER (PERSON/ADDRESS/LOCATION) is mandatory. When true and one of
	 * those types is enabled, a prompt, paste or upload whose text the native host did not
	 * check with NER (host missing, crashed, timed out, rules-only coverage, malformed reply,
	 * text over the host limit) is blocked instead of continuing rules-only; monitor mode
	 * records it as not NER-checked instead. Forces `useNativeHost` on. Absent means false
	 * (optional so policies built before the key existed stay valid; the worker always sets it).
	 */
	readonly requireNativeNer?: boolean;
	/**
	 * An uploaded picture (PNG/JPEG/WebP/...) that could not be inspected: no AIDR Privacy
	 * companion (native host with OCR), the permission is missing, or the host could not read it
	 * to a verdict. "warn": uploaded with a warning that says how to install the companion;
	 * "block": not uploaded (monitor mode only records it). Default "block" under any managed
	 * policy, "warn" otherwise. A picture whose text the host read and found clean, but whose
	 * QR codes/barcodes it could not check (IMAGE_BARCODE_NOT_CHECKED), is only warned about.
	 * Optional so policies built before the key existed stay valid (absent means "warn"; the
	 * worker always sets it).
	 */
	readonly uninspectedImages?: "warn" | "block";
	readonly telemetry: TelemetryConfig | null;
	readonly language: "auto" | "en" | "tr";
	/** Keys locked by managed policy (UI renders them read-only). */
	readonly managedKeys: readonly string[];
	/**
	 * Managed keys whose value was invalid ("*": the whole managed policy was malformed or
	 * could not be read). Each fell back to a fail-safe value, never the permissive default
	 * (src/background/policy.ts FAIL_SAFE); the popup and options page show a policy error and
	 * telemetry reports the count. Key names only, never values. Optional so policies built
	 * before the field existed stay valid; the worker always sets it.
	 */
	readonly policyErrors?: readonly string[];
	readonly policyId: string;
	/**
	 * Administrator-published AI acceptable-use notice (managed policy key `acceptableUse`),
	 * shown once per version on a protected AI site. Absent or null: no notice. Optional so
	 * policies built before the notice existed stay valid; the worker always sets it.
	 */
	readonly acceptableUse?: AcceptableUseNotice | null;
	/**
	 * Trust anchor for Shadow AI decisions made in the AIDR dashboard (managed-only key
	 * `dashboardPolicy`, see src/background/dashboard-policy.ts). Absent or null: dashboard
	 * decisions are never fetched or applied. Optional for the same reason as `acceptableUse`.
	 */
	readonly dashboardPolicy?: DashboardPolicyTrust | null;
	/**
	 * Personal vs company AI accounts (managed-only key `workAccounts`). Absent or null: no
	 * account check. Optional for the same reason as `acceptableUse`.
	 */
	readonly workAccounts?: WorkAccountPolicy | null;
}

/**
 * Keys that may sign the dashboard's Browser Guard policy document. Only an administrator
 * can set it (chrome.storage.managed), so a user cannot make the extension trust a
 * document of their own.
 */
export interface DashboardPolicyTrust {
	/** 1-4 Ed25519 public keys, SPKI PEM (the connectors' `policy_public_keys_pem`). */
	readonly publicKeysPem: readonly string[];
	/** When set, a document signed for another tenant is refused. */
	readonly tenantId: string | null;
}

/**
 * AI acceptable-use notice (AI literacy support, e.g. EU AI Act Art. 4). The text stays in
 * the browser; telemetry reports only `id` and `version` when a user acknowledges it.
 */
export interface AcceptableUseNotice {
	/** `^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`; reported in acknowledgement telemetry. */
	readonly id: string;
	/** 1..999999. Raising it shows the notice again to every user. */
	readonly version: number;
	/** 1..120 characters. */
	readonly title: string;
	/** Plain text (no markup), 1..4000 characters; blank lines separate paragraphs. */
	readonly text: string;
	/** Optional https link to the full policy (shown as a link, never fetched). */
	readonly url?: string;
}

/** Acknowledgement telemetry event (see docs/contracts/privacy-telemetry.md). No text. */
export interface AupAcknowledgementEvent {
	readonly event_id: string;
	readonly event_type: "aup_acknowledgement";
	readonly timestamp: string;
	readonly site: SiteId;
	readonly notice_id: string;
	readonly notice_version: number;
}

export interface TelemetryConfig {
	readonly controlPlaneUrl: string;
	readonly apiKey: string;
}

/** Privacy telemetry event (see docs/contracts/privacy-telemetry.md). Counts only. */
export interface PrivacyScanEvent {
	readonly event_id: string;
	readonly event_type: "privacy_scan";
	readonly timestamp: string;
	readonly site: SiteId;
	readonly action: "masked" | "blocked" | "warned" | "allowed";
	readonly channel: "prompt" | "paste" | "file";
	readonly entity_counts: Readonly<Partial<Record<EntityType, number>>>;
	readonly findings_count: number;
	readonly policy_id?: string;
	/**
	 * Whether native NER took part in the check: "used", or "unavailable" (enabled or required
	 * by policy but no NER answer: never a clean check). Absent: native NER was off.
	 */
	readonly native_ner?: NativeNerUse;
	/** "paused": the send happened while the user had paused protection (monitor mode). */
	readonly reason?: PrivacyScanReason;
	/**
	 * Number of managed policy keys whose value was invalid and fell back to a fail-safe value
	 * (1..64; "*" counts as one). Absent: the managed policy was valid (or there is none).
	 */
	readonly policy_errors?: number;
	/**
	 * Account check result on a site listed in the managed `workAccounts` (an enum only: never
	 * a workspace id, email or domain). Absent: the site is not account-checked.
	 */
	readonly account_type?: AccountType;
}

/** Why a privacy_scan event was not enforced as the policy mode says (optional). */
export type PrivacyScanReason = "paused";

/** Native NER outcome a RECORD / privacy_scan event may carry (absent: NER was off). */
export type NativeNerUse = "used" | "unavailable";

/**
 * Shadow AI usage telemetry (see docs/contracts/privacy-telemetry.md). Aggregated counts
 * of top-level visits to (or blocked navigations towards) one catalogued AI service:
 * no URL, no page title, no path, only the catalog id.
 */
export interface ShadowAiUsageEvent {
	readonly event_id: string;
	readonly event_type: "shadow_ai_usage";
	readonly timestamp: string;
	readonly service_id: string;
	readonly action: "visited" | "blocked";
	readonly count: number;
	/** Whether the service is in the policy's `sanctioned` list when the event was built. */
	readonly sanctioned: boolean;
	readonly policy_id?: string;
}

/** Any event the Browser Guard telemetry queue carries. */
export type TelemetryEvent = PrivacyScanEvent | ShadowAiUsageEvent | AupAcknowledgementEvent;

/** One UTC day of Shadow AI counts for one service (options page; never sent as such). */
export interface ShadowAiDailyUsage {
	readonly day: string;
	readonly serviceId: string;
	readonly visited: number;
	readonly blocked: number;
}

/** Host access for one administrator-configured custom site (GET_SITE_ACCESS). */
export interface CustomSiteAccess {
	readonly id: string;
	readonly label: string;
	readonly hosts: readonly string[];
	/** `https://<host>/*` for every host. */
	readonly origins: readonly string[];
	/** Host access granted for every host of the site. */
	readonly granted: boolean;
	/** The content script is registered for (some of) the site's hosts. */
	readonly active: boolean;
}

/**
 * Host access the policy needs and whether the browser granted it (GET_SITE_ACCESS).
 * Origins are `https://<host>/*` match patterns within the optional host permissions.
 */
export interface SiteAccessStatus {
	readonly shadowAi: {
		readonly mode: ShadowAiMode;
		/** Services currently blocked by policy (catalog ids). */
		readonly blocked: readonly string[];
		/** Origins Shadow AI visibility/enforcement needs; empty when it is off. */
		readonly origins: readonly string[];
		/** Subset of `origins` the browser has not granted. */
		readonly missingOrigins: readonly string[];
		/** Local per-day counts (last 30 UTC days, newest first). */
		readonly usage: readonly ShadowAiDailyUsage[];
	};
	readonly customSites: readonly CustomSiteAccess[];
}

/** Messages between content scripts / UI pages and the background worker. */
export type GuardMessage =
	| { readonly type: "GET_POLICY" }
	| { readonly type: "POLICY_CHANGED"; readonly policy: GuardPolicy }
	| {
			readonly type: "RECORD";
			readonly site: SiteId;
			readonly action: PrivacyScanEvent["action"];
			readonly channel: PrivacyScanEvent["channel"];
			readonly counts: Readonly<Partial<Record<EntityType, number>>>;
			readonly native?: NativeNerUse;
			/** Account check result when the site is listed in `workAccounts` (enum only). */
			readonly account?: AccountType;
	  }
	| { readonly type: "GET_STATS"; readonly tabId?: number }
	| { readonly type: "SET_USER_SETTINGS"; readonly settings: Partial<UserSettings> }
	/** minutes 1..60 pauses (only when policy.allowUserPause); 0 resumes. */
	| { readonly type: "PAUSE"; readonly minutes: number }
	| { readonly type: "NATIVE_SCAN"; readonly text: string }
	/**
	 * OCR of an uploaded image (or an image inside an uploaded document) by the native host:
	 * `data` is the image, base64 (at most NATIVE_IMAGE_MAX_BYTES decoded). Counts-only reply.
	 */
	| { readonly type: "NATIVE_IMAGE_SCAN"; readonly data: string }
	| { readonly type: "SET_RESTORE_VISIBLE"; readonly visible: boolean }
	/**
	 * Content script -> worker: persist this tab's vault (restorable entries only) and the
	 * placeholders already sent from it in chrome.storage.session, keyed by the sender's
	 * tab id + origin (never storage.local, never readable by page scripts).
	 */
	| {
			readonly type: "VAULT_SAVE";
			readonly snapshot: VaultSnapshot;
			readonly sent: readonly string[];
	  }
	/** Content script -> worker: the vault saved for the sender's tab id + origin, if any. */
	| { readonly type: "VAULT_LOAD" }
	/** Content script -> worker: the current acceptable-use notice and whether it was acknowledged. */
	| { readonly type: "AUP_STATUS" }
	/**
	 * Content script -> worker: the user pressed "I understand" for this notice version. The
	 * worker accepts it only for the notice currently in force and queues one counts-only
	 * acknowledgement event per version.
	 */
	| { readonly type: "AUP_ACKNOWLEDGE"; readonly noticeId: string; readonly version: number }
	/** Extension pages only: host access for Shadow AI and custom sites, plus local counts. */
	| { readonly type: "GET_SITE_ACCESS" };

/**
 * Background worker replies to GuardMessage (src/background/index.ts). Every reply is
 * `{ ok: true, ... }` or a GuardError; callers must treat a missing/`ok: false` reply as
 * a failure (fail closed). Content scripts receive the policy with `telemetry: null`.
 */
export interface GuardError {
	readonly ok: false;
	/** Stable code: SENDER_DENIED, BAD_MESSAGE, NOT_ALLOWED, LOCKED_KEYS, INVALID_SETTINGS, PAUSE_DISABLED, TOO_LARGE, INTERNAL. */
	readonly error: string;
	/** Offending setting keys for LOCKED_KEYS / INVALID_SETTINGS. */
	readonly keys?: readonly string[];
}
export interface GuardResponses {
	readonly GET_POLICY: { readonly ok: true; readonly policy: GuardPolicy };
	readonly RECORD: { readonly ok: true };
	readonly GET_STATS: { readonly ok: true; readonly stats: GuardStats };
	readonly SET_USER_SETTINGS: { readonly ok: true; readonly policy: GuardPolicy };
	readonly PAUSE: { readonly ok: true; readonly pausedUntil: number | null };
	/**
	 * `findings` is null when the host produced nothing usable (unavailable, timed out,
	 * output not mappable); `status` is the bridge state after the call, so callers can
	 * say "rules only" instead of implying NER ran.
	 */
	readonly NATIVE_SCAN: {
		readonly ok: true;
		readonly findings: readonly Finding[] | null;
		readonly status?: NativeHostStatus;
	};
	/** `inspection` is null when the host or its OCR is unavailable (the image is then not inspected). */
	readonly NATIVE_IMAGE_SCAN: {
		readonly ok: true;
		readonly inspection: ImageInspection | null;
		readonly status?: NativeHostStatus;
	};
	readonly SET_RESTORE_VISIBLE: { readonly ok: true };
	readonly VAULT_SAVE: { readonly ok: true };
	readonly VAULT_LOAD: {
		readonly ok: true;
		readonly snapshot: VaultSnapshot | null;
		readonly sent: readonly string[];
	};
	readonly AUP_STATUS: {
		readonly ok: true;
		readonly notice: AcceptableUseNotice | null;
		readonly acknowledged: boolean;
	};
	readonly AUP_ACKNOWLEDGE: { readonly ok: true };
	readonly GET_SITE_ACCESS: { readonly ok: true; readonly access: SiteAccessStatus };
}
export type GuardResponse<T extends keyof GuardResponses = keyof GuardResponses> =
	| GuardResponses[T]
	| GuardError;

/** User-editable settings (stored in chrome.storage.local; no secrets except telemetry apiKey). */
export interface UserSettings {
	readonly mode: GuardMode;
	readonly enabledEntities: readonly EntityType[];
	readonly literals: readonly LiteralRule[];
	readonly disabledSites: readonly SiteId[];
	readonly maskPaste: boolean;
	readonly restoreResponses: boolean;
	/** Opt in to the local native host (NER); also needs the optional nativeMessaging permission. */
	readonly useNativeHost: boolean;
	/** Uninspected pictures: warn (upload with a warning) or block. See GuardPolicy. */
	readonly uninspectedImages: "warn" | "block";
	readonly language: "auto" | "en" | "tr";
	readonly telemetry: TelemetryConfig | null;
}

export interface GuardStats {
	readonly site: SiteId | null;
	readonly protectedPrompts: number;
	readonly maskedItems: number;
	readonly blockedSends: number;
	readonly byType: Readonly<Partial<Record<EntityType, number>>>;
	readonly pausedUntil: number | null;
	readonly nativeHost: NativeHostStatus;
	/**
	 * For a tab (GET_STATS with a tab id): whether a Browser Guard content script fetched its
	 * policy in this tab's current page origin since the extension (re)started. False for a tab
	 * that was open before install/update/enable and has not been injected or reloaded: the
	 * popup then shows "Not protected - reload" instead of "Protected". Absent for global stats.
	 */
	readonly contentActive?: boolean;
}

export type NativeHostStatus = "connected" | "unavailable" | "disabled";

/** Result of scanning an uploaded/dropped file (src/engine/files.ts `sanitizeFile`). */
export interface FileDecision {
	readonly action: "allow" | "mask" | "block";
	/** Present when action === "mask": sanitized replacement file content. */
	readonly masked?: { readonly name: string; readonly type: string; readonly bytes: Uint8Array };
	readonly counts: Readonly<Partial<Record<EntityType, number>>>;
	/**
	 * Stable reason codes, e.g. BINARY_FILE_UNSCANNED, FILE_TOO_LARGE, FORMULA_CELL, SENSITIVE_DATA,
	 * SENSITIVE_DATA_IN_PDF, SENSITIVE_DATA_IN_LEGACY_OFFICE, SENSITIVE_DATA_IN_IMAGE,
	 * IMAGE_NOT_INSPECTED, LEGACY_OFFICE_FORMAT, LEGACY_OFFICE_PARTIAL,
	 * DOCUMENT_IMAGES_NOT_INSPECTED.
	 */
	readonly reasons: readonly string[];
}

/**
 * Reason codes that can stop an upload (`FileDecision.reasons` of a "block", or added by the
 * content script), in the order the upload bubble explains them: the first one present picks
 * the sentence the user reads. Every code has an EN and TR message in content/strings.ts
 * (`fileReasons`); codes stay out of the visible text. Families not listed here are explained
 * by their prefix: `SIGNAL_<SignalCode>` (risk-signal coaching) and `ARCHIVE_<code>` (a broken
 * ZIP container, explained like DOCUMENT_MALFORMED); host `IMAGE_*` / `NATIVE_*` details always
 * accompany IMAGE_NOT_INSPECTED or PDF_IMAGES_NOT_INSPECTED.
 */
export const FILE_BLOCK_REASONS = [
	"FILE_BLOCKED_BY_POLICY",
	"DOCUMENT_BLOCKED_BY_POLICY",
	"NATIVE_NER_UNAVAILABLE",
	"FILE_TOO_LARGE",
	"SENSITIVE_DATA_IN_PDF",
	"SENSITIVE_DATA_IN_LEGACY_OFFICE",
	"SENSITIVE_DATA_IN_IMAGE",
	"DOCUMENT_ENCRYPTED",
	"PDF_ENCRYPTED",
	"DOCUMENT_MACROS",
	"DOCUMENT_EMBEDDED_OBJECT",
	"DOCUMENT_EXTERNAL_LINKS",
	"DOCUMENT_LIMIT_EXCEEDED",
	"DOCUMENT_MALFORMED",
	"TEXT_FILE_NOT_DECODABLE",
	"SCAN_INCOMPLETE",
	"FILE_SCAN_ERROR",
	"PDF_IMAGE_OCR_UNAVAILABLE",
	"PDF_IMAGES_NOT_INSPECTED",
	"PDF_IMAGE_LIMIT",
	"PDF_IMAGE_UNSUPPORTED",
	"PDF_IMAGE_UNDECODABLE",
	"PDF_IMAGE_OCR_INCOMPLETE",
	"PDF_NO_TEXT",
	"PDF_PARTIAL",
	"PDF_EMBEDDED_FILES_NOT_INSPECTED",
	"PDF_UNPARSEABLE",
	"LEGACY_OFFICE_PARTIAL",
	"LEGACY_OFFICE_UNSUPPORTED",
	"LEGACY_OFFICE_FORMAT",
	"DOCUMENT_UNPARSEABLE",
	"IMAGE_NOT_INSPECTED",
	"BINARY_FILE_UNSCANNABLE",
] as const;

export type FileBlockReason = (typeof FILE_BLOCK_REASONS)[number];

/**
 * Reason codes that only accompany an allowed or masked file (or a monitor-mode record); they
 * never decide a block. Pass-through warnings for them are chosen in content/file-guard.ts.
 */
export const FILE_PASS_REASONS = [
	"SENSITIVE_DATA",
	"FORMULA_CELL",
	"BINARY_FILE_UNSCANNED",
	"DOCUMENT_IMAGES_NOT_INSPECTED",
	"IMAGE_OCR_CLEAN",
	"PDF_IMAGES_OCR_CLEAN",
	// Host detail next to IMAGE_NOT_INSPECTED: text clean, but no barcode decoder on the endpoint.
	"IMAGE_BARCODE_NOT_CHECKED",
] as const;

/**
 * Native-host OCR verdict for one image (packages/privacy `image-scan`): whether its text shows
 * sensitive data. Pixels are never masked; a "sensitive" image is blocked.
 *   clean       every OCR word was inspected and nothing sensitive was found;
 *   sensitive   sensitive text (per-type `counts`) or a host policy that blocks images;
 *   incomplete  not fully inspected (no text read, uncertain OCR, barcode, limits, OCR failure);
 *               callers treat it like an image that was not inspected - never as clean.
 */
export interface ImageInspection {
	readonly result: "clean" | "sensitive" | "incomplete";
	readonly counts: Readonly<Partial<Record<EntityType, number>>>;
	/** Stable host reason codes (`IMAGE_*`, `NATIVE_*`), never OCR text. */
	readonly reasons: readonly string[];
}

/** Optional native messaging bridge to the AIDR Privacy native host (NER + OCR). */
export interface NativeScanOptions {
	/** policy.requireNativeNer: a host answer without NER coverage is not a usable answer. */
	readonly requireNer?: boolean;
}

export interface NativeBridge {
	status(): NativeHostStatus;
	/**
	 * NER findings for PERSON/ADDRESS etc.; null when the host is unavailable. With
	 * `requireNer`, also null when the host reports anything but `rules-and-ner` coverage.
	 */
	scanText(text: string, options?: NativeScanOptions): Promise<readonly Finding[] | null>;
	/**
	 * OCR inspection of an image; null when the host, or OCR on the host, is unavailable. With
	 * `requireNer`, a "clean" verdict without `rules-and-ner` coverage becomes "incomplete".
	 */
	scanImage?(bytes: Uint8Array, options?: NativeScanOptions): Promise<ImageInspection | null>;
	/**
	 * Per-dataset exact-data keys (base64) the host derives from its EDM secret, by dataset id;
	 * null when the host is unavailable, too old, or has no secret configured.
	 */
	exactDataKeys?(datasetIds: readonly string[]): Promise<Readonly<Record<string, string>> | null>;
}

/*
 * Factory names every module exports (fixed so modules can be built in parallel):
 *   engine/detect.ts   export function createDetectionEngine(options: DetectionOptions): DetectionEngine
 *   engine/coaching.ts export function coachingFor(code: SignalCode, lang: "en" | "tr"): string
 *   engine/vault.ts    export function createVault(options: { neverRestore: readonly EntityType[]; ttlMs?: number; snapshot?: VaultSnapshot }): PlaceholderVault
 *   engine/files.ts    export function sanitizeFile(file: { name: string; type: string; bytes: Uint8Array }, deps: { engine: DetectionEngine; vault: PlaceholderVault; policy: GuardPolicy; inspectImage?: (bytes: Uint8Array) => Promise<ImageInspection | null> }): Promise<FileDecision>
 *   sites/index.ts     export const ADAPTERS: readonly SiteAdapter[]; export function adapterForUrl(url: string, customSites?: readonly CustomSiteConfig[]): SiteAdapter  // custom host -> id "custom"; unknown host -> generic adapter with id "other"
 *   sites/catalog.ts   export const AI_SERVICES: readonly AiService[]; export function serviceForUrl(url: unknown): AiService | null
 *   dom/editor.ts      export function findEditor(adapter: SiteAdapter, root: Document, lastFocused?: Element | null): EditorAccess | null
 *                      export function editorAccess(element: HTMLElement): EditorAccess
 *                      export function findSendButton(adapter: SiteAdapter, root: Document, editor: EditorAccess | null): HTMLElement | null
 *                      export function findEditorNear(adapter: SiteAdapter, anchor: Element): EditorMatch | null
 *   background/policy.ts export const DEFAULT_POLICY: GuardPolicy; export function mergePolicy(managed: unknown, user: Partial<UserSettings> | undefined): GuardPolicy
 *   background/native.ts export function createNativeBridge(enabled: boolean): NativeBridge
 *   content/acceptable-use.ts export function createAcceptableUseNotice(deps): AcceptableUseController
 * Entry points bundled by scripts/build.mjs:
 *   src/background/index.ts, src/content/index.ts, src/ui/popup.ts, src/ui/options.ts
 * Static assets: static/*.html, static/*.css, static/managed_schema.json, static/icons/*, _locales/{en,tr}/messages.json
 */
