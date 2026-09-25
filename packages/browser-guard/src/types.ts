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

/** Exact-data-match dataset shipped by an administrator: HMAC-SHA256 fingerprints only. */
export interface ExactDataSet {
	readonly datasetId: string;
	/** base64 HMAC key distributed with managed policy; never user-visible. */
	readonly keyB64: string;
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
	| "other";

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
	readonly allowUserPause: boolean;
	readonly allowSendAnyway: boolean;
	readonly maskPaste: boolean;
	readonly fileHandling: "scan" | "block" | "allow";
	/**
	 * Office (DOCX/XLSX/PPTX) and PDF uploads when `fileHandling` is "scan" (managed-only):
	 * "mask" masks Office text in place and scans PDFs (blocking PDFs with findings);
	 * "block" rejects every such document; "allow" skips parsing and treats them like other
	 * binary files (unscanned warning; blocked in block mode). Absent means "mask".
	 */
	readonly documentHandling: "mask" | "block" | "allow";
	readonly maxFileBytes: number;
	readonly restoreResponses: boolean;
	readonly useNativeHost: boolean;
	readonly telemetry: TelemetryConfig | null;
	readonly language: "auto" | "en" | "tr";
	/** Keys locked by managed policy (UI renders them read-only). */
	readonly managedKeys: readonly string[];
	readonly policyId: string;
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
	  }
	| { readonly type: "GET_STATS"; readonly tabId?: number }
	| { readonly type: "SET_USER_SETTINGS"; readonly settings: Partial<UserSettings> }
	/** minutes 1..60 pauses (only when policy.allowUserPause); 0 resumes. */
	| { readonly type: "PAUSE"; readonly minutes: number }
	| { readonly type: "NATIVE_SCAN"; readonly text: string }
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
	| { readonly type: "VAULT_LOAD" };

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
	readonly SET_RESTORE_VISIBLE: { readonly ok: true };
	readonly VAULT_SAVE: { readonly ok: true };
	readonly VAULT_LOAD: {
		readonly ok: true;
		readonly snapshot: VaultSnapshot | null;
		readonly sent: readonly string[];
	};
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
}

export type NativeHostStatus = "connected" | "unavailable" | "disabled";

/** Result of scanning an uploaded/dropped file (src/engine/files.ts `sanitizeFile`). */
export interface FileDecision {
	readonly action: "allow" | "mask" | "block";
	/** Present when action === "mask": sanitized replacement file content. */
	readonly masked?: { readonly name: string; readonly type: string; readonly bytes: Uint8Array };
	readonly counts: Readonly<Partial<Record<EntityType, number>>>;
	/** Stable reason codes, e.g. BINARY_FILE, FILE_TOO_LARGE, FORMULA_CELL, SENSITIVE_DATA. */
	readonly reasons: readonly string[];
}

/** Optional native messaging bridge to the AIDR Privacy native host (NER + OCR). */
export interface NativeBridge {
	status(): NativeHostStatus;
	/** NER findings for PERSON/ADDRESS etc.; null when the host is unavailable. */
	scanText(text: string): Promise<readonly Finding[] | null>;
}

/*
 * Factory names every module exports (fixed so modules can be built in parallel):
 *   engine/detect.ts   export function createDetectionEngine(options: DetectionOptions): DetectionEngine
 *   engine/coaching.ts export function coachingFor(code: SignalCode, lang: "en" | "tr"): string
 *   engine/vault.ts    export function createVault(options: { neverRestore: readonly EntityType[]; ttlMs?: number; snapshot?: VaultSnapshot }): PlaceholderVault
 *   engine/files.ts    export function sanitizeFile(file: { name: string; type: string; bytes: Uint8Array }, deps: { engine: DetectionEngine; vault: PlaceholderVault; policy: GuardPolicy }): Promise<FileDecision>
 *   sites/index.ts     export const ADAPTERS: readonly SiteAdapter[]; export function adapterForUrl(url: string): SiteAdapter  // unknown host -> generic adapter with id "other"
 *   dom/editor.ts      export function findEditor(adapter: SiteAdapter, root: Document, lastFocused?: Element | null): EditorAccess | null
 *                      export function editorAccess(element: HTMLElement): EditorAccess
 *                      export function findSendButton(adapter: SiteAdapter, root: Document, editor: EditorAccess | null): HTMLElement | null
 *   background/policy.ts export const DEFAULT_POLICY: GuardPolicy; export function mergePolicy(managed: unknown, user: Partial<UserSettings> | undefined): GuardPolicy
 *   background/native.ts export function createNativeBridge(enabled: boolean): NativeBridge
 * Entry points bundled by scripts/build.mjs:
 *   src/background/index.ts, src/content/index.ts, src/ui/popup.ts, src/ui/options.ts
 * Static assets: static/*.html, static/*.css, static/managed_schema.json, static/icons/*, _locales/{en,tr}/messages.json
 */
