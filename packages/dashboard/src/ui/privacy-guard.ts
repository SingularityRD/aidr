/**
 * Browser Privacy Guard read model for the dashboard.
 *
 * Browser Guard installs report counts-only `privacy_scan` events
 * (docs/contracts/privacy-telemetry.md). The server aggregates them with the
 * `privacy_guard_summary` RPC; this module validates that response strictly so
 * a malformed or partial answer is shown as unavailable, never as zeros.
 */

export const PRIVACY_WINDOWS = [7, 30] as const;
export type PrivacyWindow = (typeof PRIVACY_WINDOWS)[number];

const PRIVACY_ENTITY_LABELS: Readonly<Record<string, string>> = {
	PERSON: "Person name",
	EMAIL: "Email address",
	PHONE: "Phone number",
	TC_KIMLIK: "TC Kimlik No",
	IBAN: "IBAN",
	CREDIT_CARD: "Credit card",
	ADDRESS: "Postal address",
	US_SSN: "US SSN",
	DATE_OF_BIRTH: "Date of birth",
	PASSPORT: "Passport number",
	NATIONAL_ID: "National ID",
	TAX_ID: "Tax ID",
	BANK_ACCOUNT: "Bank account",
	IP_ADDRESS: "IP address",
	MAC_ADDRESS: "MAC address",
	SECRET: "Secret or credential",
	PRIVATE_KEY: "Private key",
	INTERNAL: "Internal marking",
	CLASSIFIED: "Classified marking",
	LOCATION: "Location",
	USERNAME: "Username",
	HEALTH_ID: "Health ID",
	LICENSE_PLATE: "License plate",
};

/** Entity types in the privacy engine's order (packages/privacy ENTITY_TYPES). */
export const PRIVACY_ENTITY_TYPES = Object.keys(PRIVACY_ENTITY_LABELS);

/**
 * Entity types Browser Guard masks by default: every type except the noisy USERNAME
 * and LOCATION. Must equal `DEFAULT_POLICY.enabledEntities` in
 * packages/browser-guard/src/background/policy.ts (asserted by a dashboard test), so a
 * managed policy copied from the dashboard does not silently widen the defaults.
 */
export const BROWSER_GUARD_DEFAULT_ENTITIES: readonly string[] = PRIVACY_ENTITY_TYPES.filter(
	(type) => type !== "USERNAME" && type !== "LOCATION",
);

const PRIVACY_SITE_LABELS: Readonly<Record<string, string>> = {
	chatgpt: "ChatGPT",
	gemini: "Gemini",
	claude: "Claude",
	copilot: "Copilot",
	perplexity: "Perplexity",
	deepseek: "DeepSeek",
	mistral: "Mistral",
	grok: "Grok",
	custom: "Internal AI site",
	other: "Other AI site",
};

const PRIVACY_ACTIONS = ["masked", "warned", "blocked", "allowed"] as const;
export type PrivacyAction = (typeof PRIVACY_ACTIONS)[number];
const PRIVACY_CHANNELS = ["prompt", "paste", "file"] as const;

export const GUARD_MODES = [
	{
		value: "auto",
		label: "Auto-mask",
		hint: "Replace sensitive values with placeholders before sending.",
	},
	{
		value: "confirm",
		label: "Confirm",
		hint: "Show the findings and let the user choose to mask or edit.",
	},
	{ value: "block", label: "Block", hint: "Stop any send that still contains sensitive values." },
	{ value: "monitor", label: "Monitor", hint: "Only record counts; prompts are sent unchanged." },
] as const;
export type GuardModeValue = (typeof GUARD_MODES)[number]["value"];

interface PrivacyTotals {
	scans: number;
	promptsProtected: number;
	itemsMasked: number;
	blockedSends: number;
	warnedSends: number;
	allowedSends: number;
}

export interface PrivacySummary {
	windowDays: PrivacyWindow;
	since: string;
	totals: PrivacyTotals;
	installs: { enrolled: number; active: number };
	byEntity: Array<{ entityType: string; items: number }>;
	bySite: Array<{ site: string; scans: number; items: number; blocked: number }>;
	series: Array<{ day: string; scans: number; masked: number; warned: number; blocked: number }>;
}

export interface PrivacyEventRow {
	id: number;
	createdAt: string;
	agentId: string;
	site: string;
	action: PrivacyAction;
	channel: string;
	entityCounts: Array<[string, number]>;
	findingsCount: number | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function count(value: unknown): number {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
		throw new Error("Malformed privacy summary.");
	}
	return value;
}

function text(value: unknown, pattern: RegExp): string {
	if (typeof value !== "string" || !pattern.test(value))
		throw new Error("Malformed privacy summary.");
	return value;
}

function list<T>(value: unknown, parse: (item: Record<string, unknown>) => T): T[] {
	if (!Array.isArray(value)) throw new Error("Malformed privacy summary.");
	return value.map((item) => {
		if (!isRecord(item)) throw new Error("Malformed privacy summary.");
		return parse(item);
	});
}

const SITE_PATTERN = /^[a-z0-9_-]{1,32}$/;
const ENTITY_PATTERN = /^[A-Z][A-Z0-9_]{0,31}$/;

/** Validate a `privacy_guard_summary` response for the requested window. */
export function parsePrivacySummary(value: unknown, windowDays: PrivacyWindow): PrivacySummary {
	if (!isRecord(value) || value.window_days !== windowDays) {
		throw new Error("Malformed privacy summary.");
	}
	const since = text(value.since, /^\d{4}-\d{2}-\d{2}T/);
	if (!Number.isFinite(Date.parse(since))) throw new Error("Malformed privacy summary.");
	const totals = value.totals;
	const installs = value.browser_installs;
	if (!isRecord(totals) || !isRecord(installs)) throw new Error("Malformed privacy summary.");
	const series = list(value.series, (day) => ({
		day: text(day.day, /^\d{4}-\d{2}-\d{2}$/),
		scans: count(day.scans),
		masked: count(day.masked),
		warned: count(day.warned),
		blocked: count(day.blocked),
	}));
	if (series.length !== windowDays) throw new Error("Malformed privacy summary.");
	return {
		windowDays,
		since,
		totals: {
			scans: count(totals.scans),
			promptsProtected: count(totals.prompts_protected),
			itemsMasked: count(totals.items_masked),
			blockedSends: count(totals.blocked_sends),
			warnedSends: count(totals.warned_sends),
			allowedSends: count(totals.allowed_sends),
		},
		installs: { enrolled: count(installs.enrolled), active: count(installs.active) },
		byEntity: list(value.by_entity, (row) => ({
			entityType: text(row.entity_type, ENTITY_PATTERN),
			items: count(row.items),
		})),
		bySite: list(value.by_site, (row) => ({
			site: text(row.site, SITE_PATTERN),
			scans: count(row.scans),
			items: count(row.items),
			blocked: count(row.blocked),
		})),
		series,
	};
}

/**
 * Project one stored `privacy_scan` events row. Rows that do not match the
 * counts-only contract are skipped rather than rendered.
 */
export function parsePrivacyEventRow(value: unknown): PrivacyEventRow | null {
	if (!isRecord(value) || !isRecord(value.payload)) return null;
	const { payload } = value;
	if (
		typeof value.id !== "number" ||
		typeof value.created_at !== "string" ||
		!Number.isFinite(Date.parse(value.created_at)) ||
		typeof value.agent_id !== "string" ||
		typeof payload.site !== "string" ||
		!SITE_PATTERN.test(payload.site) ||
		!PRIVACY_ACTIONS.includes(payload.action as PrivacyAction) ||
		!PRIVACY_CHANNELS.includes(payload.channel as (typeof PRIVACY_CHANNELS)[number])
	) {
		return null;
	}
	const entityCounts: Array<[string, number]> = [];
	if (isRecord(payload.entity_counts)) {
		for (const [type, amount] of Object.entries(payload.entity_counts)) {
			if (ENTITY_PATTERN.test(type) && typeof amount === "number" && Number.isSafeInteger(amount)) {
				entityCounts.push([type, amount]);
			}
		}
	}
	entityCounts.sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
	const findings = payload.findings_count;
	return {
		id: value.id,
		createdAt: value.created_at,
		agentId: value.agent_id,
		site: payload.site,
		action: payload.action as PrivacyAction,
		channel: payload.channel as string,
		entityCounts,
		findingsCount: typeof findings === "number" && Number.isSafeInteger(findings) ? findings : null,
	};
}

export function entityLabel(type: string): string {
	return PRIVACY_ENTITY_LABELS[type] ?? type;
}

export function siteLabel(site: string): string {
	return PRIVACY_SITE_LABELS[site] ?? site;
}

/** Badge class and generic decision for a guard action (contract mapping). */
export function actionBadge(action: PrivacyAction): string {
	if (action === "blocked") return "badge badge-deny";
	if (action === "warned") return "badge badge-ask";
	if (action === "masked") return "badge badge-success";
	return "badge badge-allow";
}

/** One-line, counts-only summary used by the generic event feeds. */
export function privacyEventSummary(payload: Record<string, unknown> | null | undefined): string {
	const site = typeof payload?.site === "string" ? siteLabel(payload.site) : "AI site";
	const channel = typeof payload?.channel === "string" ? payload.channel : "send";
	const action = typeof payload?.action === "string" ? payload.action : "scanned";
	const findings = payload?.findings_count;
	const items = typeof findings === "number" && Number.isSafeInteger(findings) ? findings : null;
	return `${site} ${channel}: ${action}${items === null ? "" : `, ${items} item(s)`}`;
}

/**
 * Managed-policy template for Browser Guard. The API key is never known to the
 * dashboard (keys are stored hash-only), so the administrator pastes one. It
 * should be an `ingest:browser_guard` key: managed policy is user-readable.
 */
export function managedPolicySnippet(options: {
	controlPlaneUrl: string | null;
	mode: GuardModeValue;
	acceptableUse?: AcceptableUseNoticeInput | null;
}): string {
	return JSON.stringify(
		{
			mode: options.mode,
			enabledEntities: BROWSER_GUARD_DEFAULT_ENTITIES,
			literals: [],
			telemetry: {
				controlPlaneUrl: options.controlPlaneUrl ?? "https://<your-project>.supabase.co",
				apiKey: "<paste a Browser Guard ingest-only key created on the API Keys page>",
			},
			...(options.acceptableUse ? { acceptableUse: options.acceptableUse } : {}),
		},
		null,
		2,
	);
}

/**
 * AI acceptable-use notice for Browser Guard managed policy (`acceptableUse`). Mirrors
 * `validateAcceptableUseNotice` in packages/browser-guard/src/background/policy.ts (a
 * dashboard test pins the two): the extension ignores the whole notice when any field is
 * out of range, so the dashboard refuses to emit one.
 */
export interface AcceptableUseNoticeInput {
	id: string;
	version: number;
	title: string;
	text: string;
	url?: string;
}

export const ACCEPTABLE_USE_LIMITS = Object.freeze({
	versionMax: 999_999,
	titleMax: 120,
	textMax: 4000,
});
const NOTICE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const NOTICE_CONTROL = /[^\P{Cc}\t\n\r]/u;

export function acceptableUseNotice(input: {
	id: string;
	version: string | number;
	title: string;
	text: string;
	url: string;
}): { ok: true; value: AcceptableUseNoticeInput } | { ok: false; error: string } {
	const id = input.id.trim();
	const version = typeof input.version === "number" ? input.version : Number(input.version.trim());
	const title = input.title.trim();
	const text = input.text.trim();
	const url = input.url.trim();
	if (!NOTICE_ID.test(id))
		return { ok: false, error: "Notice ID: letters, digits, . _ : - (up to 64)." };
	if (!Number.isSafeInteger(version) || version < 1 || version > ACCEPTABLE_USE_LIMITS.versionMax)
		return { ok: false, error: "Version must be a whole number from 1 to 999999." };
	if (!title || title.length > ACCEPTABLE_USE_LIMITS.titleMax || NOTICE_CONTROL.test(title))
		return { ok: false, error: "Title is required (up to 120 characters)." };
	if (!text || text.length > ACCEPTABLE_USE_LIMITS.textMax || NOTICE_CONTROL.test(text))
		return { ok: false, error: "Notice text is required (up to 4000 characters, plain text)." };
	if (url) {
		let parsed: URL;
		try {
			parsed = new URL(url);
		} catch {
			return { ok: false, error: "Policy link must be an https:// address." };
		}
		if (parsed.protocol !== "https:" || parsed.username || parsed.password || url.length > 2048)
			return { ok: false, error: "Policy link must be an https:// address." };
		return { ok: true, value: { id, version, title, text, url: parsed.href } };
	}
	return { ok: true, value: { id, version, title, text } };
}
