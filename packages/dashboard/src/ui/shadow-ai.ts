/**
 * Shadow AI read model for the Browser Privacy Guard page.
 *
 * Browser Guard installs report aggregated `shadow_ai_usage` counts per catalogued AI
 * service (docs/contracts/privacy-telemetry.md). The server aggregates them with the
 * `shadow_ai_summary` RPC; this module validates that response strictly so a malformed
 * or partial answer is shown as unavailable, never as zeros.
 */

import type { PrivacyWindow } from "./privacy-guard";

/**
 * Display names and categories of the Browser Guard catalog
 * (packages/browser-guard/src/sites/catalog.ts; pinned by a dashboard test).
 */
export const SHADOW_AI_SERVICES: Readonly<Record<string, { name: string; category: string }>> = {
	chatgpt: { name: "ChatGPT", category: "chat" },
	gemini: { name: "Google Gemini", category: "chat" },
	claude: { name: "Claude", category: "chat" },
	copilot: { name: "Microsoft Copilot", category: "chat" },
	"m365-copilot": { name: "Microsoft 365 Copilot Chat", category: "chat" },
	perplexity: { name: "Perplexity", category: "search" },
	deepseek: { name: "DeepSeek", category: "chat" },
	mistral: { name: "Mistral Le Chat", category: "chat" },
	grok: { name: "Grok", category: "chat" },
	poe: { name: "Poe", category: "chat" },
	"character-ai": { name: "Character.AI", category: "chat" },
	huggingface: { name: "Hugging Face (HuggingChat)", category: "chat" },
	"meta-ai": { name: "Meta AI", category: "chat" },
	pi: { name: "Pi", category: "chat" },
	"duck-ai": { name: "Duck.ai", category: "chat" },
	kimi: { name: "Kimi", category: "chat" },
	qwen: { name: "Qwen Chat (Tongyi)", category: "chat" },
	doubao: { name: "Doubao", category: "chat" },
	ernie: { name: "ERNIE Bot (Wenxin Yiyan)", category: "chat" },
	chatglm: { name: "ChatGLM / Z.ai", category: "chat" },
	yuanbao: { name: "Tencent Yuanbao", category: "chat" },
	cohere: { name: "Cohere Chat", category: "chat" },
	groq: { name: "GroqChat", category: "chat" },
	openrouter: { name: "OpenRouter", category: "chat" },
	together: { name: "Together AI Playground", category: "chat" },
	lmarena: { name: "LMArena", category: "chat" },
	monica: { name: "Monica", category: "chat" },
	replika: { name: "Replika", category: "chat" },
	chatpdf: { name: "ChatPDF", category: "chat" },
	notebooklm: { name: "NotebookLM", category: "chat" },
	you: { name: "You.com", category: "search" },
	consensus: { name: "Consensus", category: "search" },
	elicit: { name: "Elicit", category: "search" },
	phind: { name: "Phind", category: "coding" },
	"ai-studio": { name: "Google AI Studio", category: "coding" },
	"openai-platform": { name: "OpenAI Platform", category: "coding" },
	"anthropic-console": { name: "Anthropic Console", category: "coding" },
	"azure-ai-foundry": { name: "Azure AI Foundry", category: "coding" },
	cursor: { name: "Cursor (web)", category: "coding" },
	v0: { name: "v0 by Vercel", category: "coding" },
	bolt: { name: "Bolt.new", category: "coding" },
	lovable: { name: "Lovable", category: "coding" },
	replit: { name: "Replit", category: "coding" },
	windsurf: { name: "Windsurf (Codeium)", category: "coding" },
	tabnine: { name: "Tabnine", category: "coding" },
	blackbox: { name: "Blackbox AI", category: "coding" },
	devin: { name: "Devin", category: "agent" },
	manus: { name: "Manus", category: "agent" },
	genspark: { name: "Genspark", category: "agent" },
	jasper: { name: "Jasper", category: "writing" },
	writesonic: { name: "Writesonic (Chatsonic)", category: "writing" },
	"copy-ai": { name: "Copy.ai", category: "writing" },
	quillbot: { name: "QuillBot", category: "writing" },
	deepl: { name: "DeepL (Translator, Write)", category: "writing" },
	grammarly: { name: "Grammarly", category: "writing" },
	wordtune: { name: "Wordtune", category: "writing" },
	rytr: { name: "Rytr", category: "writing" },
	gamma: { name: "Gamma", category: "writing" },
	tome: { name: "Tome", category: "writing" },
	"beautiful-ai": { name: "Beautiful.ai", category: "writing" },
	midjourney: { name: "Midjourney", category: "image" },
	leonardo: { name: "Leonardo.Ai", category: "image" },
	ideogram: { name: "Ideogram", category: "image" },
	runway: { name: "Runway", category: "image" },
	elevenlabs: { name: "ElevenLabs", category: "image" },
	suno: { name: "Suno", category: "image" },
	pika: { name: "Pika", category: "image" },
	krea: { name: "Krea", category: "image" },
	firefly: { name: "Adobe Firefly", category: "image" },
	heygen: { name: "HeyGen", category: "image" },
	synthesia: { name: "Synthesia", category: "image" },
	otter: { name: "Otter.ai", category: "meeting" },
	fireflies: { name: "Fireflies.ai", category: "meeting" },
	tldv: { name: "tl;dv", category: "meeting" },
	fathom: { name: "Fathom", category: "meeting" },
	"read-ai": { name: "Read AI", category: "meeting" },
};

const CATEGORY_LABELS: Readonly<Record<string, string>> = {
	chat: "Chat assistant",
	coding: "Coding",
	image: "Image, video & voice",
	meeting: "Meeting assistant",
	writing: "Writing",
	search: "Search & research",
	agent: "Autonomous agent",
	other: "Other",
};

export interface ShadowAiSummary {
	windowDays: PrivacyWindow;
	since: string;
	totals: {
		visits: number;
		blockedAttempts: number;
		sanctionedVisits: number;
		unsanctionedVisits: number;
		services: number;
	};
	byService: Array<{
		serviceId: string;
		category: string;
		visits: number;
		blocked: number;
		sanctioned: boolean;
	}>;
	byCategory: Array<{ category: string; visits: number; blocked: number }>;
	series: Array<{ day: string; visits: number; unsanctionedVisits: number; blocked: number }>;
}

const MALFORMED = "Malformed Shadow AI summary.";
const SERVICE_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;
const CATEGORY_PATTERN = /^[a-z]{1,16}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function count(value: unknown): number {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
		throw new Error(MALFORMED);
	}
	return value;
}

function text(value: unknown, pattern: RegExp): string {
	if (typeof value !== "string" || !pattern.test(value)) throw new Error(MALFORMED);
	return value;
}

function list<T>(value: unknown, parse: (item: Record<string, unknown>) => T): T[] {
	if (!Array.isArray(value)) throw new Error(MALFORMED);
	return value.map((item) => {
		if (!isRecord(item)) throw new Error(MALFORMED);
		return parse(item);
	});
}

/** Validate a `shadow_ai_summary` response for the requested window. */
export function parseShadowAiSummary(value: unknown, windowDays: PrivacyWindow): ShadowAiSummary {
	if (!isRecord(value) || value.window_days !== windowDays) throw new Error(MALFORMED);
	const since = text(value.since, /^\d{4}-\d{2}-\d{2}T/);
	if (!Number.isFinite(Date.parse(since))) throw new Error(MALFORMED);
	const totals = value.totals;
	if (!isRecord(totals)) throw new Error(MALFORMED);
	const series = list(value.series, (day) => ({
		day: text(day.day, /^\d{4}-\d{2}-\d{2}$/),
		visits: count(day.visits),
		unsanctionedVisits: count(day.unsanctioned_visits),
		blocked: count(day.blocked),
	}));
	if (series.length !== windowDays) throw new Error(MALFORMED);
	return {
		windowDays,
		since,
		totals: {
			visits: count(totals.visits),
			blockedAttempts: count(totals.blocked_attempts),
			sanctionedVisits: count(totals.sanctioned_visits),
			unsanctionedVisits: count(totals.unsanctioned_visits),
			services: count(totals.services),
		},
		byService: list(value.by_service, (row) => {
			if (typeof row.sanctioned !== "boolean") throw new Error(MALFORMED);
			return {
				serviceId: text(row.service_id, SERVICE_PATTERN),
				category: text(row.category, CATEGORY_PATTERN),
				visits: count(row.visits),
				blocked: count(row.blocked),
				sanctioned: row.sanctioned,
			};
		}),
		byCategory: list(value.by_category, (row) => ({
			category: text(row.category, CATEGORY_PATTERN),
			visits: count(row.visits),
			blocked: count(row.blocked),
		})),
		series,
	};
}

export function serviceName(serviceId: string): string {
	if (serviceId === "other") return "Other AI service";
	return SHADOW_AI_SERVICES[serviceId]?.name ?? serviceId;
}

export function categoryLabel(category: string): string {
	return CATEGORY_LABELS[category] ?? category;
}

/** One-line, counts-only summary used by the generic event feeds. */
export function shadowAiEventSummary(payload: Record<string, unknown> | null | undefined): string {
	const service =
		typeof payload?.service_id === "string" ? serviceName(payload.service_id) : "AI service";
	const action = payload?.action === "blocked" ? "blocked" : "visited";
	const amount = payload?.count;
	const n = typeof amount === "number" && Number.isSafeInteger(amount) ? amount : null;
	const status = payload?.sanctioned === true ? "sanctioned" : "unsanctioned";
	return `${service} (${status}): ${action}${n === null ? "" : ` ×${n}`}`;
}

/**
 * Dashboard allow/block decision for one AI service. Decisions are AI governance register
 * entries (`ai_assets`, asset_type `ai_site`, identifier = catalog id): `approved` is
 * "allowed" and `banned` is "blocked". Enrolled Browser Guard installs receive them in a
 * signed policy document (`browser-guard-policy`) and apply them under the enterprise
 * policy, most restrictive wins.
 */
export type ShadowAiDecision = "allowed" | "blocked";

export interface ShadowAiDecisionRow {
	assetId: string;
	serviceId: string;
	status: string;
	version: number;
	decision: ShadowAiDecision | null;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ASSET_STATUS = ["proposed", "approved", "restricted", "banned", "retired"];

/** Register rows for catalogued services; malformed rows make the whole read unavailable. */
export function parseShadowAiDecisions(value: unknown): Map<string, ShadowAiDecisionRow> {
	if (!Array.isArray(value)) throw new Error("Malformed Shadow AI decisions.");
	const out = new Map<string, ShadowAiDecisionRow>();
	for (const row of value) {
		if (
			!isRecord(row) ||
			typeof row.id !== "string" ||
			!UUID_PATTERN.test(row.id) ||
			typeof row.identifier !== "string" ||
			typeof row.status !== "string" ||
			!ASSET_STATUS.includes(row.status) ||
			!Number.isSafeInteger(row.version)
		)
			throw new Error("Malformed Shadow AI decisions.");
		// Hostnames and other register identifiers are not Browser Guard catalog ids.
		if (!SERVICE_PATTERN.test(row.identifier)) continue;
		out.set(row.identifier, {
			assetId: row.id,
			serviceId: row.identifier,
			status: row.status,
			version: row.version as number,
			decision: row.status === "approved" ? "allowed" : row.status === "banned" ? "blocked" : null,
		});
	}
	return out;
}

/** `ai-governance` upsert_asset payload that records `decision` for `serviceId`. */
export function shadowAiDecisionPayload(
	serviceId: string,
	decision: ShadowAiDecision,
	existing: ShadowAiDecisionRow | undefined,
): Record<string, unknown> {
	const status = decision === "allowed" ? "approved" : "banned";
	if (existing) {
		return {
			asset_id: existing.assetId,
			expected_version: existing.version,
			fields: { status },
		};
	}
	return {
		fields: {
			asset_type: "ai_site",
			identifier: serviceId,
			name: serviceName(serviceId).slice(0, 120),
			status,
		},
	};
}

/**
 * Managed-policy fragment for Shadow AI and a custom internal site, shown next to the
 * enrollment snippet. Ids are catalog ids; hosts are exact HTTPS hostnames.
 */
export function shadowAiPolicySnippet(options: {
	mode: "monitor" | "block-unsanctioned";
	sanctioned: readonly string[];
}): string {
	return JSON.stringify(
		{
			shadowAi: { mode: options.mode, sanctioned: [...options.sanctioned], blocked: [] },
			customSites: [
				{
					id: "internal-ai",
					label: "<your internal AI portal>",
					hosts: ["ai.<your-company>.com"],
					editorSelectors: ["textarea"],
					sendButtonSelectors: ["button[type=submit]"],
					responseSelectors: [".answer"],
				},
			],
		},
		null,
		2,
	);
}
