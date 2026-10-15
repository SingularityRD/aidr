/**
 * Plain-language display text for what detection produced: rule titles,
 * categories, detection sources and dynamic reasons (toxic-flow chains,
 * typosquat hits).
 *
 * Verdicts, audit records and SIEM fields keep the raw English reason and
 * the internal labels (`heuristic`, `toxic_flow`, `package_check`). Only the
 * text a person reads goes through here, so changing the locale never changes
 * anything a program parses.
 *
 * Reasons are looked up by their exact English text. The threat loader
 * registers every rule's `title_tr`, and a detector that builds a reason at
 * run time registers its plain English and Turkish wording next to the raw
 * text it puts in the verdict. Hook processes are short-lived; in-process
 * connectors (OpenCode, OpenClaw) run for hours, so the dynamic table is
 * bounded and evicts its oldest entry.
 */
import { currentLocale, DEFAULT_LOCALE, type Locale } from "./index.js";

/** Rule title -> Turkish title. Bounded by the size of the rule set. */
const ruleTitles = new Map<string, string>();
const MAX_RULE_TITLES = 10_000;

/** Raw reason -> plain wording per locale. */
const dynamicReasons = new Map<string, Readonly<Record<Locale, string>>>();
const MAX_DYNAMIC_REASONS = 256;

/** Rule id -> its English title, so a message can lead with the deciding rule's reason. */
const titlesById = new Map<string, string>();

/**
 * Record a loaded rule's title and, when it has one, its Turkish title
 * (threat loader). Empty translations are ignored.
 */
export function registerRuleTitle(id: string, title: string, titleTr?: string): void {
	if (!title) return;
	if (titlesById.size < MAX_RULE_TITLES || titlesById.has(id)) titlesById.set(id, title);
	if (typeof titleTr !== "string" || titleTr.trim() === "") return;
	if (!ruleTitles.has(title) && ruleTitles.size >= MAX_RULE_TITLES) return;
	ruleTitles.set(title, titleTr.trim());
}

/** The English title of a loaded rule, or undefined. */
export function ruleTitleById(id: string | null | undefined): string | undefined {
	return id ? titlesById.get(id) : undefined;
}

/**
 * Record the plain wording a person should read for a raw reason built at run
 * time. The raw text stays in the verdict and the audit log.
 */
export function registerReasonDisplay(raw: string, text: Readonly<Record<Locale, string>>): void {
	if (!raw) return;
	dynamicReasons.delete(raw);
	dynamicReasons.set(raw, text);
	while (dynamicReasons.size > MAX_DYNAMIC_REASONS) {
		const oldest = dynamicReasons.keys().next().value;
		if (oldest === undefined) break;
		dynamicReasons.delete(oldest);
	}
}

/** The reason a person reads, in the display locale; the raw text when nothing is registered. */
export function displayReason(raw: string, locale?: Locale): string {
	const resolved = locale ?? currentLocale();
	const dynamic = dynamicReasons.get(raw);
	if (dynamic) return dynamic[resolved] ?? dynamic[DEFAULT_LOCALE] ?? raw;
	if (resolved !== DEFAULT_LOCALE) return ruleTitles.get(raw) ?? raw;
	return raw;
}

type Labels = Readonly<Record<string, Readonly<Record<Locale, string>>>>;

/** Rule and verdict categories in plain words. */
const CATEGORY_LABELS: Labels = {
	tool: { en: "dangerous command or tool use", tr: "tehlikeli komut ya da araç kullanımı" },
	secrets: { en: "secrets and credentials", tr: "gizli bilgiler ve kimlik bilgileri" },
	credential_access: { en: "access to credentials", tr: "kimlik bilgilerine erişim" },
	reward_hacking: { en: "skipping checks or tests", tr: "denetimleri ya da testleri atlama" },
	resource_hijacking: {
		en: "misuse of computing resources",
		tr: "bilgi işlem kaynaklarının kötüye kullanımı",
	},
	defense_evasion: { en: "hiding from security tools", tr: "güvenlik araçlarından gizlenme" },
	irreversible_action: { en: "irreversible action", tr: "geri alınamaz işlem" },
	context_poisoning: {
		en: "tampering with agent instructions",
		tr: "yapay zekâ aracının talimatlarını değiştirme",
	},
	context_poisoning_hidden_unicode: {
		en: "hidden characters in agent instructions",
		tr: "yapay zekâ aracının talimatlarında gizli karakterler",
	},
	context_poisoning_permission_widening: {
		en: "widening agent permissions",
		tr: "yapay zekâ aracının izinlerini genişletme",
	},
	ai_supply_chain: {
		en: "unsafe AI model or code download",
		tr: "güvensiz yapay zekâ modeli ya da kod indirme",
	},
	supply_chain: { en: "software supply chain", tr: "yazılım tedarik zinciri" },
	persistence: {
		en: "staying on the computer after the session",
		tr: "oturumdan sonra bilgisayarda kalıcılık",
	},
	self_defense: {
		en: "tampering with Singularity AIDR",
		tr: "Singularity AIDR'yi devre dışı bırakma girişimi",
	},
	network_egress: { en: "sending data over the network", tr: "ağ üzerinden veri gönderme" },
	discovery: { en: "scanning the system", tr: "sistemi tarama" },
	reconnaissance: { en: "scanning the system", tr: "sistemi tarama" },
	autonomy_escalation: {
		en: "the agent giving itself more power",
		tr: "yapay zekâ aracının kendi yetkisini artırması",
	},
	privilege_escalation: { en: "gaining administrator rights", tr: "yönetici yetkisi elde etme" },
	script_content: { en: "dangerous code in a script", tr: "betikte tehlikeli kod" },
	prompt_injection: {
		en: "hidden instructions for the agent",
		tr: "yapay zekâ aracına gizli talimatlar",
	},
	indirect_prompt_injection: {
		en: "hidden instructions in content",
		tr: "içerikte gizli talimatlar",
	},
	prompt_extraction: {
		en: "extracting the agent's instructions",
		tr: "yapay zekâ aracının talimatlarını ele geçirme",
	},
	agent_sabotage: {
		en: "damaging the project's history or checks",
		tr: "projenin geçmişine ya da denetimlerine zarar verme",
	},
	tool_misuse: { en: "tool misuse", tr: "aracın kötüye kullanımı" },
	memory_poisoning: {
		en: "tampering with the agent's memory",
		tr: "yapay zekâ aracının belleğini değiştirme",
	},
	lateral_movement: { en: "moving to other machines", tr: "başka makinelere geçme" },
	exfiltration: { en: "data leaving the computer", tr: "verinin bilgisayardan çıkması" },
	collection: { en: "collecting data", tr: "veri toplama" },
	command_and_control: {
		en: "remote control of the computer",
		tr: "bilgisayarın uzaktan kontrolü",
	},
	execution: { en: "running code", tr: "kod çalıştırma" },
	information_disclosure: { en: "exposing information", tr: "bilgi ifşası" },
	content_safety: { en: "unsafe content", tr: "güvensiz içerik" },
	mcp_tool_poisoning: { en: "tampered MCP tool", tr: "değiştirilmiş MCP aracı" },
	malware: { en: "malware", tr: "kötü amaçlı yazılım" },
	dlp: { en: "sensitive data", tr: "hassas veri" },
	canary: { en: "decoy credential used", tr: "tuzak kimlik bilgisi kullanıldı" },
	reputation_not_checked: {
		en: "not checked by a reputation service",
		tr: "itibar hizmetiyle denetlenmedi",
	},
	agent_profile: { en: "agent permission profile", tr: "yapay zekâ aracı izin profili" },
	policy: { en: "organisation policy", tr: "kuruluş politikası" },
};

/** Category prefixes shared by many rule families. */
const CATEGORY_PREFIX_LABELS: Labels = {
	toxic_flow: { en: "risky combination in this session", tr: "bu oturumda riskli birleşim" },
	secure_code: { en: "insecure code being written", tr: "yazılan kodda güvenlik açığı" },
	skill: { en: "unsafe agent skill", tr: "güvensiz yapay zekâ aracı becerisi" },
};

/** Detection sources a person can make sense of; internal ones are not shown. */
const SOURCE_LABELS: Labels = {
	heuristic: { en: "threat rule", tr: "tehdit kuralı" },
	policy: { en: "organisation policy", tr: "kuruluş politikası" },
	agent_profile: { en: "agent permission profile", tr: "yapay zekâ aracı izin profili" },
	toxic_flow: { en: "session activity check", tr: "oturum etkinliği denetimi" },
	package_check: { en: "package check", tr: "paket denetimi" },
	url_check: { en: "URL reputation check", tr: "URL itibar denetimi" },
	dlp: { en: "sensitive data check", tr: "hassas veri denetimi" },
	canary: { en: "decoy credential check", tr: "tuzak kimlik bilgisi denetimi" },
	amsi: { en: "Windows antivirus scan (AMSI)", tr: "Windows virüs taraması (AMSI)" },
	intel: { en: "threat intelligence", tr: "tehdit istihbaratı" },
	context_poisoning: { en: "agent instruction check", tr: "yapay zekâ aracı talimat denetimi" },
	behavioral: { en: "unusual activity check", tr: "olağandışı etkinlik denetimi" },
	runaway_guard: { en: "runaway agent check", tr: "kontrolden çıkan yapay zekâ aracı denetimi" },
	secure_code: { en: "secure code check", tr: "güvenli kod denetimi" },
	integrity: { en: "installation integrity check", tr: "kurulum bütünlüğü denetimi" },
};

function lookup(labels: Labels, key: string, locale: Locale): string | undefined {
	const entry = labels[key];
	return entry ? (entry[locale] ?? entry[DEFAULT_LOCALE]) : undefined;
}

/**
 * A category in plain words. An unknown category is shown with spaces for
 * underscores rather than as an internal identifier.
 */
export function categoryLabel(category: string, locale?: Locale): string {
	const resolved = locale ?? currentLocale();
	const exact = lookup(CATEGORY_LABELS, category, resolved);
	if (exact) return exact;
	for (const prefix of Object.keys(CATEGORY_PREFIX_LABELS)) {
		if (
			category === prefix ||
			category.startsWith(`${prefix}_`) ||
			category.startsWith(`${prefix}:`)
		) {
			return lookup(CATEGORY_PREFIX_LABELS, prefix, resolved) ?? category;
		}
	}
	return category.replace(/[_:]+/g, " ").trim();
}

/**
 * A detection source in plain words, or null for an internal source that
 * means nothing to a person (cache markers, fallbacks, test sources).
 */
export function sourceLabel(source: string | undefined, locale?: Locale): string | null {
	if (!source) return null;
	const resolved = locale ?? currentLocale();
	const bare = source.replace(/^cache\((.*)\)$/, "$1");
	return lookup(SOURCE_LABELS, bare, resolved) ?? null;
}

/** Test hook: forget every registered translation. */
export function resetDisplayRegistryForTests(): void {
	ruleTitles.clear();
	titlesById.clear();
	dynamicReasons.clear();
}
