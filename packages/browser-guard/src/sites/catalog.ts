/**
 * Shadow AI catalog: well-known generative-AI services Browser Guard can recognise by
 * the host of a top-level page, so an administrator can see which of them are used
 * (counts only) and block the ones that are not sanctioned (managed key `shadowAi`).
 *
 * Only exact hostnames that serve the product itself are listed. Services that live on a
 * path of a general-purpose host (Notion AI on notion.so, GitHub Copilot on github.com,
 * Copilot in Bing on bing.com, Microsoft 365 Copilot on the Office host) are left out on
 * purpose: blocking or counting them by host would also hit the unrelated product. Where a
 * host also serves non-AI content (Hugging Face, DeepL, Grammarly) the entry says so.
 *
 * Ids are stable identifiers shared with the telemetry contract (`service_id`,
 * docs/contracts/privacy-telemetry.md), the ingest projection and the dashboard; the
 * built-in protected sites use their SiteId. Never rename an id: add a new one.
 *
 * Pure data + lookups: no DOM, no extension APIs (the background worker imports it).
 */
import type { AiServiceCategory } from "../types.js";

export interface AiService {
	/** `^[a-z0-9][a-z0-9-]{0,31}$`; stable. */
	readonly id: string;
	readonly name: string;
	readonly category: AiServiceCategory;
	/** Exact lowercase hostnames (HTTPS); subdomains of these are matched too. */
	readonly hosts: readonly string[];
}

export const AI_SERVICE_CATEGORIES: readonly AiServiceCategory[] = Object.freeze([
	"chat",
	"coding",
	"image",
	"meeting",
	"writing",
	"search",
	"agent",
]);

const service = (
	id: string,
	name: string,
	category: AiServiceCategory,
	hosts: readonly string[],
): AiService => Object.freeze({ id, name, category, hosts: Object.freeze([...hosts]) });

export const AI_SERVICES: readonly AiService[] = Object.freeze([
	// Built-in protected sites (ids equal their SiteId; masking runs there by default).
	service("chatgpt", "ChatGPT", "chat", ["chatgpt.com", "chat.openai.com"]),
	service("gemini", "Google Gemini", "chat", ["gemini.google.com"]),
	service("claude", "Claude", "chat", ["claude.ai"]),
	service("copilot", "Microsoft Copilot", "chat", ["copilot.microsoft.com"]),
	service("perplexity", "Perplexity", "search", ["www.perplexity.ai", "perplexity.ai"]),
	service("deepseek", "DeepSeek", "chat", ["chat.deepseek.com"]),
	service("mistral", "Mistral Le Chat", "chat", ["chat.mistral.ai"]),
	service("grok", "Grok", "chat", ["grok.com"]),
	// Chat assistants.
	service("poe", "Poe", "chat", ["poe.com"]),
	service("character-ai", "Character.AI", "chat", ["character.ai"]),
	// The whole Hugging Face hub: HuggingChat is a path of huggingface.co.
	service("huggingface", "Hugging Face (HuggingChat)", "chat", ["huggingface.co"]),
	service("meta-ai", "Meta AI", "chat", ["www.meta.ai", "meta.ai"]),
	service("pi", "Pi", "chat", ["pi.ai"]),
	service("duck-ai", "Duck.ai", "chat", ["duck.ai"]),
	service("kimi", "Kimi", "chat", ["kimi.com", "www.kimi.com", "kimi.moonshot.cn"]),
	service("qwen", "Qwen Chat (Tongyi)", "chat", [
		"chat.qwen.ai",
		"tongyi.aliyun.com",
		"www.tongyi.com",
	]),
	service("doubao", "Doubao", "chat", ["www.doubao.com"]),
	service("ernie", "ERNIE Bot (Wenxin Yiyan)", "chat", ["yiyan.baidu.com"]),
	service("chatglm", "ChatGLM / Z.ai", "chat", ["chatglm.cn", "chat.z.ai"]),
	service("yuanbao", "Tencent Yuanbao", "chat", ["yuanbao.tencent.com"]),
	service("cohere", "Cohere Chat", "chat", ["coral.cohere.com"]),
	service("groq", "GroqChat", "chat", ["groq.com", "console.groq.com"]),
	service("openrouter", "OpenRouter", "chat", ["openrouter.ai"]),
	service("together", "Together AI Playground", "chat", ["api.together.ai", "api.together.xyz"]),
	service("lmarena", "LMArena", "chat", ["lmarena.ai", "chat.lmsys.org"]),
	service("monica", "Monica", "chat", ["monica.im"]),
	service("replika", "Replika", "chat", ["my.replika.com"]),
	service("chatpdf", "ChatPDF", "chat", ["www.chatpdf.com", "chatpdf.com"]),
	service("notebooklm", "NotebookLM", "chat", ["notebooklm.google.com"]),
	// Search and research.
	service("you", "You.com", "search", ["you.com"]),
	service("consensus", "Consensus", "search", ["consensus.app"]),
	service("elicit", "Elicit", "search", ["elicit.com"]),
	// Coding assistants, app builders and model consoles.
	service("phind", "Phind", "coding", ["www.phind.com", "phind.com"]),
	service("ai-studio", "Google AI Studio", "coding", ["aistudio.google.com"]),
	service("openai-platform", "OpenAI Platform", "coding", ["platform.openai.com"]),
	service("anthropic-console", "Anthropic Console", "coding", ["console.anthropic.com"]),
	service("azure-ai-foundry", "Azure AI Foundry", "coding", ["ai.azure.com"]),
	service("cursor", "Cursor (web)", "coding", ["cursor.com", "www.cursor.com"]),
	service("v0", "v0 by Vercel", "coding", ["v0.dev", "v0.app"]),
	service("bolt", "Bolt.new", "coding", ["bolt.new"]),
	service("lovable", "Lovable", "coding", ["lovable.dev"]),
	service("replit", "Replit", "coding", ["replit.com"]),
	service("windsurf", "Windsurf (Codeium)", "coding", ["windsurf.com", "codeium.com"]),
	service("tabnine", "Tabnine", "coding", ["www.tabnine.com", "tabnine.com"]),
	service("blackbox", "Blackbox AI", "coding", ["www.blackbox.ai", "blackbox.ai"]),
	// Autonomous agents.
	service("devin", "Devin", "agent", ["app.devin.ai"]),
	service("manus", "Manus", "agent", ["manus.im"]),
	service("genspark", "Genspark", "agent", ["www.genspark.ai", "genspark.ai"]),
	// Writing, translation and presentations.
	service("jasper", "Jasper", "writing", ["www.jasper.ai", "app.jasper.ai"]),
	service("writesonic", "Writesonic (Chatsonic)", "writing", [
		"writesonic.com",
		"app.writesonic.com",
	]),
	service("copy-ai", "Copy.ai", "writing", ["www.copy.ai", "app.copy.ai"]),
	service("quillbot", "QuillBot", "writing", ["quillbot.com"]),
	// Also DeepL's translator (text is processed by DeepL's models either way).
	service("deepl", "DeepL (Translator, Write)", "writing", ["www.deepl.com", "deepl.com"]),
	// Also Grammarly's marketing site.
	service("grammarly", "Grammarly", "writing", ["app.grammarly.com", "www.grammarly.com"]),
	service("wordtune", "Wordtune", "writing", ["www.wordtune.com", "app.wordtune.com"]),
	service("rytr", "Rytr", "writing", ["rytr.me", "app.rytr.me"]),
	service("gamma", "Gamma", "writing", ["gamma.app"]),
	service("tome", "Tome", "writing", ["tome.app"]),
	service("beautiful-ai", "Beautiful.ai", "writing", ["www.beautiful.ai"]),
	// Image, video, voice and music generation.
	service("midjourney", "Midjourney", "image", ["www.midjourney.com", "midjourney.com"]),
	service("leonardo", "Leonardo.Ai", "image", ["leonardo.ai", "app.leonardo.ai"]),
	service("ideogram", "Ideogram", "image", ["ideogram.ai"]),
	service("runway", "Runway", "image", ["runwayml.com", "app.runwayml.com"]),
	service("elevenlabs", "ElevenLabs", "image", ["elevenlabs.io"]),
	service("suno", "Suno", "image", ["suno.com"]),
	service("pika", "Pika", "image", ["pika.art"]),
	service("krea", "Krea", "image", ["www.krea.ai", "krea.ai"]),
	service("firefly", "Adobe Firefly", "image", ["firefly.adobe.com"]),
	service("heygen", "HeyGen", "image", ["app.heygen.com"]),
	service("synthesia", "Synthesia", "image", ["app.synthesia.io"]),
	// Meeting assistants (recordings and transcripts leave the organisation).
	service("otter", "Otter.ai", "meeting", ["otter.ai"]),
	service("fireflies", "Fireflies.ai", "meeting", ["app.fireflies.ai", "fireflies.ai"]),
	service("tldv", "tl;dv", "meeting", ["tldv.io"]),
	service("fathom", "Fathom", "meeting", ["fathom.video"]),
	service("read-ai", "Read AI", "meeting", ["app.read.ai"]),
]);

/** Every catalog id, in catalog order. */
export const AI_SERVICE_IDS: readonly string[] = Object.freeze(AI_SERVICES.map((s) => s.id));

export const AI_SERVICE_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;

const BY_ID: ReadonlyMap<string, AiService> = new Map(AI_SERVICES.map((s) => [s.id, s]));
const BY_HOST: ReadonlyMap<string, AiService> = new Map(
	AI_SERVICES.flatMap((s) => s.hosts.map((h) => [h, s] as const)),
);

export function serviceById(id: unknown): AiService | null {
	return typeof id === "string" ? (BY_ID.get(id) ?? null) : null;
}

export function isAiServiceId(id: unknown): id is string {
	return typeof id === "string" && BY_ID.has(id);
}

/**
 * Service serving `hostname`: an exact catalog host, else the longest catalog host it is
 * a subdomain of (the same scope a declarativeNetRequest `requestDomains` rule covers).
 */
export function serviceForHost(hostname: unknown): AiService | null {
	if (typeof hostname !== "string" || hostname.length === 0 || hostname.length > 253) return null;
	const host = hostname.toLowerCase().replace(/\.$/, "");
	const exact = BY_HOST.get(host);
	if (exact) return exact;
	for (let dot = host.indexOf("."); dot >= 0; dot = host.indexOf(".", dot + 1)) {
		const parent = BY_HOST.get(host.slice(dot + 1));
		if (parent) return parent;
	}
	return null;
}

/** Service for a top-level http(s) page URL, or null (other schemes are never matched). */
export function serviceForUrl(url: unknown): AiService | null {
	if (typeof url !== "string" || url.length > 8192) return null;
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return null;
	}
	if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;
	return serviceForHost(parsed.hostname);
}

/** `https://<host>/*` host-permission patterns for the given services (deduplicated). */
export function serviceOrigins(services: readonly AiService[]): string[] {
	return [...new Set(services.flatMap((s) => s.hosts.map((h) => `https://${h}/*`)))];
}
