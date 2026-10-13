/**
 * Plain-language wording (EN/TR) for a toxic-flow finding.
 *
 * The verdict and the audit log keep the technical reason (`Toxic flow
 * "exfil_chain": … Earlier steps: [private data] Read: …`), which an analyst
 * needs. A person at the agent sees this instead: what the session did, what
 * this call adds, and why the combination matters, without chain names or
 * capability tags. Built only from the redacted step summaries the record
 * already holds (hosts, rule labels), never from raw tool input.
 */

import type { Locale } from "./i18n/index.js";
import type { FlowCapability, FlowKind } from "./toxic-flow-classify.js";

type Plain = Record<Locale, string>;

/** The fields of a recorded step or a current observation this wording uses. */
interface PlainFlowItem {
	cap: FlowCapability;
	kind: FlowKind;
	summary: string;
}

export interface PlainToxicFlowInput {
	chain: "lethal_trifecta" | "exfil_chain" | "injection_to_action" | "bulk_sensitive_access";
	earlier: readonly PlainFlowItem[];
	current: readonly PlainFlowItem[];
	/** injection_to_action: the destructive command label. */
	destructive?: string;
	/** bulk_sensitive_access: distinct targets, window and threshold. */
	bulk?: { count: number; minutes: number; threshold: number };
	integrityLost: boolean;
}

/** Turkish names for the sensitive-data labels in threats/flow/capabilities.yaml. */
const SENSITIVE_LABELS_TR: Readonly<Record<string, string>> = {
	"SSH private key": "SSH özel anahtarı",
	"cloud credentials": "bulut kimlik bilgileri",
	"environment secrets file": "ortam gizli bilgi dosyası",
	"credential file": "kimlik bilgisi dosyası",
	"registry credentials": "paket deposu kimlik bilgileri",
	"cluster credentials": "küme kimlik bilgileri",
	"GitHub CLI token": "GitHub CLI belirteci",
	"private keyring": "özel anahtarlık",
	"key material": "anahtar malzemesi",
	"secret store": "gizli bilgi deposu",
	"system password store": "sistem parola deposu",
	"browser credential store": "tarayıcı parola deposu",
	"OS keychain": "işletim sistemi anahtar zinciri",
	"crypto wallet": "kripto cüzdanı",
	"shell history": "kabuk geçmişi",
	"database dump": "veritabanı dökümü",
	"environment dump": "ortam değişkenleri dökümü",
	"process environment": "süreç ortam değişkenleri",
	"keychain read": "anahtar zinciri okuma",
	"private key export": "özel anahtar dışa aktarma",
	"cloud secret read": "bulut gizli bilgisi okuma",
	"cloud token read": "bulut belirteci okuma",
	"GitHub token read": "GitHub belirteci okuma",
	"git credential read": "git kimlik bilgisi okuma",
	"cluster secret read": "küme gizli bilgisi okuma",
	"vault secret read": "kasa gizli bilgisi okuma",
	"password manager read": "parola yöneticisi okuma",
	"secret material in tool output": "araç çıktısında gizli bilgi",
	"personal data in tool output": "araç çıktısında kişisel veri",
};

function hostOf(summary: string): string | null {
	return /[←→]\s*([^\s()]+)/u.exec(summary)?.[1] ?? null;
}

/** The rule label of a private-data summary (`reads ~/.ssh/id_rsa (SSH private key)`). */
function sensitiveLabel(item: PlainFlowItem): string {
	if (item.kind === "downloaded_file") return "";
	const trailing = /\(([^()]+)\)\s*$/u.exec(item.summary)?.[1];
	return (trailing ?? item.summary).trim();
}

function labelIn(label: string, locale: Locale): string {
	return locale === "tr" ? (SENSITIVE_LABELS_TR[label] ?? label) : label;
}

/** Past ("earlier in the session") and present ("this call") wording per step shape; `{x}` is the host or label. */
const PHRASES: Readonly<Record<string, Readonly<Record<Locale, readonly [string, string]>>>> = {
	download: {
		en: [
			"read a file downloaded in this session",
			"is now reading a file downloaded in this session",
		],
		tr: [
			"bu oturumda indirilen bir dosyayı okudu",
			"şimdi bu oturumda indirilen bir dosyayı okuyor",
		],
	},
	contentFrom: {
		en: ["read content from {x}", "is now reading content from {x}"],
		tr: ["{x} adresinden içerik aldı", "şimdi {x} adresinden içerik alıyor"],
	},
	untrusted: {
		en: ["read untrusted content", "is now reading untrusted content"],
		tr: ["güvenilmeyen içerik okudu", "şimdi güvenilmeyen içerik okuyor"],
	},
	sendTo: {
		en: ["can send data out", "is now sending data to {x}"],
		tr: ["dışarı veri gönderebiliyor", "şimdi {x} adresine veri gönderiyor"],
	},
	send: {
		en: ["can send data out", "is now sending data out"],
		tr: ["dışarı veri gönderebiliyor", "şimdi dışarı veri gönderiyor"],
	},
	sensitive: {
		en: ["read sensitive data{x}", "is now reading sensitive data{x}"],
		tr: ["hassas bir veriye erişti{x}", "şimdi hassas bir veriye erişiyor{x}"],
	},
};

/** Which phrase a step uses, and the value for `{x}`. */
function phraseKey(item: PlainFlowItem, locale: Locale): { key: string; x: string } {
	const host = hostOf(item.summary);
	if (item.cap === "untrusted_content") {
		if (item.kind === "downloaded_file") return { key: "download", x: "" };
		return host ? { key: "contentFrom", x: host } : { key: "untrusted", x: "" };
	}
	if (item.cap === "external_comm")
		return host ? { key: "sendTo", x: host } : { key: "send", x: "" };
	const label = labelIn(sensitiveLabel(item), locale);
	return { key: "sensitive", x: label ? ` (${label})` : "" };
}

function phrase(item: PlainFlowItem, now: boolean, locale: Locale): string | null {
	if (item.kind === "integrity_lost") return null;
	const { key, x } = phraseKey(item, locale);
	const forms = PHRASES[key]?.[locale];
	return forms ? forms[now ? 1 : 0].replace("{x}", x) : null;
}

function joinList(items: string[], locale: Locale): string {
	if (items.length <= 1) return items.join("");
	const last = items[items.length - 1];
	return `${items.slice(0, -1).join(", ")} ${locale === "tr" ? "ve" : "and"} ${last}`;
}

const CONCLUSION: Record<Exclude<PlainToxicFlowInput["chain"], "bulk_sensitive_access">, Plain> = {
	lethal_trifecta: {
		en: "Together these could leak your data.",
		tr: "Bunlar birlikte verilerinizin sızmasına yol açabilir.",
	},
	exfil_chain: {
		en: "Together these could leak the secret.",
		tr: "Bunlar birlikte gizli bilginin sızmasına yol açabilir.",
	},
	injection_to_action: {
		en: "Instructions hidden in that content may be steering the agent.",
		tr: "Bu içerikteki gizli talimatlar yapay zekâ aracını yönlendiriyor olabilir.",
	},
};

const INTEGRITY_NOTE: Plain = {
	en: "This session's earlier activity record failed its integrity check, so Singularity AIDR assumes the worst.",
	tr: "Bu oturumun önceki etkinlik kaydı bütünlük denetiminden geçemediği için Singularity AIDR en kötü durumu varsayıyor.",
};

function sentence(input: PlainToxicFlowInput, locale: Locale): string {
	const tr = locale === "tr";
	if (input.chain === "bulk_sensitive_access" && input.bulk) {
		const { count, minutes, threshold } = input.bulk;
		return tr
			? `Yapay zekâ aracı ${minutes} dakika içinde ${count} farklı hassas dosyaya ya da kimlik bilgisi deposuna erişti (sınır ${threshold}).`
			: `The agent accessed ${count} different sensitive files or credential stores within ${minutes} minutes (limit ${threshold}).`;
	}
	const phrases = [
		...input.earlier.map((item) => phrase(item, false, locale)),
		...input.current.map((item) => phrase(item, true, locale)),
	].filter((text): text is string => text !== null);
	if (input.destructive) {
		phrases.push(
			tr
				? `şimdi yıkıcı bir komut çalıştırmak istiyor (${input.destructive})`
				: `now wants to run a destructive command (${input.destructive})`,
		);
	}
	const unique = [...new Set(phrases)];
	const head =
		unique.length > 0
			? tr
				? `Bu oturumda riskli birleşim: yapay zekâ aracı ${joinList(unique, locale)}.`
				: `Risky combination in this session: the agent ${joinList(unique, locale)}.`
			: tr
				? "Bu oturumda riskli bir işlem birleşimi var."
				: "Risky combination of actions in this session.";
	const chain = input.chain === "bulk_sensitive_access" ? null : CONCLUSION[input.chain];
	return chain ? `${head} ${chain[locale]}` : head;
}

/** The finding in plain words, per display locale. */
export function plainToxicFlowReason(input: PlainToxicFlowInput): Plain {
	const result = {} as Plain;
	for (const locale of ["en", "tr"] as const) {
		const text = sentence(input, locale);
		result[locale] = input.integrityLost ? `${text} ${INTEGRITY_NOTE[locale]}` : text;
	}
	return result;
}
