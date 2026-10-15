// Transactional mail for Edge Functions.
//
// The mailer is injectable: a handler receives a `Mailer` through its deps and
// falls back to `createMailer(runtimeEnv)` in production. Three providers exist:
//
//   - "resend": HTTPS POST to the Resend API. Requires RESEND_API_KEY and
//     AIDR_MAIL_FROM. Selected explicitly with AIDR_MAIL_PROVIDER=resend, or
//     implicitly when both variables are configured and no provider is named.
//   - "smtp": the organisation's own mail relay (on-prem, air-gapped). Reuses
//     the deployment's SMTP_* settings (the same relay Auth uses for password
//     recovery): SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_ADMIN_EMAIL,
//     SMTP_SENDER_NAME, plus AIDR_SMTP_SECURITY (starttls | tls | none) and
//     AIDR_SMTP_CA_PEM_B64 (base64 of a PEM bundle for an internal CA).
//     Selected explicitly with AIDR_MAIL_PROVIDER=smtp, or implicitly when
//     SMTP_HOST is set, no provider is named and no Resend key is configured.
//   - "none": no transport. Every send reports `not_configured`, so a caller
//     must fall back to a manual delivery path and must never claim delivery.
//
// A half-configured deployment (a key without a sender, an explicit "resend"
// without credentials, an unknown provider name, SMTP credentials over a
// plaintext session) is logged by variable NAME and degrades to "none": mail
// is a convenience channel, never a security control, and every caller
// already has a manual path.
//
// Nothing here logs a recipient, a subject, a body or a credential. Message
// bodies routinely carry single-use secrets (invitation links); the only
// operator-visible detail of a failed send is the provider's HTTP status or
// the SMTP stage and reply code.

import {
	ConfigurationError,
	type EnvReader,
	isConfiguredValue,
	logConfigFailure,
	readConfigValue,
} from "./config.ts";
import { type SmtpSecurity, type SmtpSettings, sendSmtpMessage } from "./smtp.ts";
import { denoSocketTransport, pemCertificates, type SocketTransport } from "./socket-transport.ts";

export const RESEND_API_URL = "https://api.resend.com/emails";
const DEFAULT_TIMEOUT_MS = 10_000;
const SMTP_TIMEOUT_MS = 30_000;
const ADDRESS = /^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/;
/** "Name <address>" or a bare address; no line breaks or control characters. */
const SENDER = /^(?:[^<>\p{Cc}]{1,120} <[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+>|[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+)$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:/-]{1,256}$/;
const ATTACHMENT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const ATTACHMENT_TYPES = new Set(["text/html", "application/pdf"]);
const ATTACHMENT_MAX = 3;
/** Base64 characters per attachment (about 2 MB of content). */
const ATTACHMENT_MAX_BASE64 = 2_800_000;

type MailProvider = "resend" | "smtp" | "none";

export interface MailMessage {
	to: string;
	subject: string;
	html: string;
	text: string;
	/** Provider-side de-duplication key. Must not contain a secret. */
	idempotencyKey?: string;
	/** Optional files (for example the printable executive report). */
	attachments?: MailAttachment[];
}

export interface MailAttachment {
	filename: string;
	contentType: "text/html" | "application/pdf";
	/** Base64 of the file bytes. */
	contentBase64: string;
}

export type MailResult =
	| { ok: true; provider: "resend" | "smtp"; messageId: string }
	| { ok: false; reason: "not_configured" | "invalid_message" | "rejected" | "unavailable" };

export interface Mailer {
	readonly provider: MailProvider;
	send(message: MailMessage): Promise<MailResult>;
}

export interface MailerDeps {
	fetch?: typeof fetch;
	timeoutMs?: number;
	/** Socket transport for the SMTP provider (tests substitute node:net/node:tls). */
	transport?: SocketTransport;
}

/** The mailer used when no transport is configured. It never sends. */
export const noMailer: Mailer = Object.freeze({
	provider: "none" as const,
	send: async (): Promise<MailResult> => ({ ok: false, reason: "not_configured" }),
});

export function isMailAddress(value: string): boolean {
	return value.length <= 254 && ADDRESS.test(value);
}

export function isMailSender(value: string): boolean {
	return value.length <= 320 && SENDER.test(value);
}

function validMessage(message: MailMessage): boolean {
	return (
		isMailAddress(message.to) &&
		typeof message.subject === "string" &&
		message.subject.trim() !== "" &&
		message.subject.length <= 200 &&
		!/[\r\n]/.test(message.subject) &&
		typeof message.html === "string" &&
		message.html !== "" &&
		typeof message.text === "string" &&
		message.text !== "" &&
		(message.idempotencyKey === undefined || IDEMPOTENCY_KEY.test(message.idempotencyKey)) &&
		validAttachments(message.attachments)
	);
}

function validAttachments(attachments: MailAttachment[] | undefined): boolean {
	if (attachments === undefined) return true;
	return (
		Array.isArray(attachments) &&
		attachments.length <= ATTACHMENT_MAX &&
		attachments.every(
			(item) =>
				typeof item?.filename === "string" &&
				ATTACHMENT_NAME.test(item.filename) &&
				ATTACHMENT_TYPES.has(item.contentType) &&
				typeof item.contentBase64 === "string" &&
				item.contentBase64.length > 0 &&
				item.contentBase64.length <= ATTACHMENT_MAX_BASE64 &&
				/^[A-Za-z0-9+/]+={0,2}$/.test(item.contentBase64),
		)
	);
}

/** Resend transport. Credentials are closed over and never logged. */
export function createResendMailer(apiKey: string, from: string, deps: MailerDeps = {}): Mailer {
	const send = deps.fetch ?? fetch;
	const timeoutMs = deps.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	return {
		provider: "resend",
		async send(message) {
			if (!validMessage(message)) return { ok: false, reason: "invalid_message" };
			const headers: Record<string, string> = {
				Authorization: `Bearer ${apiKey}`,
				"Content-Type": "application/json",
			};
			if (message.idempotencyKey) headers["Idempotency-Key"] = message.idempotencyKey;
			let response: Response;
			try {
				response = await send(RESEND_API_URL, {
					method: "POST",
					headers,
					body: JSON.stringify({
						from,
						to: [message.to],
						subject: message.subject,
						html: message.html,
						text: message.text,
						...(message.attachments && message.attachments.length > 0
							? {
									attachments: message.attachments.map((item) => ({
										filename: item.filename,
										content: item.contentBase64,
										content_type: item.contentType,
									})),
								}
							: {}),
					}),
					signal: AbortSignal.timeout(timeoutMs),
				});
			} catch {
				console.error("[mailer] resend request failed before a response");
				return { ok: false, reason: "unavailable" };
			}
			let body: unknown = null;
			try {
				body = await response.json();
			} catch {
				body = null;
			}
			if (!response.ok) {
				console.error("[mailer] resend rejected message", JSON.stringify({ status: response.status }));
				return { ok: false, reason: response.status >= 500 || response.status === 429 ? "unavailable" : "rejected" };
			}
			const id = body && typeof body === "object" ? (body as { id?: unknown }).id : undefined;
			if (typeof id !== "string" || id === "") {
				// A 2xx without a message id is not proof of acceptance.
				console.error("[mailer] resend accepted response without a message id");
				return { ok: false, reason: "unavailable" };
			}
			return { ok: true, provider: "resend", messageId: id };
		},
	};
}

/** SMTP transport. Credentials are closed over and never logged. */
export function createSmtpMailer(settings: SmtpSettings, deps: MailerDeps = {}): Mailer {
	const transport = deps.transport ?? denoSocketTransport;
	return {
		provider: "smtp",
		async send(message) {
			if (!validMessage(message)) return { ok: false, reason: "invalid_message" };
			const outcome = await sendSmtpMessage(
				settings,
				{
					to: message.to,
					subject: message.subject,
					text: message.text,
					html: message.html,
					// Stable per idempotency key, so a retried alert carries the same Message-ID.
					messageIdSeed: message.idempotencyKey ?? crypto.randomUUID(),
					...(message.attachments && message.attachments.length > 0
						? { attachments: message.attachments }
						: {}),
				},
				transport,
			);
			if (outcome.ok) return { ok: true, provider: "smtp", messageId: outcome.messageId };
			console.error("[mailer] smtp delivery failed", JSON.stringify({ stage: outcome.stage, code: outcome.code }));
			return { ok: false, reason: outcome.reason };
		},
	};
}

const SMTP_HOST_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const SMTP_HOST_IP = /^[0-9A-Fa-f:.]{2,45}$/;
const SMTP_SECURITIES: readonly SmtpSecurity[] = ["starttls", "tls", "none"];

function decodeCaBundle(value: string): string[] | null {
	try {
		const certificates = pemCertificates(atob(value.replace(/\s+/g, "")));
		return certificates.length > 0 && certificates.length <= 32 ? certificates : null;
	} catch {
		return null;
	}
}

/**
 * SMTP settings from the deployment's SMTP_* variables. Returns null after
 * logging, by variable name, what is missing or invalid.
 */
export function readSmtpSettings(env: EnvReader, timeoutMs = SMTP_TIMEOUT_MS): SmtpSettings | null {
	const host = readConfigValue(env, "SMTP_HOST").trim().replace(/^\[|\]$/g, "").replace(/\.$/, "");
	const portText = readConfigValue(env, "SMTP_PORT").trim();
	const securityText = readConfigValue(env, "AIDR_SMTP_SECURITY").trim().toLowerCase();
	const username = readConfigValue(env, "SMTP_USER").trim();
	const password = readConfigValue(env, "SMTP_PASS");
	const caText = readConfigValue(env, "AIDR_SMTP_CA_PEM_B64").trim();
	const explicitFrom = readConfigValue(env, "AIDR_MAIL_FROM").trim();
	const adminEmail = readConfigValue(env, "SMTP_ADMIN_EMAIL").trim();
	const senderName = readConfigValue(env, "SMTP_SENDER_NAME").trim();
	const missing: string[] = [];
	const invalid = new Set<string>();

	if (host === "") missing.push("SMTP_HOST");
	else if (host.length > 253 || !(SMTP_HOST_NAME.test(host) || (host.includes(":") || /^[0-9.]+$/.test(host)) && SMTP_HOST_IP.test(host))) {
		invalid.add("SMTP_HOST");
	}
	const port = portText === "" ? null : /^[0-9]{1,5}$/.test(portText) ? Number(portText) : Number.NaN;
	if (port !== null && !(port >= 1 && port <= 65_535)) invalid.add("SMTP_PORT");
	let security: SmtpSecurity = port === 465 ? "tls" : "starttls";
	if (securityText !== "") {
		if (SMTP_SECURITIES.includes(securityText as SmtpSecurity)) security = securityText as SmtpSecurity;
		else invalid.add("AIDR_SMTP_SECURITY");
	}
	// Credentials and a pinned CA only make sense on an encrypted session.
	if (security === "none" && username !== "") invalid.add("AIDR_SMTP_SECURITY");
	if (username === "" && isConfiguredValue(password)) missing.push("SMTP_USER");
	const caCerts = caText === "" ? undefined : decodeCaBundle(caText);
	if (caCerts === null || (caCerts && security === "none")) invalid.add("AIDR_SMTP_CA_PEM_B64");

	let from = explicitFrom;
	if (from === "") {
		if (adminEmail === "") missing.push("SMTP_ADMIN_EMAIL");
		else from = senderName !== "" && !/[<>"\p{Cc}]/u.test(senderName) ? `${senderName} <${adminEmail}>` : adminEmail;
	}
	if (from !== "" && !isMailSender(from)) invalid.add(explicitFrom === "" ? "SMTP_ADMIN_EMAIL" : "AIDR_MAIL_FROM");

	if (missing.length > 0 || invalid.size > 0) {
		logConfigFailure("mailer", new ConfigurationError({ missing, invalid: [...invalid] }));
		return null;
	}
	const envelopeFrom = /<([^<>]+)>$/.exec(from)?.[1] ?? from;
	return {
		host,
		port: port ?? (security === "tls" ? 465 : security === "starttls" ? 587 : 25),
		security,
		...(username !== "" ? { username, password } : {}),
		from,
		envelopeFrom,
		heloName: envelopeFrom.slice(envelopeFrom.lastIndexOf("@") + 1).toLowerCase(),
		...(caCerts ? { caCerts } : {}),
		timeoutMs,
	};
}

/**
 * Build the deployment's mailer from configuration. Never throws; a
 * misconfiguration is logged by variable name and yields `noMailer`.
 */
export function createMailer(env: EnvReader, deps: MailerDeps = {}): Mailer {
	const provider = readConfigValue(env, "AIDR_MAIL_PROVIDER").trim().toLowerCase();
	const apiKey = readConfigValue(env, "RESEND_API_KEY");
	const from = readConfigValue(env, "AIDR_MAIL_FROM").trim();
	if (provider === "none") return noMailer;
	if (provider !== "" && provider !== "resend" && provider !== "smtp") {
		logConfigFailure("mailer", new ConfigurationError({ invalid: ["AIDR_MAIL_PROVIDER"] }));
		return noMailer;
	}
	const hasKey = isConfiguredValue(apiKey);
	const hasFrom = isConfiguredValue(from);
	if (provider === "smtp" || (provider === "" && !hasKey && isConfiguredValue(readConfigValue(env, "SMTP_HOST")))) {
		const settings = readSmtpSettings(env, deps.timeoutMs ?? SMTP_TIMEOUT_MS);
		return settings ? createSmtpMailer(settings, deps) : noMailer;
	}
	if (!hasKey && !hasFrom) {
		if (provider === "resend") {
			logConfigFailure("mailer", new ConfigurationError({ missing: ["RESEND_API_KEY", "AIDR_MAIL_FROM"] }));
		}
		return noMailer;
	}
	if (!hasKey || !hasFrom) {
		logConfigFailure("mailer", new ConfigurationError({ missing: [hasKey ? "AIDR_MAIL_FROM" : "RESEND_API_KEY"] }));
		return noMailer;
	}
	if (!isMailSender(from)) {
		logConfigFailure("mailer", new ConfigurationError({ invalid: ["AIDR_MAIL_FROM"] }));
		return noMailer;
	}
	return createResendMailer(apiKey.trim(), from, deps);
}

/** Minimal HTML escaping for text interpolated into a mail template. */
export function escapeHtml(value: string): string {
	return value
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}
