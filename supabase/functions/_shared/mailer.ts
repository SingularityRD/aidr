// Transactional mail for Edge Functions.
//
// The mailer is injectable: a handler receives a `Mailer` through its deps and
// falls back to `createMailer(runtimeEnv)` in production. Two providers exist:
//
//   - "resend": HTTPS POST to the Resend API. Requires RESEND_API_KEY and
//     AIDR_MAIL_FROM. Selected explicitly with AIDR_MAIL_PROVIDER=resend, or
//     implicitly when both variables are configured and no provider is named.
//   - "none": no transport. Every send reports `not_configured`, so a caller
//     must fall back to a manual delivery path and must never claim delivery.
//
// A half-configured deployment (a key without a sender, an explicit "resend"
// without credentials, an unknown provider name) is logged by variable NAME
// and degrades to "none": invitation mail is a convenience channel, never a
// security control, and the caller already has a manual path.
//
// Nothing here logs a recipient, a subject, a body or a credential. Message
// bodies routinely carry single-use secrets (invitation links); the only
// operator-visible detail of a failed send is the provider's HTTP status.

import {
	ConfigurationError,
	type EnvReader,
	isConfiguredValue,
	logConfigFailure,
	readConfigValue,
} from "./config.ts";

export const RESEND_API_URL = "https://api.resend.com/emails";
const DEFAULT_TIMEOUT_MS = 10_000;
const ADDRESS = /^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/;
/** "Name <address>" or a bare address; no line breaks or control characters. */
const SENDER = /^(?:[^<>\p{Cc}]{1,120} <[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+>|[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+)$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:/-]{1,256}$/;

export type MailProvider = "resend" | "none";

export interface MailMessage {
	to: string;
	subject: string;
	html: string;
	text: string;
	/** Provider-side de-duplication key. Must not contain a secret. */
	idempotencyKey?: string;
}

export type MailResult =
	| { ok: true; provider: "resend"; messageId: string }
	| { ok: false; reason: "not_configured" | "invalid_message" | "rejected" | "unavailable" };

export interface Mailer {
	readonly provider: MailProvider;
	send(message: MailMessage): Promise<MailResult>;
}

export interface MailerDeps {
	fetch?: typeof fetch;
	timeoutMs?: number;
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
		(message.idempotencyKey === undefined || IDEMPOTENCY_KEY.test(message.idempotencyKey))
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

/**
 * Build the deployment's mailer from configuration. Never throws; a
 * misconfiguration is logged by variable name and yields `noMailer`.
 */
export function createMailer(env: EnvReader, deps: MailerDeps = {}): Mailer {
	const provider = readConfigValue(env, "AIDR_MAIL_PROVIDER").trim().toLowerCase();
	const apiKey = readConfigValue(env, "RESEND_API_KEY");
	const from = readConfigValue(env, "AIDR_MAIL_FROM").trim();
	if (provider === "none") return noMailer;
	if (provider !== "" && provider !== "resend") {
		logConfigFailure("mailer", new ConfigurationError({ invalid: ["AIDR_MAIL_PROVIDER"] }));
		return noMailer;
	}
	const hasKey = isConfiguredValue(apiKey);
	const hasFrom = isConfiguredValue(from);
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
