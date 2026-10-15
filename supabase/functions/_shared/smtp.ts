// Minimal SMTP submission client (RFC 5321) for on-prem mail relays.
//
// Air-gapped and public-sector installations cannot reach a US mail API; they
// relay through the organisation's own SMTP server, usually with a certificate
// issued by an internal CA. This client speaks exactly what that needs:
//
//   * `starttls` (default, port 587/25): EHLO, STARTTLS, EHLO again. A server
//     that does not offer STARTTLS is refused, never silently downgraded.
//   * `tls` (implicit TLS, port 465): TLS from the first byte.
//   * `none`: plaintext, for a loopback or sealed relay. Credentials are never
//     sent over it (`createSmtpMailer` refuses that configuration).
//
// Certificates are always verified: against the system roots, or only against
// the operator's CA bundle when one is configured. AUTH PLAIN or LOGIN is used
// when credentials are configured. 4xx replies and network failures are
// reported as `unavailable` (the caller retries), 5xx as `rejected`.
//
// Nothing here logs a recipient, subject, body or credential; a failure is
// reported to the caller as a stage name plus the numeric reply code.

import { type SocketTransport, type StreamConnection, StreamReader, withTimeout } from "./socket-transport.ts";

export type SmtpSecurity = "starttls" | "tls" | "none";

export interface SmtpSettings {
	host: string;
	port: number;
	security: SmtpSecurity;
	username?: string;
	password?: string;
	/** Header sender, `Name <address>` or a bare address. */
	from: string;
	/** Envelope sender (MAIL FROM) address. */
	envelopeFrom: string;
	/** EHLO name. */
	heloName: string;
	/** PEM CA certificates that replace the system roots. */
	caCerts?: string[];
	timeoutMs: number;
}

export interface SmtpMessage {
	to: string;
	subject: string;
	text: string;
	html: string;
	/** Message-ID local part seed; must not contain a secret. */
	messageIdSeed: string;
	date?: Date;
	/** Files sent after the body (already validated by the mailer). */
	attachments?: readonly SmtpAttachment[];
}

export interface SmtpAttachment {
	/** Safe file name ([A-Za-z0-9._-]); the mailer rejects anything else. */
	filename: string;
	contentType: string;
	/** Base64 of the file bytes. */
	contentBase64: string;
}

type SmtpStage = "connect" | "greeting" | "ehlo" | "starttls" | "auth" | "mail" | "rcpt" | "data";

export type SmtpOutcome =
	| { ok: true; messageId: string }
	| { ok: false; reason: "rejected" | "unavailable"; stage: SmtpStage; code: number | null };

const MAX_REPLY_LINE = 2048;
const MAX_REPLY_LINES = 64;

class SmtpReplyError extends Error {
	constructor(readonly stage: SmtpStage, readonly code: number | null) {
		super(`smtp_${stage}_${code ?? "none"}`);
	}
}

interface Reply {
	code: number;
	lines: string[];
}

async function readReply(reader: StreamReader, stage: SmtpStage): Promise<Reply> {
	const lines: string[] = [];
	for (let count = 0; count < MAX_REPLY_LINES; count += 1) {
		const line = await reader.readLine(MAX_REPLY_LINE);
		if (line === null) throw new SmtpReplyError(stage, null);
		const match = /^([2-5][0-9]{2})([ -])(.*)$/.exec(line) ?? /^([2-5][0-9]{2})()$/.exec(line);
		if (!match) throw new SmtpReplyError(stage, null);
		lines.push(match[3] ?? "");
		if (match[2] !== "-") return { code: Number(match[1]), lines };
	}
	throw new SmtpReplyError(stage, null);
}

function expect(reply: Reply, stage: SmtpStage, accepted: number[]): Reply {
	if (!accepted.includes(reply.code)) throw new SmtpReplyError(stage, reply.code);
	return reply;
}

const encoder = new TextEncoder();

function base64(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary);
}

function base64Lines(text: string): string {
	return (base64(encoder.encode(text)).match(/.{1,76}/g) ?? [""]).join("\r\n");
}

/** RFC 2047 encoded-word for a header value that is not plain printable ASCII. */
export function encodeHeaderValue(value: string): string {
	if (/^[\x20-\x7e]*$/.test(value)) return value;
	// Encode in chunks so no encoded word exceeds 75 characters.
	const words: string[] = [];
	let chunk = "";
	for (const char of value) {
		if (encoder.encode(chunk + char).length > 45) {
			words.push(`=?UTF-8?B?${base64(encoder.encode(chunk))}?=`);
			chunk = "";
		}
		chunk += char;
	}
	if (chunk) words.push(`=?UTF-8?B?${base64(encoder.encode(chunk))}?=`);
	return words.join("\r\n ");
}

function encodeSender(from: string): string {
	const match = /^(.*) <([^<>]+)>$/.exec(from);
	if (!match) return from;
	const name = match[1].trim();
	const display = /^[A-Za-z0-9 .'_-]*$/.test(name) ? `"${name}"` : encodeHeaderValue(name);
	return `${display} <${match[2]}>`;
}

function hex(bytes: ArrayBuffer): string {
	return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function domainOf(address: string): string {
	return address.slice(address.lastIndexOf("@") + 1).toLowerCase();
}

/**
 * RFC 5322 message with a text and an HTML alternative, both base64 UTF-8.
 * With attachments the alternative is wrapped in multipart/mixed and each
 * file follows it as a base64 part.
 */
export async function buildMimeMessage(
	settings: Pick<SmtpSettings, "from" | "envelopeFrom">,
	message: SmtpMessage,
): Promise<{ data: string; messageId: string }> {
	const digest = hex(await crypto.subtle.digest("SHA-256", encoder.encode(message.messageIdSeed)));
	const messageId = `<${digest.slice(0, 40)}@${domainOf(settings.envelopeFrom)}>`;
	const boundary = `aidr-${hex(crypto.getRandomValues(new Uint8Array(12)).buffer)}`;
	const attachments = message.attachments ?? [];
	const date = (message.date ?? new Date()).toUTCString().replace("GMT", "+0000");
	const headers = [
		`From: ${encodeSender(settings.from)}`,
		`To: <${message.to}>`,
		`Subject: ${encodeHeaderValue(message.subject)}`,
		`Date: ${date}`,
		`Message-ID: ${messageId}`,
		"MIME-Version: 1.0",
		"Auto-Submitted: auto-generated",
	];
	const part = (type: string, body: string) =>
		[`--${boundary}`, `Content-Type: ${type}; charset=UTF-8`, "Content-Transfer-Encoding: base64", "", base64Lines(body)].join("\r\n");
	const alternative = [part("text/plain", message.text), part("text/html", message.html), `--${boundary}--`];
	if (attachments.length === 0) {
		const data = [...headers, `Content-Type: multipart/alternative; boundary="${boundary}"`, "", ...alternative, ""].join("\r\n");
		return { data, messageId };
	}
	const mixed = `${boundary}-mixed`;
	const file = (item: SmtpAttachment) =>
		[
			`--${mixed}`,
			`Content-Type: ${item.contentType}; name="${item.filename}"`,
			`Content-Disposition: attachment; filename="${item.filename}"`,
			"Content-Transfer-Encoding: base64",
			"",
			(item.contentBase64.match(/.{1,76}/g) ?? [""]).join("\r\n"),
		].join("\r\n");
	const data = [
		...headers,
		`Content-Type: multipart/mixed; boundary="${mixed}"`,
		"",
		`--${mixed}`,
		`Content-Type: multipart/alternative; boundary="${boundary}"`,
		"",
		...alternative,
		...attachments.map(file),
		`--${mixed}--`,
		"",
	].join("\r\n");
	return { data, messageId };
}

/** RFC 5321 transparency: a line starting with "." gets a second one. */
export function dotStuff(data: string): string {
	return data.replace(/\r\n/g, "\n").replace(/\n/g, "\r\n").replace(/(^|\r\n)\./g, "$1..");
}

/** Send one message. Never throws. */
export async function sendSmtpMessage(
	settings: SmtpSettings,
	message: SmtpMessage,
	transport: SocketTransport,
): Promise<SmtpOutcome> {
	let connection: StreamConnection | null = null;
	let stage: SmtpStage = "connect";
	const run = async (): Promise<string> => {
		connection = await transport.connect({ hostname: settings.host, port: settings.port });
		if (settings.security === "tls") {
			connection = await transport.startTls(connection, { serverName: settings.host, caCerts: settings.caCerts });
		}
		let reader = new StreamReader(connection);
		const send = async (line: string) => {
			await (connection as StreamConnection).write(encoder.encode(`${line}\r\n`));
		};
		stage = "greeting";
		expect(await readReply(reader, stage), stage, [220]);
		stage = "ehlo";
		await send(`EHLO ${settings.heloName}`);
		let ehlo = expect(await readReply(reader, stage), stage, [250]);
		if (settings.security === "starttls") {
			stage = "starttls";
			if (!ehlo.lines.some((line) => /^STARTTLS\b/i.test(line))) throw new SmtpReplyError(stage, 502);
			await send("STARTTLS");
			expect(await readReply(reader, stage), stage, [220]);
			connection = await transport.startTls(connection, { serverName: settings.host, caCerts: settings.caCerts });
			reader = new StreamReader(connection);
			stage = "ehlo";
			await send(`EHLO ${settings.heloName}`);
			ehlo = expect(await readReply(reader, stage), stage, [250]);
		}
		if (settings.username) {
			stage = "auth";
			const mechanisms = ehlo.lines
				.filter((line) => /^AUTH[ =]/i.test(line))
				.flatMap((line) => line.slice(5).toUpperCase().split(/\s+/));
			if (mechanisms.includes("PLAIN")) {
				const token = base64(encoder.encode(`\0${settings.username}\0${settings.password ?? ""}`));
				await send(`AUTH PLAIN ${token}`);
				expect(await readReply(reader, stage), stage, [235]);
			} else if (mechanisms.includes("LOGIN")) {
				await send("AUTH LOGIN");
				expect(await readReply(reader, stage), stage, [334]);
				await send(base64(encoder.encode(settings.username)));
				expect(await readReply(reader, stage), stage, [334]);
				await send(base64(encoder.encode(settings.password ?? "")));
				expect(await readReply(reader, stage), stage, [235]);
			} else {
				throw new SmtpReplyError(stage, 504);
			}
		}
		stage = "mail";
		await send(`MAIL FROM:<${settings.envelopeFrom}>`);
		expect(await readReply(reader, stage), stage, [250]);
		stage = "rcpt";
		await send(`RCPT TO:<${message.to}>`);
		expect(await readReply(reader, stage), stage, [250, 251]);
		stage = "data";
		await send("DATA");
		expect(await readReply(reader, stage), stage, [354]);
		const mime = await buildMimeMessage(settings, message);
		await connection.write(encoder.encode(`${dotStuff(mime.data)}\r\n.\r\n`));
		expect(await readReply(reader, stage), stage, [250]);
		// The message is accepted; a failed QUIT changes nothing.
		try {
			await send("QUIT");
		} catch {
			// ignore
		}
		return mime.messageId;
	};
	try {
		const messageId = await withTimeout(run(), settings.timeoutMs, () => (connection as StreamConnection | null)?.close());
		return { ok: true, messageId };
	} catch (error) {
		if (error instanceof SmtpReplyError) {
			const permanent = error.code !== null && error.code >= 500;
			return { ok: false, reason: permanent ? "rejected" : "unavailable", stage: error.stage, code: error.code };
		}
		return { ok: false, reason: "unavailable", stage, code: null };
	} finally {
		(connection as StreamConnection | null)?.close();
	}
}
