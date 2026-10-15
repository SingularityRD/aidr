// SMTP mail provider (E2): real sockets against a local SMTP relay that speaks
// STARTTLS / implicit TLS with a throwaway private CA, so the exact protocol
// code the Edge Functions ship is exercised end to end.
import { type AddressInfo, createServer, type Server, type Socket } from "node:net";
import { TLSSocket } from "node:tls";
import { afterEach, describe, expect, it, vi } from "vitest";
import { selfSignedLoopbackTls } from "../../../packages/core/src/__tests__/self-signed-tls.ts";
import { createMailer, createSmtpMailer, readSmtpSettings } from "../_shared/mailer.ts";
import { buildMimeMessage, dotStuff, encodeHeaderValue } from "../_shared/smtp.ts";
import { nodeSocketTransport } from "./node-socket-transport.ts";

const PASSWORD = "relay-password-never-logged";
const identity = selfSignedLoopbackTls();
const CA_B64 = Buffer.from(identity.cert).toString("base64");

interface Session {
	commands: string[];
	data: string;
	tls: boolean;
}

interface RelayOptions {
	implicitTls?: boolean;
	offerStartTls?: boolean;
	auth?: "PLAIN" | "LOGIN" | null;
	rcptReply?: string;
	mailReply?: string;
}

const servers: Server[] = [];
afterEach(async () => {
	vi.restoreAllMocks();
	for (const server of servers.splice(0)) await new Promise<void>((done) => server.close(() => done()));
});

async function relay(options: RelayOptions = {}): Promise<{ port: number; sessions: Session[] }> {
	const sessions: Session[] = [];
	const server = createServer((raw) => {
		const session: Session = { commands: [], data: "", tls: false };
		sessions.push(session);
		let socket: Socket = raw;
		let buffer = "";
		let inData = false;
		let loginStep = 0;
		const reply = (line: string) => socket.write(`${line}\r\n`);
		const ehlo = () => {
			const lines = ["250-relay.test"];
			if (options.offerStartTls !== false && !session.tls) lines.push("250-STARTTLS");
			if (options.auth) lines.push(`250-AUTH ${options.auth}`);
			lines.push("250 8BITMIME");
			socket.write(`${lines.join("\r\n")}\r\n`);
		};
		const onData = (chunk: Buffer) => {
			buffer += chunk.toString("utf8");
			for (;;) {
				if (inData) {
					const end = buffer.indexOf("\r\n.\r\n");
					if (end < 0) return;
					session.data = buffer.slice(0, end);
					buffer = buffer.slice(end + 5);
					inData = false;
					reply("250 2.0.0 queued");
					continue;
				}
				const index = buffer.indexOf("\r\n");
				if (index < 0) return;
				const line = buffer.slice(0, index);
				buffer = buffer.slice(index + 2);
				session.commands.push(line);
				if (loginStep === 1) {
					loginStep = 2;
					reply("334 UGFzc3dvcmQ6");
				} else if (loginStep === 2) {
					loginStep = 0;
					reply("235 2.7.0 ok");
				} else if (/^EHLO /.test(line)) ehlo();
				else if (line === "STARTTLS") {
					reply("220 2.0.0 ready");
					socket.removeListener("data", onData);
					const secure = new TLSSocket(socket, { isServer: true, key: identity.key, cert: identity.cert });
					session.tls = true;
					socket = secure;
					secure.on("data", onData);
					secure.on("error", () => undefined);
				} else if (/^AUTH PLAIN /.test(line)) reply("235 2.7.0 ok");
				else if (line === "AUTH LOGIN") {
					loginStep = 1;
					reply("334 VXNlcm5hbWU6");
				} else if (/^MAIL FROM:/.test(line)) reply(options.mailReply ?? "250 ok");
				else if (/^RCPT TO:/.test(line)) reply(options.rcptReply ?? "250 ok");
				else if (line === "DATA") {
					inData = true;
					reply("354 go ahead");
				} else if (line === "QUIT") {
					reply("221 bye");
					socket.end();
				} else reply("502 unknown");
			}
		};
		raw.on("error", () => undefined);
		if (options.implicitTls) {
			const secure = new TLSSocket(raw, { isServer: true, key: identity.key, cert: identity.cert });
			session.tls = true;
			socket = secure;
			secure.on("error", () => undefined);
			secure.on("data", onData);
			reply("220 relay.test ESMTP");
		} else {
			raw.on("data", onData);
			reply("220 relay.test ESMTP");
		}
	});
	servers.push(server);
	const port = await new Promise<number>((resolve) =>
		server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)),
	);
	return { port, sessions };
}

function env(values: Record<string, string>) {
	return (name: string) => values[name];
}

const MESSAGE = {
	to: "soc@customer.example",
	subject: "Kritik olay: şüpheli komut engellendi",
	html: "<p>.leading dot</p>",
	text: ".leading dot\nsecond line",
	idempotencyKey: "aidr-notification:7c1f0a52-3a8e-4b8e-9d6c-2f7b8a1e4c90:0",
};

function decodeParts(data: string): string[] {
	return [...data.matchAll(/Content-Transfer-Encoding: base64\r\n\r\n([A-Za-z0-9+/=\r\n]+?)\r\n--/g)].map((match) =>
		Buffer.from(match[1].replace(/\r\n/g, ""), "base64").toString("utf8"),
	);
}

describe("SMTP settings from the on-prem SMTP_* variables", () => {
	it("reuses the Auth relay settings and selects SMTP implicitly", () => {
		const mailer = createMailer(
			env({ SMTP_HOST: "relay.corp.example", SMTP_ADMIN_EMAIL: "aidr@corp.example", SMTP_SENDER_NAME: "AIDR" }),
		);
		expect(mailer.provider).toBe("smtp");
		expect(
			readSmtpSettings(env({ SMTP_HOST: "relay.corp.example", SMTP_PORT: "465", SMTP_ADMIN_EMAIL: "aidr@corp.example" })),
		).toMatchObject({ port: 465, security: "tls", envelopeFrom: "aidr@corp.example" });
		expect(
			readSmtpSettings(env({ SMTP_HOST: "relay.corp.example", SMTP_ADMIN_EMAIL: "aidr@corp.example", SMTP_SENDER_NAME: "AIDR" })),
		).toMatchObject({ port: 587, security: "starttls", from: "AIDR <aidr@corp.example>", heloName: "corp.example" });
		// A configured Resend key keeps the existing implicit choice.
		expect(
			createMailer(env({ SMTP_HOST: "relay.corp.example", RESEND_API_KEY: "re_x", AIDR_MAIL_FROM: "a@b.example" })).provider,
		).toBe("resend");
	});

	it("refuses unsafe or broken SMTP settings by variable name, never by value", () => {
		const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
		const base = { SMTP_HOST: "relay.corp.example", SMTP_ADMIN_EMAIL: "aidr@corp.example" };
		const cases: Array<[Record<string, string>, string]> = [
			[{ ...base, AIDR_SMTP_SECURITY: "none", SMTP_USER: "aidr", SMTP_PASS: PASSWORD }, "AIDR_SMTP_SECURITY"],
			[{ ...base, AIDR_SMTP_SECURITY: "ssl3" }, "AIDR_SMTP_SECURITY"],
			[{ ...base, SMTP_PORT: "99999" }, "SMTP_PORT"],
			[{ ...base, SMTP_HOST: "relay host; rm" }, "SMTP_HOST"],
			[{ ...base, AIDR_SMTP_CA_PEM_B64: Buffer.from("not a pem").toString("base64") }, "AIDR_SMTP_CA_PEM_B64"],
			[{ SMTP_HOST: "relay.corp.example" }, "SMTP_ADMIN_EMAIL"],
			[{ ...base, SMTP_PASS: PASSWORD }, "SMTP_USER"],
			[{ AIDR_MAIL_PROVIDER: "smtp" }, "SMTP_HOST"],
		];
		for (const [values, variable] of cases) {
			error.mockClear();
			expect(createMailer(env(values)).provider).toBe("none");
			const output = JSON.stringify(error.mock.calls);
			expect(output).toContain(variable);
			expect(output).not.toContain(PASSWORD);
		}
	});
});

describe("SMTP delivery over real sockets", () => {
	it("upgrades with STARTTLS, verifies the internal CA, authenticates and sends a MIME message", async () => {
		const server = await relay({ auth: "PLAIN" });
		const transport = nodeSocketTransport(() => ({ host: "127.0.0.1", port: server.port }));
		const mailer = createMailer(
			env({
				SMTP_HOST: "127.0.0.1",
				SMTP_PORT: String(server.port),
				SMTP_USER: "aidr",
				SMTP_PASS: PASSWORD,
				SMTP_ADMIN_EMAIL: "aidr@corp.example",
				SMTP_SENDER_NAME: "Singularity AIDR",
				AIDR_SMTP_CA_PEM_B64: CA_B64,
			}),
			{ transport },
		);
		const result = await mailer.send(MESSAGE);
		expect(result).toMatchObject({ ok: true, provider: "smtp" });
		const [session] = server.sessions;
		expect(session.tls).toBe(true);
		expect(transport.log.tls).toEqual([{ serverName: "127.0.0.1", caCerts: 1 }]);
		// AUTH only after STARTTLS; credentials never on the plaintext leg.
		const starttls = session.commands.indexOf("STARTTLS");
		const auth = session.commands.findIndex((line) => line.startsWith("AUTH PLAIN "));
		expect(starttls).toBeGreaterThanOrEqual(0);
		expect(auth).toBeGreaterThan(starttls);
		expect(Buffer.from(session.commands[auth].slice(11), "base64").toString()).toBe(`\0aidr\0${PASSWORD}`);
		expect(session.commands).toContain("MAIL FROM:<aidr@corp.example>");
		expect(session.commands).toContain("RCPT TO:<soc@customer.example>");
		expect(session.data).toContain('From: "Singularity AIDR" <aidr@corp.example>');
		expect(session.data).toContain("Subject: =?UTF-8?B?");
		expect(session.data).toMatch(/Message-ID: <[0-9a-f]{40}@corp\.example>/);
		expect(decodeParts(session.data)).toEqual([MESSAGE.text, MESSAGE.html]);
		// Same idempotency key, same Message-ID on a retry.
		const again = await mailer.send(MESSAGE);
		expect(again.ok && result.ok && again.messageId === result.messageId).toBe(true);
	});

	it("supports implicit TLS and AUTH LOGIN", async () => {
		const server = await relay({ implicitTls: true, auth: "LOGIN" });
		const transport = nodeSocketTransport(() => ({ host: "127.0.0.1", port: server.port }));
		const settings = readSmtpSettings(
			env({
				SMTP_HOST: "127.0.0.1",
				SMTP_PORT: "465",
				SMTP_USER: "aidr",
				SMTP_PASS: PASSWORD,
				SMTP_ADMIN_EMAIL: "aidr@corp.example",
				AIDR_SMTP_CA_PEM_B64: CA_B64,
			}),
		);
		expect(settings?.security).toBe("tls");
		const result = await createSmtpMailer(settings as NonNullable<typeof settings>, { transport }).send(MESSAGE);
		expect(result).toMatchObject({ ok: true, provider: "smtp" });
		expect(server.sessions[0].commands.slice(0, 2)).toEqual(["EHLO corp.example", "AUTH LOGIN"]);
	});

	it("refuses a certificate the configured CA did not issue", async () => {
		const server = await relay();
		const other = selfSignedLoopbackTls();
		const transport = nodeSocketTransport(() => ({ host: "127.0.0.1", port: server.port }));
		vi.spyOn(console, "error").mockImplementation(() => undefined);
		const mailer = createMailer(
			env({
				SMTP_HOST: "127.0.0.1",
				SMTP_PORT: String(server.port),
				SMTP_ADMIN_EMAIL: "aidr@corp.example",
				AIDR_SMTP_CA_PEM_B64: Buffer.from(other.cert).toString("base64"),
			}),
			{ transport },
		);
		expect(await mailer.send(MESSAGE)).toEqual({ ok: false, reason: "unavailable" });
		expect(server.sessions[0].commands).not.toContain("MAIL FROM:<aidr@corp.example>");
	});

	it("never downgrades when the relay does not offer STARTTLS", async () => {
		const server = await relay({ offerStartTls: false, auth: "PLAIN" });
		const transport = nodeSocketTransport(() => ({ host: "127.0.0.1", port: server.port }));
		const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
		const mailer = createMailer(
			env({
				SMTP_HOST: "127.0.0.1",
				SMTP_PORT: String(server.port),
				SMTP_USER: "aidr",
				SMTP_PASS: PASSWORD,
				SMTP_ADMIN_EMAIL: "aidr@corp.example",
			}),
			{ transport },
		);
		expect(await mailer.send(MESSAGE)).toEqual({ ok: false, reason: "rejected" });
		expect(server.sessions[0].commands.some((line) => line.startsWith("AUTH"))).toBe(false);
		expect(JSON.stringify(error.mock.calls)).not.toContain(PASSWORD);
	});

	it("maps 4xx to retryable and 5xx to permanent without logging the recipient", async () => {
		const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
		for (const [rcptReply, reason] of [
			["450 4.2.1 mailbox busy", "unavailable"],
			["550 5.1.1 no such user", "rejected"],
		] as const) {
			const server = await relay({ rcptReply });
			const transport = nodeSocketTransport(() => ({ host: "127.0.0.1", port: server.port }));
			const mailer = createMailer(
				env({
					SMTP_HOST: "127.0.0.1",
					SMTP_PORT: String(server.port),
					SMTP_ADMIN_EMAIL: "aidr@corp.example",
					AIDR_SMTP_CA_PEM_B64: CA_B64,
				}),
				{ transport },
			);
			expect(await mailer.send(MESSAGE)).toEqual({ ok: false, reason });
		}
		const output = JSON.stringify(error.mock.calls);
		expect(output).toMatch(/stage\W{1,6}rcpt/);
		expect(output).not.toContain("soc@customer.example");
	});

	it("reports an unreachable relay as retryable", async () => {
		const transport = nodeSocketTransport(() => ({ host: "127.0.0.1", port: 1 }));
		vi.spyOn(console, "error").mockImplementation(() => undefined);
		const mailer = createMailer(env({ SMTP_HOST: "relay.corp.example", SMTP_ADMIN_EMAIL: "aidr@corp.example" }), {
			transport,
		});
		expect(await mailer.send(MESSAGE)).toEqual({ ok: false, reason: "unavailable" });
	});
});

describe("MIME encoding", () => {
	it("dot-stuffs and encodes non-ASCII headers without line injection", async () => {
		expect(dotStuff("a\r\n.b\r\n..c")).toBe("a\r\n..b\r\n...c");
		expect(encodeHeaderValue("plain")).toBe("plain");
		const encoded = encodeHeaderValue("Şüpheli ğ ı ".repeat(8));
		expect(encoded).not.toMatch(/\r\n(?! )/);
		const { data } = await buildMimeMessage(
			{ from: "Evil <a@b.example>", envelopeFrom: "a@b.example" },
			{ to: "x@y.example", subject: "s", text: "t", html: "h", messageIdSeed: "seed" },
		);
		expect(data.split("\r\n\r\n")[0]).not.toMatch(/^Bcc:/m);
	});
	it("sends attachments as base64 parts after the text and HTML alternative", async () => {
		const pdf = btoa("%PDF-1.4 report");
		const { data } = await buildMimeMessage(
			{ from: "AIDR <aidr@corp.example>", envelopeFrom: "aidr@corp.example" },
			{
				to: "x@y.example",
				subject: "s",
				text: "t",
				html: "h",
				messageIdSeed: "seed",
				attachments: [{ filename: "report.pdf", contentType: "application/pdf", contentBase64: pdf }],
			},
		);
		const [head] = data.split("\r\n\r\n");
		expect(head).toMatch(/^Content-Type: multipart\/mixed; boundary="(aidr-[0-9a-f]+-mixed)"$/m);
		expect(data).toMatch(/Content-Type: multipart\/alternative; boundary="aidr-[0-9a-f]+"/);
		expect(data).toContain('Content-Disposition: attachment; filename="report.pdf"');
		expect(data).toContain(`\r\n${pdf}\r\n`);
		expect(data.indexOf("text/html")).toBeLessThan(data.indexOf("report.pdf"));
		expect(data.trimEnd()).toMatch(/--aidr-[0-9a-f]+-mixed--$/);
	});

	it("passes the mailer's attachments to the relay", async () => {
		const server = await relay();
		const transport = nodeSocketTransport(() => ({ host: "127.0.0.1", port: server.port }));
		const mailer = createMailer(
			env({
				SMTP_HOST: "127.0.0.1",
				SMTP_PORT: String(server.port),
				SMTP_ADMIN_EMAIL: "aidr@corp.example",
				AIDR_SMTP_CA_PEM_B64: CA_B64,
			}),
			{ transport },
		);
		const result = await mailer.send({
			...MESSAGE,
			attachments: [{ filename: "report.html", contentType: "text/html", contentBase64: btoa("<p>r</p>") }],
		});
		expect(result).toMatchObject({ ok: true, provider: "smtp" });
		expect(server.sessions[0].data).toContain('filename="report.html"');
	});
});
