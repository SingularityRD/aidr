import { afterEach, describe, expect, it, vi } from "vitest";
import {
	createMailer,
	createResendMailer,
	escapeHtml,
	isMailSender,
	noMailer,
	RESEND_API_URL,
} from "../_shared/mailer.ts";
import { invitationEmail } from "../team-invite/email.ts";

const KEY = "re_unit_key_never_logged";

function env(values: Record<string, string>) {
	return (name: string) => values[name];
}

afterEach(() => {
	vi.restoreAllMocks();
});

describe("mailer configuration", () => {
	it("selects Resend only when both credentials are configured", () => {
		const fetchMock = vi.fn();
		const implicit = createMailer(env({ RESEND_API_KEY: KEY, AIDR_MAIL_FROM: "no-reply@aidr.example" }), {
			fetch: fetchMock as unknown as typeof fetch,
		});
		expect(implicit.provider).toBe("resend");
		const explicit = createMailer(
			env({ AIDR_MAIL_PROVIDER: "Resend", RESEND_API_KEY: KEY, AIDR_MAIL_FROM: "AIDR <no-reply@aidr.example>" }),
		);
		expect(explicit.provider).toBe("resend");
		expect(createMailer(env({})).provider).toBe("none");
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("honours an explicit 'none' even when credentials are present", () => {
		expect(
			createMailer(env({ AIDR_MAIL_PROVIDER: "none", RESEND_API_KEY: KEY, AIDR_MAIL_FROM: "a@b.example" })),
		).toBe(noMailer);
	});

	it("logs half-configured, invalid or unknown settings by name and degrades to none", () => {
		const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
		const cases: Array<[Record<string, string>, string]> = [
			[{ RESEND_API_KEY: KEY }, "AIDR_MAIL_FROM"],
			[{ AIDR_MAIL_FROM: "a@b.example" }, "RESEND_API_KEY"],
			[{ AIDR_MAIL_PROVIDER: "resend" }, "RESEND_API_KEY"],
			[{ AIDR_MAIL_PROVIDER: "smtp", RESEND_API_KEY: KEY, AIDR_MAIL_FROM: "a@b.example" }, "AIDR_MAIL_PROVIDER"],
			[{ RESEND_API_KEY: KEY, AIDR_MAIL_FROM: "Evil\r\nBcc: x@y.example <a@b.example>" }, "AIDR_MAIL_FROM"],
		];
		for (const [values, variable] of cases) {
			error.mockClear();
			expect(createMailer(env(values)).provider).toBe("none");
			const output = JSON.stringify(error.mock.calls);
			expect(output).toContain(variable);
			expect(output).not.toContain(KEY);
		}
	});

	it("accepts only single-line sender addresses", () => {
		expect(isMailSender("no-reply@aidr.example")).toBe(true);
		expect(isMailSender("Singularity AIDR <no-reply@aidr.example>")).toBe(true);
		expect(isMailSender("no-reply")).toBe(false);
		expect(isMailSender("A\n<no-reply@aidr.example>")).toBe(false);
	});

	it("never sends through the 'none' mailer", async () => {
		expect(await noMailer.send({ to: "a@b.example", subject: "s", html: "h", text: "t" })).toEqual({
			ok: false,
			reason: "not_configured",
		});
	});
});

describe("Resend transport", () => {
	it("posts one JSON message with bearer auth and returns the provider id", async () => {
		const fetchMock = vi.fn(async () => new Response(JSON.stringify({ id: "msg_42" }), { status: 200 }));
		const mailer = createResendMailer(KEY, "no-reply@aidr.example", { fetch: fetchMock as unknown as typeof fetch });
		const result = await mailer.send({
			to: "person@example.com",
			subject: "Hello",
			html: "<p>Hi</p>",
			text: "Hi",
			idempotencyKey: "team-invite/abc/0123456789abcdef",
		});
		expect(result).toEqual({ ok: true, provider: "resend", messageId: "msg_42" });
		expect(fetchMock).toHaveBeenCalledOnce();
		const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe(RESEND_API_URL);
		expect(init.method).toBe("POST");
		expect(init.headers).toMatchObject({
			Authorization: `Bearer ${KEY}`,
			"Content-Type": "application/json",
			"Idempotency-Key": "team-invite/abc/0123456789abcdef",
		});
		expect(JSON.parse(String(init.body))).toEqual({
			from: "no-reply@aidr.example",
			to: ["person@example.com"],
			subject: "Hello",
			html: "<p>Hi</p>",
			text: "Hi",
		});
		expect(init.signal).toBeInstanceOf(AbortSignal);
	});

	it("refuses malformed messages without a network call", async () => {
		const fetchMock = vi.fn();
		const mailer = createResendMailer(KEY, "no-reply@aidr.example", { fetch: fetchMock as unknown as typeof fetch });
		for (const message of [
			{ to: "not-an-address", subject: "s", html: "h", text: "t" },
			{ to: "a@b.example", subject: "line\r\nbreak", html: "h", text: "t" },
			{ to: "a@b.example", subject: "s", html: "", text: "t" },
			{ to: "a@b.example", subject: "s", html: "h", text: "t", idempotencyKey: "has space" },
		]) {
			expect(await mailer.send(message)).toEqual({ ok: false, reason: "invalid_message" });
		}
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("maps provider failures without logging the key, recipient or body", async () => {
		const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
		const cases: Array<[() => Response, string]> = [
			[() => new Response("{}", { status: 422 }), "rejected"],
			[() => new Response("{}", { status: 429 }), "unavailable"],
			[() => new Response("oops", { status: 502 }), "unavailable"],
			[() => new Response("{}", { status: 200 }), "unavailable"],
			[() => { throw new TypeError("offline"); }, "unavailable"],
		];
		for (const [respond, reason] of cases) {
			const mailer = createResendMailer(KEY, "no-reply@aidr.example", {
				fetch: vi.fn(async () => respond()) as unknown as typeof fetch,
			});
			expect(await mailer.send({ to: "secret-person@example.com", subject: "s", html: "token-abc", text: "token-abc" }))
				.toEqual({ ok: false, reason });
		}
		const output = JSON.stringify(error.mock.calls);
		expect(output).not.toContain(KEY);
		expect(output).not.toContain("secret-person@example.com");
		expect(output).not.toContain("token-abc");
	});
});

describe("invitation email template", () => {
	const base = {
		to: "person@example.com",
		role: "admin",
		inviteUrl: "https://app.aidr.example/enterprise?invite=" + "a".repeat(64),
		expiresAt: "2030-01-08T00:00:00.000Z",
		invitationId: "44444444-4444-4444-8444-444444444444",
		tokenHash: "f".repeat(64),
	};

	it("renders HTML and plain text with the link, role and expiry", () => {
		const message = invitationEmail({ ...base, workspaceName: "Acme Security" });
		expect(message.subject).toBe("You're invited to join Acme Security on Singularity AIDR");
		expect(message.text).toContain(base.inviteUrl);
		expect(message.text).toContain("as Administrator");
		expect(message.text).toContain("Tue, 08 Jan 2030 00:00:00 GMT");
		expect(message.html).toContain(`href="${base.inviteUrl}"`);
		expect(message.html).toContain("<strong>Administrator</strong>");
		expect(message.idempotencyKey).toBe(`team-invite/${base.invitationId}/${"f".repeat(16)}`);
	});

	it("escapes and single-lines customer-controlled workspace names", () => {
		const message = invitationEmail({ ...base, workspaceName: "<img src=x onerror=alert(1)>\r\nBcc: x" });
		expect(message.html).not.toContain("<img");
		expect(message.html).toContain("&lt;img src=x onerror=alert(1)&gt; Bcc: x");
		expect(message.subject).not.toMatch(/[\r\n]/);
		expect(invitationEmail({ ...base, workspaceName: "   " }).subject).toContain("an AIDR workspace");
	});

	it("escapes every HTML-significant character", () => {
		expect(escapeHtml(`<a href="x">'&'</a>`)).toBe("&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;");
	});
});
