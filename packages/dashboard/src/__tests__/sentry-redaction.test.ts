import { describe, expect, it } from "vitest";
import { redactSentryEvent, redactSentryString, redactSentryUrl } from "../sentry";

describe("dashboard telemetry redaction", () => {
	it("removes URL query strings and fragments instead of enumerating secret names", () => {
		expect(
			redactSentryUrl(
				"https://dashboard.example/auth/callback?code=oauth-code&state=signed#access_token=bearer-token",
			),
		).toBe("https://dashboard.example/auth/callback");
		expect(redactSentryString("to=/enterprise?invite=invite-secret")).toBe("to=/enterprise");
		expect(redactSentryString("to=/auth/recover?grant=grant-secret")).toBe("to=/auth/recover");
	});

	it("removes request and breadcrumb URL details from complete events", () => {
		const event = redactSentryEvent({
			request: {
				url: "https://dashboard.example/enterprise?invite=invite-secret",
				query_string: "invite=invite-secret",
			},
			breadcrumbs: [{ data: { from: "/login", to: "/auth/recover?grant=grant-secret" } }],
		});
		expect(event).toEqual({
			request: {
				url: "https://dashboard.example/enterprise",
			},
			breadcrumbs: [{ data: { from: "/login", to: "/auth/recover" } }],
		});
	});

	it("does not export identity or request payloads from browser error events", () => {
		const input = {
			user: { id: "customer-user", email: "person@example.test" },
			request: {
				method: "POST",
				url: "https://dashboard.example/incident?case=customer-secret",
				data: { note: "private customer investigation" },
				headers: { "x-internal": "private header value" },
			},
		};
		const event = redactSentryEvent(input);

		expect(event.user).toBeUndefined();
		expect(event.request).toEqual({
			method: "POST",
			url: "https://dashboard.example/incident",
		});
		expect(input.user.email).toBe("person@example.test");
		expect(input.request.data.note).toBe("private customer investigation");
	});
});
