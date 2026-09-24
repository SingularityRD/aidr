// @vitest-environment jsdom

import { afterEach, beforeEach, expect, it, vi } from "vitest";

const { browserTracingIntegration, init } = vi.hoisted(() => ({
	browserTracingIntegration: vi.fn(() => ({ name: "browser-tracing" })),
	init: vi.fn(),
}));

vi.mock("@sentry/browser", () => ({ browserTracingIntegration, init }));

import { initSentry } from "../sentry";

beforeEach(() => {
	vi.clearAllMocks();
	window.__AIDR_CONFIG__ = {
		sentryDsn: "https://public-key@o123.ingest.sentry.io/456",
		sentryEnvironment: "production",
		sentryTracesSampleRate: 0.2,
	};
});

afterEach(() => {
	delete window.__AIDR_CONFIG__;
});

it("boots the production bundle with runtime Sentry settings", () => {
	initSentry();

	expect(browserTracingIntegration).toHaveBeenCalledOnce();
	expect(init).toHaveBeenCalledWith(
		expect.objectContaining({
			dsn: "https://public-key@o123.ingest.sentry.io/456",
			environment: "production",
			tracesSampleRate: 0.2,
		}),
	);
});

it("does not initialize browser telemetry without a runtime DSN", () => {
	window.__AIDR_CONFIG__ = { sentryDsn: "" };
	initSentry();
	expect(init).not.toHaveBeenCalled();
});
