import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_ENV = { ...process.env };

async function importFreshSentry() {
	vi.resetModules();
	return import("../sentry.js");
}

describe("sentry integration", () => {
	beforeEach(() => {
		vi.resetModules();
		vi.doUnmock("@sentry/node");
		process.env = { ...ORIGINAL_ENV };
		delete process.env.SENTRY_DSN;
		delete process.env.SENTRY_ENABLED;
		delete process.env.SENTRY_DEBUG;
		delete process.env.SENTRY_SAMPLE_RATE;
		delete process.env.SENTRY_TRACES_SAMPLE_RATE;
		delete process.env.AIDR_PACKAGE_NAME;
		delete process.env.AIDR_RUNTIME;
	});

	afterEach(() => {
		vi.resetModules();
		vi.doUnmock("@sentry/node");
		process.env = { ...ORIGINAL_ENV };
	});

	it("marks Sentry initialized without loading the SDK when disabled", async () => {
		process.env.SENTRY_ENABLED = "false";
		const sentry = await importFreshSentry();

		await sentry.initSentry();

		expect(sentry.isSentryInitialized()).toBe(true);
	});

	it("redacts sensitive extra and context fields before sending events", async () => {
		let beforeSend:
			| ((event: Record<string, unknown>) => Record<string, unknown> | null)
			| undefined;
		const init = vi.fn((options: { beforeSend?: typeof beforeSend }) => {
			beforeSend = options.beforeSend;
		});
		vi.doMock("@sentry/node", () => ({
			init,
			getClient: vi.fn(() => ({ enabled: true })),
			captureException: vi.fn(() => "event-id"),
			captureMessage: vi.fn(() => "message-id"),
			startSpan: vi.fn((_options, operation) => operation({ name: "span" })),
			setUser: vi.fn(),
			setTags: vi.fn(),
			flush: vi.fn(async () => true),
			close: vi.fn(async () => undefined),
		}));

		const sentry = await importFreshSentry();
		await sentry.initSentry({
			enabled: true,
			dsn: "https://public@example.invalid/1",
			name: "core-tests",
		});

		expect(init).toHaveBeenCalledOnce();
		expect(beforeSend).toBeTypeOf("function");

		const event = beforeSend?.({
			message: "request failed token=live-secret",
			extra: {
				apiKey: "sk-live-secret",
				nested: { authorization: "Bearer token", safe: "kept" },
			},
			contexts: {
				request: { password: "secret", route: "/health" },
			},
			exception: {
				values: [{ value: "upstream failed token=live-secret" }],
			},
			request: { url: "https://example.test/callback?token=live-secret" },
		});

		expect(event).toMatchObject({
			extra: {
				apiKey: "[Redacted]",
				nested: { authorization: "[Redacted]", safe: "kept" },
			},
			contexts: {
				request: { password: "[Redacted]", route: "/health" },
			},
			message: "request failed token=[Redacted]",
			exception: {
				values: [{ value: "upstream failed token=[Redacted]" }],
			},
			request: { url: "https://example.test/callback?token=[Redacted]" },
		});
	});

	it("returns empty capture ids when the SDK has no active client", async () => {
		vi.doMock("@sentry/node", () => ({
			init: vi.fn(),
			getClient: vi.fn(() => null),
			captureException: vi.fn(() => "should-not-be-used"),
			captureMessage: vi.fn(() => "should-not-be-used"),
			startSpan: vi.fn(),
			setUser: vi.fn(),
			setTags: vi.fn(),
			flush: vi.fn(async () => true),
			close: vi.fn(async () => undefined),
		}));
		const sentry = await importFreshSentry();

		await sentry.initSentry({ enabled: false });

		await expect(sentry.captureException(new Error("boom"))).resolves.toBe("");
		await expect(sentry.captureMessage("hello")).resolves.toBe("");
	});

	it("wraps sync and async failures with capture context while preserving thrown errors", async () => {
		const captureException = vi.fn(() => "event-id");
		vi.doMock("@sentry/node", () => ({
			init: vi.fn(),
			getClient: vi.fn(() => ({ enabled: true })),
			captureException,
			captureMessage: vi.fn(() => "message-id"),
			startSpan: vi.fn((_options, operation) => operation({ name: "span" })),
			setUser: vi.fn(),
			setTags: vi.fn(),
			flush: vi.fn(async () => true),
			close: vi.fn(async () => undefined),
		}));
		const sentry = await importFreshSentry();
		await sentry.initSentry({ enabled: true, dsn: "https://public@example.invalid/1" });

		const syncError = new Error("sync failed");
		const syncFn = sentry.withSentry(
			() => {
				throw syncError;
			},
			{ component: "sync" },
		);
		expect(syncFn).toThrow(syncError);

		const asyncError = new Error("async failed");
		const asyncFn = sentry.withSentry(
			async (_input: string) => {
				throw asyncError;
			},
			{ component: "async" },
		);
		await expect(asyncFn("payload")).rejects.toThrow(asyncError);

		await vi.waitFor(() => {
			expect(captureException).toHaveBeenCalledTimes(2);
		});
		expect(captureException).toHaveBeenNthCalledWith(
			1,
			syncError,
			expect.objectContaining({ extra: { component: "sync", args: [] } }),
		);
		expect(captureException).toHaveBeenNthCalledWith(
			2,
			asyncError,
			expect.objectContaining({ extra: { component: "async", args: ["payload"] } }),
		);
	});
});
