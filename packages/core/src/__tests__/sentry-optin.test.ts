import { afterEach, describe, expect, it, vi } from "vitest";

const originalDsn = process.env.SENTRY_DSN;
const originalEnabled = process.env.SENTRY_ENABLED;

afterEach(() => {
	if (originalDsn === undefined) delete process.env.SENTRY_DSN;
	else process.env.SENTRY_DSN = originalDsn;
	if (originalEnabled === undefined) delete process.env.SENTRY_ENABLED;
	else process.env.SENTRY_ENABLED = originalEnabled;
	vi.resetModules();
	vi.doUnmock("@sentry/node");
});

describe("Sentry opt-in", () => {
	it("does not initialize or send when only a placeholder DSN is present", async () => {
		process.env.SENTRY_DSN =
			"https://xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx@xxxxxxx.ingest.sentry.io/0000000";
		delete process.env.SENTRY_ENABLED;
		const init = vi.fn();
		const captureException = vi.fn();
		const captureMessage = vi.fn();
		const startSpan = vi.fn();
		const setUser = vi.fn();
		const setTags = vi.fn();
		const flush = vi.fn();
		const close = vi.fn();
		vi.doMock("@sentry/node", () => ({
			init,
			getClient: () => ({ enabled: true }), // Host application may have its own SDK client.
			captureException,
			captureMessage,
			startSpan,
			setUser,
			setTags,
			flush,
			close,
		}));
		vi.resetModules();
		const sentry = await import("../sentry.js");

		await sentry.initSentry();
		await expect(sentry.captureException(new Error("local failure"))).resolves.toBe("");
		await expect(sentry.captureMessage("local failure")).resolves.toBe("");
		await expect(sentry.startSpan("local span", () => 42)).resolves.toBe(42);
		await sentry.setUser({ id: "local-user" });
		await sentry.setTags({ local: "tag" });
		await expect(sentry.flush()).resolves.toBe(false);
		await sentry.close();
		expect(init).not.toHaveBeenCalled();
		expect(captureException).not.toHaveBeenCalled();
		expect(captureMessage).not.toHaveBeenCalled();
		expect(startSpan).not.toHaveBeenCalled();
		expect(setUser).not.toHaveBeenCalled();
		expect(setTags).not.toHaveBeenCalled();
		expect(flush).not.toHaveBeenCalled();
		expect(close).not.toHaveBeenCalled();
	});

	it("initializes only when explicitly enabled with a DSN", async () => {
		process.env.SENTRY_DSN = "https://public@example.invalid/1";
		process.env.SENTRY_ENABLED = "true";
		const init = vi.fn();
		vi.doMock("@sentry/node", () => ({ init }));
		vi.resetModules();
		const sentry = await import("../sentry.js");

		await sentry.initSentry();
		expect(init).toHaveBeenCalledOnce();
	});
});
