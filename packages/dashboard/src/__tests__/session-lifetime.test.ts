// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ getSession: vi.fn(), signOut: vi.fn(), invoke: vi.fn() }));
vi.mock("../lib/supabase", () => ({
	supabase: { auth: mocks, functions: { invoke: mocks.invoke } },
}));

const ACTIVITY_KEY = "aidr.session.activity.v1";
const USER_ID = "22222222-2222-4222-8222-222222222222";
let dispose: (() => void) | undefined;

beforeEach(() => {
	vi.resetModules();
	vi.useFakeTimers();
	vi.setSystemTime(new Date("2026-10-05T09:00:00Z"));
	localStorage.clear();
	let session: object | null = { user: { id: USER_ID } };
	mocks.getSession.mockReset().mockImplementation(async () => ({ data: { session }, error: null }));
	mocks.signOut.mockReset().mockImplementation(async () => {
		session = null;
		return { error: null };
	});
	mocks.invoke.mockReset().mockResolvedValue({
		data: { ok: true, scope: "global", reauthentication_required: true },
		error: null,
	});
});

afterEach(() => {
	dispose?.();
	dispose = undefined;
	vi.restoreAllMocks();
	vi.useRealTimers();
});

describe("Dashboard idle watchdog", () => {
	it("expires sessions again after signing back in without a page reload", async () => {
		const { installInactivityTimeout, INACTIVITY_TIMEOUT_MS } = await import("../ui/session");
		const expired = vi.fn();
		dispose = installInactivityTimeout(expired);
		await vi.advanceTimersByTimeAsync(INACTIVITY_TIMEOUT_MS + 30_000);
		expect(expired).toHaveBeenCalledTimes(1);
		mocks.getSession.mockResolvedValue({
			data: { session: { user: { id: USER_ID } } },
			error: null,
		});
		await vi.advanceTimersByTimeAsync(INACTIVITY_TIMEOUT_MS + 60_000);
		expect(expired).toHaveBeenCalledTimes(2);
	});

	it("checks expiry before a returning tab can refresh the activity timestamp", async () => {
		const { installInactivityTimeout, INACTIVITY_TIMEOUT_MS } = await import("../ui/session");
		const expired = vi.fn();
		localStorage.setItem(ACTIVITY_KEY, JSON.stringify({ user_id: USER_ID, at: Date.now() }));
		dispose = installInactivityTimeout(expired);
		await vi.advanceTimersByTimeAsync(0);
		vi.setSystemTime(Date.now() + INACTIVITY_TIMEOUT_MS + 1_000);
		window.dispatchEvent(new Event("focus"));
		await vi.advanceTimersByTimeAsync(30_000);
		expect(expired).toHaveBeenCalledTimes(1);
		expect(localStorage.getItem(ACTIVITY_KEY)).toBeNull();
	});

	it("does not start duplicate revocations while an expiry request is pending", async () => {
		const { installInactivityTimeout, INACTIVITY_TIMEOUT_MS } = await import("../ui/session");
		let finish!: (value: unknown) => void;
		mocks.invoke.mockImplementation(
			() =>
				new Promise((resolve) => {
					finish = resolve;
				}),
		);
		localStorage.setItem(
			ACTIVITY_KEY,
			JSON.stringify({
				user_id: USER_ID,
				at: Date.now() - INACTIVITY_TIMEOUT_MS - 1_000,
			}),
		);
		const expired = vi.fn();
		dispose = installInactivityTimeout(expired);
		await vi.advanceTimersByTimeAsync(90_000);
		expect(mocks.invoke).toHaveBeenCalledTimes(1);
		finish({ data: { ok: true, scope: "global", reauthentication_required: true }, error: null });
		await vi.advanceTimersByTimeAsync(0);
		expect(expired).toHaveBeenCalledTimes(1);
	});

	it.each([false, true])(
		"keeps the idle clock when storage writes are blocked (reads blocked: %s)",
		async (readsBlocked) => {
			const { readSession, INACTIVITY_TIMEOUT_MS } = await import("../ui/session");
			if (readsBlocked)
				vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
					throw new Error("blocked");
				});
			vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
				throw new Error("blocked");
			});
			expect((await readSession()).status.state).toBe("active");
			vi.setSystemTime(Date.now() + INACTIVITY_TIMEOUT_MS + 1_000);
			expect((await readSession()).status.state).toBe("expired");
		},
	);

	it("keeps an expired session blocked when both remote revocation and local sign-out fail", async () => {
		const { readSession, INACTIVITY_TIMEOUT_MS } = await import("../ui/session");
		mocks.invoke.mockRejectedValue(new Error("offline"));
		mocks.signOut.mockResolvedValue({ error: new Error("local cleanup failed") });
		localStorage.setItem(
			ACTIVITY_KEY,
			JSON.stringify({ user_id: USER_ID, at: Date.now() - INACTIVITY_TIMEOUT_MS - 1_000 }),
		);
		expect((await readSession()).status.state).toBe("expired");
		expect((await readSession()).status.state).toBe("expired");
	});
});
