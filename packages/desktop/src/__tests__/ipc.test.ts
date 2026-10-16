import { describe, expect, it, vi } from "vitest";
import {
	type AppServices,
	assertHandlersMatchContract,
	createIpcHandlers,
	isTrustedSender,
} from "../main/ipc.js";
import { DEFAULT_PREFERENCES, INVOKE_CHANNELS } from "../shared/contract.js";

function services(overrides: Partial<AppServices> = {}): AppServices {
	const ok = { ok: true, message: "", log: "" };
	const info = {
		appVersion: "1",
		language: "en" as const,
		preferences: DEFAULT_PREFERENCES,
		platform: "win32/x64",
	};
	return {
		info: () => info,
		status: vi.fn(async () => ({}) as never),
		previewConnect: vi.fn(async () => ({}) as never),
		connect: vi.fn(async () => ok),
		disconnect: vi.fn(async () => ok),
		selfTest: vi.fn(async () => ({}) as never),
		recentAudit: () => [],
		incidentList: vi.fn(async () => []),
		incidentDetail: vi.fn(async () => null),
		exportAudit: vi.fn(async () => ok),
		setLogClean: vi.fn(async () => ok),
		browserGuardStatus: vi.fn(async () => ({}) as never),
		stageBrowserGuard: vi.fn(async () => ok),
		openExtensionsPage: vi.fn(async () => ok),
		setPreferences: vi.fn(async () => info),
		open: vi.fn(async () => ok),
		...overrides,
	};
}

describe("IPC handlers", () => {
	it("cover exactly the contract's channels", () => {
		const handlers = createIpcHandlers(services());
		expect(Object.keys(handlers).sort()).toEqual([...INVOKE_CHANNELS].sort());
		expect(() => assertHandlersMatchContract(handlers)).not.toThrow();
		expect(() =>
			assertHandlersMatchContract({ ...handlers, "evil:channel": async () => 1 } as never),
		).toThrow();
	});

	it("reject payloads on channels that take none", async () => {
		const handlers = createIpcHandlers(services());
		await expect(handlers["claude:connect"]({ force: true })).rejects.toThrow(/no payload/);
		await expect(handlers["status:get"]("x")).rejects.toThrow(/no payload/);
	});

	it("validate typed payloads strictly", async () => {
		const api = services();
		const handlers = createIpcHandlers(api);
		await expect(handlers["audit:setLogClean"]({ enabled: "yes" })).rejects.toThrow(/boolean/);
		await expect(handlers["audit:setLogClean"]({ enabled: true, extra: 1 })).rejects.toThrow(
			/unexpected field/,
		);
		await expect(
			handlers["browserGuard:openExtensionsPage"]({ browser: "firefox" }),
		).rejects.toThrow(/chrome or edge/);
		await expect(handlers["open:target"]({ target: "C:\\Windows\\System32" })).rejects.toThrow(
			/unknown open target/,
		);
		await expect(handlers["prefs:set"]({ language: "de" })).rejects.toThrow(/invalid language/);
		await expect(handlers["prefs:set"]({ startAtLogin: "true" })).rejects.toThrow(/boolean/);
		await expect(
			handlers["prefs:set"]({ __proto__: { polluted: true }, theme: "dark" }),
		).resolves.toBeDefined();
		await handlers["audit:setLogClean"]({ enabled: true });
		expect(api.setLogClean).toHaveBeenCalledWith(true);
		await handlers["open:target"]({ target: "auditLog" });
		expect(api.open).toHaveBeenCalledWith("auditLog");
		await expect(handlers["audit:export"]({ format: "xml" })).rejects.toThrow(/jsonl or csv/);
		await expect(handlers["audit:export"]({ format: "csv", output: "C:\\x" })).rejects.toThrow(
			/unexpected field/,
		);
		await expect(handlers["incidents:get"]({ id: 42 })).rejects.toThrow(/non-empty string/);
		await expect(handlers["incidents:get"]({ id: "" })).rejects.toThrow(/non-empty string/);
		await expect(handlers["incidents:list"]({})).rejects.toThrow(/no payload/);
		await handlers["audit:export"]({ format: "csv" });
		expect(api.exportAudit).toHaveBeenCalledWith("csv");
		await handlers["incidents:get"]({ id: "inc_1" });
		expect(api.incidentDetail).toHaveBeenCalledWith("inc_1");
		await handlers["prefs:set"]({ theme: "dark", notifyOnDeny: false });
		expect(api.setPreferences).toHaveBeenLastCalledWith({ theme: "dark", notifyOnDeny: false });
	});

	it("never runs two configuration-changing actions at once", async () => {
		let release: () => void = () => undefined;
		const slow = new Promise<void>((resolve) => {
			release = resolve;
		});
		const handlers = createIpcHandlers(
			services({
				connect: async () => {
					await slow;
					return { ok: true, message: "", log: "" };
				},
			}),
		);
		const first = handlers["claude:connect"](undefined);
		await expect(handlers["claude:disconnect"](undefined)).rejects.toThrow(/still running/);
		await expect(handlers["selftest:run"](undefined)).rejects.toThrow(/still running/);
		release();
		await expect(first).resolves.toMatchObject({ ok: true });
		await expect(handlers["claude:disconnect"](undefined)).resolves.toMatchObject({ ok: true });
	});
});

describe("isTrustedSender", () => {
	it.each([
		["app://aidr/index.html", true],
		["app://aidr/", true],
		["app://evil/index.html", false],
		["file:///C:/app/index.html", false],
		["https://aidr/index.html", false],
		["", false],
		[undefined, false],
	])("%s -> %s", (url, expected) => {
		expect(isTrustedSender(url)).toBe(expected);
	});
});
