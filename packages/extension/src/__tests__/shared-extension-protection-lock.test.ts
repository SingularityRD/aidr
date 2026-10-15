// C10: the machine-policy protection lock gates "Disable protection" and
// restores hooks a user deleted by hand; every refused attempt is recorded so
// `aidr heartbeat` reports it to the administrator.
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	commands: new Map<string, () => Promise<void>>(),
	executeCommand: vi.fn(() => Promise.resolve()),
	locked: { value: false },
	recordProtectionEvent: vi.fn(() => Promise.resolve(true)),
	showInformationMessage: vi.fn(),
	showWarningMessage: vi.fn(),
}));

vi.mock("@singularityrd/aidr-core", () => ({
	ConfigSchema: { parse: (value: unknown) => value },
	checkForUpdate: vi.fn(),
	formatSessionStartMessage: vi.fn(),
	getInstallationId: vi.fn(),
	getRecentEntries: vi.fn(() => Promise.resolve([])),
	loadConfig: vi.fn(() =>
		Promise.resolve({ mode: "local", version_check: { enabled: false }, auth: {}, logging: {} }),
	),
	runSessionStart: vi.fn(),
	pruneOrphanedTmpFiles: vi.fn(() => Promise.resolve()),
	readProtectionLock: () => ({
		locked: mocks.locked.value,
		source: mocks.locked.value ? "linux_policy_file" : "none",
	}),
	recordProtectionEvent: mocks.recordProtectionEvent,
	resolvePath: () => "/test/.singularity-aidr",
}));

vi.mock("vscode", () => ({
	version: "1.137.0",
	env: { appRoot: "" },
	commands: {
		registerCommand: (name: string, callback: () => Promise<void>) => {
			mocks.commands.set(name, callback);
			return { dispose() {} };
		},
		executeCommand: mocks.executeCommand,
	},
	workspace: {
		getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }),
		workspaceFolders: [],
	},
	window: {
		showInformationMessage: mocks.showInformationMessage,
		showWarningMessage: mocks.showWarningMessage,
		showErrorMessage: vi.fn(),
	},
}));

import { activateManagedHooksExtension } from "../shared_extension.js";

const health = (events: string[]) => ({
	configPath: "/test/.cursor/hooks.json",
	runnerPath: "/test/aidr-hook.cjs",
	installedEvents: events,
	managedCommands: events.length > 0 ? ["aidr-hook cursor"] : [],
	healthy: true,
	problems: [],
});

describe("protection lock from machine policy", () => {
	const installer = {
		installManagedHooks: vi.fn(),
		removeManagedHooks: vi.fn(),
		getHookHealth: vi.fn(),
		repairManagedHooks: vi.fn(),
	};
	const context = {
		extension: { packageJSON: { version: "0.6.0" } },
		subscriptions: [],
		asAbsolutePath: (relativePath: string) => `/extension/${relativePath}`,
	};
	const target = { hostName: "Cursor", scopeSettingKey: "aidr.cursor.scope", installer };

	beforeEach(() => {
		vi.clearAllMocks();
		mocks.commands.clear();
		installer.repairManagedHooks.mockResolvedValue([]);
		installer.removeManagedHooks.mockResolvedValue("/test/.cursor/hooks.json");
		installer.installManagedHooks.mockResolvedValue(health(["beforeShellExecution"]));
	});

	it("refuses Disable protection while locked, keeps the hooks and records the attempt", async () => {
		mocks.locked.value = true;
		installer.getHookHealth.mockResolvedValue(health(["beforeShellExecution"]));
		activateManagedHooksExtension(context as never, target);
		expect(mocks.executeCommand).toHaveBeenCalledWith("setContext", "aidr.protectionLocked", true);
		await mocks.commands.get("aidr.disableProtection")?.();
		expect(installer.removeManagedHooks).not.toHaveBeenCalled();
		expect(mocks.recordProtectionEvent).toHaveBeenCalledWith("cursor", "disable_blocked");
		expect(String(mocks.showWarningMessage.mock.calls.at(-1)?.[0])).toContain(
			"locked by your organization's policy",
		);
	});

	it("restores hooks the user deleted by hand when locked", async () => {
		mocks.locked.value = true;
		installer.getHookHealth.mockResolvedValue(health([]));
		activateManagedHooksExtension(context as never, target);
		await vi.waitFor(() => expect(installer.installManagedHooks).toHaveBeenCalledTimes(1));
		await vi.waitFor(() =>
			expect(mocks.recordProtectionEvent).toHaveBeenCalledWith("cursor", "hook_restored"),
		);
	});

	it("still lets the user disable protection when no lock is set, and counts it", async () => {
		mocks.locked.value = false;
		activateManagedHooksExtension(context as never, target);
		expect(mocks.executeCommand).toHaveBeenCalledWith("setContext", "aidr.protectionLocked", false);
		await mocks.commands.get("aidr.disableProtection")?.();
		expect(installer.removeManagedHooks).toHaveBeenCalledWith("user");
		expect(mocks.recordProtectionEvent).toHaveBeenCalledWith("cursor", "disabled_by_user");
		await new Promise(setImmediate);
		expect(installer.installManagedHooks).not.toHaveBeenCalled();
	});
});
