import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	commands: new Map<string, () => Promise<void>>(),
	getConfiguration: vi.fn(),
	loadConfig: vi.fn(),
	getRecentEntries: vi.fn(),
	showInformationMessage: vi.fn(),
	showWarningMessage: vi.fn(),
	configurationUpdate: vi.fn(),
}));

vi.mock("@singularityrd/aidr-core", () => ({
	ConfigSchema: { parse: (value: unknown) => value },
	ControlPlaneClient: class {},
	checkForUpdate: vi.fn(),
	getInstallationId: vi.fn(),
	getRecentEntries: mocks.getRecentEntries,
	loadConfig: mocks.loadConfig,
	pruneOrphanedTmpFiles: vi.fn(() => Promise.resolve()),
	resolvePath: () => "/test/.singularity-aidr",
}));

vi.mock("vscode", () => ({
	version: "1.99.0",
	commands: {
		registerCommand: (name: string, callback: () => Promise<void>) => {
			mocks.commands.set(name, callback);
			return { dispose() {} };
		},
	},
	workspace: {
		getConfiguration: mocks.getConfiguration,
		workspaceFolders: [],
	},
	window: {
		showInformationMessage: mocks.showInformationMessage,
		showWarningMessage: mocks.showWarningMessage,
	},
}));

import { activateManagedHooksExtension } from "../shared_extension.js";

describe("VS Code Local hook setting prerequisite", () => {
	const installer = {
		installManagedHooks: vi.fn(),
		removeManagedHooks: vi.fn(),
		getHookHealth: vi.fn(),
	};
	const context = { extension: { packageJSON: { version: "0.6.0" } }, subscriptions: [] };
	let localHooksEnabled = false;

	beforeEach(() => {
		vi.clearAllMocks();
		mocks.commands.clear();
		localHooksEnabled = false;
		mocks.getConfiguration.mockImplementation((section?: string) => {
			if (section === "chat") {
				return {
					get: (_key: string, fallback = false) => localHooksEnabled ?? fallback,
					update: mocks.configurationUpdate,
				};
			}
			return {
				get: (key: string, fallback: unknown) => (key === "aidr.vscode.scope" ? "user" : fallback),
			};
		});
		mocks.loadConfig.mockResolvedValue({
			version_check: { enabled: false },
			auth: { api_key: "test-token" },
			logging: {},
		});
		mocks.getRecentEntries.mockResolvedValue([]);
		installer.installManagedHooks.mockResolvedValue({
			configPath: "/test/.claude/settings.json",
			runnerPath: "/test/aidr-hook.cjs",
			installedEvents: ["PreToolUse", "PostToolUse"],
			managedCommands: ["aidr-hook vscode"],
		});
		installer.getHookHealth.mockResolvedValue({
			configPath: "/test/.claude/settings.json",
			runnerPath: "/test/aidr-hook.cjs",
			installedEvents: ["PreToolUse", "PostToolUse"],
			managedCommands: ["aidr-hook vscode"],
		});
	});

	it("requires the user-managed setting and reports it without changing it", async () => {
		activateManagedHooksExtension(context as never, {
			hostName: "VS Code",
			scopeSettingKey: "aidr.vscode.scope",
			installer,
		});

		await mocks.commands.get("aidr.enableProtection")?.();
		expect(installer.installManagedHooks).not.toHaveBeenCalled();
		expect(mocks.showWarningMessage).toHaveBeenCalledWith(
			expect.stringContaining("chat.useClaudeHooks"),
		);
		expect(mocks.configurationUpdate).not.toHaveBeenCalled();

		await mocks.commands.get("aidr.showHookHealth")?.();
		expect(mocks.showInformationMessage).toHaveBeenCalledWith(
			expect.stringContaining("chat.useClaudeHooks: disabled (required"),
			{ modal: true },
		);
		expect(mocks.configurationUpdate).not.toHaveBeenCalled();
	});

	it("installs hooks after the user enables the required setting", async () => {
		localHooksEnabled = true;
		activateManagedHooksExtension(context as never, {
			hostName: "VS Code",
			scopeSettingKey: "aidr.vscode.scope",
			installer,
		});

		await mocks.commands.get("aidr.enableProtection")?.();
		expect(installer.installManagedHooks).toHaveBeenCalledTimes(1);
		expect(mocks.configurationUpdate).not.toHaveBeenCalled();
	});
});
