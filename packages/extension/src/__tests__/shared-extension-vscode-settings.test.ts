import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	commands: new Map<string, () => Promise<void>>(),
	getConfiguration: vi.fn(),
	loadConfig: vi.fn(),
	formatSessionStartMessage: vi.fn(),
	runSessionStart: vi.fn(),
	getRecentEntries: vi.fn(),
	showInformationMessage: vi.fn(),
	showWarningMessage: vi.fn(),
	configurationUpdate: vi.fn(),
}));

vi.mock("@singularityrd/aidr-core", () => ({
	ConfigSchema: { parse: (value: unknown) => value },
	ControlPlaneClient: class {},
	checkForUpdate: vi.fn(),
	formatSessionStartMessage: mocks.formatSessionStartMessage,
	getInstallationId: vi.fn(),
	getRecentEntries: mocks.getRecentEntries,
	loadConfig: mocks.loadConfig,
	runSessionStart: mocks.runSessionStart,
	pruneOrphanedTmpFiles: vi.fn(() => Promise.resolve()),
	readProtectionLock: () => ({ locked: false, source: "none" }),
	recordProtectionEvent: () => Promise.resolve(true),
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
		repairManagedHooks: vi.fn(),
	};
	const context = {
		extension: { packageJSON: { version: "0.6.0" } },
		subscriptions: [],
		asAbsolutePath: (relativePath: string) => `/extension/${relativePath}`,
	};
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
			mode: "local",
			version_check: { enabled: false },
			auth: { api_key: "test-token" },
			logging: {},
		});
		mocks.getRecentEntries.mockResolvedValue([]);
		installer.repairManagedHooks.mockResolvedValue([]);
		installer.installManagedHooks.mockResolvedValue({
			configPath: "/test/.claude/settings.json",
			runnerPath: "/test/aidr-hook.cjs",
			installedEvents: ["PreToolUse", "PostToolUse"],
			managedCommands: ["aidr-hook vscode"],
			problems: [],
			healthy: true,
		});
		installer.getHookHealth.mockResolvedValue({
			configPath: "/test/.claude/settings.json",
			runnerPath: "/test/aidr-hook.cjs",
			installedEvents: ["PreToolUse", "PostToolUse"],
			managedCommands: ["aidr-hook vscode"],
			problems: [],
			healthy: true,
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
		expect(mocks.runSessionStart).not.toHaveBeenCalled();
		expect(mocks.configurationUpdate).not.toHaveBeenCalled();
	});

	it("finishes managed browser activation through the shared persisted bootstrap on retry", async () => {
		localHooksEnabled = true;
		mocks.loadConfig.mockResolvedValue({
			mode: "managed",
			version_check: { enabled: false },
			auth: {},
		});
		mocks.runSessionStart
			.mockResolvedValueOnce({
				enabled: false,
				bootstrap: { verification_url: "https://aidr.test/verify", user_code: "ABCD" },
			})
			.mockResolvedValueOnce({ enabled: true });
		activateManagedHooksExtension(context as never, {
			hostName: "VS Code",
			scopeSettingKey: "aidr.vscode.scope",
			installer,
		});
		await mocks.commands.get("aidr.enableProtection")?.();
		expect(mocks.showInformationMessage).toHaveBeenCalledWith(
			expect.stringContaining("run Enable protection again to finish activation"),
			{ modal: true },
			"Open browser",
		);
		await mocks.commands.get("aidr.enableProtection")?.();
		expect(mocks.runSessionStart).toHaveBeenCalledTimes(2);
		expect(mocks.runSessionStart).toHaveBeenCalledWith(
			expect.objectContaining({ agentRuntime: "vscode", plugins: [] }),
		);
		expect(mocks.showInformationMessage).toHaveBeenLastCalledWith(
			expect.stringContaining("enabled for VS Code"),
		);
	});

	it.each(["VS Code", "Cursor"])(
		"shows shared operator repair guidance in %s without offering a stale bootstrap",
		async (hostName) => {
			localHooksEnabled = true;
			mocks.loadConfig.mockResolvedValue({
				mode: "managed",
				version_check: { enabled: false },
				auth: {},
			});
			const startup = {
				enabled: false,
				disabled_reason: "enrollment_repair_required",
				bootstrap: { verification_url: "https://aidr.test/stale", user_code: "CONSUMED-CODE" },
				scanResults: [],
				versionCheck: null,
			};
			mocks.runSessionStart.mockResolvedValueOnce(startup);
			mocks.formatSessionStartMessage.mockReturnValueOnce(
				"Operator repair required: revoke affected key and approve fresh pairing.",
			);
			activateManagedHooksExtension(context as never, {
				hostName,
				scopeSettingKey: "aidr.vscode.scope",
				installer,
			});
			await mocks.commands.get("aidr.enableProtection")?.();
			expect(mocks.formatSessionStartMessage).toHaveBeenCalledWith("0.6.0", startup);
			expect(mocks.showWarningMessage).toHaveBeenCalledWith(
				"Operator repair required: revoke affected key and approve fresh pairing.",
			);
			expect(mocks.showInformationMessage).not.toHaveBeenCalled();
		},
	);
});
