import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	loadConfig: vi.fn(),
	getInstallationId: vi.fn(),
	checkForUpdate: vi.fn(),
	loadManagedState: vi.fn(),
	showInformationMessage: vi.fn(),
	showWarningMessage: vi.fn(),
	vscodeVersion: { value: "1.137.0" },
}));

vi.mock("@singularityrd/aidr-core", () => ({
	loadConfig: mocks.loadConfig,
	getInstallationId: mocks.getInstallationId,
	checkForUpdate: mocks.checkForUpdate,
	loadManagedState: mocks.loadManagedState,
	managedStatePath: () => "/test/.singularity-aidr/managed.json",
	getEffectiveManagedApiKey: (apiKey: string | undefined) => apiKey?.trim() || undefined,
	// Same contract as core: managed + control plane -> that control plane.
	versionCheckEndpoint: (config?: { mode?: string; control_plane?: { endpoint?: string } }) =>
		config?.mode === "managed" && config.control_plane?.endpoint
			? `${config.control_plane.endpoint}/v1/version-check`
			: "https://public.example/v1/version-check",
	pruneOrphanedTmpFiles: () => Promise.resolve(),
	readProtectionLock: () => ({ locked: false, source: "none" }),
	recordProtectionEvent: () => Promise.resolve(true),
	resolvePath: () => "/test/.singularity-aidr",
}));

vi.mock("vscode", () => ({
	get version() {
		return mocks.vscodeVersion.value;
	},
	env: { appRoot: "" },
	commands: { registerCommand: () => ({ dispose() {} }) },
	window: {
		showInformationMessage: mocks.showInformationMessage,
		showWarningMessage: mocks.showWarningMessage,
	},
}));

import { activateManagedHooksExtension, formatUpdateNotice } from "../shared_extension.js";

const context = { extension: { packageJSON: { version: "0.6.0" } }, subscriptions: [] };
const target = {
	hostName: "Cursor",
	scopeSettingKey: "aidr.cursor.scope",
	installer: {
		installManagedHooks: vi.fn(),
		removeManagedHooks: vi.fn(),
		getHookHealth: vi.fn(),
		repairManagedHooks: vi.fn(),
	},
};

describe("extension version-check opt-in", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		mocks.vscodeVersion.value = "1.137.0";
		mocks.getInstallationId.mockResolvedValue("test-installation-id");
		mocks.checkForUpdate.mockResolvedValue(null);
		mocks.loadManagedState.mockResolvedValue({});
		target.installer.repairManagedHooks.mockResolvedValue([]);
	});

	it("does not create an installation ID or contact update service by default", async () => {
		mocks.loadConfig.mockResolvedValue({ version_check: { enabled: false } });
		activateManagedHooksExtension(context as never, target);
		await new Promise(setImmediate);
		expect(mocks.getInstallationId).not.toHaveBeenCalled();
		expect(mocks.checkForUpdate).not.toHaveBeenCalled();
	});

	it("checks only when enabled, on the public endpoint for a local install", async () => {
		mocks.loadConfig.mockResolvedValue({ mode: "local", version_check: { enabled: true } });
		activateManagedHooksExtension(context as never, target);
		await vi.waitFor(() => expect(mocks.checkForUpdate).toHaveBeenCalledTimes(1));
		expect(mocks.checkForUpdate).toHaveBeenCalledWith(
			"0.6.0",
			undefined,
			undefined,
			{ agentRuntime: "cursor", agentRuntimeVersion: "1.137.0", iid: "test-installation-id" },
			undefined,
			"https://public.example/v1/version-check",
		);
	});

	it("asks the managed control plane, never the public endpoint, for a managed install", async () => {
		mocks.loadConfig.mockResolvedValue({
			mode: "managed",
			version_check: { enabled: true },
			control_plane: { endpoint: "https://cp.customer.example" },
			auth: { api_key: "managed-key" },
			licensing: {},
		});
		activateManagedHooksExtension(context as never, target);
		await vi.waitFor(() => expect(mocks.checkForUpdate).toHaveBeenCalledTimes(1));
		const args = mocks.checkForUpdate.mock.calls[0] ?? [];
		expect(args[5]).toBe("https://cp.customer.example/v1/version-check");
		expect(args[4]).toBe("managed-key");
	});

	it("points the update notice at a reachable install path, not the private repository", async () => {
		mocks.loadConfig.mockResolvedValue({ mode: "local", version_check: { enabled: true } });
		mocks.checkForUpdate.mockResolvedValue({
			currentVersion: "0.6.0",
			latestVersion: "0.7.0",
			updateAvailable: true,
		});
		activateManagedHooksExtension(context as never, target);
		await vi.waitFor(() => expect(mocks.showInformationMessage).toHaveBeenCalledTimes(1));
		const notice = formatUpdateNotice({ currentVersion: "0.6.0", latestVersion: "0.7.0" });
		expect(mocks.showInformationMessage).toHaveBeenCalledWith(notice);
		expect(notice).not.toContain("github.com");
		expect(notice).toContain("v0.6.0 → v0.7.0");
	});

	it("warns once when the host build is outside the verified host versions", async () => {
		mocks.loadConfig.mockResolvedValue({ version_check: { enabled: false } });
		mocks.vscodeVersion.value = "1.150.0";
		const store = new Map<string, unknown>();
		const globalState = {
			get: (key: string) => store.get(key),
			update: async (key: string, value: unknown) => {
				store.set(key, value);
			},
		};
		const vsCodeTarget = { ...target, hostName: "VS Code", scopeSettingKey: "aidr.vscode.scope" };
		activateManagedHooksExtension({ ...context, globalState } as never, vsCodeTarget);
		activateManagedHooksExtension({ ...context, globalState } as never, vsCodeTarget);
		const hostWarnings = mocks.showWarningMessage.mock.calls.filter(([message]) =>
			String(message).includes("unverified"),
		);
		expect(hostWarnings).toHaveLength(1);
		expect(String(hostWarnings[0]?.[0])).toContain("VS Code 1.150.0, which is newer than");
	});
});
