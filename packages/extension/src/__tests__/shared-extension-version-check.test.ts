import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	loadConfig: vi.fn(),
	getInstallationId: vi.fn(),
	checkForUpdate: vi.fn(),
	showInformationMessage: vi.fn(),
}));

vi.mock("@singularityrd/aidr-core", () => ({
	loadConfig: mocks.loadConfig,
	getInstallationId: mocks.getInstallationId,
	checkForUpdate: mocks.checkForUpdate,
	pruneOrphanedTmpFiles: () => Promise.resolve(),
	resolvePath: () => "/test/.singularity-aidr",
}));

vi.mock("vscode", () => ({
	version: "1.99.0",
	commands: { registerCommand: () => ({ dispose() {} }) },
	window: { showInformationMessage: mocks.showInformationMessage },
}));

import { activateManagedHooksExtension } from "../shared_extension.js";

const context = { extension: { packageJSON: { version: "0.6.0" } }, subscriptions: [] };
const target = {
	hostName: "Cursor",
	scopeSettingKey: "aidr.cursor.scope",
	installer: {
		installManagedHooks: vi.fn(),
		removeManagedHooks: vi.fn(),
		getHookHealth: vi.fn(),
	},
};

describe("extension version-check opt-in", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		mocks.getInstallationId.mockResolvedValue("test-installation-id");
		mocks.checkForUpdate.mockResolvedValue(null);
	});

	it("does not create an installation ID or contact update service by default", async () => {
		mocks.loadConfig.mockResolvedValue({ version_check: { enabled: false } });
		activateManagedHooksExtension(context as never, target);
		await new Promise(setImmediate);
		expect(mocks.getInstallationId).not.toHaveBeenCalled();
		expect(mocks.checkForUpdate).not.toHaveBeenCalled();
	});

	it("checks only when enabled and includes the host context", async () => {
		mocks.loadConfig.mockResolvedValue({ version_check: { enabled: true } });
		activateManagedHooksExtension(context as never, target);
		await vi.waitFor(() => expect(mocks.checkForUpdate).toHaveBeenCalledTimes(1));
		expect(mocks.checkForUpdate).toHaveBeenCalledWith(
			"0.6.0",
			undefined,
			undefined,
			{ agentRuntime: "cursor", agentRuntimeVersion: "1.99.0", iid: "test-installation-id" },
		);
	});
});
