import { createChildLogger, getLogger, initSentry } from "@singularityrd/aidr-core";
import type * as vscode from "vscode";

import { activateManagedHooksExtension } from "./shared_extension.js";
import * as vscodeHookInstaller from "./vscode_hook_installer.js";

export function activate(context: vscode.ExtensionContext): void {
	// Initialize Sentry
	initSentry({ name: "aidr-extension-vscode" });

	const logger = createChildLogger(getLogger(), "vscode-extension");
	logger.info("Activating Singularity AIDR VS Code extension");

	activateManagedHooksExtension(context, {
		hostName: "VS Code",
		scopeSettingKey: "aidr.vscode.scope",
		installer: vscodeHookInstaller,
	});
}

export function deactivate(): void {
	// No background resources to dispose.
}
