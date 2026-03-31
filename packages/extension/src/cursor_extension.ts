import { createChildLogger, getLogger } from "@singularityrd/aidr-core";
import type * as vscode from "vscode";
import * as cursorHookInstaller from "./cursor_hook_installer.js";
import { activateManagedHooksExtension } from "./shared_extension.js";
import { initSentry } from "./sentry.js";

export function activate(context: vscode.ExtensionContext): void {
	// Initialize Sentry
	initSentry();

	const logger = createChildLogger(getLogger(), "cursor-extension");
	logger.info("Activating Singularity AIDR Cursor extension");

	activateManagedHooksExtension(context, {
		hostName: "Cursor",
		scopeSettingKey: "aidr.cursor.scope",
		installer: cursorHookInstaller,
	});
}

export function deactivate(): void {
	// No background resources to dispose.
}
