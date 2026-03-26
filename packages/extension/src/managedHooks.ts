import type * as vscode from "vscode";

export type ManagedHookScope = "workspace" | "user";

export interface ManagedHookInstallOptions {
	context: vscode.ExtensionContext;
	scope: ManagedHookScope;
}

export interface ManagedHookHealth {
	configPath: string;
	runnerPath: string | undefined;
	installedEvents: string[];
	managedCommands: string[];
}
