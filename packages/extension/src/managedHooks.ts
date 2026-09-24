import type * as vscode from "vscode";

export type ManagedHookScope = "workspace" | "user";

export interface ManagedHookInstallOptions {
	context: vscode.ExtensionContext;
	scope: ManagedHookScope;
}

/**
 * Events that carry a managed hook: those in `registrationOrder` first, in that
 * order, then any other managed event. `installedEvents` therefore never depends
 * on the key order of the customer's hooks file.
 */
export function inRegistrationOrder(
	managedEvents: readonly string[],
	registrationOrder: readonly string[],
): string[] {
	return [
		...registrationOrder.filter((event) => managedEvents.includes(event)),
		...managedEvents.filter((event) => !registrationOrder.includes(event)),
	];
}

export interface ManagedHookHealth {
	configPath: string;
	runnerPath: string | undefined;
	installedEvents: string[];
	managedCommands: string[];
}
