import * as vscode from "vscode";

/**
 * Translate a runtime message through the editor's display language
 * (`vscode.l10n`, bundles in ../l10n). The English message is the key and
 * `{0}`, `{1}` mark arguments. When the host exposes no l10n API (an old fork,
 * or a test stub) the English message is formatted directly, so a missing
 * translation never stops a command.
 */
export function localize(message: string, ...args: Array<string | number | boolean>): string {
	try {
		const l10n = vscode.l10n;
		if (l10n && typeof l10n.t === "function") return l10n.t(message, ...args);
	} catch {
		// No l10n API: fall through to the English text.
	}
	return message.replace(/\{(\d+)\}/g, (match, index: string) => {
		const value = args[Number(index)];
		return value === undefined ? match : String(value);
	});
}
