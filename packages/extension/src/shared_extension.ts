import { access, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import {
	type AgentRuntime,
	ConfigSchema,
	checkForUpdate,
	formatSessionStartMessage,
	getInstallationId,
	getRecentEntries,
	loadConfig,
	pruneOrphanedTmpFiles,
	resolvePath,
	runSessionStart,
} from "@singularityrd/aidr-core";
import * as vscode from "vscode";
import { localize } from "./l10n.js";
import type {
	ManagedHookHealth,
	ManagedHookInstallOptions,
	ManagedHookScope,
} from "./managedHooks.js";
import { MAX_INSPECTED_OUTPUT_BYTES } from "./output-inspection.js";

interface ManagedHookInstaller {
	installManagedHooks(options: ManagedHookInstallOptions): Promise<ManagedHookHealth>;
	removeManagedHooks(scope: ManagedHookScope): Promise<string>;
	getHookHealth(options: ManagedHookInstallOptions): Promise<ManagedHookHealth>;
}

interface ExtensionTarget {
	hostName: string;
	scopeSettingKey: string;
	installer: ManagedHookInstaller;
}

export function activateManagedHooksExtension(
	context: vscode.ExtensionContext,
	target: ExtensionTarget,
): void {
	// Best-effort cleanup of orphaned .tmp files from crashed atomic writes
	pruneOrphanedTmpFiles(resolvePath("~/.singularity-aidr")).catch(() => {});

	const version = (context.extension.packageJSON as Record<string, unknown>).version as string;
	if (version) {
		const agentRuntime: AgentRuntime = target.hostName === "Cursor" ? "cursor" : "vscode";
		const aidrDirPath = resolvePath("~/.singularity-aidr");
		loadConfig()
			.then(async (config) => {
				if (!config.version_check.enabled) return null;
				const iid = await getInstallationId(aidrDirPath).catch(() => undefined);
				return checkForUpdate(version, undefined, undefined, {
					agentRuntime,
					agentRuntimeVersion: vscode.version,
					iid,
				});
			})
			.then((result) => {
				if (result?.updateAvailable) {
					void vscode.window.showInformationMessage(
						localize(
							"Singularity AIDR: Update available v{0} → v{1} (https://github.com/singularityrd/aidr)",
							result.currentVersion,
							result.latestVersion,
						),
					);
				}
			})
			.catch(() => {
				// Fail-open: never block extension activation
			});
	}

	context.subscriptions.push(
		vscode.commands.registerCommand("aidr.enableProtection", async () => {
			await withErrorBoundary(async () => {
				if (warnIfVsCodeLocalHooksDisabled(target.hostName)) return;
				const scope = getScope(target.scopeSettingKey);
				const health = await target.installer.installManagedHooks({ context, scope });

				const cfg = await loadConfig();
				if (cfg.mode !== "managed") {
					void vscode.window.showInformationMessage(
						localize(
							"Singularity AIDR enabled for {0}. Managed hooks configured at {1}.",
							target.hostName,
							health.configPath,
						),
					);
					return;
				}

				// Reuse the shared persisted bootstrap and enrollment exchange. A retry
				// after browser authorization polls the same device session.
				const agentRuntime: AgentRuntime = target.hostName === "Cursor" ? "cursor" : "vscode";
				const startup = await runSessionStart({
					plugins: [],
					threatsDir: context.asAbsolutePath(path.join("dist", "resources", "threats")),
					allowlistsDir: context.asAbsolutePath(path.join("dist", "resources", "allowlists")),
					version,
					agentRuntime,
					agentRuntimeVersion: vscode.version,
				});
				if (startup.enabled) {
					void vscode.window.showInformationMessage(
						localize(
							"Singularity AIDR enabled for {0}. Managed hooks configured at {1}.",
							target.hostName,
							health.configPath,
						),
					);
					// Bundled rules that did not load or verify: protection is degraded, say so.
					if (startup.rulesIncomplete) {
						void vscode.window.showWarningMessage(formatSessionStartMessage(version, startup));
					}
					return;
				}
				if (startup.disabled_reason === "enrollment_repair_required") {
					void vscode.window.showWarningMessage(formatSessionStartMessage(version, startup));
					return;
				}
				if (startup.bootstrap) {
					const { verification_url: verifyUrl, user_code: userCode } = startup.bootstrap;
					const openBrowser = localize("Open browser");
					const choice = await vscode.window.showInformationMessage(
						localize(
							"Singularity AIDR hooks installed. To activate managed protection, open {0} and enter code {1}. After authorizing, run Enable protection again to finish activation.",
							verifyUrl,
							userCode,
						),
						{ modal: true },
						openBrowser,
					);
					if (choice === openBrowser) {
						void vscode.env.openExternal(vscode.Uri.parse(verifyUrl));
					}
					return;
				}

				void vscode.window.showWarningMessage(
					localize(
						"Singularity AIDR hooks installed, but managed protection could not activate ({0}). Check the AIDR configuration and try Enable protection again.",
						startup.disabled_reason ?? localize("startup unavailable"),
					),
				);
			});
		}),
	);

	context.subscriptions.push(
		vscode.commands.registerCommand("aidr.disableProtection", async () => {
			await withErrorBoundary(async () => {
				const scope = getScope(target.scopeSettingKey);
				const configPath = await target.installer.removeManagedHooks(scope);
				vscode.window.showInformationMessage(
					localize("Singularity AIDR managed hooks removed from {0}.", configPath),
				);
			});
		}),
	);

	context.subscriptions.push(
		vscode.commands.registerCommand("aidr.openConfig", async () => {
			await withErrorBoundary(async () => {
				const configPath = path.join(resolvePath("~/.singularity-aidr"), "config.json");
				await ensureFile(configPath, `${JSON.stringify(ConfigSchema.parse({}), null, 2)}\n`);
				const document = await vscode.workspace.openTextDocument(configPath);
				await vscode.window.showTextDocument(document);
			});
		}),
	);

	context.subscriptions.push(
		vscode.commands.registerCommand("aidr.openAuditLog", async () => {
			await withErrorBoundary(async () => {
				const config = await loadConfig();
				const auditPath = resolvePath(config.logging.path);
				await ensureFile(auditPath, "");
				const document = await vscode.workspace.openTextDocument(auditPath);
				await vscode.window.showTextDocument(document);
			});
		}),
	);

	context.subscriptions.push(
		vscode.commands.registerCommand("aidr.showHookHealth", async () => {
			await withErrorBoundary(async () => {
				const scope = getScope(target.scopeSettingKey);
				const health = await target.installer.getHookHealth({ context, scope });
				const config = await loadConfig();
				const recentEntries = await getRecentEntries(config.logging, 1);
				const latest =
					recentEntries.length > 0 &&
					typeof recentEntries[0] === "object" &&
					recentEntries[0] !== null
						? (recentEntries[0] as Record<string, unknown>)
						: undefined;
				const lastVerdict =
					latest && typeof latest.verdict === "string" && typeof latest.severity === "string"
						? `${latest.verdict} (${latest.severity})`
						: localize("none");

				const message = [
					localize("target: {0}", target.hostName),
					...describeVsCodeLocalHooksSetting(target.hostName),
					localize("hooks config: {0}", health.configPath),
					localize(
						"hook command: {0}",
						health.managedCommands.length > 0
							? health.managedCommands.join(" | ")
							: localize("none"),
					),
					localize("runner bundle: {0}", health.runnerPath ?? localize("not found")),
					localize(
						"managed events: {0}",
						health.installedEvents.length > 0
							? health.installedEvents.join(", ")
							: localize("none"),
					),
					...describeOutputInspection(target.hostName),
					localize("last verdict: {0}", lastVerdict),
				].join("\n");

				void vscode.window.showInformationMessage(message, { modal: true });
			});
		}),
	);
}

function isVsCodeLocalHooksEnabled(): boolean {
	try {
		return vscode.workspace.getConfiguration("chat").get<boolean>("useClaudeHooks", false);
	} catch {
		return false;
	}
}

function warnIfVsCodeLocalHooksDisabled(hostName: string): boolean {
	if (hostName !== "VS Code" || isVsCodeLocalHooksEnabled()) return false;
	void vscode.window.showWarningMessage(
		localize(
			"VS Code Local hooks require chat.useClaudeHooks to be enabled in User Settings. Enable that setting, then run Enable protection again. Singularity AIDR does not change editor settings.",
		),
	);
	return true;
}

function describeVsCodeLocalHooksSetting(hostName: string): string[] {
	if (hostName !== "VS Code") return [];
	const state = isVsCodeLocalHooksEnabled() ? localize("enabled") : localize("disabled");
	return [
		localize(
			"VS Code Local hook setting chat.useClaudeHooks: {0} (required; Singularity AIDR does not change editor settings)",
			state,
		),
	];
}

function describeOutputInspection(hostName: string): string[] {
	if (hostName === "Cursor") {
		return [
			localize(
				"tool output inspection: MCP replacement before model consumption; non-MCP advisory only",
			),
			localize(
				"assistant response inspection: observe-only after display (host cannot block or replace)",
			),
			outputInspectionLimitLine(),
		];
	}
	return [
		localize("tool output inspection: blocks further model processing"),
		localize("assistant response inspection: unsupported by the host hook API"),
		outputInspectionLimitLine(),
	];
}

function outputInspectionLimitLine(): string {
	return localize(
		"output inspection limit: {0} bytes; larger output is coverage-limited, never clean",
		MAX_INSPECTED_OUTPUT_BYTES,
	);
}

function getScope(scopeSettingKey: string): ManagedHookScope {
	const value = vscode.workspace.getConfiguration().get<string>(scopeSettingKey);
	return value === "workspace" ? "workspace" : "user";
}

async function ensureFile(filePath: string, content: string): Promise<void> {
	try {
		await access(filePath);
	} catch {
		await mkdir(path.dirname(filePath), { recursive: true });
		await writeFile(filePath, content, "utf8");
	}
}

async function withErrorBoundary(work: () => Promise<void>): Promise<void> {
	try {
		await work();
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		void vscode.window.showErrorMessage(localize("Singularity AIDR: {0}", message));
	}
}
