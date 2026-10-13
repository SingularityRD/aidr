import { access, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import {
	type AgentRuntime,
	type Config,
	ConfigSchema,
	checkForUpdate,
	formatSessionStartMessage,
	getEffectiveManagedApiKey,
	getInstallationId,
	getRecentEntries,
	loadConfig,
	loadManagedState,
	managedStatePath,
	pruneOrphanedTmpFiles,
	resolvePath,
	runSessionStart,
	versionCheckEndpoint,
} from "@singularityrd/aidr-core";
import * as vscode from "vscode";

import type { ExtensionHookHost } from "./hook-responses.js";
import { assessHostVersion, detectHostVersion, type HostVersionAssessment } from "./host-compat.js";
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
	repairManagedHooks(context: vscode.ExtensionContext): Promise<ManagedHookHealth[]>;
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

	const host = hookHostOf(target);
	const version = (context.extension.packageJSON as Record<string, unknown>).version as string;
	const hostVersion = detectHostVersion(host, vscode.version, safeAppRoot());
	const hostAssessment = assessHostVersion(host, hostVersion);
	void repairInstalledHooks(context, target);
	warnOnceForUnverifiedHost(context, hostAssessment);
	if (version) {
		void checkForExtensionUpdate(version, host);
	}

	context.subscriptions.push(
		vscode.commands.registerCommand("aidr.enableProtection", async () => {
			await withErrorBoundary(async () => {
				if (warnIfVsCodeLocalHooksDisabled(target.hostName)) return;
				const scope = getScope(target.scopeSettingKey);
				const health = await target.installer.installManagedHooks({ context, scope });
				warnIfUnreachable(health);

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
					...describeHookHealth(health, hostAssessment),
					localize("target: {0}", target.hostName),
					...describeVsCodeLocalHooksSetting(target.hostName),
					localize("hooks config: {0}", health.configPath),
					localize(
						"hook command: {0}",
						health.managedCommands.length > 0
							? health.managedCommands.join(" | ")
							: localize("none"),
					),
					localize(
						"runner bundle: {0} (resolved through the stable hook launcher)",
						health.runnerPath ?? localize("not found"),
					),
					localize(
						"managed events: {0}",
						health.installedEvents.length > 0
							? health.installedEvents.join(", ")
							: localize("none"),
					),
					...describeOutputInspection(target.hostName),
					localize("last verdict: {0}", lastVerdict),
				].join("\n");

				showHealthReport(health, message);
			});
		}),
	);
}

function hookHostOf(target: ExtensionTarget): ExtensionHookHost {
	return target.hostName === "Cursor" ? "cursor" : "vscode";
}

function safeAppRoot(): string | undefined {
	try {
		return vscode.env.appRoot;
	} catch {
		return undefined;
	}
}

function describeHookHealth(
	health: ManagedHookHealth,
	hostAssessment: HostVersionAssessment,
): string[] {
	return [
		`status: ${describeHealthStatus(health)}`,
		...health.problems.map((problem) => `problem: ${problem}`),
		`host version: ${hostAssessment.version ?? "unknown"} (${hostAssessment.status}; verified: ${hostAssessment.verified.join(", ")})`,
	];
}

/** A modal warning when installed hooks cannot reach a runner, otherwise informational. */
function showHealthReport(health: ManagedHookHealth, message: string): void {
	if (health.installedEvents.length > 0 && !health.healthy) {
		void vscode.window.showWarningMessage(message, { modal: true });
		return;
	}
	void vscode.window.showInformationMessage(message, { modal: true });
}

function warnIfUnreachable(health: ManagedHookHealth): void {
	if (health.healthy) return;
	void vscode.window.showWarningMessage(
		`Singularity AIDR hooks were written to ${health.configPath} but cannot reach a hook runner: ${health.problems.join("; ")}`,
	);
}

export function describeHealthStatus(health: ManagedHookHealth): string {
	if (health.installedEvents.length === 0) return "not installed";
	return health.healthy
		? "protected (every managed hook reaches a hook runner)"
		: "BROKEN: managed hooks are installed but cannot reach a hook runner; tool calls are denied until repaired (run Enable protection)";
}

/**
 * On every activation (onStartupFinished), re-point installed managed hooks at
 * this extension version so an update never leaves a dangling shim. Scopes
 * without managed entries are not touched.
 */
async function repairInstalledHooks(
	context: vscode.ExtensionContext,
	target: ExtensionTarget,
): Promise<void> {
	try {
		const results = await target.installer.repairManagedHooks(context);
		const broken = results.filter((health) => !health.healthy);
		if (broken.length === 0) return;
		void vscode.window.showWarningMessage(
			`Singularity AIDR hooks in ${broken.map((health) => health.configPath).join(", ")} could not be repaired: ${broken.flatMap((health) => health.problems).join("; ")}. Run Enable protection or Show hook health.`,
		);
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		void vscode.window.showWarningMessage(
			`Singularity AIDR could not verify its installed hooks (${message}). Run Show hook health.`,
		);
	}
}

const HOST_WARNING_STATE_KEY = "aidr.hostVersionWarning";

/** Show the unverified-host warning once per host version. */
function warnOnceForUnverifiedHost(
	context: vscode.ExtensionContext,
	assessment: HostVersionAssessment,
): void {
	if (!assessment.warning) return;
	const key = `${assessment.host}@${assessment.version ?? "unknown"}`;
	const state = (context as Partial<vscode.ExtensionContext>).globalState;
	if (state?.get<string>(HOST_WARNING_STATE_KEY) === key) return;
	void state?.update(HOST_WARNING_STATE_KEY, key);
	void vscode.window.showWarningMessage(assessment.warning);
}

/**
 * Opt-in update check. A managed install asks its own control plane
 * (versionCheckEndpoint), like the core session start, so a managed
 * deployment never contacts the public endpoint.
 */
async function checkForExtensionUpdate(version: string, host: ExtensionHookHost): Promise<void> {
	try {
		const config = await loadConfig();
		if (!config.version_check.enabled) return;
		const aidrDirPath = resolvePath("~/.singularity-aidr");
		const iid = await getInstallationId(aidrDirPath).catch(() => undefined);
		const result = await checkForUpdate(
			version,
			undefined,
			undefined,
			{ agentRuntime: host, agentRuntimeVersion: vscode.version, iid },
			await managedVersionCheckToken(config),
			versionCheckEndpoint(config),
		);
		if (result?.updateAvailable) {
			void vscode.window.showInformationMessage(formatUpdateNotice(result));
		}
	} catch {
		// Advisory only: never block extension activation.
	}
}

async function managedVersionCheckToken(config: Config): Promise<string | undefined> {
	if (config.mode !== "managed") return undefined;
	const configured = config.auth.api_key?.trim() || config.auth.enrollment_token?.trim();
	try {
		const state = await loadManagedState(managedStatePath(), {
			authToken: configured || undefined,
			publicKeysPem: config.licensing.public_keys_pem,
		});
		return getEffectiveManagedApiKey(config.auth.api_key, state) || configured || undefined;
	} catch {
		return configured || undefined;
	}
}

export function formatUpdateNotice(result: {
	currentVersion: string;
	latestVersion: string;
}): string {
	return localize(
		"Singularity AIDR: Update available v{0} → v{1}. Install it from the Extensions view, or from the VSIX your organisation distributes.",
		result.currentVersion,
		result.latestVersion,
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
