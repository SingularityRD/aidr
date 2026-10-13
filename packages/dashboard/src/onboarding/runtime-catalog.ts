/**
 * Per-runtime install and enrollment guidance for the download center.
 *
 * The steps restate the published guides (docs/platform-guides/*,
 * docs/package-installation.md and the package READMEs) with the exact version
 * and file name from the validated release manifest filled in. Nothing here is
 * a download source: links come only from the manifest.
 */

import type { DashboardMessageKey } from "../i18n/en";
import { englishT, type Translate } from "../i18n/I18nProvider";
import { artifactFileName, type ReleaseArtifact, type ReleaseArtifactId } from "./release-manifest";

type InstallStep = { text: string; command?: string };

/**
 * How an installation becomes visible to this tenant.
 * - device: the connector shows a short code at session start (managed mode).
 * - managed-config: the operator deploys the signed runtime configuration.
 * - api-key: configured with a tenant API key (options page or managed policy).
 * - none: the component does not check in with the control plane.
 */
type EnrollmentKind = "device" | "managed-config" | "api-key" | "none";

export type RuntimeCatalogEntry = {
	id: ReleaseArtifactId;
	/** English name; product names are shown as-is in every language. */
	label: string;
	/** Translated name when the label is not a product name ("MCP gateway"). */
	labelKey?: DashboardMessageKey;
	summary: DashboardMessageKey;
	guide: string;
	enrollment: EnrollmentKind;
	/** agents.agent_runtime values (and optional version prefixes) that prove a check-in. */
	detection: { runtimes: string[]; versionPrefixes?: string[] } | null;
	installSteps: (artifact: ReleaseArtifact | null, t?: Translate) => InstallStep[];
};

/** The entry's name in the current language. */
export function runtimeLabel(entry: RuntimeCatalogEntry, t: Translate): string {
	return entry.labelKey ? t(entry.labelKey) : entry.label;
}

function fileOf(artifact: ReleaseArtifact | null, fallback: string): string {
	return artifact ? artifactFileName(artifact) : fallback;
}

function versionOf(artifact: ReleaseArtifact | null): string {
	return artifact?.version ?? "VERSION";
}

const registryStep = (t: Translate): InstallStep => ({ text: t("rc.registry") });

/**
 * Codex hook registration, identical (comments aside) to the TOML in
 * packages/codex/README.md and docs/platform-guides/codex.md. All three events
 * are required: PreToolUse (tool calls), UserPromptSubmit (prompt protection)
 * and PostToolUse (tool-output inspection). A drift test compares them.
 */
export const CODEX_HOOKS_TOML = [
	"[[hooks.PreToolUse]]",
	'matcher = "^(Bash|apply_patch|mcp__.+)$"',
	"",
	"[[hooks.PreToolUse.hooks]]",
	'type = "command"',
	'command = "aidr-codex-hook"',
	"timeout = 10",
	"",
	"# Prompt protection. No matcher: Codex ignores matchers for this event.",
	"[[hooks.UserPromptSubmit]]",
	"",
	"[[hooks.UserPromptSubmit.hooks]]",
	'type = "command"',
	'command = "aidr-codex-hook"',
	"timeout = 10",
	"",
	"# Tool-output inspection.",
	"[[hooks.PostToolUse]]",
	'matcher = "^(Bash|mcp__.+)$"',
	"",
	"[[hooks.PostToolUse.hooks]]",
	'type = "command"',
	'command = "aidr-codex-hook"',
	"timeout = 10",
].join("\n");

export const RUNTIME_CATALOG: readonly RuntimeCatalogEntry[] = [
	{
		id: "claude-code",
		label: "Claude Code",
		summary: "rc.claude.summary",
		guide: "docs/platform-guides/claude-code.md",
		enrollment: "device",
		detection: { runtimes: ["claude-code"] },
		installSteps: (artifact, t = englishT) => [
			{ text: t("rc.claude.node") },
			{
				text: t("rc.claude.extract"),
				command: `mkdir aidr-claude-plugin && tar -xzf ${fileOf(artifact, "aidr-claude-plugin-VERSION.tar.gz")} -C aidr-claude-plugin`,
			},
			{
				text: t("rc.claude.marketplace"),
				command:
					"/plugin marketplace add /absolute/path/to/aidr-claude-plugin\n/plugin install aidr@aidr",
			},
			{ text: t("rc.claude.restart") },
		],
	},
	{
		id: "cursor",
		label: "Cursor",
		summary: "rc.cursor.summary",
		guide: "docs/platform-guides/cursor.md",
		enrollment: "device",
		detection: { runtimes: ["cursor"] },
		installSteps: (artifact, t = englishT) => [
			{
				text: t("rc.vsix"),
				command: `cursor --install-extension ./${fileOf(artifact, "aidr-cursor.vsix")}`,
			},
			{ text: t("rc.cursor.enable") },
			{ text: t("rc.cursor.health") },
		],
	},
	{
		id: "vscode",
		label: "VS Code",
		summary: "rc.vscode.summary",
		guide: "docs/platform-guides/cursor.md",
		enrollment: "device",
		detection: { runtimes: ["vscode"] },
		installSteps: (artifact, t = englishT) => [
			{ text: t("rc.vscode.setting") },
			{
				text: t("rc.vsix"),
				command: `code --install-extension ./${fileOf(artifact, "aidr-vscode.vsix")}`,
			},
			{ text: t("rc.vscode.enable") },
		],
	},
	{
		id: "openclaw",
		label: "OpenClaw",
		summary: "rc.openclaw.summary",
		guide: "docs/platform-guides/openclaw.md",
		enrollment: "device",
		detection: { runtimes: ["openclaw"] },
		installSteps: (artifact, t = englishT) => [
			registryStep(t),
			{
				text: t("rc.openclaw.install"),
				command: `openclaw plugins install npm:@singularityrd/aidr-openclaw@${versionOf(artifact)}`,
			},
			{ text: t("rc.openclaw.restart") },
		],
	},
	{
		id: "opencode",
		label: "OpenCode",
		summary: "rc.opencode.summary",
		guide: "docs/platform-guides/opencode.md",
		enrollment: "device",
		detection: { runtimes: ["opencode"] },
		installSteps: (artifact, t = englishT) => [
			registryStep(t),
			{
				text: t("rc.opencode.pin"),
				command: `{\n  "dependencies": {\n    "@singularityrd/aidr-opencode": "${versionOf(artifact)}"\n  }\n}`,
			},
			{
				text: t("rc.opencode.enable"),
				command: `{\n  "plugin": ["@singularityrd/aidr-opencode"]\n}`,
			},
			{ text: t("rc.opencode.restart") },
		],
	},
	{
		id: "codex",
		label: "Codex CLI",
		summary: "rc.codex.summary",
		guide: "packages/codex/README.md",
		enrollment: "managed-config",
		detection: { runtimes: ["codex"] },
		installSteps: (artifact, t = englishT) => [
			registryStep(t),
			{
				text: t("rc.exact"),
				command: `npm install --global @singularityrd/aidr-codex@${versionOf(artifact)}`,
			},
			{ text: t("rc.codex.config") },
			{ text: t("rc.codex.hooks"), command: CODEX_HOOKS_TOML },
			{ text: t("rc.codex.trust") },
		],
	},
	{
		id: "cli",
		label: "AIDR CLI",
		labelKey: "rc.cli.label",
		summary: "rc.cli.summary",
		guide: "packages/cli/README.md",
		enrollment: "none",
		detection: null,
		installSteps: (artifact, t = englishT) => [
			...(artifact && !artifactFileName(artifact).endsWith(".tgz")
				? [
						{
							text: t("rc.cli.binary"),
							command: `install -m 0755 ./${artifactFileName(artifact)} /usr/local/bin/aidr`,
						},
					]
				: [
						registryStep(t),
						{
							text: t("rc.exact"),
							command: `npm install --global @singularityrd/aidr-cli@${versionOf(artifact)}`,
						},
					]),
			{ text: t("rc.cli.help"), command: "aidr --help" },
			{ text: t("rc.cli.setup") },
		],
	},
	{
		id: "browser-guard-chrome",
		label: "Browser Guard for Chrome and Edge",
		labelKey: "rc.bgChrome.label",
		summary: "rc.bg.summary",
		guide: "packages/browser-guard/README.md",
		enrollment: "api-key",
		detection: { runtimes: ["browser_guard"], versionPrefixes: ["chrome-", "edge-"] },
		installSteps: (artifact, t = englishT) => [
			{ text: t("rc.bgChrome.fleet") },
			{ text: t("rc.bgChrome.eval", { file: fileOf(artifact, t("rc.bgChrome.archive")) }) },
		],
	},
	{
		id: "browser-guard-firefox",
		label: "Browser Guard for Firefox",
		labelKey: "rc.bgFirefox.label",
		summary: "rc.bg.summary",
		guide: "packages/browser-guard/README.md",
		enrollment: "api-key",
		detection: { runtimes: ["browser_guard"], versionPrefixes: ["firefox-"] },
		installSteps: (artifact, t = englishT) => [
			{ text: t("rc.bgFirefox.fleet") },
			{ text: t("rc.bgFirefox.eval", { file: fileOf(artifact, t("rc.package")) }) },
		],
	},
	{
		id: "mcp-gateway",
		label: "MCP gateway",
		labelKey: "rc.mcp.label",
		summary: "rc.mcp.summary",
		guide: "packages/mcp-gateway/README.md",
		enrollment: "none",
		detection: null,
		installSteps: (artifact, t = englishT) => [
			{ text: t("rc.mcp.unpack", { file: fileOf(artifact, t("rc.package")) }) },
			{ text: t("rc.mcp.config") },
			{
				text: t("rc.mcp.start"),
				command: "node dist/aidr-mcp-gateway.mjs /secure/path/gateway.json",
			},
			{ text: t("rc.mcp.point") },
		],
	},
];

export type AgentCheckIn = {
	agent_runtime: string | null;
	agent_runtime_version: string | null;
	last_seen: string;
};

/** Latest check-in of an agent whose runtime matches the catalog entry, if any. */
export function latestCheckIn(entry: RuntimeCatalogEntry, agents: AgentCheckIn[]): string | null {
	const detection = entry.detection;
	if (!detection) return null;
	let latest: number | null = null;
	for (const agent of agents) {
		if (!agent.agent_runtime || !detection.runtimes.includes(agent.agent_runtime)) continue;
		if (
			detection.versionPrefixes &&
			!detection.versionPrefixes.some((prefix) =>
				(agent.agent_runtime_version ?? "").toLowerCase().startsWith(prefix),
			)
		) {
			continue;
		}
		const seen = Date.parse(agent.last_seen);
		if (Number.isFinite(seen) && (latest === null || seen > latest)) latest = seen;
	}
	return latest === null ? null : new Date(latest).toISOString();
}
