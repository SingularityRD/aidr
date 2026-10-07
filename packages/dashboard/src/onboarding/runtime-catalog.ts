/**
 * Per-runtime install and enrollment guidance for the download center.
 *
 * The steps restate the published guides (docs/platform-guides/*,
 * docs/package-installation.md and the package READMEs) with the exact version
 * and file name from the validated release manifest filled in. Nothing here is
 * a download source: links come only from the manifest.
 */

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
	label: string;
	summary: string;
	guide: string;
	enrollment: EnrollmentKind;
	/** agents.agent_runtime values (and optional version prefixes) that prove a check-in. */
	detection: { runtimes: string[]; versionPrefixes?: string[] } | null;
	installSteps: (artifact: ReleaseArtifact | null) => InstallStep[];
};

function fileOf(artifact: ReleaseArtifact | null, fallback: string): string {
	return artifact ? artifactFileName(artifact) : fallback;
}

function versionOf(artifact: ReleaseArtifact | null): string {
	return artifact?.version ?? "VERSION";
}

const REGISTRY_STEP: InstallStep = {
	text: "Your administrator configures read access to the private @singularityrd registry through a secret manager (NODE_AUTH_TOKEN). Never paste the token into a command.",
};

export const RUNTIME_CATALOG: readonly RuntimeCatalogEntry[] = [
	{
		id: "claude-code",
		label: "Claude Code",
		summary: "Hook plugin that inspects every Claude Code tool call before it runs.",
		guide: "docs/platform-guides/claude-code.md",
		enrollment: "device",
		detection: { runtimes: ["claude-code"] },
		installSteps: (artifact) => [
			{ text: "Requires Node.js 22.12 or later on PATH." },
			{
				text: "After the digest check passes, extract the plugin archive:",
				command: `mkdir aidr-claude-plugin && tar -xzf ${fileOf(artifact, "aidr-claude-plugin-VERSION.tar.gz")} -C aidr-claude-plugin`,
			},
			{
				text: "From the Claude Code prompt, add the extracted directory as a local marketplace and install the plugin:",
				command:
					"/plugin marketplace add /absolute/path/to/aidr-claude-plugin\n/plugin install aidr@aidr",
			},
			{ text: "Restart Claude Code. AIDR loads automatically on every session." },
		],
	},
	{
		id: "cursor",
		label: "Cursor",
		summary: "Cursor extension that installs and monitors AIDR's managed agent hooks.",
		guide: "docs/platform-guides/cursor.md",
		enrollment: "device",
		detection: { runtimes: ["cursor"] },
		installSteps: (artifact) => [
			{
				text: "Install the verified VSIX (or use Extensions > Install from VSIX):",
				command: `cursor --install-extension ./${fileOf(artifact, "aidr-cursor.vsix")}`,
			},
			{ text: "Open the command palette and run “Singularity AIDR: Enable protection”." },
			{
				text: "Run “Singularity AIDR: Show hook health” and confirm the reported extension version.",
			},
		],
	},
	{
		id: "vscode",
		label: "VS Code",
		summary: "VS Code extension for local agent hooks.",
		guide: "docs/platform-guides/cursor.md",
		enrollment: "device",
		detection: { runtimes: ["vscode"] },
		installSteps: (artifact) => [
			{
				text: "Enable chat.useClaudeHooks in VS Code User Settings. The extension checks this prerequisite but does not change it.",
			},
			{
				text: "Install the verified VSIX (or use Extensions > Install from VSIX):",
				command: `code --install-extension ./${fileOf(artifact, "aidr-vscode.vsix")}`,
			},
			{ text: "Run “Singularity AIDR: Enable protection”, then “Show hook health”." },
		],
	},
	{
		id: "openclaw",
		label: "OpenClaw",
		summary: "In-process OpenClaw plugin that blocks unsafe tool calls.",
		guide: "docs/platform-guides/openclaw.md",
		enrollment: "device",
		detection: { runtimes: ["openclaw"] },
		installSteps: (artifact) => [
			REGISTRY_STEP,
			{
				text: "Install the exact release version. Its digest must match the verified package above:",
				command: `openclaw plugins install npm:@singularityrd/aidr-openclaw@${versionOf(artifact)}`,
			},
			{ text: "Restart the OpenClaw gateway and confirm the installed plugin version." },
		],
	},
	{
		id: "opencode",
		label: "OpenCode",
		summary: "OpenCode plugin that checks tool calls before they run.",
		guide: "docs/platform-guides/opencode.md",
		enrollment: "device",
		detection: { runtimes: ["opencode"] },
		installSteps: (artifact) => [
			REGISTRY_STEP,
			{
				text: "Pin the exact version in ~/.config/opencode/package.json:",
				command: `{\n  "dependencies": {\n    "@singularityrd/aidr-opencode": "${versionOf(artifact)}"\n  }\n}`,
			},
			{
				text: "Enable the plugin in ~/.config/opencode/opencode.json:",
				command: `{\n  "plugin": ["@singularityrd/aidr-opencode"]\n}`,
			},
			{ text: "Restart OpenCode and confirm the installed plugin version." },
		],
	},
	{
		id: "codex",
		label: "Codex CLI",
		summary: "Native Codex PreToolUse hook. It denies on ask and on internal errors.",
		guide: "packages/codex/README.md",
		enrollment: "managed-config",
		detection: { runtimes: ["codex"] },
		installSteps: (artifact) => [
			REGISTRY_STEP,
			{
				text: "Install the exact release version:",
				command: `npm install --global @singularityrd/aidr-codex@${versionOf(artifact)}`,
			},
			{
				text: "Deploy the operator-generated runtime configuration (scripts/deployment-prepare.mjs) as ~/.singularity-aidr/config.json. Without it the hook refuses to start.",
			},
			{
				text: "Register the hook in ~/.codex/config.toml:",
				command:
					'[[hooks.PreToolUse]]\nmatcher = "^(Bash|apply_patch)$"\n\n[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = "aidr-codex-hook"\ntimeout = 10',
			},
			{ text: "In Codex, review and trust the registered hook with /hooks." },
		],
	},
	{
		id: "cli",
		label: "AIDR CLI",
		summary: "Local setup and diagnostics. It does not install or activate connectors.",
		guide: "packages/cli/README.md",
		enrollment: "none",
		detection: null,
		installSteps: (artifact) => [
			...(artifact && !artifactFileName(artifact).endsWith(".tgz")
				? [
						{
							text: "Put the verified binary on PATH as aidr and mark it executable:",
							command: `install -m 0755 ./${artifactFileName(artifact)} /usr/local/bin/aidr`,
						},
					]
				: [
						REGISTRY_STEP,
						{
							text: "Install the exact release version:",
							command: `npm install --global @singularityrd/aidr-cli@${versionOf(artifact)}`,
						},
					]),
			{ text: "Inspect the available commands:", command: "aidr --help" },
			{
				text: "Run aidr setup only after your operator supplies the approved runtime configuration.",
			},
		],
	},
	{
		id: "browser-guard-chrome",
		label: "Browser Guard for Chrome and Edge",
		summary:
			"Masks sensitive data in prompts, pastes and files before they reach AI chat products.",
		guide: "packages/browser-guard/README.md",
		enrollment: "api-key",
		detection: { runtimes: ["browser_guard"], versionPrefixes: ["chrome-", "edge-"] },
		installSteps: (artifact) => [
			{
				text: "For fleet rollout, your administrator deploys the extension through managed browser policy.",
			},
			{
				text: `For an evaluation on one browser, extract ${fileOf(artifact, "the verified archive")}, open chrome://extensions (or edge://extensions), turn on Developer mode, and choose Load unpacked.`,
			},
		],
	},
	{
		id: "browser-guard-firefox",
		label: "Browser Guard for Firefox",
		summary:
			"Masks sensitive data in prompts, pastes and files before they reach AI chat products.",
		guide: "packages/browser-guard/README.md",
		enrollment: "api-key",
		detection: { runtimes: ["browser_guard"], versionPrefixes: ["firefox-"] },
		installSteps: (artifact) => [
			{
				text: "For fleet rollout, your administrator installs the signed add-on through Firefox enterprise policy (ExtensionSettings).",
			},
			{
				text: `For an evaluation, open about:debugging, choose This Firefox, then Load Temporary Add-on and select ${fileOf(artifact, "the verified package")}.`,
			},
		],
	},
	{
		id: "mcp-gateway",
		label: "MCP gateway",
		summary: "Loopback gateway that inspects MCP tool results before they reach the model.",
		guide: "packages/mcp-gateway/README.md",
		enrollment: "none",
		detection: null,
		installSteps: (artifact) => [
			{
				text: `Unpack ${fileOf(artifact, "the verified package")} on the host that runs the MCP client.`,
			},
			{
				text: "Write the gateway configuration with the tenant, client token SHA-256, tool allowlist, signed manifest and trusted signer keys. Keep this file private.",
			},
			{
				text: "Start the gateway. It listens on 127.0.0.1 only:",
				command: "node dist/aidr-mcp-gateway.mjs /secure/path/gateway.json",
			},
			{
				text: "Point the MCP client at http://127.0.0.1:7789/mcp/<serverId> and send its bearer token on every request. Remove any direct route to the upstream server.",
			},
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
