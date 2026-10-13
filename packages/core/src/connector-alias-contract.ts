/**
 * Declared connector ↔ core tool-name contract.
 *
 * Why this exists: core selects security legs (package intelligence, filesystem
 * policy, AMSI, MCP policy) by canonical tool name. A connector whose edit tool
 * is named something core does not know therefore routes *around* those legs.
 * That is exactly how `apply_patch` — Codex's and OpenClaw's file-edit tool —
 * carried a rewritten `package.json` past `extractPackagesFromManifest`.
 *
 * The fix for that particular hole is the alias map in `tool-normalization.ts`.
 * This module is the guard against the next one: it declares, per connector,
 * which source file defines the connector's tool vocabulary, and the vocabulary
 * itself is *derived from that source* rather than copied here. A new or renamed
 * connector tool name is then a contract failure until somebody decides whether
 * it is a canonical operation (alias it) or a deliberate pass-through.
 */

import { CANONICAL_TOOL_NAMES } from "./tool-normalization.js";

export interface ConnectorToolSurface {
	/** Connector identity, matching the `agentRuntime` value core records. */
	readonly connector: string;
	/**
	 * Repo-relative source file that performs the connector's tool-name
	 * dispatch. The declared names are derived from this file's contents so the
	 * contract cannot drift away from the code it describes.
	 */
	readonly dispatchSource: string;
	/**
	 * Tool names this connector emits that deliberately map to no canonical core
	 * operation. Each entry is an explicit decision, not a silent bypass: the
	 * operation stays on core's unknown-tool path, and the connector remains
	 * responsible for extracting its own artifacts.
	 */
	readonly passThrough: readonly string[];
	/** Justification for `passThrough`; required whenever it is non-empty. */
	readonly passThroughReason?: string;
	/** Clarifies how `dispatchSource` defines the vocabulary, when not obvious. */
	readonly note?: string;
	/**
	 * The host's own built-in tool list, captured from the pinned host build.
	 * The source-derived vocabulary only shows names the connector already
	 * handles; a host tool the source never names is invisible to it. Every
	 * inventory tool must therefore be dispatched by the connector, be a
	 * canonical alias, or be listed in `genericInspection`.
	 */
	readonly hostInventory?: HostToolInventory;
}

interface HostToolInventory {
	/** `<npm package>@<version>` the list was captured from (the real-host E2E pin). */
	readonly host: string;
	/** Where in that build the list comes from, so it can be re-captured. */
	readonly source: string;
	readonly tools: readonly string[];
	/** Host tools deliberately left to core's generic unknown-tool inspection. */
	readonly genericInspection: readonly string[];
	/** Why `genericInspection` tools need no dedicated mapping. */
	readonly genericInspectionReason: string;
}

/**
 * The connectors core ships. `dispatchSource` points at the file that decides
 * the tool vocabulary for that connector — for the pass-through connectors that
 * is core's own extractor dispatch, because they forward the host's `tool_name`
 * unchanged.
 */
export const CONNECTOR_TOOL_SURFACES: readonly ConnectorToolSurface[] = [
	{
		connector: "claude-code",
		dispatchSource: "packages/core/src/extractors.ts",
		passThrough: [],
		note: "Claude Code forwards the host's tool_name straight to core (packages/claude-code/src/pre-tool-use.ts), so the vocabulary core dispatches on is the connector's vocabulary.",
	},
	{
		connector: "cursor",
		dispatchSource: "packages/extension/src/aidr-hook.ts",
		passThrough: [],
	},
	{
		connector: "vscode",
		dispatchSource: "packages/extension/src/aidr-hook.ts",
		passThrough: [],
	},
	{
		connector: "openclaw",
		dispatchSource: "packages/openclaw/src/tool-handler.ts",
		passThrough: ["ls", "nodes", "process", "terminal"],
		passThroughReason:
			"process (write/paste/send-keys/submit), terminal (input) and nodes (run/invoke) are command channels the connector rewrites onto `exec` before core sees them (packages/openclaw/src/process-input.ts): the delivered text is evaluated as a shell command and an unrecognised action is denied. ls is a read-only directory listing whose path the connector extracts as a file_path artifact.",
		hostInventory: {
			host: "openclaw@2026.9.6",
			source:
				"CORE_TOOL_FACTORY_DESCRIPTORS (dist/core-tool-factory-descriptors-*.mjs) of the npm package; extension-provided tools (code_execution, browser, ...) are not core tools and are not listed.",
			tools: [
				"agents_list",
				"agents_wait",
				"apply_patch",
				"ask_user",
				"automations",
				"computer",
				"conversations_list",
				"conversations_send",
				"conversations_turn",
				"create_goal",
				"dashboard",
				"dismiss_task",
				"edit",
				"exec",
				"gateway",
				"get_goal",
				"github_identity_status",
				"github_publish",
				"heartbeat_respond",
				"image_generate",
				"ls",
				"message",
				"mobile_ui",
				"music_generate",
				"nodes",
				"openclaw",
				"pdf",
				"plugins",
				"portal",
				"process",
				"progress_card",
				"read",
				"screen",
				"secrets",
				"session_status",
				"sessions",
				"sessions_history",
				"sessions_list",
				"sessions_search",
				"sessions_send",
				"sessions_spawn",
				"sessions_yield",
				"show_widget",
				"skill_workshop",
				"structured_output",
				"subagents",
				"suggest_task",
				"terminal",
				"theme",
				"transcripts",
				"tts",
				"update_goal",
				"video_generate",
				"view_image",
				"web_fetch",
				"web_search",
				"write",
			],
			genericInspection: [
				"agents_list",
				"agents_wait",
				"ask_user",
				"automations",
				"computer",
				"conversations_list",
				"conversations_send",
				"conversations_turn",
				"create_goal",
				"dashboard",
				"dismiss_task",
				"gateway",
				"get_goal",
				"github_identity_status",
				"github_publish",
				"heartbeat_respond",
				"image_generate",
				"message",
				"mobile_ui",
				"music_generate",
				"openclaw",
				"pdf",
				"plugins",
				"portal",
				"progress_card",
				"screen",
				"secrets",
				"session_status",
				"sessions",
				"sessions_history",
				"sessions_list",
				"sessions_search",
				"sessions_send",
				"sessions_spawn",
				"sessions_yield",
				"show_widget",
				"skill_workshop",
				"structured_output",
				"subagents",
				"suggest_task",
				"theme",
				"transcripts",
				"tts",
				"update_goal",
				"video_generate",
				"view_image",
				"web_search",
			],
			genericInspectionReason:
				"None of these runs a shell command, feeds a process's stdin or writes a workspace file by path: they manage agents, sessions, goals, media, messaging, UI and gateway config (gateway exposes only config.get, config.schema.lookup and update.run). Their string arguments are inspected as content/URLs/paths on core's unknown-tool path. computer and mobile_ui drive a GUI, not a shell; screen captures.",
		},
	},
	{
		connector: "opencode",
		dispatchSource: "packages/opencode/src/extractors.ts",
		passThrough: [
			"codesearch",
			"glob",
			"grep",
			"list",
			"ls",
			"question",
			"read_lines",
			"task",
			"websearch",
		],
		passThroughReason:
			"Non-edit OpenCode tools with no canonical core equivalent. The connector extracts their artifacts itself (glob/grep/list/ls search roots and patterns as file_path artifacts) and core inspects them on the unknown-tool path; none of them writes a file. The file-writing patch/multiedit tools are canonical Edit aliases instead.",
		hostInventory: {
			host: "opencode-ai@1.18.32",
			source:
				"ToolRegistry builtin list in the opencode-linux-x64@1.18.32 binary (invalid, question, bash, read, glob, grep, edit, write, task, webfetch, todowrite, websearch, skill, apply_patch, experimental execute/lsp/plan_exit).",
			tools: [
				"apply_patch",
				"bash",
				"edit",
				"execute",
				"glob",
				"grep",
				"invalid",
				"lsp",
				"plan_exit",
				"question",
				"read",
				"skill",
				"task",
				"todowrite",
				"webfetch",
				"websearch",
				"write",
			],
			// `execute` (experimental code mode, off by default) needs no entry: core
			// already aliases the name to Bash. Its script is not a shell command,
			// so that alias finds no command to inspect: an open gap while code
			// mode stays experimental.
			genericInspection: ["invalid", "lsp", "plan_exit", "skill", "todowrite"],
			genericInspectionReason:
				"invalid reports a malformed call, lsp queries a language server for a file position, plan_exit ends plan mode, skill loads a named skill and todowrite edits the session todo list; none runs a shell command or writes a file.",
		},
	},
	{
		connector: "codex",
		dispatchSource: "packages/codex/src/extractors.ts",
		passThrough: [],
	},
];

/** `case "<name>":` labels — how every connector switch names its tools. */
const CASE_LABEL_PATTERN = /^[ \t]*case\s+"([^"]+)":/gm;

/** `toolName: "<name>"` literals — how the extension builds a normalized call. */
const ASSIGNED_TOOL_NAME_PATTERN = /toolName:\s*"([^"]+)"/g;

/**
 * Derive the tool names a connector source actually dispatches on.
 *
 * Pure by design: the caller supplies the file contents, so this module needs
 * no filesystem access and can be exercised directly. Deliberately structural
 * rather than a parsed AST — both patterns are how this repo spells a tool name,
 * and a source that abandons them trips the "no names derived" assertion in the
 * contract test instead of silently passing.
 */
export function extractDeclaredToolNames(source: string): string[] {
	const names = new Set<string>();
	for (const match of source.matchAll(CASE_LABEL_PATTERN)) {
		const name = match[1];
		if (name !== undefined && name !== "") names.add(name);
	}
	for (const match of source.matchAll(ASSIGNED_TOOL_NAME_PATTERN)) {
		const name = match[1];
		if (name !== undefined && name !== "") names.add(name);
	}
	return [...names].sort();
}

export interface ConnectorToolSurfaceViolation {
	readonly connector: string;
	readonly toolName: string;
	readonly kind:
		| "unmapped"
		| "undeclared-pass-through"
		| "stale-pass-through"
		| "unclassified-host-tool"
		| "stale-generic-inspection";
	readonly detail: string;
}

/** True when `toolName` resolves to a canonical core operation. */
export function isCanonicalToolAlias(toolName: string): boolean {
	return CANONICAL_TOOL_NAMES.has(toolName.trim().toLowerCase());
}

/** Classify one derived tool name against the alias map and the declaration. */
function classifyToolName(
	surface: ConnectorToolSurface,
	toolName: string,
	declaredPassThrough: ReadonlySet<string>,
): ConnectorToolSurfaceViolation | undefined {
	const isAlias = isCanonicalToolAlias(toolName);
	if (isAlias && declaredPassThrough.has(toolName)) {
		return {
			connector: surface.connector,
			toolName,
			kind: "stale-pass-through",
			detail: `${toolName} is declared pass-through but now resolves to a canonical operation; remove it from passThrough.`,
		};
	}
	if (!isAlias && !declaredPassThrough.has(toolName)) {
		return {
			connector: surface.connector,
			toolName,
			kind: "unmapped",
			detail: `${toolName} is emitted by ${surface.dispatchSource} but is neither a canonical alias nor a declared pass-through. Alias it in CANONICAL_TOOL_NAMES or declare it pass-through with a reason.`,
		};
	}
	return undefined;
}

/** Check a pinned host tool inventory against what the connector handles. */
function hostInventoryViolations(
	surface: ConnectorToolSurface,
	inventory: HostToolInventory,
	dispatched: readonly string[],
): ConnectorToolSurfaceViolation[] {
	const violations: ConnectorToolSurfaceViolation[] = [];
	const handled = (toolName: string) =>
		dispatched.includes(toolName) || isCanonicalToolAlias(toolName);
	const generic = new Set(inventory.genericInspection);
	for (const toolName of inventory.tools) {
		if (handled(toolName) || generic.has(toolName)) continue;
		violations.push({
			connector: surface.connector,
			toolName,
			kind: "unclassified-host-tool",
			detail: `${inventory.host} exposes ${toolName}, which ${surface.dispatchSource} does not dispatch, core does not alias, and genericInspection does not list. Map it or declare it generic with a reason.`,
		});
	}
	for (const toolName of inventory.genericInspection) {
		if (inventory.tools.includes(toolName) && !handled(toolName)) continue;
		violations.push({
			connector: surface.connector,
			toolName,
			kind: "stale-generic-inspection",
			detail: `${toolName} is listed for generic inspection but is ${handled(toolName) ? "now handled by the connector or core" : `not in the ${inventory.host} inventory`}.`,
		});
	}
	return violations;
}

/**
 * Compare the derived connector vocabularies against the declaration.
 *
 * A violation means somebody must decide: alias the name onto a canonical
 * operation, or declare it pass-through with a reason. Silence is not an option
 * because silence is how `apply_patch` reached the package leg as a stranger.
 */
export function findConnectorToolSurfaceViolations(
	derived: ReadonlyMap<string, readonly string[]>,
	surfaces: readonly ConnectorToolSurface[] = CONNECTOR_TOOL_SURFACES,
): ConnectorToolSurfaceViolation[] {
	const violations: ConnectorToolSurfaceViolation[] = [];

	for (const surface of surfaces) {
		const names = derived.get(surface.connector) ?? [];
		const declared = new Set(surface.passThrough);

		for (const toolName of names) {
			const violation = classifyToolName(surface, toolName, declared);
			if (violation) violations.push(violation);
		}

		for (const toolName of surface.passThrough) {
			if (names.includes(toolName)) continue;
			violations.push({
				connector: surface.connector,
				toolName,
				kind: "stale-pass-through",
				detail: `${toolName} is declared pass-through but ${surface.dispatchSource} no longer emits it.`,
			});
		}

		if (surface.hostInventory) {
			violations.push(...hostInventoryViolations(surface, surface.hostInventory, names));
		}

		if (surface.passThrough.length > 0 && !surface.passThroughReason) {
			violations.push({
				connector: surface.connector,
				toolName: surface.passThrough.join(", "),
				kind: "undeclared-pass-through",
				detail: `${surface.connector} declares pass-through tools without a passThroughReason.`,
			});
		}
	}

	return violations;
}
