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
		passThrough: [],
	},
	{
		connector: "opencode",
		dispatchSource: "packages/opencode/src/extractors.ts",
		passThrough: [
			"codesearch",
			"glob",
			"grep",
			"ls",
			"question",
			"read_lines",
			"task",
			"websearch",
		],
		passThroughReason:
			"Non-edit OpenCode tools with no canonical core equivalent. The connector extracts their artifacts itself and core inspects them on the unknown-tool path; none of them writes a file.",
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
	readonly kind: "unmapped" | "undeclared-pass-through" | "stale-pass-through";
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
