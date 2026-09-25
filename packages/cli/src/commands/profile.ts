/**
 * `aidr profile` — inspect, validate and dry-run agent permission profiles.
 *
 * Read-only: the command never writes a profile. Operators edit the local
 * document (`~/.singularity-aidr/agent-profiles.json`) themselves; managed
 * profiles arrive only inside the signed tenant bundle.
 */
import { readFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import {
	AGENT_PROFILE_CONNECTORS,
	AGENT_PROFILE_TEMPLATE_NAMES,
	type AgentProfile,
	type AgentProfileConnector,
	type AgentProfileContext,
	type AgentProfileLayer,
	type AgentRuntime,
	agentProfileTemplateDocument,
	type DetectorProvisionedContext,
	escapeTerminalText,
	evaluateAgentProfilesForToolCall,
	inspectLocalAgentProfiles,
	type LocalAgentProfilesState,
	loadProvisionedDetectorContext,
	localAgentProfileLayer,
	localAgentProfilesPath,
	validateAgentProfileSource,
} from "@singularityrd/aidr-core";

/** Connectors that receive profiles through detector provisioning (not the MCP gateway). */
const RUNTIME_CONNECTORS = AGENT_PROFILE_CONNECTORS.filter(
	(connector): connector is AgentRuntime & AgentProfileConnector => connector !== "mcp-gateway",
);
const MAX_TOOL_CALL_BYTES = 1024 * 1024;

/** Test seams; production callers pass nothing. */
export interface ProfileCommandDeps {
	localPath?: string;
	loadContext?: (runtime: AgentRuntime) => Promise<DetectorProvisionedContext>;
	cwd?: string;
	print?: (line: string) => void;
	printError?: (line: string) => void;
}

function printer(deps: ProfileCommandDeps) {
	return {
		out: deps.print ?? ((line: string) => console.log(line)),
		err: deps.printError ?? ((line: string) => console.error(line)),
	};
}

function fail(deps: ProfileCommandDeps, message: string): void {
	printer(deps).err(message);
	process.exitCode = 1;
}

function message(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function describeScope(profile: AgentProfile): string {
	const connectors = profile.applies_to?.connectors?.join(",") ?? "all connectors";
	const repositories = profile.applies_to?.repositories?.join(",") ?? "all repositories";
	return `${connectors}; ${repositories}`;
}

interface ManagedEntry {
	connector: AgentProfileConnector;
	layer?: AgentProfileLayer;
	error?: string;
}

async function managedLayers(deps: ProfileCommandDeps): Promise<ManagedEntry[]> {
	const load = deps.loadContext ?? ((runtime) => loadProvisionedDetectorContext(runtime));
	const entries: ManagedEntry[] = [];
	for (const connector of RUNTIME_CONNECTORS) {
		try {
			const context = await load(connector);
			const layer = context.agentProfiles?.layers.find((item) => item.source === "managed");
			if (layer) entries.push({ connector, layer });
		} catch (error) {
			entries.push({ connector, error: message(error) });
		}
	}
	return entries;
}

function localState(deps: ProfileCommandDeps): Promise<LocalAgentProfilesState> {
	return inspectLocalAgentProfiles(deps.localPath ?? localAgentProfilesPath());
}

/** `aidr profile list` */
export async function profileListCommand(
	options: { json?: boolean } = {},
	deps: ProfileCommandDeps = {},
): Promise<void> {
	const { out } = printer(deps);
	const local = await localState(deps);
	const managed = await managedLayers(deps);
	const problems =
		local.status === "invalid" ||
		managed.some((entry) => entry.error || entry.layer?.status === "invalid");
	if (options.json) {
		out(
			JSON.stringify(
				{
					local: {
						path: local.path,
						status: local.status,
						...(local.status === "invalid" ? { reason: local.reason } : {}),
						profiles: local.status === "loaded" ? local.document.profiles : [],
						diagnostics: local.status === "loaded" ? local.diagnostics : [],
					},
					managed: managed.map((entry) => ({
						connector: entry.connector,
						...(entry.error ? { status: "unavailable", reason: entry.error } : {}),
						...(entry.layer?.status === "invalid"
							? { status: "invalid", reason: entry.layer.reason }
							: {}),
						...(entry.layer?.status === "loaded"
							? { status: "loaded", profiles: entry.layer.document.profiles }
							: {}),
					})),
					templates: AGENT_PROFILE_TEMPLATE_NAMES,
				},
				null,
				2,
			),
		);
	} else {
		out(`Local profiles (${local.path}):`);
		if (local.status === "absent") out("  none (file not present)");
		else if (local.status === "invalid") {
			out(`  INVALID — not loaded, not enforced: ${escapeTerminalText(local.reason)}`);
		} else {
			for (const profile of local.document.profiles) {
				out(
					`  ${profile.name}  default=${profile.default}  scope=${escapeTerminalText(describeScope(profile))}`,
				);
			}
			for (const diagnostic of local.diagnostics) {
				out(`  ! ${diagnostic.profile}: ${diagnostic.message}`);
			}
		}
		out("Managed profiles (signed tenant bundle):");
		if (managed.length === 0) out("  none provisioned");
		for (const entry of managed) {
			if (entry.error) {
				out(
					`  ${entry.connector}: UNAVAILABLE — calls are blocked: ${escapeTerminalText(entry.error)}`,
				);
			} else if (entry.layer?.status === "invalid") {
				out(
					`  ${entry.connector}: INVALID — every call is denied: ${escapeTerminalText(entry.layer.reason)}`,
				);
			} else if (entry.layer?.status === "loaded") {
				const names = entry.layer.document.profiles.map((profile) => profile.name).join(", ");
				out(`  ${entry.connector}: ${names}`);
			}
		}
		out(
			`Templates: ${AGENT_PROFILE_TEMPLATE_NAMES.join(", ")} (aidr profile show <name> --template)`,
		);
	}
	if (problems) process.exitCode = 1;
}

/** `aidr profile show <name>` */
export async function profileShowCommand(
	name: string,
	options: { template?: boolean } = {},
	deps: ProfileCommandDeps = {},
): Promise<void> {
	const { out } = printer(deps);
	if (options.template) {
		const document = agentProfileTemplateDocument(name);
		if (!document) {
			fail(
				deps,
				`Unknown template "${escapeTerminalText(name)}". Templates: ${AGENT_PROFILE_TEMPLATE_NAMES.join(", ")}.`,
			);
			return;
		}
		out(JSON.stringify(document, null, 2));
		return;
	}
	const found: { source: string; profile: AgentProfile }[] = [];
	const local = await localState(deps);
	if (local.status === "loaded") {
		const profile = local.document.profiles.find((item) => item.name === name);
		if (profile) found.push({ source: `local (${local.path})`, profile });
	}
	for (const entry of await managedLayers(deps)) {
		if (entry.layer?.status !== "loaded") continue;
		const profile = entry.layer.document.profiles.find((item) => item.name === name);
		if (profile) found.push({ source: `managed (${entry.connector})`, profile });
	}
	if (found.length === 0) {
		fail(
			deps,
			`No local or managed profile named "${escapeTerminalText(name)}". Use --template to show a shipped template.`,
		);
		return;
	}
	out(JSON.stringify(found, null, 2));
}

async function readBounded(path: string): Promise<string> {
	const text = await readFile(path, "utf8");
	if (Buffer.byteLength(text, "utf8") > MAX_TOOL_CALL_BYTES) throw new Error("file is too large");
	return text;
}

/** `aidr profile validate [file]` */
export async function profileValidateCommand(
	file: string | undefined,
	options: { json?: boolean } = {},
	deps: ProfileCommandDeps = {},
): Promise<void> {
	const { out } = printer(deps);
	const path = file
		? resolve(deps.cwd ?? process.cwd(), file)
		: (deps.localPath ?? localAgentProfilesPath());
	let source: string;
	try {
		source = await readBounded(path);
	} catch (error) {
		fail(deps, `Cannot read ${path}: ${message(error)}`);
		return;
	}
	const result = validateAgentProfileSource(source);
	if (options.json) {
		out(JSON.stringify({ path, ...result }, null, 2));
		if (!result.ok) process.exitCode = 1;
		return;
	}
	if (!result.ok) {
		out(`✗ ${path} is invalid; it would not be loaded:`);
		for (const error of result.errors) out(`  - ${escapeTerminalText(error)}`);
		process.exitCode = 1;
		return;
	}
	out(`✓ ${path} is valid: ${result.document.profiles.length} profile(s).`);
	for (const diagnostic of result.diagnostics) {
		out(`  ! ${diagnostic.profile}: ${diagnostic.message}`);
	}
}

interface ParsedToolCall {
	toolName: string;
	toolInput: Record<string, unknown>;
	cwd?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return !!value && typeof value === "object" && !Array.isArray(value);
}

/** `{"tool_name":…,"tool_input":…}` as hosts send it, or `toolName`/`toolInput`. */
function parseToolCall(text: string): ParsedToolCall {
	let value: unknown;
	try {
		value = JSON.parse(text);
	} catch {
		throw new Error("tool call is not valid JSON");
	}
	if (!isRecord(value)) throw new Error("tool call must be a JSON object");
	const toolName = value.tool_name ?? value.toolName;
	const toolInput = value.tool_input ?? value.toolInput ?? value.params ?? {};
	if (typeof toolName !== "string" || !toolName.trim()) {
		throw new Error("tool call needs a tool_name");
	}
	if (!isRecord(toolInput)) throw new Error("tool_input must be a JSON object");
	return {
		toolName,
		toolInput,
		...(typeof value.cwd === "string" ? { cwd: value.cwd } : {}),
	};
}

function parseConnector(value: string | undefined): AgentProfileConnector | null {
	const connector = value ?? "claude-code";
	return (AGENT_PROFILE_CONNECTORS as readonly string[]).includes(connector)
		? (connector as AgentProfileConnector)
		: null;
}

/** `aidr profile test <tool-call-json>` — dry-run one call; detection is not run. */
export async function profileTestCommand(
	toolCallArg: string,
	options: { connector?: string; cwd?: string; file?: string; json?: boolean } = {},
	deps: ProfileCommandDeps = {},
): Promise<void> {
	const { out } = printer(deps);
	const connector = parseConnector(options.connector);
	if (!connector) {
		fail(deps, `Unknown connector. Use one of: ${AGENT_PROFILE_CONNECTORS.join(", ")}.`);
		return;
	}
	let call: ParsedToolCall;
	try {
		const text = toolCallArg.startsWith("@")
			? await readBounded(resolve(deps.cwd ?? process.cwd(), toolCallArg.slice(1)))
			: toolCallArg;
		call = parseToolCall(text);
	} catch (error) {
		fail(deps, `Invalid tool call: ${message(error)}`);
		return;
	}

	let context: AgentProfileContext | undefined;
	if (options.file) {
		const state = await inspectLocalAgentProfiles(resolve(deps.cwd ?? process.cwd(), options.file));
		if (state.status !== "loaded") {
			fail(
				deps,
				state.status === "absent"
					? `Profile file ${state.path} does not exist.`
					: `Profile file ${state.path} is invalid: ${state.reason}`,
			);
			return;
		}
		const layer = localAgentProfileLayer(state);
		context = layer ? { connector, layers: [layer] } : undefined;
	} else if (connector === "mcp-gateway") {
		fail(deps, "The MCP gateway reads profiles from its own configuration; pass --file.");
		return;
	} else {
		try {
			const load = deps.loadContext ?? ((runtime) => loadProvisionedDetectorContext(runtime));
			context = (await load(connector)).agentProfiles;
		} catch (error) {
			fail(
				deps,
				`Profiles for ${connector} could not be loaded (calls are blocked): ${message(error)}`,
			);
			return;
		}
	}

	const cwdInput = options.cwd ?? call.cwd ?? deps.cwd ?? process.cwd();
	const workingDirectory = isAbsolute(cwdInput)
		? cwdInput
		: resolve(deps.cwd ?? process.cwd(), cwdInput);
	const evaluation = context
		? await evaluateAgentProfilesForToolCall(context, call.toolName, call.toolInput, {
				workingDirectory,
			})
		: { decision: "allow" as const, selected: [], deciding: null };

	if (options.json) {
		out(JSON.stringify({ connector, workingDirectory, ...evaluation }, null, 2));
		return;
	}
	out(`Connector: ${connector}   Working directory: ${escapeTerminalText(workingDirectory)}`);
	if (evaluation.selected.length === 0) {
		out("No agent permission profile applies to this call; only threat detection decides.");
	} else {
		out(
			`Profiles: ${evaluation.selected.map((item) => `${item.profile} (${item.source})`).join(", ")}`,
		);
	}
	out(`Profile decision: ${evaluation.decision.toUpperCase()}`);
	if (evaluation.deciding) {
		out(`Rule: ${escapeTerminalText(evaluation.deciding.rule)}`);
		out(`Why: ${escapeTerminalText(evaluation.deciding.detail)}`);
	}
	out("Threat detection still applies on top of this result (deny > ask > allow).");
}
