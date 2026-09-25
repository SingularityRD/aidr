/**
 * Agent permission profiles: least-privilege declarations of what one agent
 * (connector) may do, optionally scoped to repositories.
 *
 * A profile is a restriction layer on top of threat detection. It can turn an
 * allowed call into `ask` or `deny`, never the reverse: the evaluator merges
 * the profile outcome with the detection verdict using deny > ask > allow, so a
 * profile `allow` cannot override a threat `deny`.
 *
 * Profiles come from two places (see `agent-profile-loader.ts`): the operator's
 * local `agent-profiles.json` and, in managed mode, the Ed25519-signed tenant
 * detector bundle. Both layers are evaluated and the strictest outcome wins, so
 * a local document can narrow a managed profile but never widen it.
 */
import { homedir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { parseDocument } from "yaml";
import { type ZodIssue, z } from "zod";
import {
	commandMatchesAllowPrefixes,
	findDeniedPrefix,
	hostMatchesDomain,
	isPathWithin,
	pathMatchesGlob,
	urlHost,
} from "./agent-profile-match.js";
import { commandFromValue } from "./command-argv.js";
import { resolvePolicyPath } from "./policy.js";
import type { AgentRuntime, Artifact, Verdict } from "./types.js";

// ── Vocabulary ─────────────────────────────────────────────────────

export const AGENT_PROFILE_CONNECTORS = [
	"claude-code",
	"cursor",
	"vscode",
	"openclaw",
	"opencode",
	"codex",
	"mcp-gateway",
] as const satisfies readonly (AgentRuntime | "mcp-gateway")[];
export type AgentProfileConnector = (typeof AGENT_PROFILE_CONNECTORS)[number];

export const AGENT_PROFILE_ACTIONS = ["allow", "ask", "deny"] as const;
export type AgentProfileAction = (typeof AGENT_PROFILE_ACTIONS)[number];

export const AGENT_PROFILE_TOOL_CLASSES = [
	"shell",
	"file_read",
	"file_write",
	"web_fetch",
	"mcp",
	"other",
] as const;
export type AgentProfileToolClass = (typeof AGENT_PROFILE_TOOL_CLASSES)[number];

/** Placeholder for the host-reported working directory of the agent session. */
export const WORKSPACE_PLACEHOLDER = "${workspace}";

const RANK: Record<AgentProfileAction, number> = { allow: 0, ask: 1, deny: 2 };
const MAX_DOCUMENT_BYTES = 256 * 1024;

// ── Schema ─────────────────────────────────────────────────────────

const actionSchema = z.enum(AGENT_PROFILE_ACTIONS);
const NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const TOOL_NAME = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/;
const MCP_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const DOMAIN = /^(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,62})(?:\.[a-z0-9](?:[a-z0-9-]{0,62}))*\.?$/;
const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;

const profileName = z.string().regex(NAME, "must be a lowercase name (a-z, 0-9, . _ -)");

function boundedList<T extends z.ZodTypeAny>(item: T, max = 200) {
	return z.array(item).max(max);
}

const textEntry = (max: number) =>
	z
		.string()
		.trim()
		.min(1)
		.max(max)
		.refine((value) => !CONTROL.test(value), "must not contain control characters");

/** Only `${workspace}` at the very start is a placeholder; any other `${` is refused. */
function placeholderIsValid(value: string): boolean {
	const rest = value.startsWith(WORKSPACE_PLACEHOLDER)
		? value.slice(WORKSPACE_PLACEHOLDER.length)
		: value;
	return !rest.includes("${");
}

function isAnchoredPath(value: string): boolean {
	return (
		value.startsWith("/") ||
		value === "~" ||
		value.startsWith("~/") ||
		value.startsWith(WORKSPACE_PLACEHOLDER) ||
		/^[A-Za-z]:[\\/]/.test(value) ||
		value.startsWith("\\\\")
	);
}

const rootEntry = textEntry(512)
	.refine(placeholderIsValid, "only ${workspace} at the start is supported")
	.refine(
		isAnchoredPath,
		"must be absolute, start with ~/ or ${workspace} (relative roots are ambiguous)",
	);

const denyPathEntry = textEntry(512)
	.refine(placeholderIsValid, "only ${workspace} at the start is supported")
	.refine(
		(value) => isAnchoredPath(value) || value.startsWith("**") || !/[\\/]/.test(value),
		"must be absolute, start with ~/, ${workspace} or **/, or be a bare file name pattern",
	);

const repositoryEntry = textEntry(512)
	.refine((value) => !value.includes("${"), "placeholders are not supported in repositories")
	.refine(
		(value) => isAnchoredPath(value) || value.startsWith("**"),
		"must be absolute, start with ~/ or **/",
	);

const domainEntry = z
	.string()
	.trim()
	.toLowerCase()
	.max(253)
	.refine(
		(value) => DOMAIN.test(value) || IPV4.test(value),
		"must be a host name, *.host name or IPv4 address",
	);

const mcpIdentifier = z.string().regex(MCP_ID, "must be an MCP identifier");

const toolsSchema = z
	.object(
		Object.fromEntries(
			AGENT_PROFILE_TOOL_CLASSES.map((toolClass) => [toolClass, actionSchema.optional()]),
		) as Record<AgentProfileToolClass, z.ZodOptional<typeof actionSchema>>,
	)
	.strict();

const profileSchema = z
	.object({
		name: profileName,
		description: z.string().max(500).optional(),
		applies_to: z
			.object({
				connectors: z.array(z.enum(AGENT_PROFILE_CONNECTORS)).min(1).max(7).optional(),
				repositories: boundedList(repositoryEntry, 50).min(1).optional(),
			})
			.strict()
			.optional(),
		default: actionSchema,
		tools: toolsSchema.optional(),
		tool_overrides: z
			.record(z.string().regex(TOOL_NAME, "must be a tool name"), actionSchema)
			.refine((value) => Object.keys(value).length <= 100, "at most 100 tool overrides")
			.optional(),
		commands: z
			.object({
				allow_prefixes: boundedList(textEntry(256)).optional(),
				deny_prefixes: boundedList(textEntry(256)).optional(),
				unmatched: actionSchema.optional(),
			})
			.strict()
			.optional(),
		files: z
			.object({
				read_roots: boundedList(rootEntry, 50).optional(),
				write_roots: boundedList(rootEntry, 50).optional(),
				deny: boundedList(denyPathEntry).optional(),
				outside_roots: actionSchema.optional(),
			})
			.strict()
			.optional(),
		network: z
			.object({
				allow_domains: boundedList(domainEntry).optional(),
				deny_domains: boundedList(domainEntry).optional(),
				unmatched: actionSchema.optional(),
			})
			.strict()
			.optional(),
		mcp: z
			.object({
				servers: z
					.record(mcpIdentifier, actionSchema)
					.refine((value) => Object.keys(value).length <= 200, "at most 200 servers")
					.optional(),
				tools: z
					.record(
						mcpIdentifier,
						z
							.record(mcpIdentifier, actionSchema)
							.refine((value) => Object.keys(value).length <= 200, "at most 200 tools"),
					)
					.refine((value) => Object.keys(value).length <= 200, "at most 200 servers")
					.optional(),
				unmatched: actionSchema.optional(),
			})
			.strict()
			.optional(),
	})
	.strict();

export const AgentProfileDocumentSchema = z
	.object({
		version: z.literal(1),
		description: z.string().max(2000).optional(),
		default_profile: profileName.optional(),
		profiles: z.array(profileSchema).min(1).max(50),
	})
	.strict()
	.superRefine((document, context) => {
		const seen = new Set<string>();
		document.profiles.forEach((profile, index) => {
			if (seen.has(profile.name)) {
				context.addIssue({
					code: z.ZodIssueCode.custom,
					path: ["profiles", index, "name"],
					message: "profile names must be unique",
				});
			}
			seen.add(profile.name);
		});
		if (document.default_profile && !seen.has(document.default_profile)) {
			context.addIssue({
				code: z.ZodIssueCode.custom,
				path: ["default_profile"],
				message: "must name a profile in this document",
			});
		}
	});

export type AgentProfileDocument = z.infer<typeof AgentProfileDocumentSchema>;
export type AgentProfile = AgentProfileDocument["profiles"][number];

// ── Parsing and validation ─────────────────────────────────────────

export interface AgentProfileDiagnostic {
	profile: string;
	code: "no_effect" | "same_selector";
	message: string;
}

export type AgentProfileValidation =
	| { ok: true; document: AgentProfileDocument; diagnostics: AgentProfileDiagnostic[] }
	| { ok: false; errors: string[] };

/** Issue locations and messages only; never the offending value. */
function describeAgentProfileIssues(issues: readonly ZodIssue[], max = 8): string[] {
	const listed = issues.slice(0, max).map((issue) => {
		const path = issue.path.length > 0 ? issue.path.join(".") : "(document)";
		const message =
			issue.code === "invalid_enum_value"
				? `must be one of ${issue.options.join(", ")}`
				: issue.code === "unrecognized_keys"
					? `unsupported field(s) ${issue.keys.join(", ")}`
					: issue.message;
		return `${path}: ${message}`;
	});
	if (issues.length > max) listed.push(`and ${issues.length - max} more issue(s)`);
	return listed;
}

/** Parse JSON or YAML profile text (no aliases, no duplicate keys, bounded size). */
export function parseAgentProfileSource(source: string): unknown {
	if (typeof source !== "string" || source.trim() === "") throw new Error("document is empty");
	if (Buffer.byteLength(source, "utf8") > MAX_DOCUMENT_BYTES) {
		throw new Error("document exceeds the 256 KiB size limit");
	}
	try {
		return JSON.parse(source);
	} catch {
		// Not JSON; YAML is accepted as well.
	}
	const document = parseDocument(source, { schema: "core", uniqueKeys: true, prettyErrors: false });
	if (document.errors.length > 0) throw new Error("document is neither valid JSON nor YAML");
	try {
		return document.toJS({ maxAliasCount: 0 });
	} catch {
		throw new Error("document uses YAML aliases, which are not supported");
	}
}

function gate(profile: AgentProfile, toolClass: AgentProfileToolClass): AgentProfileAction {
	return profile.tools?.[toolClass] ?? profile.default;
}

function diagnose(document: AgentProfileDocument): AgentProfileDiagnostic[] {
	const diagnostics: AgentProfileDiagnostic[] = [];
	const selectorKeys = new Map<string, string>();
	for (const profile of document.profiles) {
		const noEffect = (field: string, toolClasses: AgentProfileToolClass[]) => {
			if (toolClasses.every((toolClass) => gate(profile, toolClass) === "deny")) {
				diagnostics.push({
					profile: profile.name,
					code: "no_effect",
					message: `${field} has no effect: tools.${toolClasses.join(" and tools.")} resolve to deny.`,
				});
			}
		};
		if (profile.commands?.allow_prefixes) noEffect("commands.allow_prefixes", ["shell"]);
		if (profile.files?.read_roots) noEffect("files.read_roots", ["file_read"]);
		if (profile.files?.write_roots) noEffect("files.write_roots", ["file_write"]);
		if (profile.network?.allow_domains) noEffect("network.allow_domains", ["shell", "web_fetch"]);
		if (profile.mcp?.servers || profile.mcp?.tools) noEffect("mcp", ["mcp"]);
		const selector = JSON.stringify([
			[...(profile.applies_to?.connectors ?? [])].sort(),
			[...(profile.applies_to?.repositories ?? [])].sort(),
		]);
		const earlier = selectorKeys.get(selector);
		if (earlier) {
			diagnostics.push({
				profile: profile.name,
				code: "same_selector",
				message: `Selects the same calls as "${earlier}"; both apply and the stricter outcome wins.`,
			});
		} else selectorKeys.set(selector, profile.name);
	}
	return diagnostics;
}

export function validateAgentProfileDocument(value: unknown): AgentProfileValidation {
	const parsed = AgentProfileDocumentSchema.safeParse(value);
	if (!parsed.success)
		return { ok: false, errors: describeAgentProfileIssues(parsed.error.issues) };
	return { ok: true, document: parsed.data, diagnostics: diagnose(parsed.data) };
}

/** Parse and validate profile text in one step; parse failures become errors. */
export function validateAgentProfileSource(source: string): AgentProfileValidation {
	let value: unknown;
	try {
		value = parseAgentProfileSource(source);
	} catch (error) {
		return { ok: false, errors: [error instanceof Error ? error.message : "unreadable document"] };
	}
	return validateAgentProfileDocument(value);
}

// ── Selection ──────────────────────────────────────────────────────

export interface AgentProfileEnvironment {
	/** Absolute working directory of the agent session (host-reported). */
	workingDirectory: string;
	/** Home directory used for `~` expansion. */
	home?: string;
}

function homeDirectory(environment: AgentProfileEnvironment): string {
	const envHome = process.env.HOME?.trim();
	return environment.home ?? (envHome ? envHome : homedir());
}

/** Expand `~` and `${workspace}` and resolve relative paths against the workspace. */
function expandProfilePath(value: string, environment: AgentProfileEnvironment): string {
	let path = value;
	if (path.startsWith(WORKSPACE_PLACEHOLDER)) {
		path = environment.workingDirectory + path.slice(WORKSPACE_PLACEHOLDER.length);
	} else if (path === "~" || path.startsWith("~/") || path.startsWith("~\\")) {
		path = homeDirectory(environment) + path.slice(1);
	} else if (path.startsWith("$HOME/")) {
		path = homeDirectory(environment) + path.slice(5);
	}
	if (path.startsWith("**")) return path;
	return isAbsolute(path) ? path : resolve(environment.workingDirectory, path);
}

function selectorScore(profile: AgentProfile): number {
	return (profile.applies_to?.repositories ? 2 : 0) + (profile.applies_to?.connectors ? 1 : 0);
}

function profileApplies(
	profile: AgentProfile,
	connector: AgentProfileConnector,
	environment: AgentProfileEnvironment,
): boolean {
	const connectors = profile.applies_to?.connectors;
	if (connectors && !connectors.includes(connector)) return false;
	const repositories = profile.applies_to?.repositories;
	if (!repositories) return true;
	return repositories.some((pattern) =>
		pathMatchesGlob(environment.workingDirectory, expandProfilePath(pattern, environment)),
	);
}

/**
 * The profiles that govern one call: the matching profiles with the most
 * specific selector (repository > connector > unconditional). Ties all apply.
 * With no match, `default_profile` applies when the document names one.
 */
export function selectAgentProfiles(
	document: AgentProfileDocument,
	connector: AgentProfileConnector,
	environment: AgentProfileEnvironment,
): AgentProfile[] {
	const matching = document.profiles.filter((profile) =>
		profileApplies(profile, connector, environment),
	);
	if (matching.length === 0) {
		const fallback = document.profiles.find((profile) => profile.name === document.default_profile);
		return fallback ? [fallback] : [];
	}
	const best = Math.max(...matching.map(selectorScore));
	return matching.filter((profile) => selectorScore(profile) === best);
}

// ── Tool classification ────────────────────────────────────────────

const SHELL_TOOLS = new Set([
	"bash",
	"shell",
	"bashoutput",
	"killshell",
	"killbash",
	"exec_command",
	"write_stdin",
	"terminal",
	"run_in_terminal",
]);
/** Shell tools that manage an existing process and carry no command line. */
const SHELL_TOOLS_WITHOUT_COMMAND = new Set(["bashoutput", "killshell", "killbash", "write_stdin"]);
const FILE_READ_TOOLS = new Set([
	"read",
	"glob",
	"grep",
	"ls",
	"list",
	"notebookread",
	"list_dir",
	"list_directory",
	"codebase_search",
	"grep_search",
	"file_search",
	"search_files",
	"view",
	"read_many_files",
]);
const FILE_WRITE_TOOLS = new Set([
	"write",
	"edit",
	"multiedit",
	"notebookedit",
	"delete",
	"patch",
	"str_replace_editor",
	"str_replace_based_edit_tool",
	"rename_file",
	"move_file",
	"replace",
]);
const WEB_TOOLS = new Set([
	"webfetch",
	"websearch",
	"web_search",
	"web_fetch",
	"fetch",
	"browser",
	"google_web_search",
]);

export function classifyAgentTool(toolName: string): AgentProfileToolClass {
	const name = toolName.trim().toLowerCase();
	if (name === "mcp" || name.startsWith("mcp__")) return "mcp";
	if (SHELL_TOOLS.has(name)) return "shell";
	if (FILE_READ_TOOLS.has(name)) return "file_read";
	if (FILE_WRITE_TOOLS.has(name)) return "file_write";
	if (WEB_TOOLS.has(name)) return "web_fetch";
	return "other";
}

// ── Evaluation ─────────────────────────────────────────────────────

export interface AgentProfileCall {
	/** Canonical tool name (after core tool normalization). */
	toolName: string;
	toolInput: Record<string, unknown>;
	artifacts: Artifact[];
}

type AgentProfileCheck =
	| "tool"
	| "command"
	| "file"
	| "network"
	| "mcp"
	| "selection"
	| "invalid";

export interface AgentProfileOutcome {
	action: AgentProfileAction;
	/** Rule path inside the profile, e.g. `commands.deny_prefixes["rm -rf"]`. */
	rule: string;
	/** Human-readable explanation; never contains tool input beyond a host name or path. */
	detail: string;
	check: AgentProfileCheck;
	artifacts: string[];
}

const MATCHED_IDS: Record<AgentProfileCheck, string> = {
	tool: "AGENT-PROFILE-TOOL",
	command: "AGENT-PROFILE-COMMAND",
	file: "AGENT-PROFILE-FILE",
	network: "AGENT-PROFILE-NETWORK",
	mcp: "AGENT-PROFILE-MCP",
	selection: "AGENT-PROFILE-SELECTION",
	invalid: "AGENT-PROFILE-INVALID",
};

function stricter(current: AgentProfileOutcome, candidate: AgentProfileOutcome) {
	if (RANK[candidate.action] > RANK[current.action]) return candidate;
	// Equal outcome: report the more specific rule rather than the tool gate.
	if (
		RANK[candidate.action] === RANK[current.action] &&
		candidate.action !== "allow" &&
		current.check === "tool" &&
		candidate.check !== "tool"
	) {
		return candidate;
	}
	return current;
}

function quoted(value: string): string {
	return JSON.stringify(value);
}

function toolGate(profile: AgentProfile, toolName: string): AgentProfileOutcome {
	const override = profile.tool_overrides?.[toolName];
	if (override) {
		return {
			action: override,
			rule: `tool_overrides[${quoted(toolName)}]`,
			detail: `tool ${quoted(toolName)} is set to ${override}`,
			check: "tool",
			artifacts: [],
		};
	}
	const toolClass = classifyAgentTool(toolName);
	const configured = profile.tools?.[toolClass];
	const action = configured ?? profile.default;
	return {
		action,
		rule: configured ? `tools.${toolClass}` : "default",
		detail: configured
			? `${toolClass} tools are set to ${action}`
			: `${toolClass} tools are not listed, so the profile default (${action}) applies`,
		check: "tool",
		artifacts: [],
	};
}

function commandStrings(call: AgentProfileCall): string[] {
	const out: string[] = [];
	for (const key of ["command", "cmd"]) {
		const value = call.toolInput[key];
		if (value === undefined) continue;
		const parsed = commandFromValue(value);
		if (parsed.ok && parsed.command) out.push(parsed.command);
	}
	if (out.length === 0) {
		for (const artifact of call.artifacts) {
			if (artifact.type === "command" && !artifact.context) out.push(artifact.value);
		}
	}
	return out;
}

function commandChecks(profile: AgentProfile, call: AgentProfileCall): AgentProfileOutcome[] {
	const rules = profile.commands;
	if (!rules) return [];
	const commands = commandStrings(call);
	const outcomes: AgentProfileOutcome[] = [];
	for (const command of commands) {
		const denied = findDeniedPrefix(command, rules.deny_prefixes ?? []);
		if (denied) {
			outcomes.push({
				action: "deny",
				rule: `commands.deny_prefixes[${quoted(denied)}]`,
				detail: `the command runs ${quoted(denied)}, which this profile denies`,
				check: "command",
				artifacts: [command],
			});
		}
	}
	if (rules.allow_prefixes) {
		const unmatched = rules.unmatched ?? profile.default;
		const noCommandTool = SHELL_TOOLS_WITHOUT_COMMAND.has(call.toolName.toLowerCase());
		if (commands.length === 0 && !noCommandTool) {
			outcomes.push({
				action: unmatched,
				rule: "commands.unmatched",
				detail: "the command line could not be read, so it cannot match an allowed prefix",
				check: "command",
				artifacts: [],
			});
		}
		for (const command of commands) {
			const result = commandMatchesAllowPrefixes(command, rules.allow_prefixes);
			if (!result.matched) {
				outcomes.push({
					action: unmatched,
					rule: "commands.unmatched",
					detail:
						result.offending === "command substitution"
							? "the command uses command substitution, so it cannot be matched against allowed prefixes"
							: "a command segment does not start with an allowed prefix (or redirects output into a file)",
					check: "command",
					artifacts: [command],
				});
			}
		}
	}
	return outcomes;
}

const MAX_COMMAND_PATH_WORDS = 64;

/** Words of a shell command that may name a file, for deny-pattern checks. */
function commandPathWords(commands: string[]): string[] {
	const words = new Set<string>();
	for (const command of commands) {
		for (const raw of command.split(/[\s;&|<>()`]+/)) {
			let word = raw.replace(/["'\\]/g, "");
			if (word.startsWith("-")) {
				const eq = word.indexOf("=");
				if (eq === -1) continue;
				word = word.slice(eq + 1);
			}
			word = word.replace(/^\$\{HOME\}/, "$HOME");
			if (!word || word.includes("://")) continue;
			words.add(word);
			if (words.size >= MAX_COMMAND_PATH_WORDS) return [...words];
		}
	}
	return [...words];
}

const CANONICAL_FILE_CONTEXTS = new Set(["read", "write", "edit", "delete"]);
const PATH_KEY =
	/^(?:file_?path|path|paths|notebook_path|target_file|filename|file|dir|directory|cwd|root|target|destination|source)$|_(?:path|file|dir|directory)$/i;

/** Paths the file tool will operate on (not every path-looking string in its input). */
function scopedFilePaths(call: AgentProfileCall): string[] {
	const out = new Set<string>();
	for (const artifact of call.artifacts) {
		if (artifact.type !== "file_path" || !artifact.value.trim()) continue;
		const context = artifact.context ?? "";
		if (CANONICAL_FILE_CONTEXTS.has(context)) {
			out.add(artifact.value.trim());
			continue;
		}
		const field = context.startsWith("tool:") ? context.slice(context.lastIndexOf(":") + 1) : "";
		const key = (field.split(".").pop() ?? "").replace(/\[\d+\]$/, "");
		if (key && PATH_KEY.test(key)) out.add(artifact.value.trim());
	}
	return [...out];
}

async function resolvedCandidates(path: string, environment: AgentProfileEnvironment) {
	const lexical = expandProfilePath(path, environment);
	const resolved = await resolvePolicyPath(lexical).catch(() => null);
	return { lexical, resolved };
}

async function fileChecks(
	profile: AgentProfile,
	call: AgentProfileCall,
	toolClass: AgentProfileToolClass,
	environment: AgentProfileEnvironment,
): Promise<AgentProfileOutcome[]> {
	const rules = profile.files;
	if (!rules) return [];
	const outcomes: AgentProfileOutcome[] = [];
	// Deny patterns apply to every path any tool names, including MCP arguments
	// and the words of a shell command (`cat ~/.ssh/id_rsa`).
	const allPaths = new Set(
		call.artifacts
			.filter((artifact) => artifact.type === "file_path" && artifact.value.trim())
			.map((artifact) => artifact.value.trim()),
	);
	// Shell words are checked lexically only: resolving every word would cost a
	// filesystem walk per word, and a symlink created to evade a pattern has to
	// name the protected path itself (and is denied) in an earlier command.
	const shellWords =
		toolClass === "shell" && rules.deny?.length
			? commandPathWords(commandStrings(call)).filter((word) => !allPaths.has(word))
			: [];
	const denyPatterns = (rules.deny ?? []).map((pattern) => ({
		pattern,
		expanded: expandProfilePath(pattern, environment),
	}));
	const candidates = [
		...[...allPaths].map((path) => ({ path, resolve: true })),
		...shellWords.map((path) => ({ path, resolve: false })),
	];
	for (const { path, resolve: follow } of denyPatterns.length > 0 ? candidates : []) {
		const { lexical, resolved } = follow
			? await resolvedCandidates(path, environment)
			: { lexical: expandProfilePath(path, environment), resolved: null };
		const hit = denyPatterns.find(
			({ expanded }) =>
				pathMatchesGlob(lexical, expanded) ||
				(resolved !== null && pathMatchesGlob(resolved, expanded)),
		);
		if (hit) {
			outcomes.push({
				action: "deny",
				rule: `files.deny[${quoted(hit.pattern)}]`,
				detail: `the path matches ${quoted(hit.pattern)}, which this profile denies`,
				check: "file",
				artifacts: [path],
			});
		}
	}

	const roots =
		toolClass === "file_read"
			? { list: rules.read_roots, field: "files.read_roots" }
			: toolClass === "file_write"
				? { list: rules.write_roots, field: "files.write_roots" }
				: null;
	if (!roots?.list) return outcomes;
	const outside = rules.outside_roots ?? profile.default;
	let targets = scopedFilePaths(call);
	if (targets.length === 0) {
		if (toolClass === "file_write") {
			outcomes.push({
				action: outside,
				rule: `${roots.field} (outside_roots)`,
				detail:
					"the write target could not be determined, so it cannot be proven inside an allowed root",
				check: "file",
				artifacts: [],
			});
			return outcomes;
		}
		// Search/list tools without a path operate on the working directory.
		targets = [environment.workingDirectory];
	}
	const resolvedRoots = await Promise.all(
		roots.list.map(async (root) => {
			const lexical = expandProfilePath(root, environment);
			return (await resolvePolicyPath(lexical).catch(() => null)) ?? lexical;
		}),
	);
	for (const target of targets) {
		const { resolved } = await resolvedCandidates(target, environment);
		const inside = resolved !== null && resolvedRoots.some((root) => isPathWithin(resolved, root));
		if (!inside) {
			outcomes.push({
				action: outside,
				rule: `${roots.field} (outside_roots)`,
				detail: `the path is outside every ${roots.field.slice(6).replace("_", " ")} of this profile`,
				check: "file",
				artifacts: [target],
			});
		}
	}
	return outcomes;
}

const CONTENT_URL_CONTEXTS = new Set([
	"from_file_content",
	"from_edit_content",
	"from_read_content",
]);

function networkChecks(
	profile: AgentProfile,
	call: AgentProfileCall,
	toolClass: AgentProfileToolClass,
): AgentProfileOutcome[] {
	const rules = profile.network;
	if (!rules || toolClass === "file_read" || toolClass === "file_write") return [];
	const outcomes: AgentProfileOutcome[] = [];
	const urls = new Set(
		call.artifacts
			.filter(
				(artifact) => artifact.type === "url" && !CONTENT_URL_CONTEXTS.has(artifact.context ?? ""),
			)
			.map((artifact) => artifact.value),
	);
	for (const url of urls) {
		const host = urlHost(url);
		const denied = host
			? rules.deny_domains?.find((entry) => hostMatchesDomain(host, entry))
			: null;
		if (denied) {
			outcomes.push({
				action: "deny",
				rule: `network.deny_domains[${quoted(denied)}]`,
				detail: `the call reaches ${host}, which this profile denies`,
				check: "network",
				artifacts: [url],
			});
			continue;
		}
		if (
			rules.allow_domains &&
			!(host && rules.allow_domains.some((e) => hostMatchesDomain(host, e)))
		) {
			const action = rules.unmatched ?? profile.default;
			outcomes.push({
				action,
				rule: "network.unmatched",
				detail: host
					? `the call reaches ${host}, which is not in network.allow_domains`
					: "the call reaches a URL whose host could not be read",
				check: "network",
				artifacts: [url],
			});
		}
	}
	return outcomes;
}

/** Server and tool of an MCP call, from `mcp__<server>__<tool>` or the host's generic MCP shape. */
export function mcpCallIdentity(
	toolName: string,
	toolInput: Record<string, unknown>,
): { server: string; tool: string } | null {
	if (toolName.startsWith("mcp__")) {
		const parts = toolName.split("__");
		const server = parts[1];
		const tool = parts.slice(2).join("__");
		return server && tool ? { server, tool } : null;
	}
	const nested =
		toolInput.tool_input && typeof toolInput.tool_input === "object"
			? (toolInput.tool_input as Record<string, unknown>)
			: {};
	const server = [toolInput.server, nested.server].find((v) => typeof v === "string" && v);
	const tool = [toolInput.name, toolInput.tool_name, nested.name].find(
		(v) => typeof v === "string" && v,
	);
	return typeof server === "string" && typeof tool === "string" ? { server, tool } : null;
}

function mcpChecks(
	profile: AgentProfile,
	call: AgentProfileCall,
	toolClass: AgentProfileToolClass,
): AgentProfileOutcome[] {
	const rules = profile.mcp;
	if (toolClass !== "mcp" || !rules || (!rules.servers && !rules.tools)) return [];
	const unmatched = rules.unmatched ?? profile.default;
	const identity = mcpCallIdentity(call.toolName, call.toolInput);
	if (!identity) {
		return [
			{
				action: unmatched,
				rule: "mcp.unmatched",
				detail: "the MCP server and tool could not be identified",
				check: "mcp",
				artifacts: [],
			},
		];
	}
	const { server, tool } = identity;
	const toolAction = rules.tools?.[server]?.[tool];
	if (toolAction) {
		return [
			{
				action: toolAction,
				rule: `mcp.tools[${quoted(server)}][${quoted(tool)}]`,
				detail: `MCP tool ${server}/${tool} is set to ${toolAction}`,
				check: "mcp",
				artifacts: [],
			},
		];
	}
	const serverAction = rules.servers?.[server];
	if (serverAction) {
		return [
			{
				action: serverAction,
				rule: `mcp.servers[${quoted(server)}]`,
				detail: `MCP server ${server} is set to ${serverAction}`,
				check: "mcp",
				artifacts: [],
			},
		];
	}
	return [
		{
			action: unmatched,
			rule: "mcp.unmatched",
			detail: `MCP tool ${server}/${tool} is not listed in this profile`,
			check: "mcp",
			artifacts: [],
		},
	];
}

/** Evaluate one call against one profile. The strictest applicable rule wins. */
export async function evaluateAgentProfile(
	profile: AgentProfile,
	call: AgentProfileCall,
	environment: AgentProfileEnvironment,
): Promise<AgentProfileOutcome> {
	const toolClass = classifyAgentTool(call.toolName);
	let result = toolGate(profile, call.toolName);
	const outcomes = [
		...(toolClass === "shell" ? commandChecks(profile, call) : []),
		...(await fileChecks(profile, call, toolClass, environment)),
		...networkChecks(profile, call, toolClass),
		...mcpChecks(profile, call, toolClass),
	];
	for (const outcome of outcomes) result = stricter(result, outcome);
	return result;
}

// ── Context and verdicts ───────────────────────────────────────────

export type AgentProfileSource = "managed" | "local";

export type AgentProfileLayer =
	| {
			status: "loaded";
			source: AgentProfileSource;
			/** Where the document came from (a file path or bundle name), for diagnostics. */
			origin: string;
			document: AgentProfileDocument;
	  }
	| { status: "invalid"; source: AgentProfileSource; origin: string; reason: string };

/**
 * Trusted, caller-owned profile context. Connectors receive it from the
 * detector provisioning loader; a tool payload can never select it.
 */
export interface AgentProfileContext {
	connector: AgentProfileConnector;
	layers: AgentProfileLayer[];
	/** Explicit profile name (MCP gateway clients); absent means selector-based choice. */
	profileName?: string;
}

export interface AgentProfileEvaluation {
	decision: AgentProfileAction;
	/** Every profile that governed the call, per layer. */
	selected: { profile: string; source: AgentProfileSource }[];
	/** The rule that decided a non-allow outcome. */
	deciding: (AgentProfileOutcome & { profile: string; source: AgentProfileSource }) | null;
}

function invalidOutcome(layer: Extract<AgentProfileLayer, { status: "invalid" }>) {
	return {
		action: "deny" as const,
		rule: "document",
		detail: `the ${layer.source} agent permission profile document is invalid (${layer.reason}); every call is denied until it is repaired`,
		check: "invalid" as const,
		artifacts: [],
		profile: "(invalid)",
		source: layer.source,
	};
}

/**
 * Evaluate a call against every profile layer. An invalid managed layer denies
 * the call (fail closed); an invalid local layer is never passed here because
 * the loader refuses to load it.
 */
export async function evaluateAgentProfiles(
	context: AgentProfileContext,
	call: AgentProfileCall,
	environment: AgentProfileEnvironment,
): Promise<AgentProfileEvaluation> {
	const selected: AgentProfileEvaluation["selected"] = [];
	let deciding: AgentProfileEvaluation["deciding"] = null;
	const consider = (outcome: NonNullable<AgentProfileEvaluation["deciding"]>) => {
		if (outcome.action === "allow") return;
		if (!deciding || RANK[outcome.action] > RANK[deciding.action]) deciding = outcome;
	};
	for (const layer of context.layers) {
		if (layer.status === "invalid") {
			consider(invalidOutcome(layer));
			continue;
		}
		let profiles: AgentProfile[];
		if (context.profileName) {
			const named = layer.document.profiles.find((profile) => profile.name === context.profileName);
			if (!named) {
				consider({
					action: "deny",
					rule: "profile",
					detail: `profile ${quoted(context.profileName)} assigned to this ${context.connector} client does not exist in the ${layer.source} document`,
					check: "selection",
					artifacts: [],
					profile: context.profileName,
					source: layer.source,
				});
				continue;
			}
			profiles = [named];
		} else {
			profiles = selectAgentProfiles(layer.document, context.connector, environment);
		}
		for (const profile of profiles) {
			selected.push({ profile: profile.name, source: layer.source });
			const outcome = await evaluateAgentProfile(profile, call, environment);
			consider({ ...outcome, profile: profile.name, source: layer.source });
		}
	}
	const decided = deciding as AgentProfileEvaluation["deciding"];
	return { decision: decided?.action ?? "allow", selected, deciding: decided };
}

/** A blocking verdict naming the profile and the rule; null for an allow. */
export function agentProfileVerdict(evaluation: AgentProfileEvaluation): Verdict | null {
	const deciding = evaluation.deciding;
	if (!deciding || deciding.action === "allow") return null;
	const label =
		deciding.check === "invalid"
			? `Agent permission profile (${deciding.source})`
			: `Agent permission profile ${quoted(deciding.profile)} (${deciding.source})`;
	return {
		decision: deciding.action,
		category: deciding.check === "invalid" ? "agent_profile_invalid" : "agent_profile",
		confidence: 1,
		severity: deciding.action === "deny" ? "critical" : "warning",
		source: "agent_profile",
		artifacts: deciding.artifacts,
		matchedThreatId: MATCHED_IDS[deciding.check],
		reasons: [
			`${label} ${deciding.action === "deny" ? "denied" : "requires approval for"} this call: rule ${deciding.rule} — ${deciding.detail}.`,
		],
		agentProfile: { profile: deciding.profile, source: deciding.source, rule: deciding.rule },
	};
}

/**
 * Merge a profile verdict into the detection verdict with deny > ask > allow.
 * A profile can only make the outcome stricter; on a tie the detection verdict
 * keeps its identity and gains the profile's reason.
 */
export function mergeAgentProfileVerdict(verdict: Verdict, profile: Verdict | null): Verdict {
	if (!profile || profile.decision === "allow") return verdict;
	const current = RANK[verdict.decision];
	const candidate = RANK[profile.decision];
	if (candidate > current) {
		return verdict.delegation ? { ...profile, delegation: verdict.delegation } : profile;
	}
	if (candidate === current) {
		return { ...verdict, reasons: [...verdict.reasons, ...profile.reasons] };
	}
	return verdict;
}

/** A fixed deny for a profile evaluation that failed unexpectedly. */
export function agentProfileFailureVerdict(): Verdict {
	return {
		decision: "deny",
		category: "agent_profile_invalid",
		confidence: 1,
		severity: "critical",
		source: "agent_profile",
		artifacts: [],
		matchedThreatId: MATCHED_IDS.invalid,
		reasons: [
			"Agent permission profile could not be evaluated for this call; execution was denied.",
		],
	};
}
