// Generated from packages/core/src/agent-profile-schema.ts; do not edit.
// Regenerate: node scripts/sync-agent-profile-edge-schema.mjs --write
import { type ZodIssue, z } from "npm:zod@3.25.76";

/**
 * Agent permission profile schema and document validation.
 *
 * This module depends on zod only, so the SAME schema can be deployed with the
 * control plane: `scripts/sync-agent-profile-edge-schema.mjs` copies it
 * byte-for-byte (with the zod import pinned) to
 * `supabase/functions/_shared/agent-profile-schema.ts`, where policy-management
 * validates dashboard-staged profiles before they are stored. Evaluation,
 * selection and parsing of JSON/YAML text stay in `agent-profile.ts`.
 */

// ── Vocabulary ─────────────────────────────────────────────────────

export const AGENT_PROFILE_CONNECTORS = [
	"claude-code",
	"cursor",
	"vscode",
	"openclaw",
	"opencode",
	"codex",
	"mcp-gateway",
] as const;
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

// ── Document validation ────────────────────────────────────────────

export interface AgentProfileDiagnostic {
	profile: string;
	code: "no_effect" | "same_selector";
	message: string;
}

export type AgentProfileValidation =
	| { ok: true; document: AgentProfileDocument; diagnostics: AgentProfileDiagnostic[] }
	| { ok: false; errors: string[] };

/** Issue locations and messages only; never the offending value. */
export function describeAgentProfileIssues(issues: readonly ZodIssue[], max = 8): string[] {
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
