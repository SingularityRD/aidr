import { parseDocument } from "yaml";
import { z } from "zod";
import {
	matchesMcpToolSelector,
	mcpToolSelector,
	parseLegacyMcpToolSelector,
} from "./mcp-tool-identity.js";

export const POLICY_DOCUMENT_ACTIONS = ["allow", "ask", "deny"] as const;
type PolicyDocumentAction = (typeof POLICY_DOCUMENT_ACTIONS)[number];
type RuntimePolicyCategory = "command" | "file" | "url" | "package" | "output";

const actionSchema = z.enum(POLICY_DOCUMENT_ACTIONS);
const mcpIdentitySchema = z
	.string()
	.min(1)
	.max(256)
	.regex(/^[A-Za-z0-9][A-Za-z0-9._:/_-]{0,255}$/, "must be an MCP identifier");
const legacyToolIdSchema = z
	.string()
	.min(3)
	.max(513)
	.regex(
		/^[A-Za-z0-9][A-Za-z0-9_:/-]{0,255}\.[A-Za-z0-9][A-Za-z0-9_:/-]{0,255}$/,
		"legacy selectors must use server.tool with no dots inside either name",
	);
const structuredToolIdSchema = z
	.object({ server: mcpIdentitySchema, tool: mcpIdentitySchema })
	.strict();
const toolIdSchema = z.union([legacyToolIdSchema, structuredToolIdSchema]);

const categoryDefaultsSchema = z
	.object({
		command: actionSchema.optional(),
		file: actionSchema.optional(),
		url: actionSchema.optional(),
		package: actionSchema.optional(),
		output: actionSchema.optional(),
	})
	.strict();

const conditionSchema = z
	.object({
		mcp_server: mcpIdentitySchema.optional(),
		mcp_tool: toolIdSchema.optional(),
	})
	.strict()
	.superRefine((value, context) => {
		if (Number(value.mcp_server !== undefined) + Number(value.mcp_tool !== undefined) !== 1) {
			context.addIssue({
				code: z.ZodIssueCode.custom,
				message: "condition must contain exactly one of mcp_server or mcp_tool",
			});
		}
	});

const policyRuleSchema = z
	.object({
		name: z.string().trim().min(1).max(160),
		condition: conditionSchema,
		action: actionSchema,
		priority: z.number().int().min(0).max(1_000),
	})
	.strict();

export const PolicyDocumentSchema = z
	.object({
		version: z.union([z.literal("1.0"), z.literal(1)]),
		description: z.string().max(2_000).optional(),
		default_action: actionSchema,
		unknown_action: actionSchema.default("ask"),
		risky_action: actionSchema.default("deny"),
		category_defaults: categoryDefaultsSchema.default({}),
		rules: z.array(policyRuleSchema).max(200),
	})
	.strict();

export type PolicyDocument = z.infer<typeof PolicyDocumentSchema>;

export interface CompiledRuntimePolicy {
	command_default: PolicyDocumentAction;
	file_default: PolicyDocumentAction;
	url_default: PolicyDocumentAction;
	package_default: PolicyDocumentAction;
	output_default: PolicyDocumentAction;
	mcp_default: PolicyDocumentAction;
	mcp_unknown: PolicyDocumentAction;
	mcp_risky: PolicyDocumentAction;
	mcp_allow_servers: string[];
	mcp_require_approval_servers: string[];
	mcp_deny_servers: string[];
	mcp_allow_tools: string[];
	mcp_require_approval_tools: string[];
	mcp_deny_tools: string[];
}

export interface PolicyCompilationDiagnostic {
	code: "shadowed_rule";
	rule: string;
	selector: string;
	winner: string;
	message: string;
}

export interface PolicyCompilationResult {
	document: PolicyDocument;
	runtime_policy: CompiledRuntimePolicy;
	diagnostics: PolicyCompilationDiagnostic[];
	semantics: {
		precedence: readonly ["deny", "ask", "allow"];
		unknown_mcp: PolicyDocumentAction;
		risky_mcp: PolicyDocumentAction;
		mcp_fallback: PolicyDocumentAction;
	};
}

export type PolicySimulationInput =
	| { kind: RuntimePolicyCategory }
	| {
			kind: "mcp";
			server: string;
			tool: string;
			inventory: "known" | "unknown" | "risky";
	  };

export interface PolicySimulationResult {
	action: PolicyDocumentAction;
	source:
		| "category_default"
		| "mcp_tool"
		| "mcp_server"
		| "mcp_risky"
		| "mcp_unknown"
		| "mcp_default";
	matched: string | null;
}

const ACTION_WEIGHT: Record<PolicyDocumentAction, number> = { allow: 1, ask: 2, deny: 3 };
const CATEGORY_KEYS: Record<RuntimePolicyCategory, keyof CompiledRuntimePolicy> = {
	command: "command_default",
	file: "file_default",
	url: "url_default",
	package: "package_default",
	output: "output_default",
};

function compiledMcpTarget(condition: PolicyDocument["rules"][number]["condition"]): {
	scope: "server" | "tool";
	target: string;
} {
	if (condition.mcp_server) return { scope: "server", target: condition.mcp_server };
	const tool = condition.mcp_tool;
	if (typeof tool === "string") return { scope: "tool", target: tool };
	if (tool) return { scope: "tool", target: mcpToolSelector(tool.server, tool.tool) };
	throw new Error("invalid_policy_document:missing MCP selector");
}

function selectorFor(rule: PolicyDocument["rules"][number]): string {
	const { scope, target } = compiledMcpTarget(rule.condition);
	if (scope === "tool" && typeof rule.condition.mcp_tool === "string") {
		const identity = parseLegacyMcpToolSelector(rule.condition.mcp_tool);
		if (!identity) throw new Error("invalid_policy_document:ambiguous MCP tool selector");
		return `tool:${mcpToolSelector(...identity)}`;
	}
	return `${scope}:${target}`;
}

function listKey(
	scope: "server" | "tool",
	action: PolicyDocumentAction,
): keyof CompiledRuntimePolicy {
	if (scope === "server") {
		return action === "deny"
			? "mcp_deny_servers"
			: action === "ask"
				? "mcp_require_approval_servers"
				: "mcp_allow_servers";
	}
	return action === "deny"
		? "mcp_deny_tools"
		: action === "ask"
			? "mcp_require_approval_tools"
			: "mcp_allow_tools";
}

/** Parse a bounded YAML/JSON policy document without accepting aliases or duplicate keys. */
export function parsePolicyDocument(source: string): unknown {
	if (typeof source !== "string" || source.length === 0) throw new Error("policy_document_empty");
	if (source.length > 65_536) throw new Error("policy_document_too_large");
	const document = parseDocument(source, {
		schema: "core",
		uniqueKeys: true,
		prettyErrors: false,
	});
	if (document.errors.length > 0)
		throw new Error(`invalid_policy_yaml:${document.errors[0]?.message ?? "parse_error"}`);
	try {
		return document.toJS({ maxAliasCount: 0 });
	} catch (error) {
		throw new Error(
			`invalid_policy_yaml:${error instanceof Error ? error.message : "alias_not_allowed"}`,
		);
	}
}

function describeSchemaError(error: z.ZodError): string {
	const issue = error.issues[0];
	const path = issue?.path.length ? issue.path.join(".") : "document";
	return `invalid_policy_document:${path}:${issue?.message ?? "invalid value"}`;
}

/**
 * Compile the authoring document to the exact control-plane runtime contract.
 * Conflicts are deterministic: priority first, then deny > ask > allow, then source order.
 */
export function compilePolicyDocument(value: unknown): PolicyCompilationResult {
	const parsed = PolicyDocumentSchema.safeParse(value);
	if (!parsed.success) throw new Error(describeSchemaError(parsed.error));
	const document = parsed.data;
	const runtimePolicy: CompiledRuntimePolicy = {
		command_default: document.category_defaults.command ?? document.default_action,
		file_default: document.category_defaults.file ?? document.default_action,
		url_default: document.category_defaults.url ?? document.default_action,
		package_default: document.category_defaults.package ?? document.default_action,
		output_default: document.category_defaults.output ?? document.default_action,
		mcp_default: document.default_action,
		mcp_unknown: document.unknown_action,
		mcp_risky: document.risky_action,
		mcp_allow_servers: [],
		mcp_require_approval_servers: [],
		mcp_deny_servers: [],
		mcp_allow_tools: [],
		mcp_require_approval_tools: [],
		mcp_deny_tools: [],
	};
	const diagnostics: PolicyCompilationDiagnostic[] = [];
	const indexed = document.rules.map((rule, index) => ({ rule, index }));
	indexed.sort(
		(a, b) =>
			b.rule.priority - a.rule.priority ||
			ACTION_WEIGHT[b.rule.action] - ACTION_WEIGHT[a.rule.action] ||
			a.index - b.index,
	);
	const winners = new Map<string, (typeof indexed)[number]>();
	for (const candidate of indexed) {
		const selector = selectorFor(candidate.rule);
		const winner = winners.get(selector);
		if (winner) {
			diagnostics.push({
				code: "shadowed_rule",
				rule: candidate.rule.name,
				selector,
				winner: winner.rule.name,
				message: `Rule "${candidate.rule.name}" is shadowed by "${winner.rule.name}" for ${selector}.`,
			});
			continue;
		}
		winners.set(selector, candidate);
		const { scope, target } = compiledMcpTarget(candidate.rule.condition);
		(runtimePolicy[listKey(scope, candidate.rule.action)] as string[]).push(target);
	}
	for (const key of [
		"mcp_allow_servers",
		"mcp_require_approval_servers",
		"mcp_deny_servers",
		"mcp_allow_tools",
		"mcp_require_approval_tools",
		"mcp_deny_tools",
	] as const)
		runtimePolicy[key].sort();

	return {
		document,
		runtime_policy: runtimePolicy,
		diagnostics,
		semantics: {
			precedence: ["deny", "ask", "allow"],
			unknown_mcp: document.unknown_action,
			risky_mcp: document.risky_action,
			mcp_fallback: document.default_action,
		},
	};
}

export function compilePolicyDocumentYaml(source: string): PolicyCompilationResult {
	return compilePolicyDocument(parsePolicyDocument(source));
}

function includes(
	policy: CompiledRuntimePolicy,
	key: keyof CompiledRuntimePolicy,
	value: string,
): boolean {
	const entries = policy[key];
	return Array.isArray(entries) && entries.includes(value);
}

/** Evaluate a dry-run input with the same precedence used by the runtime evaluator. */
export function simulateRuntimePolicy(
	policy: CompiledRuntimePolicy,
	input: PolicySimulationInput,
): PolicySimulationResult {
	if (input.kind !== "mcp") {
		return {
			action: policy[CATEGORY_KEYS[input.kind]] as PolicyDocumentAction,
			source: "category_default",
			matched: input.kind,
		};
	}
	const server = mcpIdentitySchema.parse(input.server);
	const tool = mcpIdentitySchema.parse(input.tool);
	for (const [action, toolKey, serverKey] of [
		["deny", "mcp_deny_tools", "mcp_deny_servers"],
		["ask", "mcp_require_approval_tools", "mcp_require_approval_servers"],
		["allow", "mcp_allow_tools", "mcp_allow_servers"],
	] as const) {
		if (matchesMcpToolSelector(policy[toolKey], server, tool))
			return { action, source: "mcp_tool", matched: mcpToolSelector(server, tool) };
		if (includes(policy, serverKey, server))
			return { action, source: "mcp_server", matched: server };
	}
	if (input.inventory === "risky")
		return { action: policy.mcp_risky, source: "mcp_risky", matched: null };
	if (input.inventory === "unknown" && policy.mcp_unknown !== "allow")
		return { action: policy.mcp_unknown, source: "mcp_unknown", matched: null };
	return { action: policy.mcp_default, source: "mcp_default", matched: null };
}
