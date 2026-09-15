export type PolicyAction = "allow" | "ask" | "deny";

export interface RuntimePolicyDocumentCompilation {
	runtime_policy: Record<string, unknown>;
	diagnostics: Array<{ code: "shadowed_rule"; rule: string; selector: string; winner: string; message: string }>;
	semantics: {
		precedence: ["deny", "ask", "allow"];
		unknown_mcp: PolicyAction;
		risky_mcp: PolicyAction;
		mcp_fallback: PolicyAction;
	};
}

/** Compile and fingerprint the exact UTF-8 source, never a parsed/reserialized copy.
 * The caller supplies the platform YAML parser (Deno's pinned npm parser at the
 * Edge); the same source is passed unchanged to it and later to the CAS write.
 */
export async function compileRuntimePolicyDraft(
	source: unknown,
	parseYaml: (source: string) => unknown,
): Promise<RuntimePolicyDocumentCompilation & { source_sha256: string }> {
	if (typeof source !== "string") throw new Error("invalid_policy_document:content:must_be_string");
	if (!source) throw new Error("policy_document_empty");
	const bytes = new TextEncoder().encode(source);
	if (bytes.byteLength > 65_536) throw new Error("policy_document_too_large");
	const compilation = compileRuntimePolicyDocument(parseYaml(source));
	const digest = await crypto.subtle.digest("SHA-256", bytes);
	const source_sha256 = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
	return { ...compilation, source_sha256 };
}

type Rule = {
	name: string;
	condition: { mcp_server?: string; mcp_tool?: string };
	action: PolicyAction;
	priority: number;
};

const ACTION_WEIGHT: Record<PolicyAction, number> = { allow: 1, ask: 2, deny: 3 };
const ACTIONS = new Set(["allow", "ask", "deny"]);
const SERVER = /^[a-z0-9][a-z0-9._-]{0,79}$/;
const TOOL = /^[a-z0-9][a-z0-9._-]{0,79}\.[a-z0-9][a-z0-9_.-]{0,159}$/;

function object(value: unknown, field: string): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`invalid_policy_document:${field}:must_be_object`);
	return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[], field: string): void {
	const unsupported = Object.keys(value).find((key) => !allowed.includes(key));
	if (unsupported) throw new Error(`invalid_policy_document:${field}:unsupported_field:${unsupported}`);
}

function action(value: unknown, field: string, fallback?: PolicyAction): PolicyAction {
	if (value === undefined && fallback) return fallback;
	if (typeof value !== "string" || !ACTIONS.has(value)) throw new Error(`invalid_policy_document:${field}:invalid_action`);
	return value as PolicyAction;
}

function boundedString(value: unknown, field: string, max: number, optional = false): string | undefined {
	if (value === undefined && optional) return undefined;
	if (typeof value !== "string" || value.trim().length === 0 || value.length > max) throw new Error(`invalid_policy_document:${field}:invalid_string`);
	return value.trim();
}

function parseRule(value: unknown, index: number): Rule {
	const field = `rules.${index}`;
	const row = object(value, field);
	exactKeys(row, ["name", "condition", "action", "priority"], field);
	const condition = object(row.condition, `${field}.condition`);
	exactKeys(condition, ["mcp_server", "mcp_tool"], `${field}.condition`);
	const server = condition.mcp_server;
	const tool = condition.mcp_tool;
	if (Number(server !== undefined) + Number(tool !== undefined) !== 1) throw new Error(`invalid_policy_document:${field}.condition:exactly_one_selector_required`);
	if (server !== undefined && (typeof server !== "string" || !SERVER.test(server))) throw new Error(`invalid_policy_document:${field}.condition.mcp_server:invalid_server_id`);
	if (tool !== undefined && (typeof tool !== "string" || !TOOL.test(tool))) throw new Error(`invalid_policy_document:${field}.condition.mcp_tool:invalid_tool_id`);
	if (!Number.isInteger(row.priority) || Number(row.priority) < 0 || Number(row.priority) > 1_000) throw new Error(`invalid_policy_document:${field}.priority:invalid_priority`);
	return {
		name: boundedString(row.name, `${field}.name`, 160) as string,
		condition: { ...(server !== undefined ? { mcp_server: server as string } : {}), ...(tool !== undefined ? { mcp_tool: tool as string } : {}) },
		action: action(row.action, `${field}.action`),
		priority: Number(row.priority),
	};
}

function listKey(scope: "server" | "tool", mode: PolicyAction): string {
	if (scope === "server") return mode === "deny" ? "mcp_deny_servers" : mode === "ask" ? "mcp_require_approval_servers" : "mcp_allow_servers";
	return mode === "deny" ? "mcp_deny_tools" : mode === "ask" ? "mcp_require_approval_tools" : "mcp_allow_tools";
}

/** Server-side mirror of the core compiler used before a stored draft can be published. */
export function compileRuntimePolicyDocument(value: unknown): RuntimePolicyDocumentCompilation {
	const document = object(value, "document");
	exactKeys(document, ["version", "description", "default_action", "unknown_action", "risky_action", "category_defaults", "rules"], "document");
	if (document.version !== "1.0" && document.version !== 1) throw new Error("invalid_policy_document:version:unsupported_version");
	if (document.description !== undefined && (typeof document.description !== "string" || document.description.length > 2_000)) throw new Error("invalid_policy_document:description:invalid_string");
	const defaultAction = action(document.default_action, "default_action");
	const unknownAction = action(document.unknown_action, "unknown_action", "ask");
	const riskyAction = action(document.risky_action, "risky_action", "deny");
	const categoryDefaults = document.category_defaults === undefined ? {} : object(document.category_defaults, "category_defaults");
	exactKeys(categoryDefaults, ["command", "file", "url", "package", "output"], "category_defaults");
	if (!Array.isArray(document.rules) || document.rules.length > 200) throw new Error("invalid_policy_document:rules:invalid_rules");
	const rules = document.rules.map(parseRule);
	const runtimePolicy: Record<string, unknown> = {
		command_default: action(categoryDefaults.command, "category_defaults.command", defaultAction),
		file_default: action(categoryDefaults.file, "category_defaults.file", defaultAction),
		url_default: action(categoryDefaults.url, "category_defaults.url", defaultAction),
		package_default: action(categoryDefaults.package, "category_defaults.package", defaultAction),
		output_default: action(categoryDefaults.output, "category_defaults.output", defaultAction),
		mcp_default: defaultAction,
		mcp_unknown: unknownAction,
		mcp_risky: riskyAction,
		mcp_allow_servers: [], mcp_require_approval_servers: [], mcp_deny_servers: [],
		mcp_allow_tools: [], mcp_require_approval_tools: [], mcp_deny_tools: [],
	};
	const indexed = rules.map((rule, index) => ({ rule, index })).sort((a, b) => b.rule.priority - a.rule.priority || ACTION_WEIGHT[b.rule.action] - ACTION_WEIGHT[a.rule.action] || a.index - b.index);
	const winners = new Map<string, (typeof indexed)[number]>();
	const diagnostics: RuntimePolicyDocumentCompilation["diagnostics"] = [];
	for (const candidate of indexed) {
		const scope = candidate.rule.condition.mcp_server ? "server" : "tool";
		const target = candidate.rule.condition.mcp_server ?? candidate.rule.condition.mcp_tool as string;
		const selector = `${scope}:${target}`;
		const winner = winners.get(selector);
		if (winner) {
			diagnostics.push({ code: "shadowed_rule", rule: candidate.rule.name, selector, winner: winner.rule.name, message: `Rule "${candidate.rule.name}" is shadowed by "${winner.rule.name}" for ${selector}.` });
			continue;
		}
		winners.set(selector, candidate);
		(runtimePolicy[listKey(scope, candidate.rule.action)] as string[]).push(target);
	}
	for (const key of ["mcp_allow_servers", "mcp_require_approval_servers", "mcp_deny_servers", "mcp_allow_tools", "mcp_require_approval_tools", "mcp_deny_tools"]) (runtimePolicy[key] as string[]).sort();
	return {
		runtime_policy: runtimePolicy,
		diagnostics,
		semantics: { precedence: ["deny", "ask", "allow"], unknown_mcp: unknownAction, risky_mcp: riskyAction, mcp_fallback: defaultAction },
	};
}

export function simulateCompiledRuntimePolicy(policy: Record<string, unknown>, value: unknown): { action: PolicyAction; source: string; matched: string | null } {
	const input = object(value, "simulation");
	if (["command", "file", "url", "package", "output"].includes(String(input.kind))) {
		exactKeys(input, ["kind"], "simulation");
		return { action: action(policy[`${input.kind}_default`], `${input.kind}_default`), source: "category_default", matched: String(input.kind) };
	}
	if (input.kind !== "mcp") throw new Error("invalid_policy_document:simulation:invalid_kind");
	exactKeys(input, ["kind", "server", "tool", "inventory"], "simulation");
	if (typeof input.server !== "string" || !SERVER.test(input.server)) throw new Error("invalid_policy_document:simulation.server:invalid_server_id");
	if (typeof input.tool !== "string" || !SERVER.test(input.tool)) throw new Error("invalid_policy_document:simulation.tool:invalid_tool_name");
	if (!["known", "unknown", "risky"].includes(String(input.inventory))) throw new Error("invalid_policy_document:simulation.inventory:invalid_inventory");
	const fullTool = `${input.server}.${input.tool}`;
	for (const [mode, toolKey, serverKey] of [
		["deny", "mcp_deny_tools", "mcp_deny_servers"],
		["ask", "mcp_require_approval_tools", "mcp_require_approval_servers"],
		["allow", "mcp_allow_tools", "mcp_allow_servers"],
	] as const) {
		if ((policy[toolKey] as string[]).includes(fullTool)) return { action: mode, source: "mcp_tool", matched: fullTool };
		if ((policy[serverKey] as string[]).includes(input.server)) return { action: mode, source: "mcp_server", matched: input.server };
	}
	if (input.inventory === "risky") return { action: action(policy.mcp_risky, "mcp_risky"), source: "mcp_risky", matched: null };
	if (input.inventory === "unknown" && policy.mcp_unknown !== "allow") return { action: action(policy.mcp_unknown, "mcp_unknown"), source: "mcp_unknown", matched: null };
	return { action: action(policy.mcp_default, "mcp_default"), source: "mcp_default", matched: null };
}
