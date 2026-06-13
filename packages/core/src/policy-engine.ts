import { z } from "zod";
import type { Logger } from "./types.js";
import { nullLogger } from "./types.js";

export const PolicyRuleSchema = z.object({
	id: z.string(),
	name: z.string(),
	enabled: z.boolean().default(true),
	match: z.object({
		tool: z.string().optional(),
		file_path: z.string().optional(),
		command_pattern: z.string().optional(),
		url_pattern: z.string().optional(),
		content_pattern: z.string().optional(),
	}),
	action: z.enum(["allow", "deny", "ask", "log"]),
	severity: z.enum(["info", "warning", "critical"]).default("warning"),
	message: z.string().optional(),
	conditions: z
		.array(
			z.object({
				type: z.enum(["time_window", "rate_limit", "environment", "user_confirm"]),
				config: z.record(z.unknown()),
			}),
		)
		.default([]),
});

export const PolicySchema = z.object({
	version: z.string().default("1.0"),
	name: z.string(),
	description: z.string().optional(),
	defaultAction: z.enum(["allow", "deny", "ask"]).default("ask"),
	rules: z.array(PolicyRuleSchema),
});

export type PolicyRule = z.infer<typeof PolicyRuleSchema>;
export type Policy = z.infer<typeof PolicySchema>;

export interface PolicyMatch {
	rule: PolicyRule;
	confidence: number;
	matchedFields: string[];
}

export interface PolicyEvaluation {
	decision: "allow" | "deny" | "ask" | "log";
	ruleId?: string;
	reason: string;
	severity: "info" | "warning" | "critical";
	confidence: number;
}

export class PolicyEngine {
	private policies: Policy[] = [];
	private readonly logger: Logger;

	constructor(logger: Logger = nullLogger) {
		this.logger = logger;
	}

	loadPolicy(policy: Policy): void {
		const validated = PolicySchema.parse(policy);
		this.policies.push(validated);
		this.logger.info(`Loaded policy: ${validated.name} with ${validated.rules.length} rules`);
	}

	loadPoliciesFromYaml(yamlContent: string): void {
		try {
			const parsed = JSON.parse(yamlContent);
			if (Array.isArray(parsed)) {
				for (const p of parsed) {
					this.loadPolicy(p);
				}
			} else {
				this.loadPolicy(parsed);
			}
		} catch (error) {
			this.logger.error("Failed to load policies", { error: String(error) });
		}
	}

	evaluate(
		toolName: string,
		toolInput: Record<string, unknown>,
		context: { environment?: string; user?: string; timestamp?: Date } = {},
	): PolicyEvaluation {
		for (const policy of this.policies) {
			for (const rule of policy.rules) {
				if (!rule.enabled) continue;

				const match = this.matchesRule(rule, toolName, toolInput, context);
				if (match) {
					return {
						decision: rule.action,
						ruleId: rule.id,
						reason: rule.message || `Matched policy rule: ${rule.name}`,
						severity: rule.severity,
						confidence: match.confidence,
					};
				}
			}
		}

		return {
			decision: "allow",
			reason: "No policy rules matched",
			severity: "info",
			confidence: 1.0,
		};
	}

	private matchesRule(
		rule: PolicyRule,
		toolName: string,
		toolInput: Record<string, unknown>,
		_context: { environment?: string; user?: string; timestamp?: Date },
	): { confidence: number; matchedFields: string[] } | null {
		const matchedFields: string[] = [];
		let confidence = 0;

		if (rule.match.tool) {
			const toolPattern = new RegExp(rule.match.tool, "i");
			if (toolPattern.test(toolName)) {
				matchedFields.push("tool");
				confidence += 0.3;
			} else {
				return null;
			}
		}

		if (rule.match.file_path && toolInput.file_path) {
			const filePathPattern = new RegExp(rule.match.file_path, "i");
			if (filePathPattern.test(String(toolInput.file_path))) {
				matchedFields.push("file_path");
				confidence += 0.3;
			} else {
				return null;
			}
		}

		if (rule.match.command_pattern && toolInput.command) {
			const cmdPattern = new RegExp(rule.match.command_pattern, "i");
			if (cmdPattern.test(String(toolInput.command))) {
				matchedFields.push("command");
				confidence += 0.4;
			} else {
				return null;
			}
		}

		if (rule.match.url_pattern && toolInput.url) {
			const urlPattern = new RegExp(rule.match.url_pattern, "i");
			if (urlPattern.test(String(toolInput.url))) {
				matchedFields.push("url");
				confidence += 0.3;
			} else {
				return null;
			}
		}

		if (matchedFields.length === 0) return null;

		return { confidence: Math.min(confidence, 1.0), matchedFields };
	}

	getPolicySummary(): { totalPolicies: number; totalRules: number; activeRules: number } {
		const totalRules = this.policies.reduce((sum, p) => sum + p.rules.length, 0);
		const activeRules = this.policies.reduce(
			(sum, p) => sum + p.rules.filter((r) => r.enabled).length,
			0,
		);

		return {
			totalPolicies: this.policies.length,
			totalRules,
			activeRules,
		};
	}
}

export function createPolicyEngine(logger?: Logger): PolicyEngine {
	return new PolicyEngine(logger);
}
