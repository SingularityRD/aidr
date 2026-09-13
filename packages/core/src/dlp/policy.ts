import { z } from "zod";

const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const MIME_PATTERN = /^[a-z0-9][a-z0-9!#$&^_.+-]*\/(?:[a-z0-9][a-z0-9!#$&^_.+-]*|\*)$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;

const IdentifierSchema = z.string().min(1).max(128).regex(IDENTIFIER_PATTERN);

function addPolicyIssue(context: z.RefinementCtx, message: string, path: (string | number)[]) {
	context.addIssue({ code: z.ZodIssueCode.custom, message, path });
}

function validateTenantOwnedIds(
	items: { id: string; tenantId: string }[],
	tenantId: string,
	collection: string,
	context: z.RefinementCtx,
): Set<string> {
	const ids = new Set<string>();
	for (const [index, item] of items.entries()) {
		if (item.tenantId !== tenantId) {
			addPolicyIssue(
				context,
				`${collection.slice(0, -1)} tenantId must match the policy tenantId`,
				[collection, index, "tenantId"],
			);
		}
		if (ids.has(item.id)) {
			addPolicyIssue(context, `${collection.slice(0, -1)} ids must be unique`, [
				collection,
				index,
				"id",
			]);
		}
		ids.add(item.id);
	}
	return ids;
}

function validateReferences<Field extends string>(
	items: Record<Field, string>[],
	field: Field,
	validIds: Set<string>,
	collection: string,
	target: string,
	context: z.RefinementCtx,
): void {
	for (const [index, item] of items.entries()) {
		const referencedId = item[field];
		if (referencedId && !validIds.has(referencedId)) {
			addPolicyIssue(context, `${collection.slice(0, -1)} ${field} must reference a ${target}`, [
				collection,
				index,
				field,
			]);
		}
	}
}

function isUnsafeRegex(pattern: string): boolean {
	return (
		/\\[1-9]/.test(pattern) || /\([^)]*[+*][^)]*\)[+*{]/.test(pattern) || /\.\*.*\.\*/.test(pattern)
	);
}

export const DlpSensitivitySchema = z.enum(["public", "internal", "confidential", "restricted"]);

export const DlpDirectionSchema = z.enum(["input", "output"]);
export const DlpRuleActionSchema = z.enum(["redact", "block", "ask"]);
export const DlpUnavailableActionSchema = z.enum(["block", "ask"]);

/** Tenant-owned business classification attached to one or more DLP rules. */
export const DlpLabelSchema = z
	.object({
		id: IdentifierSchema,
		tenantId: IdentifierSchema,
		name: z.string().trim().min(1).max(100),
		description: z.string().trim().max(500).optional(),
		sensitivity: DlpSensitivitySchema,
		redactionToken: z.string().min(1).max(80).default("[REDACTED]"),
	})
	.strict();

const KeywordMatcherSchema = z
	.object({
		type: z.literal("keyword"),
		values: z.array(z.string().min(1).max(256)).min(1).max(500),
		caseSensitive: z.boolean().default(false),
		wholeWord: z.boolean().default(true),
	})
	.strict();

const RegexMatcherSchema = z
	.object({
		type: z.literal("regex"),
		pattern: z.string().min(1).max(512),
		flags: z
			.string()
			.regex(/^(?!.*(.).*\1)[imsu]*$/, "flags must be unique and limited to i, m, s and u")
			.default("i"),
	})
	.strict()
	.superRefine((matcher, context) => {
		try {
			const expression = new RegExp(matcher.pattern, matcher.flags);
			if (expression.test("")) {
				context.addIssue({
					code: z.ZodIssueCode.custom,
					message: "regex matchers must not match an empty string",
					path: ["pattern"],
				});
			}
			if (isUnsafeRegex(matcher.pattern)) {
				context.addIssue({
					code: z.ZodIssueCode.custom,
					message: "pattern contains a high-risk regular-expression construct",
					path: ["pattern"],
				});
			}
		} catch {
			context.addIssue({
				code: z.ZodIssueCode.custom,
				message: "pattern must be a valid regular expression",
				path: ["pattern"],
			});
		}
	});

export const DlpMatcherSchema = z.union([KeywordMatcherSchema, RegexMatcherSchema]);

/** A deterministic rule. The referenced label must belong to the same tenant. */
export const DlpRuleSchema = z
	.object({
		id: IdentifierSchema,
		tenantId: IdentifierSchema,
		labelId: IdentifierSchema,
		name: z.string().trim().min(1).max(120),
		enabled: z.boolean().default(true),
		priority: z.number().int().min(0).max(10_000).default(100),
		directions: z.array(DlpDirectionSchema).min(1).max(2).default(["input", "output"]),
		action: DlpRuleActionSchema,
		matchMode: z.enum(["any", "all"]).default("any"),
		matchers: z.array(DlpMatcherSchema).min(1).max(50),
		replacement: z.string().min(1).max(80).optional(),
	})
	.strict();

export const DlpExceptionScopeSchema = z.enum(["rule", "content", "match"]);

/**
 * A time-bounded, attributable false-positive exception. Content and match
 * exceptions use SHA-256 fingerprints so the sensitive value is never stored.
 */
export const DlpExceptionSchema = z
	.object({
		id: IdentifierSchema,
		tenantId: IdentifierSchema,
		ruleId: IdentifierSchema,
		ownerId: IdentifierSchema,
		justification: z.string().trim().min(1).max(500),
		scope: DlpExceptionScopeSchema,
		fingerprint: z.string().regex(SHA256_PATTERN).optional(),
		expiresAt: z.string().datetime({ offset: true }),
		createdAt: z.string().datetime({ offset: true }).optional(),
	})
	.strict()
	.superRefine((exception, context) => {
		const requiresFingerprint = exception.scope !== "rule";
		if (requiresFingerprint !== (exception.fingerprint !== undefined)) {
			context.addIssue({
				code: z.ZodIssueCode.custom,
				message:
					exception.scope === "rule"
						? "rule exceptions must not include a fingerprint"
						: `${exception.scope} exceptions require a SHA-256 fingerprint`,
				path: ["fingerprint"],
			});
		}
		if (exception.createdAt && Date.parse(exception.createdAt) >= Date.parse(exception.expiresAt)) {
			context.addIssue({
				code: z.ZodIssueCode.custom,
				message: "expiresAt must be later than createdAt",
				path: ["expiresAt"],
			});
		}
	});

export const DlpPolicySchema = z
	.object({
		version: z.number().int().positive(),
		tenantId: IdentifierSchema,
		maxContentBytes: z
			.number()
			.int()
			.min(1)
			.max(10 * 1024 * 1024)
			.default(1024 * 1024),
		supportedFormats: z
			.array(z.string().toLowerCase().regex(MIME_PATTERN))
			.min(1)
			.max(50)
			.default(["text/*", "application/json"]),
		unavailableAction: DlpUnavailableActionSchema.default("block"),
		labels: z.array(DlpLabelSchema).min(1).max(500),
		rules: z.array(DlpRuleSchema).max(2_000),
		exceptions: z.array(DlpExceptionSchema).max(10_000).default([]),
	})
	.strict()
	.superRefine((policy, context) => {
		const labelIds = validateTenantOwnedIds(policy.labels, policy.tenantId, "labels", context);
		const ruleIds = validateTenantOwnedIds(policy.rules, policy.tenantId, "rules", context);
		validateReferences(policy.rules, "labelId", labelIds, "rules", "label in this policy", context);
		validateTenantOwnedIds(policy.exceptions, policy.tenantId, "exceptions", context);
		validateReferences(
			policy.exceptions,
			"ruleId",
			ruleIds,
			"exceptions",
			"rule in this policy",
			context,
		);
	});

export type DlpSensitivity = z.infer<typeof DlpSensitivitySchema>;
export type DlpDirection = z.infer<typeof DlpDirectionSchema>;
export type DlpRuleAction = z.infer<typeof DlpRuleActionSchema>;
export type DlpUnavailableAction = z.infer<typeof DlpUnavailableActionSchema>;
export type DlpLabel = z.infer<typeof DlpLabelSchema>;
export type DlpMatcher = z.infer<typeof DlpMatcherSchema>;
export type DlpRule = z.infer<typeof DlpRuleSchema>;
export type DlpExceptionScope = z.infer<typeof DlpExceptionScopeSchema>;
export type DlpException = z.infer<typeof DlpExceptionSchema>;
export type DlpPolicy = z.infer<typeof DlpPolicySchema>;
