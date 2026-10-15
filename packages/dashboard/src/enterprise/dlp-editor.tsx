/**
 * Tenant DLP policy editor.
 *
 * The core engine already validates a tenant DLP policy (`packages/core/src/dlp/policy.ts`)
 * and scans content with it (`scanner.ts`), but nothing in the dashboard let an
 * operator author one. This surface manages the three tenant-owned collections
 * that policy is made of:
 *
 *   - labels, including the redaction token the scanner substitutes for a
 *     `redact` match;
 *   - rules, with priority, directions, action, match mode and matchers;
 *   - exceptions, with scope, owner, justification and expiry.
 *
 * ## Schema, not a new contract
 *
 * `validateDlpPolicyDocument` mirrors `DlpPolicySchema` exactly — required
 * fields, identifier/MIME/SHA-256 patterns, keyword/regex/detector matcher
 * rules, the fixed checksum-validator list, the structural ReDoS refusal
 * (`regexRiskIssue`), policy-wide regex/keyword caps, tenant/id/reference
 * consistency, the expired-exception
 * dominance refusal and every zod default — and normalises the draft the same
 * way `DlpPolicySchema.parse` does, so what this editor serialises is what the
 * engine parses. The dashboard deliberately does not depend on
 * `@singularityrd/aidr-core` at runtime, so the mirror lives here and
 * `dlp-editor.test.tsx` drives both this module and the engine's real schema
 * over the same documents to prove the two agree. No new backend contract is
 * introduced.
 *
 * ## Persistence is probed, never assumed
 *
 * `policy-management` authenticates, validates and stores tenant DLP policies.
 * This editor requires a confirmed saved revision and explicitly reports that
 * it has NOT been delivered through signed provisioning. Older deployments or
 * refused reads keep saving disabled; a successful HTTP response alone is not
 * proof of a save. Only tenant owners/admins can save, with MFA checked server-side.
 *
 * ## `ask` is resolved out of band — there is no approval control here
 *
 * A rule action of `ask` blocks the action pending approval by a human operator
 * outside this dashboard (see CLAUDE.md). The model only ever receives the
 * block reason, so an operator surface that could approve an `ask` would let a
 * prompt-injected agent approve its own block. This editor states that
 * boundary in the UI and exposes no approve/resolve/allow/dismiss control
 * anywhere — `dlp-editor.test.tsx` asserts that absence directly.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import type { DashboardMessageKey } from "../i18n/en";
import { useRichT, useT } from "../i18n/I18nProvider";
import { pendingPolicyChangeNotice } from "../lib/ai-governance";
import { readErrorMessage } from "../lib/errors";
import { supabase } from "../lib/supabase";
import { EnterpriseAuth } from "./auth";
import { DlpPolicyHistory } from "./dlp-history";
import { useTeam } from "./team-provider";

/* ── Schema mirror ──────────────────────────────────────────────────────── */

const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const MIME_PATTERN = /^[a-z0-9][a-z0-9!#$&^_.+-]*\/(?:[a-z0-9][a-z0-9!#$&^_.+-]*|\*)$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
/** Unique flags limited to i, m, s and u (DlpMatcherSchema). */
const REGEX_FLAGS_PATTERN = /^(?!.*(.).*\1)[imsu]*$/;
/** `z.string().datetime({ offset: true })`: a full timestamp with an offset. */
const DATETIME_PATTERN =
	/^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/;

const DEFAULT_MAX_CONTENT_BYTES = 1024 * 1024;
const MAX_CONTENT_BYTES_CEILING = 10 * 1024 * 1024;
const DEFAULT_SUPPORTED_FORMATS = ["text/*", "application/json"];
const DEFAULT_REDACTION_TOKEN = "[REDACTED]";

const SENSITIVITIES = ["public", "internal", "confidential", "restricted"] as const;
const DIRECTIONS = ["input", "output"] as const;
const RULE_ACTIONS = ["redact", "block", "ask"] as const;
const UNAVAILABLE_ACTIONS = ["block", "ask"] as const;
const MATCH_MODES = ["any", "all"] as const;
const EXCEPTION_SCOPES = ["rule", "content", "match"] as const;
/** `DlpMatchValidatorSchema`: the fixed checksum list a tenant regex may name. */
const MATCH_VALIDATORS = ["luhn", "iban_mod97", "tc_kimlik", "tr_vkn", "us_ssn"] as const;
/** `DlpDetectorSchema`: built-in TR/EN detectors a detector matcher may name. */
const DETECTORS = [
	"tc_kimlik",
	"iban",
	"phone",
	"email",
	"credit_card",
	"us_ssn",
	"address",
	"person",
	"date_of_birth",
	"passport",
	"national_id",
	"tax_id",
	"bank_account",
	"ip_address",
	"mac_address",
	"secret",
	"private_key",
	"classified",
] as const;
/** Policy-wide bounds, as in the core schema. */
const MAX_REGEX_REPEAT = 1_000;
const MAX_UNBOUNDED_QUANTIFIERS = 4;
const MAX_POLICY_REGEX_MATCHERS = 256;
const MAX_POLICY_KEYWORD_TERMS = 10_000;

/**
 * Machine-readable refusal code shared with the core (`DLP_EXPIRED_EXCEPTION_DOMINANCE`).
 * It prefixes the issue message so a gate can branch on it without parsing prose.
 */
export const DLP_EXPIRED_EXCEPTION_DOMINANCE = "DLP_EXPIRED_EXCEPTION_DOMINANCE";

/**
 * A one-record exception list is exempt from the dominance refusal, exactly as
 * in the core schema: a single expired record is routine bookkeeping that the
 * scanner prunes, while an expired majority of two or more means the list is
 * being kept as an archive instead of a bounded set of live exceptions.
 */
const EXCEPTION_DOMINANCE_MINIMUM = 2;

type DlpSensitivity = (typeof SENSITIVITIES)[number];
type DlpDirection = (typeof DIRECTIONS)[number];
type DlpRuleAction = (typeof RULE_ACTIONS)[number];
type DlpUnavailableAction = (typeof UNAVAILABLE_ACTIONS)[number];
type DlpExceptionScope = (typeof EXCEPTION_SCOPES)[number];

export interface DlpLabelDocument {
	id: string;
	tenantId: string;
	name: string;
	description?: string;
	sensitivity: DlpSensitivity;
	redactionToken: string;
}

interface DlpKeywordMatcherDocument {
	type: "keyword";
	values: string[];
	caseSensitive: boolean;
	wholeWord: boolean;
}

interface DlpRegexMatcherDocument {
	type: "regex";
	pattern: string;
	flags: string;
	validator?: (typeof MATCH_VALIDATORS)[number];
}

interface DlpDetectorMatcherDocument {
	type: "detector";
	detectors: (typeof DETECTORS)[number][];
}

type DlpMatcherDocument =
	| DlpKeywordMatcherDocument
	| DlpRegexMatcherDocument
	| DlpDetectorMatcherDocument;

export interface DlpRuleDocument {
	id: string;
	tenantId: string;
	labelId: string;
	name: string;
	enabled: boolean;
	priority: number;
	directions: DlpDirection[];
	action: DlpRuleAction;
	matchMode: (typeof MATCH_MODES)[number];
	matchers: DlpMatcherDocument[];
	replacement?: string;
}

export interface DlpExceptionDocument {
	id: string;
	tenantId: string;
	ruleId: string;
	ownerId: string;
	justification: string;
	scope: DlpExceptionScope;
	fingerprint?: string;
	expiresAt: string;
	createdAt?: string;
}

export interface DlpPolicyDocument {
	version: number;
	tenantId: string;
	maxContentBytes: number;
	supportedFormats: string[];
	unavailableAction: DlpUnavailableAction;
	labels: DlpLabelDocument[];
	rules: DlpRuleDocument[];
	exceptions: DlpExceptionDocument[];
}

export interface DlpValidationIssue {
	/** Dotted path into the policy document (`rules.0.priority`); empty for the document root. */
	path: string;
	message: string;
}

export type DlpValidationResult =
	| { ok: true; policy: DlpPolicyDocument }
	| { ok: false; issues: DlpValidationIssue[] };

const POLICY_KEYS = [
	"version",
	"tenantId",
	"maxContentBytes",
	"supportedFormats",
	"unavailableAction",
	"labels",
	"rules",
	"exceptions",
] as const;
const LABEL_KEYS = [
	"id",
	"tenantId",
	"name",
	"description",
	"sensitivity",
	"redactionToken",
] as const;
const KEYWORD_MATCHER_KEYS = ["type", "values", "caseSensitive", "wholeWord"] as const;
const REGEX_MATCHER_KEYS = ["type", "pattern", "flags", "validator"] as const;
const DETECTOR_MATCHER_KEYS = ["type", "detectors"] as const;
const RULE_KEYS = [
	"id",
	"tenantId",
	"labelId",
	"name",
	"enabled",
	"priority",
	"directions",
	"action",
	"matchMode",
	"matchers",
	"replacement",
] as const;
const EXCEPTION_KEYS = [
	"id",
	"tenantId",
	"ruleId",
	"ownerId",
	"justification",
	"scope",
	"fingerprint",
	"expiresAt",
	"createdAt",
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function unknownKey(
	value: Record<string, unknown>,
	allowed: readonly string[],
): string | undefined {
	return Object.keys(value).find((key) => !allowed.includes(key));
}

function formatPath(parts: (string | number)[]): string {
	return parts.map(String).join(".");
}

/** `Dlp*.strict()`: an unrecognised key is a refusal, never a silently dropped field. */
function readStrictRecord(
	value: unknown,
	keys: readonly string[],
	path: (string | number)[],
	issues: DlpValidationIssue[],
	label: string,
): Record<string, unknown> | null {
	if (!isRecord(value)) {
		issues.push({ path: formatPath(path), message: `${label} must be a mapping` });
		return null;
	}
	const extra = unknownKey(value, keys);
	if (extra) {
		issues.push({
			path: formatPath([...path, extra]),
			message: `${label} has unsupported field "${extra}"`,
		});
		return null;
	}
	return value;
}

function readIdentifier(
	value: unknown,
	path: (string | number)[],
	issues: DlpValidationIssue[],
	label: string,
): string | null {
	if (
		typeof value !== "string" ||
		value.length < 1 ||
		value.length > 128 ||
		!IDENTIFIER_PATTERN.test(value)
	) {
		issues.push({
			path: formatPath(path),
			message: `${label} must be 1-128 characters matching ${IDENTIFIER_PATTERN.source} (letters, digits, . _ : -)`,
		});
		return null;
	}
	return value;
}

/** `z.string().trim().min(1).max(n)`: the length is checked after trimming. */
function readTrimmedString(
	value: unknown,
	path: (string | number)[],
	issues: DlpValidationIssue[],
	label: string,
	maxLength: number,
): string | null {
	if (typeof value !== "string") {
		issues.push({ path: formatPath(path), message: `${label} must be a string` });
		return null;
	}
	const trimmed = value.trim();
	if (trimmed.length < 1 || trimmed.length > maxLength) {
		issues.push({
			path: formatPath(path),
			message: `${label} must be 1-${maxLength} characters after trimming`,
		});
		return null;
	}
	return trimmed;
}

function readEnum<T extends string>(
	value: unknown,
	allowed: readonly T[],
	path: (string | number)[],
	issues: DlpValidationIssue[],
	label: string,
): T | null {
	if (typeof value !== "string" || !(allowed as readonly string[]).includes(value)) {
		issues.push({
			path: formatPath(path),
			message: `${label} must be one of ${allowed.join(", ")}`,
		});
		return null;
	}
	return value as T;
}

/**
 * `isUnsafeRegex` from the core schema: a back-reference, a quantified group
 * that is itself quantified, or two unbounded wildcards.
 */
function isUnsafeRegex(pattern: string): boolean {
	return (
		/\\[1-9]/.test(pattern) ||
		/\([^)]*[+*][^)]*\)[+*{]/.test(pattern) ||
		/\.\*.*\.\*/.test(pattern) ||
		regexRiskIssue(pattern) !== undefined
	);
}

interface RegexGroupFrame {
	quantified: boolean;
	alternation: boolean;
}

function readRegexQuantifier(
	pattern: string,
	index: number,
): { length: number; min: number; max: number } | undefined {
	const character = pattern[index];
	if (character === "*") return { length: 1, min: 0, max: Number.POSITIVE_INFINITY };
	if (character === "+") return { length: 1, min: 1, max: Number.POSITIVE_INFINITY };
	if (character === "?") return { length: 1, min: 0, max: 1 };
	if (character !== "{") return undefined;
	const bound = /^\{(\d+)(,(\d*))?\}/.exec(pattern.slice(index, index + 32));
	if (!bound) return undefined;
	const min = Number(bound[1]);
	const max =
		bound[2] === undefined ? min : bound[3] === "" ? Number.POSITIVE_INFINITY : Number(bound[3]);
	return { length: bound[0].length, min, max };
}

/**
 * `regexRiskIssue` from the core schema (structural ReDoS guard): refuses
 * back-references, a repeated group whose body is quantified or alternates,
 * repetition bounds above 1000 and more than four unbounded quantifiers.
 */
export function regexRiskIssue(pattern: string): string | undefined {
	const stack: RegexGroupFrame[] = [{ quantified: false, alternation: false }];
	let previous: "none" | "atom" | RegexGroupFrame = "none";
	let unbounded = 0;
	let index = 0;
	while (index < pattern.length) {
		const character = pattern[index];
		const top = stack[stack.length - 1] as RegexGroupFrame;
		if (character === "\\") {
			const next = pattern[index + 1] ?? "";
			if (/[1-9]/.test(next) || next === "k") return "back-references are not allowed";
			index += 2;
			if (/[pPu]/.test(next) && pattern[index] === "{") {
				const close = pattern.indexOf("}", index);
				index = close < 0 ? pattern.length : close + 1;
			}
			previous = "atom";
			continue;
		}
		if (character === "[") {
			index++;
			while (index < pattern.length && pattern[index] !== "]") {
				index += pattern[index] === "\\" ? 2 : 1;
			}
			index++;
			previous = "atom";
			continue;
		}
		if (character === "(") {
			stack.push({ quantified: false, alternation: false });
			index++;
			if (pattern[index] === "?") {
				const kind = pattern[index + 1] ?? "";
				if (kind === "<" && !/[=!]/.test(pattern[index + 2] ?? "")) {
					const close = pattern.indexOf(">", index);
					index = close < 0 ? pattern.length : close + 1;
				} else {
					index += kind === "<" ? 3 : 2;
				}
			}
			previous = "none";
			continue;
		}
		if (character === ")") {
			const frame = stack.length > 1 ? (stack.pop() as RegexGroupFrame) : top;
			const parent = stack[stack.length - 1] as RegexGroupFrame;
			parent.quantified ||= frame.quantified;
			parent.alternation ||= frame.alternation;
			previous = frame;
			index++;
			continue;
		}
		if (character === "|") {
			top.alternation = true;
			previous = "none";
			index++;
			continue;
		}
		const quantifier = readRegexQuantifier(pattern, index);
		if (!quantifier || previous === "none") {
			previous = "atom";
			index++;
			continue;
		}
		if (
			quantifier.min > MAX_REGEX_REPEAT ||
			(quantifier.max !== Number.POSITIVE_INFINITY && quantifier.max > MAX_REGEX_REPEAT)
		) {
			return `repetition bounds above ${MAX_REGEX_REPEAT} are not allowed`;
		}
		if (quantifier.max === Number.POSITIVE_INFINITY) unbounded++;
		if (unbounded > MAX_UNBOUNDED_QUANTIFIERS) {
			return `more than ${MAX_UNBOUNDED_QUANTIFIERS} unbounded quantifiers are not allowed`;
		}
		if (previous !== "atom" && quantifier.max > 1 && (previous.quantified || previous.alternation)) {
			return "a repeated group must not contain a quantifier or an alternation";
		}
		if (quantifier.min !== quantifier.max) top.quantified = true;
		index += quantifier.length;
		if (pattern[index] === "?") index++;
		previous = "none";
	}
	return undefined;
}

// i18n-exempt: schema diagnostics name the JSON fields of the DLP document.
function normalizeMatcher(
	value: unknown,
	path: (string | number)[],
	issues: DlpValidationIssue[],
): DlpMatcherDocument | null {
	if (!isRecord(value)) {
		issues.push({ path: formatPath(path), message: "matcher must be a mapping" });
		return null;
	}
	if (value.type === "keyword") {
		const record = readStrictRecord(value, KEYWORD_MATCHER_KEYS, path, issues, "keyword matcher");
		if (!record) return null;
		const rawValues = record.values;
		if (!Array.isArray(rawValues) || rawValues.length < 1 || rawValues.length > 500) {
			issues.push({
				path: formatPath([...path, "values"]),
				message: "keyword matcher values must be a list of 1-500 entries",
			});
			return null;
		}
		const values: string[] = [];
		for (const [index, entry] of rawValues.entries()) {
			if (typeof entry !== "string" || entry.length < 1 || entry.length > 256) {
				issues.push({
					path: formatPath([...path, "values", index]),
					message: "keyword must be 1-256 characters",
				});
				return null;
			}
			values.push(entry);
		}
		// A default applies to an absent key only: `caseSensitive: null` is a
		// refusal in the schema, not a request for the default.
		const caseSensitive = record.caseSensitive === undefined ? false : record.caseSensitive;
		const wholeWord = record.wholeWord === undefined ? true : record.wholeWord;
		if (typeof caseSensitive !== "boolean") {
			issues.push({
				path: formatPath([...path, "caseSensitive"]),
				message: "caseSensitive must be a boolean",
			});
			return null;
		}
		if (typeof wholeWord !== "boolean") {
			issues.push({
				path: formatPath([...path, "wholeWord"]),
				message: "wholeWord must be a boolean",
			});
			return null;
		}
		return { type: "keyword", values, caseSensitive, wholeWord };
	}
	if (value.type === "regex") {
		const record = readStrictRecord(value, REGEX_MATCHER_KEYS, path, issues, "regex matcher");
		if (!record) return null;
		if (
			typeof record.pattern !== "string" ||
			record.pattern.length < 1 ||
			record.pattern.length > 512
		) {
			issues.push({
				path: formatPath([...path, "pattern"]),
				message: "regex pattern must be 1-512 characters",
			});
			return null;
		}
		const flags = record.flags === undefined ? "i" : record.flags;
		if (typeof flags !== "string" || !REGEX_FLAGS_PATTERN.test(flags)) {
			issues.push({
				path: formatPath([...path, "flags"]),
				message: "flags must be unique and limited to i, m, s and u",
			});
			return null;
		}
		try {
			const expression = new RegExp(record.pattern, flags);
			if (expression.test("")) {
				issues.push({
					path: formatPath([...path, "pattern"]),
					message: "regex matchers must not match an empty string",
				});
				return null;
			}
			if (isUnsafeRegex(record.pattern)) {
				issues.push({
					path: formatPath([...path, "pattern"]),
					message: "pattern contains a high-risk regular-expression construct",
				});
				return null;
			}
		} catch {
			issues.push({
				path: formatPath([...path, "pattern"]),
				message: "pattern must be a valid regular expression",
			});
			return null;
		}
		if (record.validator === undefined) return { type: "regex", pattern: record.pattern, flags };
		const validator = readEnum(
			record.validator,
			MATCH_VALIDATORS,
			[...path, "validator"],
			issues,
			"regex validator",
		);
		if (!validator) return null;
		return { type: "regex", pattern: record.pattern, flags, validator };
	}
	if (value.type === "detector") {
		const record = readStrictRecord(value, DETECTOR_MATCHER_KEYS, path, issues, "detector matcher");
		if (!record) return null;
		const raw = record.detectors;
		if (!Array.isArray(raw) || raw.length < 1 || raw.length > DETECTORS.length) {
			issues.push({
				path: formatPath([...path, "detectors"]),
				message: `detectors must list 1-${DETECTORS.length} built-in detectors`,
			});
			return null;
		}
		const detectors: DlpDetectorMatcherDocument["detectors"] = [];
		for (const [index, entry] of raw.entries()) {
			const detector = readEnum(entry, DETECTORS, [...path, "detectors", index], issues, "detector");
			if (!detector) return null;
			detectors.push(detector);
		}
		if (new Set(detectors).size !== detectors.length) {
			issues.push({
				path: formatPath([...path, "detectors"]),
				message: "detectors must be unique",
			});
			return null;
		}
		return { type: "detector", detectors };
	}
	issues.push({
		path: formatPath([...path, "type"]),
		message: 'matcher type must be "keyword", "regex" or "detector"',
	});
	return null;
}

// i18n-exempt: schema diagnostics name the JSON fields of the DLP document.
function normalizeLabel(
	value: unknown,
	tenantId: string,
	path: (string | number)[],
	issues: DlpValidationIssue[],
): DlpLabelDocument | null {
	const record = readStrictRecord(value, LABEL_KEYS, path, issues, "label");
	if (!record) return null;
	const id = readIdentifier(record.id, [...path, "id"], issues, "label id");
	const labelTenantId = readIdentifier(
		record.tenantId,
		[...path, "tenantId"],
		issues,
		"label tenantId",
	);
	const name = readTrimmedString(record.name, [...path, "name"], issues, "label name", 100);
	const sensitivity = readEnum(
		record.sensitivity,
		SENSITIVITIES,
		[...path, "sensitivity"],
		issues,
		"label sensitivity",
	);
	let description: string | undefined;
	if (record.description !== undefined) {
		description =
			readTrimmedString(
				record.description,
				[...path, "description"],
				issues,
				"label description",
				500,
			) ?? undefined;
	}
	let redactionToken: string | null = DEFAULT_REDACTION_TOKEN;
	if (record.redactionToken !== undefined) {
		const token = record.redactionToken;
		if (typeof token !== "string" || token.length < 1 || token.length > 80) {
			issues.push({
				path: formatPath([...path, "redactionToken"]),
				message: "redactionToken must be 1-80 characters",
			});
			redactionToken = null;
		} else {
			redactionToken = token;
		}
	}
	if (tenantId !== "" && labelTenantId && labelTenantId !== tenantId) {
		issues.push({
			path: formatPath([...path, "tenantId"]),
			message: "label tenantId must match the policy tenantId",
		});
	}
	if (!id || !labelTenantId || !name || !sensitivity || !redactionToken) return null;
	return {
		id,
		tenantId: labelTenantId,
		name,
		...(description === undefined ? {} : { description }),
		sensitivity,
		redactionToken,
	};
}

// i18n-exempt: schema diagnostics name the JSON fields of the DLP document.
function normalizeRule(
	value: unknown,
	tenantId: string,
	path: (string | number)[],
	issues: DlpValidationIssue[],
): DlpRuleDocument | null {
	const record = readStrictRecord(value, RULE_KEYS, path, issues, "rule");
	if (!record) return null;
	const id = readIdentifier(record.id, [...path, "id"], issues, "rule id");
	const ruleTenantId = readIdentifier(
		record.tenantId,
		[...path, "tenantId"],
		issues,
		"rule tenantId",
	);
	const labelId = readIdentifier(record.labelId, [...path, "labelId"], issues, "rule labelId");
	const name = readTrimmedString(record.name, [...path, "name"], issues, "rule name", 120);
	const action = readEnum(record.action, RULE_ACTIONS, [...path, "action"], issues, "rule action");
	const matchMode = readEnum(
		record.matchMode === undefined ? "any" : record.matchMode,
		MATCH_MODES,
		[...path, "matchMode"],
		issues,
		"rule matchMode",
	);
	const enabled = record.enabled === undefined ? true : record.enabled;
	if (typeof enabled !== "boolean") {
		issues.push({ path: formatPath([...path, "enabled"]), message: "enabled must be a boolean" });
		return null;
	}
	const priority = record.priority === undefined ? 100 : record.priority;
	if (
		typeof priority !== "number" ||
		!Number.isInteger(priority) ||
		priority < 0 ||
		priority > 10_000
	) {
		issues.push({
			path: formatPath([...path, "priority"]),
			message: "priority must be an integer from 0 to 10000",
		});
		return null;
	}
	const rawDirections = record.directions === undefined ? ["input", "output"] : record.directions;
	if (!Array.isArray(rawDirections) || rawDirections.length < 1 || rawDirections.length > 2) {
		issues.push({
			path: formatPath([...path, "directions"]),
			message: "directions must list one or two of input, output",
		});
		return null;
	}
	const directions: DlpDirection[] = [];
	for (const [index, entry] of rawDirections.entries()) {
		const direction = readEnum(
			entry,
			DIRECTIONS,
			[...path, "directions", index],
			issues,
			"rule direction",
		);
		if (!direction) return null;
		directions.push(direction);
	}
	const rawMatchers = record.matchers;
	if (!Array.isArray(rawMatchers) || rawMatchers.length < 1 || rawMatchers.length > 50) {
		issues.push({
			path: formatPath([...path, "matchers"]),
			message: "matchers must list 1-50 matchers",
		});
		return null;
	}
	const matchers: DlpMatcherDocument[] = [];
	for (const [index, entry] of rawMatchers.entries()) {
		const matcher = normalizeMatcher(entry, [...path, "matchers", index], issues);
		if (!matcher) return null;
		matchers.push(matcher);
	}
	let replacement: string | undefined;
	if (record.replacement !== undefined) {
		const candidate = record.replacement;
		if (typeof candidate !== "string" || candidate.length < 1 || candidate.length > 80) {
			issues.push({
				path: formatPath([...path, "replacement"]),
				message: "replacement must be 1-80 characters",
			});
			return null;
		}
		replacement = candidate;
	}
	if (tenantId !== "" && ruleTenantId && ruleTenantId !== tenantId) {
		issues.push({
			path: formatPath([...path, "tenantId"]),
			message: "rule tenantId must match the policy tenantId",
		});
	}
	if (!id || !ruleTenantId || !labelId || !name || !action || !matchMode) return null;
	return {
		id,
		tenantId: ruleTenantId,
		labelId,
		name,
		enabled,
		priority,
		directions,
		action,
		matchMode,
		matchers,
		...(replacement === undefined ? {} : { replacement }),
	};
}

// i18n-exempt: schema diagnostics name the JSON fields of the DLP document.
function normalizeException(
	value: unknown,
	tenantId: string,
	path: (string | number)[],
	issues: DlpValidationIssue[],
): DlpExceptionDocument | null {
	const record = readStrictRecord(value, EXCEPTION_KEYS, path, issues, "exception");
	if (!record) return null;
	const id = readIdentifier(record.id, [...path, "id"], issues, "exception id");
	const exceptionTenantId = readIdentifier(
		record.tenantId,
		[...path, "tenantId"],
		issues,
		"exception tenantId",
	);
	const ruleId = readIdentifier(record.ruleId, [...path, "ruleId"], issues, "exception ruleId");
	const ownerId = readIdentifier(record.ownerId, [...path, "ownerId"], issues, "exception ownerId");
	const justification = readTrimmedString(
		record.justification,
		[...path, "justification"],
		issues,
		"exception justification",
		500,
	);
	const scope = readEnum(
		record.scope,
		EXCEPTION_SCOPES,
		[...path, "scope"],
		issues,
		"exception scope",
	);
	let expiresAt: string | null = null;
	if (
		typeof record.expiresAt !== "string" ||
		!DATETIME_PATTERN.test(record.expiresAt) ||
		Number.isNaN(Date.parse(record.expiresAt))
	) {
		issues.push({
			path: formatPath([...path, "expiresAt"]),
			message: "expiresAt must be an ISO-8601 timestamp with an offset",
		});
	} else {
		expiresAt = record.expiresAt;
	}
	let fingerprint: string | undefined;
	if (record.fingerprint !== undefined) {
		if (typeof record.fingerprint !== "string" || !SHA256_PATTERN.test(record.fingerprint)) {
			issues.push({
				path: formatPath([...path, "fingerprint"]),
				message: "fingerprint must be a lowercase SHA-256 hex digest",
			});
			return null;
		}
		fingerprint = record.fingerprint;
	}
	let createdAt: string | undefined;
	if (record.createdAt !== undefined) {
		if (
			typeof record.createdAt !== "string" ||
			!DATETIME_PATTERN.test(record.createdAt) ||
			Number.isNaN(Date.parse(record.createdAt))
		) {
			issues.push({
				path: formatPath([...path, "createdAt"]),
				message: "createdAt must be an ISO-8601 timestamp with an offset",
			});
			return null;
		}
		createdAt = record.createdAt;
	}
	// Content and match exceptions bind a SHA-256 fingerprint; a rule exception
	// must not carry one. Both halves of the mismatch are refused.
	if (scope) {
		const requiresFingerprint = scope !== "rule";
		if (requiresFingerprint !== (fingerprint !== undefined)) {
			issues.push({
				path: formatPath([...path, "fingerprint"]),
				message:
					scope === "rule"
						? "rule exceptions must not include a fingerprint"
						: `${scope} exceptions require a SHA-256 fingerprint`,
			});
			return null;
		}
	}
	if (
		createdAt !== undefined &&
		expiresAt !== null &&
		Date.parse(createdAt) >= Date.parse(expiresAt)
	) {
		issues.push({
			path: formatPath([...path, "expiresAt"]),
			message: "expiresAt must be later than createdAt",
		});
		return null;
	}
	if (tenantId !== "" && exceptionTenantId && exceptionTenantId !== tenantId) {
		issues.push({
			path: formatPath([...path, "tenantId"]),
			message: "exception tenantId must match the policy tenantId",
		});
	}
	if (!id || !exceptionTenantId || !ruleId || !ownerId || !justification || !scope || !expiresAt) {
		return null;
	}
	return {
		id,
		tenantId: exceptionTenantId,
		ruleId,
		ownerId,
		justification,
		scope,
		...(fingerprint === undefined ? {} : { fingerprint }),
		expiresAt,
		...(createdAt === undefined ? {} : { createdAt }),
	};
}

// i18n-exempt: schema diagnostics name the JSON fields of the DLP document.
function readSupportedFormats(value: unknown, issues: DlpValidationIssue[]): string[] | null {
	if (!Array.isArray(value) || value.length < 1 || value.length > 50) {
		issues.push({
			path: "supportedFormats",
			message: "supportedFormats must list 1-50 media types",
		});
		return null;
	}
	const formats: string[] = [];
	for (const [index, entry] of value.entries()) {
		if (typeof entry !== "string") {
			issues.push({
				path: formatPath(["supportedFormats", index]),
				message: "supported format must be a string",
			});
			return null;
		}
		const lowered = entry.toLowerCase();
		if (!MIME_PATTERN.test(lowered)) {
			issues.push({
				path: formatPath(["supportedFormats", index]),
				message: `"${entry}" is not a valid media type such as text/plain or application/*`,
			});
			return null;
		}
		formats.push(lowered);
	}
	return formats;
}

/** Collect tenant ownership and id uniqueness. Returns the ids seen so far. */
// i18n-exempt: schema diagnostics name the JSON fields of the DLP document.
function readTenantOwnedIds<Item extends { id: string; tenantId: string }>(
	items: Item[],
	tenantId: string,
	collection: "labels" | "rules" | "exceptions",
	issues: DlpValidationIssue[],
): Set<string> {
	const seen = new Set<string>();
	for (const [index, item] of items.entries()) {
		if (item.tenantId !== tenantId) {
			issues.push({
				path: formatPath([collection, index, "tenantId"]),
				message: `item tenantId must match the policy tenantId`,
			});
		}
		if (seen.has(item.id)) {
			issues.push({
				path: formatPath([collection, index, "id"]),
				message: `${collection} ids must be unique`,
			});
		}
		seen.add(item.id);
	}
	return seen;
}

function isExpiredExceptionDominance(issue: DlpValidationIssue): boolean {
	return (
		issue.path === "exceptions" && issue.message.startsWith(`${DLP_EXPIRED_EXCEPTION_DOMINANCE}:`)
	);
}

// i18n-exempt: schema diagnostics name the JSON fields of the DLP document.
function normalizePolicy(input: unknown): {
	policy: DlpPolicyDocument | null;
	issues: DlpValidationIssue[];
} {
	const issues: DlpValidationIssue[] = [];
	const record = readStrictRecord(input, POLICY_KEYS, [], issues, "DLP policy");
	if (!record) return { policy: null, issues };

	let healthy = true;
	let policyVersion: number | null = null;
	if (
		typeof record.version !== "number" ||
		!Number.isInteger(record.version) ||
		record.version <= 0
	) {
		issues.push({ path: "version", message: "version must be a positive integer" });
		healthy = false;
	} else {
		policyVersion = record.version;
	}
	const tenantId = readIdentifier(record.tenantId, ["tenantId"], issues, "policy tenantId");
	if (!tenantId) healthy = false;

	let maxContentBytes = DEFAULT_MAX_CONTENT_BYTES;
	if (record.maxContentBytes !== undefined) {
		const candidate = record.maxContentBytes;
		if (
			typeof candidate !== "number" ||
			!Number.isInteger(candidate) ||
			candidate < 1 ||
			candidate > MAX_CONTENT_BYTES_CEILING
		) {
			issues.push({
				path: "maxContentBytes",
				message: `maxContentBytes must be an integer from 1 to ${MAX_CONTENT_BYTES_CEILING}`,
			});
			healthy = false;
		} else {
			maxContentBytes = candidate;
		}
	}

	let supportedFormats = [...DEFAULT_SUPPORTED_FORMATS];
	if (record.supportedFormats !== undefined) {
		const formats = readSupportedFormats(record.supportedFormats, issues);
		if (!formats) healthy = false;
		else supportedFormats = formats;
	}

	let unavailableAction: DlpUnavailableAction = "block";
	if (record.unavailableAction !== undefined) {
		const action = readEnum(
			record.unavailableAction,
			UNAVAILABLE_ACTIONS,
			["unavailableAction"],
			issues,
			"unavailableAction",
		);
		if (!action) healthy = false;
		else unavailableAction = action;
	}

	if (!Array.isArray(record.labels) || record.labels.length < 1 || record.labels.length > 500) {
		issues.push({ path: "labels", message: "labels must list 1-500 labels" });
		return { policy: null, issues };
	}
	const labels: DlpLabelDocument[] = [];
	for (const [index, entry] of record.labels.entries()) {
		const label = normalizeLabel(entry, tenantId ?? "", ["labels", index], issues);
		if (!label) healthy = false;
		else labels.push(label);
	}

	if (!Array.isArray(record.rules) || record.rules.length > 2_000) {
		issues.push({ path: "rules", message: "rules must be a list of at most 2000 rules" });
		return { policy: null, issues };
	}
	const rules: DlpRuleDocument[] = [];
	for (const [index, entry] of record.rules.entries()) {
		const rule = normalizeRule(entry, tenantId ?? "", ["rules", index], issues);
		if (!rule) healthy = false;
		else rules.push(rule);
	}

	const rawExceptions = record.exceptions === undefined ? [] : record.exceptions;
	if (!Array.isArray(rawExceptions) || rawExceptions.length > 10_000) {
		issues.push({
			path: "exceptions",
			message: "exceptions must be a list of at most 10000 records",
		});
		return { policy: null, issues };
	}
	const exceptions: DlpExceptionDocument[] = [];
	for (const [index, entry] of rawExceptions.entries()) {
		const exception = normalizeException(entry, tenantId ?? "", ["exceptions", index], issues);
		if (!exception) healthy = false;
		else exceptions.push(exception);
	}

	if (!healthy || !tenantId || policyVersion === null) return { policy: null, issues };

	const labelIds = readTenantOwnedIds(labels, tenantId, "labels", issues);
	const ruleIds = readTenantOwnedIds(rules, tenantId, "rules", issues);
	const matchers = rules.flatMap((rule) => rule.matchers);
	if (matchers.filter((matcher) => matcher.type === "regex").length > MAX_POLICY_REGEX_MATCHERS) {
		issues.push({
			path: "rules",
			message: `a policy may contain at most ${MAX_POLICY_REGEX_MATCHERS} regex matchers`,
		});
	}
	const keywordTerms = matchers.reduce(
		(total, matcher) => total + (matcher.type === "keyword" ? matcher.values.length : 0),
		0,
	);
	if (keywordTerms > MAX_POLICY_KEYWORD_TERMS) {
		issues.push({
			path: "rules",
			message: `a policy may contain at most ${MAX_POLICY_KEYWORD_TERMS} keyword terms`,
		});
	}
	for (const [index, rule] of rules.entries()) {
		if (!labelIds.has(rule.labelId)) {
			issues.push({
				path: formatPath(["rules", index, "labelId"]),
				message: "rule labelId must reference a label in this policy",
			});
		}
	}
	readTenantOwnedIds(exceptions, tenantId, "exceptions", issues);
	for (const [index, exception] of exceptions.entries()) {
		if (!ruleIds.has(exception.ruleId)) {
			issues.push({
				path: formatPath(["exceptions", index, "ruleId"]),
				message: "exception ruleId must reference a rule in this policy",
			});
		}
	}

	// A list dominated by already-expired exceptions is refused rather than
	// silently pruned: dead records are what fill the 10,000-entry cap.
	const now = Date.now();
	const expired = exceptions.filter((exception) => Date.parse(exception.expiresAt) <= now).length;
	if (exceptions.length >= EXCEPTION_DOMINANCE_MINIMUM && expired * 2 > exceptions.length) {
		issues.push({
			path: "exceptions",
			message: `${DLP_EXPIRED_EXCEPTION_DOMINANCE}: ${expired} of ${exceptions.length} exceptions have already expired; remove the expired records and re-publish the policy`,
		});
	}

	// Keep an otherwise valid stored document editable when only time has made
	// its exception list stale. The public validator still rejects ANY issues;
	// this candidate is for explicit repair, never an automatically valid save.
	if (issues.some((issue) => !isExpiredExceptionDominance(issue))) {
		return { policy: null, issues };
	}
	return {
		policy: {
			version: policyVersion,
			tenantId,
			maxContentBytes,
			supportedFormats,
			unavailableAction,
			labels,
			rules,
			exceptions,
		},
		issues,
	};
}

/**
 * Validate and normalise a candidate policy exactly as `DlpPolicySchema.parse`
 * does. Nothing is published unless this returns `ok: true`, and the value it
 * returns is the document that is serialised, so the editor cannot save a draft
 * the engine would refuse.
 */
export function validateDlpPolicyDocument(input: unknown): DlpValidationResult {
	const { policy, issues } = normalizePolicy(input);
	if (!policy || issues.length > 0) return { ok: false, issues };
	return { ok: true, policy };
}

/** Canonical JSON for the draft; key order follows the schema's field order. */
export function serializeDlpPolicy(policy: DlpPolicyDocument): string {
	return JSON.stringify(policy, null, 2);
}

function formatDlpIssues(issues: DlpValidationIssue[]): string {
	return issues.map((issue) => `${issue.path || "policy"}: ${issue.message}`).join("; ");
}

function nextId(prefix: string, taken: readonly string[]): string {
	let index = taken.length + 1;
	while (taken.includes(`${prefix}-${index}`)) index += 1;
	return `${prefix}-${index}`;
}

function newDlpLabel(tenantId: string, taken: readonly string[] = []): DlpLabelDocument {
	return {
		id: nextId("label", taken),
		tenantId,
		name: "",
		sensitivity: "internal",
		redactionToken: DEFAULT_REDACTION_TOKEN,
	};
}

function newDlpRule(
	tenantId: string,
	labelId: string,
	taken: readonly string[] = [],
): DlpRuleDocument {
	return {
		id: nextId("rule", taken),
		tenantId,
		labelId,
		name: "",
		enabled: true,
		priority: 100,
		directions: ["input", "output"],
		action: "redact",
		matchMode: "any",
		matchers: [{ type: "keyword", values: [], caseSensitive: false, wholeWord: true }],
	};
}

function newDlpException(
	tenantId: string,
	ruleId: string,
	ownerId: string,
	taken: readonly string[] = [],
): DlpExceptionDocument {
	return {
		id: nextId("exception", taken),
		tenantId,
		ruleId,
		ownerId,
		justification: "",
		scope: "rule",
		expiresAt: "",
	};
}

/**
 * A valid starting point for a tenant that has no stored policy yet, so the
 * editor does not open on a document the schema refuses (labels need at least
 * one entry). It redacts customer identifiers on both directions; nothing is
 * published until the operator chooses to.
 */
export function createStarterDlpPolicy(tenantId: string): DlpPolicyDocument {
	const label: DlpLabelDocument = {
		id: "label-customer-data",
		tenantId,
		name: "Customer data",
		sensitivity: "confidential",
		redactionToken: DEFAULT_REDACTION_TOKEN,
	};
	const rule: DlpRuleDocument = {
		id: "rule-customer-identifier",
		tenantId,
		labelId: label.id,
		name: "Customer identifiers",
		enabled: true,
		priority: 100,
		directions: ["input", "output"],
		action: "redact",
		matchMode: "any",
		matchers: [{ type: "keyword", values: ["customer_id"], caseSensitive: false, wholeWord: true }],
	};
	return {
		version: 1,
		tenantId,
		maxContentBytes: DEFAULT_MAX_CONTENT_BYTES,
		supportedFormats: [...DEFAULT_SUPPORTED_FORMATS],
		unavailableAction: "block",
		labels: [label],
		rules: [rule],
		exceptions: [],
	};
}

/* ── Persistence seam ───────────────────────────────────────────────────── */

/**
 * Actions probed and used on the existing `policy-management` invoke seam.
 * They are ordinary request actions, not a new backend contract: a deployment
 * that does not implement them rejects the request, and the editor says so
 * instead of reporting a save.
 */
export const DLP_READ_ACTION = "read_dlp_policy";
export const DLP_PUBLISH_ACTION = "publish_dlp_policy";

async function isMfaRequired(error: unknown): Promise<boolean> {
	const context = (error as { context?: unknown } | null | undefined)?.context;
	if (!(context instanceof Response) || context.status !== 403) return false;
	try {
		const body: unknown = await context.clone().json();
		return Boolean(
			body && typeof body === "object" && "error" in body && body.error === "mfa_required",
		);
	} catch {
		return false;
	}
}

interface DlpReadResponse {
	ok?: unknown;
	policy?: unknown;
	version?: unknown;
}

interface DlpPublishResponse {
	ok?: unknown;
	version?: unknown;
	policy?: unknown;
	saved?: unknown;
	delivered?: unknown;
	delivery_status?: unknown;
}

type StoreState =
	| { kind: "loading" }
	| { kind: "mfa_required" }
	| { kind: "unavailable"; detail: string }
	| { kind: "unreadable"; detail: string }
	| { kind: "loaded"; version: number };

interface Outcome {
	tone: "success" | "error";
	message: string;
}

function toDatetimeLocalValue(isoTimestamp: string): string {
	const parsed = Date.parse(isoTimestamp);
	if (Number.isNaN(parsed)) return "";
	const date = new Date(parsed - new Date(parsed).getTimezoneOffset() * 60_000);
	return date.toISOString().slice(0, 16);
}

function fromDatetimeLocalValue(value: string): string {
	if (value === "") return "";
	const parsed = Date.parse(value);
	return Number.isNaN(parsed) ? value : new Date(parsed).toISOString();
}

/** Drop the optional `createdAt` key entirely (an empty input means "absent"). */
function exceptionWithoutCreatedAt(exception: DlpExceptionDocument): DlpExceptionDocument {
	return {
		id: exception.id,
		tenantId: exception.tenantId,
		ruleId: exception.ruleId,
		ownerId: exception.ownerId,
		justification: exception.justification,
		scope: exception.scope,
		...(exception.fingerprint === undefined ? {} : { fingerprint: exception.fingerprint }),
		expiresAt: exception.expiresAt,
	};
}

/* ── Component ──────────────────────────────────────────────────────────── */

const SENSITIVITY_LABEL: Record<DlpSensitivity, DashboardMessageKey> = {
	public: "dlp.sens.public",
	internal: "dlp.sens.internal",
	confidential: "dlp.sens.confidential",
	restricted: "dlp.sens.restricted",
};
const DIRECTION_LABEL: Record<DlpDirection, DashboardMessageKey> = {
	input: "dlp.dir.input",
	output: "dlp.dir.output",
};
const SCOPE_LABEL: Record<DlpExceptionScope, DashboardMessageKey> = {
	rule: "dlp.scope.rule",
	content: "dlp.scope.content",
	match: "dlp.scope.match",
};

export function DlpPolicyEditor() {
	const t = useT();
	const richT = useRichT();
	// The loader reads the translator through a ref so a language switch does not refetch.
	const translator = useRef(t);
	translator.current = t;
	const { currentTeam, canManageTeam, isLoading: teamLoading, error: teamError } = useTeam();
	const teamId = currentTeam?.id ?? null;
	const [draft, setDraft] = useState<DlpPolicyDocument | null>(null);
	const [store, setStore] = useState<StoreState>({ kind: "loading" });
	const [isPublishing, setIsPublishing] = useState(false);
	const [outcome, setOutcome] = useState<Outcome | null>(null);
	const tenantGeneration = useRef(0);

	useEffect(() => {
		tenantGeneration.current += 1;
		const t = translator.current;
		let cancelled = false;
		setOutcome(null);
		setDraft(null);
		setIsPublishing(false);
		if (!teamId) {
			setStore({ kind: "loading" });
			return;
		}
		setStore({ kind: "loading" });
		void (async () => {
			try {
				const { data, error } = await supabase.functions.invoke("policy-management", {
					body: { action: DLP_READ_ACTION, tenant_id: teamId },
				});
				if (cancelled) return;
				if (error) {
					if (await isMfaRequired(error)) {
						if (!cancelled) {
							setDraft(null);
							setStore({ kind: "mfa_required" });
						}
						return;
					}
					if (cancelled) return;
					// No DLP store in this deployment. Authoring and validation still
					// work locally — the operator can build the document and hand the
					// validated JSON to whatever channel does persist it — but the
					// surface says outright that nothing here is stored, and publishing
					// stays disabled rather than reporting a save that did not happen.
					setDraft(createStarterDlpPolicy(teamId));
					setStore({ kind: "unavailable", detail: readErrorMessage(error, t("dlp.unknownError")) });
					return;
				}
				const payload = (data ?? null) as DlpReadResponse | null;
				if (!payload || payload.ok !== true) {
					setDraft(createStarterDlpPolicy(teamId));
					setStore({
						kind: "unavailable",
						detail: t("dlp.noStore"),
					});
					return;
				}
				if (!Number.isSafeInteger(payload.version) || Number(payload.version) < 0) {
					setStore({ kind: "unreadable", detail: t("dlp.notConfirmedVersion") });
					return;
				}
				const version = payload.version as number;
				if (payload.policy === null && version === 0) {
					setDraft(createStarterDlpPolicy(teamId));
					setStore({ kind: "loaded", version });
					return;
				}
				const candidate = normalizePolicy(payload.policy);
				if (
					!candidate.policy ||
					candidate.policy.tenantId !== teamId ||
					candidate.policy.version !== version
				) {
					// Only an expired-majority document can be loaded for repair.
					// Structural/reference/tenant errors never become an editable guess.
					setStore({
						kind: "unreadable",
						detail: formatDlpIssues(candidate.issues) || t("dlp.mismatch"),
					});
					return;
				}
				setDraft(candidate.policy);
				setStore({ kind: "loaded", version });
			} catch (error) {
				if (!cancelled) {
					setStore({ kind: "unavailable", detail: readErrorMessage(error, t("dlp.unknownError")) });
				}
			}
		})();
		return () => {
			cancelled = true;
			tenantGeneration.current += 1;
		};
	}, [teamId]);

	const validation = useMemo(() => (draft ? validateDlpPolicyDocument(draft) : null), [draft]);
	const isPublishable = store.kind === "loaded" && validation?.ok === true;

	// Transient edits are allowed to be invalid; only a validated document is
	// ever published, and the issue list below is what makes an invalid field
	// visible instead of silently unpublishable.
	function editDraft(update: (current: DlpPolicyDocument) => DlpPolicyDocument) {
		if (isPublishing || !canManageTeam) return;
		setOutcome(null);
		setDraft((current) => (current ? update(current) : current));
	}

	function updateLabel(index: number, patch: Partial<DlpLabelDocument>) {
		editDraft((current) => ({
			...current,
			labels: current.labels.map((label, position) =>
				position === index ? { ...label, ...patch } : label,
			),
		}));
	}

	function updateRule(index: number, patch: Partial<DlpRuleDocument>) {
		editDraft((current) => ({
			...current,
			rules: current.rules.map((rule, position) =>
				position === index ? { ...rule, ...patch } : rule,
			),
		}));
	}

	function updateException(index: number, exception: DlpExceptionDocument) {
		editDraft((current) => ({
			...current,
			exceptions: current.exceptions.map((entry, position) =>
				position === index ? exception : entry,
			),
		}));
	}

	async function publish() {
		if (!teamId || !draft || !canManageTeam || store.kind !== "loaded" || isPublishing) return;
		const generation = tenantGeneration.current;
		const expectedVersion = store.version;
		const validated = validateDlpPolicyDocument(draft);
		if (!validated.ok) {
			setOutcome({
				tone: "error",
				message: t("dlp.saveNotConfirmed", { detail: formatDlpIssues(validated.issues) }),
			});
			return;
		}
		setIsPublishing(true);
		setOutcome(null);
		try {
			const { data, error } = await supabase.functions.invoke("policy-management", {
				body: {
					action: DLP_PUBLISH_ACTION,
					tenant_id: teamId,
					expected_version: expectedVersion,
					policy: validated.policy,
				},
			});
			if (tenantGeneration.current !== generation) return;
			if (error) throw error;
			const pendingChange = pendingPolicyChangeNotice(data, t);
			if (pendingChange) {
				setOutcome({ tone: "success", message: t("dlp.filed", { pending: pendingChange }) });
				return;
			}
			const payload = (data ?? null) as DlpPublishResponse | null;
			// A 200 or an echoed version alone proves neither storage nor delivery.
			// This endpoint saves only; reject missing or contradictory evidence.
			const savedPolicy = validateDlpPolicyDocument(payload?.policy);
			if (
				!payload ||
				payload.ok !== true ||
				payload.saved !== true ||
				payload.delivered !== false ||
				payload.delivery_status !== "not_delivered" ||
				!Number.isSafeInteger(payload.version) ||
				payload.version !== expectedVersion + 1 ||
				!savedPolicy.ok ||
				savedPolicy.policy.tenantId !== teamId ||
				savedPolicy.policy.version !== payload.version ||
				serializeDlpPolicy(savedPolicy.policy) !==
					serializeDlpPolicy({ ...validated.policy, version: expectedVersion + 1 })
			) {
				throw new Error(
					"the function did not confirm a stored DLP policy version and its not-delivered status",
				);
			}
			setDraft(savedPolicy.policy);
			setStore({ kind: "loaded", version: payload.version as number });
			setOutcome({
				tone: "success",
				message: t("dlp.saved", { version: String(payload.version) }),
			});
		} catch (error) {
			if (tenantGeneration.current !== generation) return;
			setOutcome({
				tone: "error",
				message: t("dlp.saveNotConfirmed", {
					detail: readErrorMessage(error, t("dlp.unknownError")),
				}),
			});
		} finally {
			if (tenantGeneration.current === generation) setIsPublishing(false);
		}
	}

	const issues = validation && !validation.ok ? validation.issues : [];

	return (
		<div className="stack">
			<section className="card">
				<h2 style={{ margin: 0 }}>{t("dlp.title")}</h2>
				<p className="muted" style={{ margin: "6px 0 0", maxWidth: 760 }}>
					{t("dlp.lead")}
				</p>
			</section>

			<div className="notice notice-warning" role="status">
				<b>{t("dlp.askTitle")}</b>
				<div className="muted small" style={{ marginTop: 6 }}>
					{richT("dlp.askBody", {
						ask: <span className="mono">ask</span>,
						ask2: <span className="mono">ask</span>,
					})}
				</div>
			</div>

			{teamLoading ? (
				<section className="card">
					<p className="muted">{t("dlp.loading")}</p>
				</section>
			) : !currentTeam ? (
				<section className="card">
					{teamError ? (
						<>
							<div className="notice notice-danger" role="alert" aria-live="assertive">
								<b>{t("dlp.teamFailed")}</b>
								<div className="muted small" style={{ marginTop: 6 }}>
									{teamError}
								</div>
							</div>
							<p className="muted">{t("dlp.noTeamState")}</p>
						</>
					) : (
						<p className="muted">{t("dlp.noTeam")}</p>
					)}
				</section>
			) : !canManageTeam ? (
				<section className="card">
					<p className="muted">{t("dlp.readOnly", { team: currentTeam.name })}</p>
					{draft && store.kind === "loaded" && store.version > 0 ? (
						<textarea
							className="input mono"
							rows={12}
							readOnly
							aria-label={t("dlp.documentLabel")}
							value={serializeDlpPolicy(draft)}
						/>
					) : (
						<p className="muted">
							{store.kind === "loading"
								? t("dlp.loading")
								: store.kind === "loaded"
									? t("dlp.notSaved")
									: t("dlp.notLoaded")}
						</p>
					)}
				</section>
			) : (
				<>
					{store.kind === "loading" ? (
						<section className="card">
							<p className="muted">{t("dlp.loading")}</p>
						</section>
					) : null}

					{store.kind === "unavailable" ? (
						<section className="card">
							<div className="notice notice-danger" role="status" aria-live="polite">
								<b>{t("dlp.storeUnavailable")}</b>
								<div className="muted small" style={{ marginTop: 6 }}>
									{t("dlp.storeUnavailableBody", { detail: store.detail })}
								</div>
							</div>
						</section>
					) : null}

					{store.kind === "mfa_required" ? (
						<section className="card">
							<div className="notice notice-warning" role="alert">
								<b>{t("dlp.mfa")}</b>
								<div className="muted small" style={{ marginTop: 6 }}>
									{t("dlp.mfaBody")}
								</div>
								<Link
									className="button"
									to={`/auth/dlp-step-up?tenant=${encodeURIComponent(currentTeam.id)}`}
								>
									{t("common.verifyMfa")}
								</Link>
							</div>
						</section>
					) : null}

					{store.kind === "unreadable" ? (
						<section className="card">
							<div className="notice notice-danger" role="alert" aria-live="assertive">
								<b>{t("dlp.unreadable")}</b>
								<div className="muted small" style={{ marginTop: 6 }}>
									{store.detail}
								</div>
								<div className="muted small" style={{ marginTop: 6 }}>
									{t("dlp.unreadableBody")}
								</div>
							</div>
						</section>
					) : null}

					{issues.some(isExpiredExceptionDominance) ? (
						<section className="card">
							<p className="muted">{t("dlp.expired")}</p>
							<button
								type="button"
								className="btn"
								onClick={() =>
									editDraft((current) => ({
										...current,
										exceptions: current.exceptions.filter(
											(exception) => Date.parse(exception.expiresAt) > Date.now(),
										),
									}))
								}
							>
								{t("dlp.removeExpired")}
							</button>
						</section>
					) : null}

					{draft ? (
						<fieldset
							disabled={isPublishing}
							className="stack"
							style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}
						>
							<section className="card">
								<div className="row space-between">
									<div>
										<h3 style={{ margin: 0 }}>{t("dlp.document")}</h3>
										<p className="muted small" style={{ margin: "6px 0 0" }}>
											{store.kind === "loaded"
												? t("dlp.storedVersion", { tenant: draft.tenantId, version: store.version })
												: t("dlp.notStored", { tenant: draft.tenantId })}
										</p>
									</div>
									<div className="row">
										<span className={`pill ${validation?.ok ? "" : "notice-danger"}`}>
											{validation?.ok ? t("dlp.valid") : t("dlp.invalid")}
										</span>
										<button
											type="button"
											className="btn btn-primary"
											onClick={() => void publish()}
											disabled={!isPublishable || isPublishing}
										>
											{isPublishing ? t("dlp.saving") : t("dlp.save")}
										</button>
									</div>
								</div>
								<div className="grid" style={{ gridTemplateColumns: "repeat(3, 1fr)" }}>
									<label className="label">
										{t("dlp.docVersion")}
										<input
											className="input"
											type="number"
											min={1}
											value={draft.version}
											aria-label={t("dlp.versionLabel")}
											readOnly
										/>
									</label>
									<label className="label">
										{t("dlp.maxBytes")}
										<input
											className="input"
											type="number"
											min={1}
											max={MAX_CONTENT_BYTES_CEILING}
											aria-label={t("dlp.maxBytes")}
											value={draft.maxContentBytes}
											onChange={(event) =>
												editDraft((current) => ({
													...current,
													maxContentBytes: Number(event.target.value),
												}))
											}
										/>
									</label>
									<label className="label">
										{t("dlp.uninspectable")}
										<select
											className="input"
											aria-label={t("dlp.uninspectableLabel")}
											value={draft.unavailableAction}
											onChange={(event) =>
												editDraft((current) => ({
													...current,
													unavailableAction: event.target.value as DlpUnavailableAction,
												}))
											}
										>
											<option value="block">{t("dlp.action.block")}</option>
											<option value="ask">{t("dlp.action.ask")}</option>
										</select>
									</label>
								</div>
								<label className="label">
									{t("dlp.formats")}
									<textarea
										className="input mono"
										rows={2}
										aria-label={t("dlp.formatsLabel")}
										value={draft.supportedFormats.join(", ")}
										onChange={(event) =>
											editDraft((current) => ({
												...current,
												supportedFormats: event.target.value
													.split(",")
													.map((entry) => entry.trim())
													.filter((entry) => entry.length > 0),
											}))
										}
									/>
								</label>
							</section>

							<section className="card stack">
								<div className="row space-between">
									<h3 style={{ margin: 0 }}>{t("dlp.labels", { count: draft.labels.length })}</h3>
									<button
										type="button"
										className="btn"
										onClick={() =>
											editDraft((current) => ({
												...current,
												labels: [
													...current.labels,
													newDlpLabel(
														current.tenantId,
														current.labels.map((label) => label.id),
													),
												],
											}))
										}
									>
										{t("dlp.addLabel")}
									</button>
								</div>
								{draft.labels.map((label, index) => (
									<div key={`label-${index}`} className="card">
										<div className="row space-between">
											<b>{t("dlp.label", { n: index + 1 })}</b>
											<button
												type="button"
												className="button button-secondary button-sm"
												onClick={() =>
													editDraft((current) => ({
														...current,
														labels: current.labels.filter((_, position) => position !== index),
													}))
												}
											>
												{t("dlp.removeLabel", { n: index + 1 })}
											</button>
										</div>
										<div className="grid" style={{ gridTemplateColumns: "repeat(2, 1fr)" }}>
											<label className="label">
												{t("dlp.id")}
												<input
													className="input mono"
													aria-label={t("dlp.labelId", { n: index + 1 })}
													value={label.id}
													onChange={(event) => updateLabel(index, { id: event.target.value })}
												/>
											</label>
											<label className="label">
												{t("dlp.name")}
												<input
													className="input"
													aria-label={t("dlp.labelName", { n: index + 1 })}
													value={label.name}
													onChange={(event) => updateLabel(index, { name: event.target.value })}
												/>
											</label>
											<label className="label">
												{t("dlp.description")}
												<input
													className="input"
													aria-label={t("dlp.labelDescription", { n: index + 1 })}
													value={label.description ?? ""}
													onChange={(event) =>
														updateLabel(index, {
															description:
																event.target.value === "" ? undefined : event.target.value,
														})
													}
												/>
											</label>
											<label className="label">
												{t("dlp.sensitivity")}
												<select
													className="input"
													aria-label={t("dlp.labelSensitivity", { n: index + 1 })}
													value={label.sensitivity}
													onChange={(event) =>
														updateLabel(index, {
															sensitivity: event.target.value as DlpSensitivity,
														})
													}
												>
													{SENSITIVITIES.map((sensitivity) => (
														<option key={sensitivity} value={sensitivity}>
															{t(SENSITIVITY_LABEL[sensitivity])}
														</option>
													))}
												</select>
											</label>
											<label className="label">
												{t("dlp.redactionToken")}
												<input
													className="input mono"
													aria-label={t("dlp.labelToken", { n: index + 1 })}
													value={label.redactionToken}
													onChange={(event) =>
														updateLabel(index, { redactionToken: event.target.value })
													}
												/>
											</label>
										</div>
									</div>
								))}
							</section>

							<section className="card stack">
								<div className="row space-between">
									<h3 style={{ margin: 0 }}>{t("dlp.rules", { count: draft.rules.length })}</h3>
									<button
										type="button"
										className="btn"
										onClick={() =>
											editDraft((current) => ({
												...current,
												rules: [
													...current.rules,
													newDlpRule(
														current.tenantId,
														current.labels[0]?.id ?? "",
														current.rules.map((rule) => rule.id),
													),
												],
											}))
										}
									>
										{t("dlp.addRule")}
									</button>
								</div>
								{draft.rules.map((rule, index) => (
									<div key={`rule-${index}`} className="card">
										<div className="row space-between">
											<b>{t("dlp.rule", { n: index + 1 })}</b>
											<button
												type="button"
												className="button button-secondary button-sm"
												onClick={() =>
													editDraft((current) => ({
														...current,
														rules: current.rules.filter((_, position) => position !== index),
													}))
												}
											>
												{t("dlp.removeRule", { n: index + 1 })}
											</button>
										</div>
										<div className="grid" style={{ gridTemplateColumns: "repeat(2, 1fr)" }}>
											<label className="label">
												{t("dlp.id")}
												<input
													className="input mono"
													aria-label={t("dlp.ruleId", { n: index + 1 })}
													value={rule.id}
													onChange={(event) => updateRule(index, { id: event.target.value })}
												/>
											</label>
											<label className="label">
												{t("dlp.name")}
												<input
													className="input"
													aria-label={t("dlp.ruleName", { n: index + 1 })}
													value={rule.name}
													onChange={(event) => updateRule(index, { name: event.target.value })}
												/>
											</label>
											<label className="label">
												{t("dlp.labelField")}
												<select
													className="input"
													aria-label={t("dlp.ruleLabel", { n: index + 1 })}
													value={rule.labelId}
													onChange={(event) => updateRule(index, { labelId: event.target.value })}
												>
													{draft.labels.map((label) => (
														<option key={label.id} value={label.id}>
															{label.name || label.id}
														</option>
													))}
												</select>
											</label>
											<label className="label">
												{t("dlp.priority")}
												<input
													className="input"
													type="number"
													min={0}
													max={10_000}
													aria-label={t("dlp.rulePriority", { n: index + 1 })}
													value={rule.priority}
													onChange={(event) =>
														updateRule(index, { priority: Number(event.target.value) })
													}
												/>
											</label>
											<label className="label">
												{t("dlp.action")}
												<select
													className="input"
													aria-label={t("dlp.ruleAction", { n: index + 1 })}
													value={rule.action}
													onChange={(event) =>
														updateRule(index, { action: event.target.value as DlpRuleAction })
													}
												>
													<option value="redact">{t("dlp.action.redact")}</option>
													<option value="block">{t("dlp.action.block")}</option>
													<option value="ask">{t("dlp.action.askLong")}</option>
												</select>
											</label>
											<label className="label">
												{t("dlp.matchMode")}
												<select
													className="input"
													aria-label={t("dlp.ruleMatchMode", { n: index + 1 })}
													value={rule.matchMode}
													onChange={(event) =>
														updateRule(index, {
															matchMode: event.target.value as DlpRuleDocument["matchMode"],
														})
													}
												>
													<option value="any">{t("dlp.matchAny")}</option>
													<option value="all">{t("dlp.matchAll")}</option>
												</select>
											</label>
											<label className="label">
												{t("dlp.replacement")}
												<input
													className="input mono"
													aria-label={t("dlp.ruleReplacement", { n: index + 1 })}
													value={rule.replacement ?? ""}
													onChange={(event) =>
														updateRule(index, {
															replacement:
																event.target.value === "" ? undefined : event.target.value,
														})
													}
												/>
											</label>
											<label className="label">
												{t("dlp.enabled")}
												<input
													type="checkbox"
													aria-label={t("dlp.ruleEnabled", { n: index + 1 })}
													checked={rule.enabled}
													onChange={(event) => updateRule(index, { enabled: event.target.checked })}
												/>
											</label>
										</div>
										<div className="row">
											{DIRECTIONS.map((direction) => (
												<label key={direction} className="label">
													<input
														type="checkbox"
														aria-label={t("dlp.ruleDirection", { n: index + 1, direction })}
														checked={rule.directions.includes(direction)}
														onChange={(event) => {
															const next = event.target.checked
																? [...rule.directions, direction]
																: rule.directions.filter((entry) => entry !== direction);
															updateRule(index, { directions: next });
														}}
													/>{" "}
													{t(DIRECTION_LABEL[direction])}
												</label>
											))}
										</div>

										<h4>{t("dlp.matchers", { count: rule.matchers.length })}</h4>
										{rule.matchers.map((matcher, matcherIndex) => (
											<div key={`rule-${index}-matcher-${matcherIndex}`} className="card">
												<div className="row space-between">
													<span className="muted small">
														{t("dlp.matcherOf", { m: matcherIndex + 1, n: index + 1 })}
													</span>
													<button
														type="button"
														className="button button-secondary button-sm"
														onClick={() =>
															updateRule(index, {
																matchers: rule.matchers.filter(
																	(_, position) => position !== matcherIndex,
																),
															})
														}
													>
														{t("dlp.removeMatcher", { m: matcherIndex + 1, n: index + 1 })}
													</button>
												</div>
												<label className="label">
													{t("dlp.type")}
													<select
														className="input"
														aria-label={t("dlp.matcherType", { n: index + 1, m: matcherIndex + 1 })}
														value={matcher.type}
														onChange={(event) => {
															const type = event.target.value;
															updateRule(index, {
																matchers: rule.matchers.map((entry, position) =>
																	position === matcherIndex
																		? type === "keyword"
																			? {
																					type: "keyword" as const,
																					values: [],
																					caseSensitive: false,
																					wholeWord: true,
																				}
																			: type === "detector"
																				? { type: "detector" as const, detectors: [] }
																				: { type: "regex" as const, pattern: "", flags: "i" }
																		: entry,
																),
															});
														}}
													>
														<option value="keyword">{t("dlp.keyword")}</option>
														<option value="regex">{t("dlp.regex")}</option>
														<option value="detector">{t("dlp.detector")}</option>
													</select>
												</label>
												{matcher.type === "detector" ? (
													<label className="label">
														{t("dlp.detectors")}
														<select
															className="input mono"
															multiple
															size={6}
															aria-label={t("dlp.matcherDetectors", {
																n: index + 1,
																m: matcherIndex + 1,
															})}
															value={matcher.detectors}
															onChange={(event) =>
																updateRule(index, {
																	matchers: rule.matchers.map((entry, position) =>
																		position === matcherIndex
																			? {
																					type: "detector" as const,
																					detectors: Array.from(
																						event.target.selectedOptions,
																						(option) =>
																							option.value as DlpDetectorMatcherDocument["detectors"][number],
																					),
																				}
																			: entry,
																	),
																})
															}
														>
															{DETECTORS.map((detector) => (
																<option key={detector} value={detector}>
																	{detector}
																</option>
															))}
														</select>
													</label>
												) : matcher.type === "keyword" ? (
													<>
														<label className="label">
															{t("dlp.keywords")}
															<textarea
																className="input mono"
																rows={3}
																aria-label={t("dlp.matcherKeywords", {
																	n: index + 1,
																	m: matcherIndex + 1,
																})}
																value={matcher.values.join("\n")}
																onChange={(event) =>
																	updateRule(index, {
																		matchers: rule.matchers.map((entry, position) =>
																			position === matcherIndex
																				? {
																						...matcher,
																						values: event.target.value
																							.split("\n")
																							.map((value) => value.trim())
																							.filter((value) => value.length > 0),
																					}
																				: entry,
																		),
																	})
																}
															/>
														</label>
														<div className="row">
															<label className="label">
																<input
																	type="checkbox"
																	aria-label={t("dlp.matcherCase", {
																		n: index + 1,
																		m: matcherIndex + 1,
																	})}
																	checked={matcher.caseSensitive}
																	onChange={(event) =>
																		updateRule(index, {
																			matchers: rule.matchers.map((entry, position) =>
																				position === matcherIndex
																					? { ...matcher, caseSensitive: event.target.checked }
																					: entry,
																			),
																		})
																	}
																/>{" "}
																{t("dlp.caseSensitive")}
															</label>
															<label className="label">
																<input
																	type="checkbox"
																	aria-label={t("dlp.matcherWhole", {
																		n: index + 1,
																		m: matcherIndex + 1,
																	})}
																	checked={matcher.wholeWord}
																	onChange={(event) =>
																		updateRule(index, {
																			matchers: rule.matchers.map((entry, position) =>
																				position === matcherIndex
																					? { ...matcher, wholeWord: event.target.checked }
																					: entry,
																			),
																		})
																	}
																/>{" "}
																{t("dlp.wholeWord")}
															</label>
														</div>
													</>
												) : (
													<div className="grid" style={{ gridTemplateColumns: "2fr 1fr 1fr" }}>
														<label className="label">
															{t("dlp.pattern")}
															<input
																className="input mono"
																aria-label={t("dlp.matcherPattern", {
																	n: index + 1,
																	m: matcherIndex + 1,
																})}
																value={matcher.pattern}
																onChange={(event) =>
																	updateRule(index, {
																		matchers: rule.matchers.map((entry, position) =>
																			position === matcherIndex
																				? { ...matcher, pattern: event.target.value }
																				: entry,
																		),
																	})
																}
															/>
														</label>
														<label className="label">
															{t("dlp.flags")}
															<input
																className="input mono"
																aria-label={t("dlp.matcherFlags", {
																	n: index + 1,
																	m: matcherIndex + 1,
																})}
																value={matcher.flags}
																onChange={(event) =>
																	updateRule(index, {
																		matchers: rule.matchers.map((entry, position) =>
																			position === matcherIndex
																				? { ...matcher, flags: event.target.value }
																				: entry,
																		),
																	})
																}
															/>
														</label>
														<label className="label">
															{t("dlp.validator")}
															<select
																className="input mono"
																aria-label={t("dlp.matcherValidator", {
																	n: index + 1,
																	m: matcherIndex + 1,
																})}
																value={matcher.validator ?? ""}
																onChange={(event) => {
																	const chosen = event.target.value;
																	const next: DlpRegexMatcherDocument = {
																		type: "regex",
																		pattern: matcher.pattern,
																		flags: matcher.flags,
																		...(chosen === ""
																			? {}
																			: {
																					validator:
																						chosen as (typeof MATCH_VALIDATORS)[number],
																				}),
																	};
																	updateRule(index, {
																		matchers: rule.matchers.map((entry, position) =>
																			position === matcherIndex ? next : entry,
																		),
																	});
																}}
															>
																<option value="">{t("dlp.validatorNone")}</option>
																{MATCH_VALIDATORS.map((validator) => (
																	<option key={validator} value={validator}>
																		{validator}
																	</option>
																))}
															</select>
														</label>
													</div>
												)}
											</div>
										))}
										<button
											type="button"
											className="btn"
											onClick={() =>
												updateRule(index, {
													matchers: [
														...rule.matchers,
														{ type: "keyword", values: [], caseSensitive: false, wholeWord: true },
													],
												})
											}
										>
											{t("dlp.addMatcher", { n: index + 1 })}
										</button>
									</div>
								))}
							</section>

							<section className="card stack">
								<div className="row space-between">
									<h3 style={{ margin: 0 }}>
										{t("dlp.exceptions", { count: draft.exceptions.length })}
									</h3>
									<button
										type="button"
										className="btn"
										onClick={() =>
											editDraft((current) => ({
												...current,
												exceptions: [
													...current.exceptions,
													newDlpException(
														current.tenantId,
														current.rules[0]?.id ?? "",
														"",
														current.exceptions.map((exception) => exception.id),
													),
												],
											}))
										}
									>
										{t("dlp.addException")}
									</button>
								</div>
								<p className="muted small">{t("dlp.exceptionsLead")}</p>
								{draft.exceptions.map((exception, index) => (
									<div key={`exception-${index}`} className="card">
										<div className="row space-between">
											<b>{t("dlp.exception", { n: index + 1 })}</b>
											<button
												type="button"
												className="button button-secondary button-sm"
												onClick={() =>
													editDraft((current) => ({
														...current,
														exceptions: current.exceptions.filter(
															(_, position) => position !== index,
														),
													}))
												}
											>
												{t("dlp.removeException", { n: index + 1 })}
											</button>
										</div>
										<div className="grid" style={{ gridTemplateColumns: "repeat(2, 1fr)" }}>
											<label className="label">
												{t("dlp.id")}
												<input
													className="input mono"
													aria-label={t("dlp.exceptionId", { n: index + 1 })}
													value={exception.id}
													onChange={(event) =>
														updateException(index, { ...exception, id: event.target.value })
													}
												/>
											</label>
											<label className="label">
												{t("dlp.ruleField")}
												<select
													className="input"
													aria-label={t("dlp.exceptionRule", { n: index + 1 })}
													value={exception.ruleId}
													onChange={(event) =>
														updateException(index, { ...exception, ruleId: event.target.value })
													}
												>
													{draft.rules.map((rule) => (
														<option key={rule.id} value={rule.id}>
															{rule.name || rule.id}
														</option>
													))}
												</select>
											</label>
											<label className="label">
												{t("dlp.owner")}
												<input
													className="input mono"
													aria-label={t("dlp.exceptionOwner", { n: index + 1 })}
													value={exception.ownerId}
													onChange={(event) =>
														updateException(index, { ...exception, ownerId: event.target.value })
													}
												/>
											</label>
											<label className="label">
												{t("dlp.scope")}
												<select
													className="input"
													aria-label={t("dlp.exceptionScope", { n: index + 1 })}
													value={exception.scope}
													onChange={(event) => {
														const scope = event.target.value as DlpExceptionScope;
														// The fingerprint follows the scope: a rule exception must
														// carry none, a content/match exception must carry one.
														const withoutFingerprint: DlpExceptionDocument = {
															id: exception.id,
															tenantId: exception.tenantId,
															ruleId: exception.ruleId,
															ownerId: exception.ownerId,
															justification: exception.justification,
															scope,
															expiresAt: exception.expiresAt,
															...(exception.createdAt === undefined
																? {}
																: { createdAt: exception.createdAt }),
														};
														updateException(
															index,
															scope === "rule"
																? withoutFingerprint
																: { ...withoutFingerprint, fingerprint: "" },
														);
													}}
												>
													{EXCEPTION_SCOPES.map((scope) => (
														<option key={scope} value={scope}>
															{t(SCOPE_LABEL[scope])}
														</option>
													))}
												</select>
											</label>
											<label className="label">
												{t("dlp.expiresAt")}
												<input
													className="input"
													type="datetime-local"
													aria-label={t("dlp.exceptionExpiry", { n: index + 1 })}
													value={toDatetimeLocalValue(exception.expiresAt)}
													onChange={(event) =>
														updateException(index, {
															...exception,
															expiresAt: fromDatetimeLocalValue(event.target.value),
														})
													}
												/>
											</label>
											<label className="label">
												{t("dlp.createdAt")}
												<input
													className="input"
													type="datetime-local"
													aria-label={t("dlp.exceptionCreated", { n: index + 1 })}
													value={
														exception.createdAt === undefined
															? ""
															: toDatetimeLocalValue(exception.createdAt)
													}
													onChange={(event) => {
														const next = fromDatetimeLocalValue(event.target.value);
														if (next === "") {
															updateException(index, exceptionWithoutCreatedAt(exception));
															return;
														}
														updateException(index, { ...exception, createdAt: next });
													}}
												/>
											</label>
											<label className="label">
												{t("dlp.justification")}
												<textarea
													className="input"
													rows={2}
													aria-label={t("dlp.exceptionJustification", { n: index + 1 })}
													value={exception.justification}
													onChange={(event) =>
														updateException(index, {
															...exception,
															justification: event.target.value,
														})
													}
												/>
											</label>
											{exception.scope !== "rule" ? (
												<label className="label">
													{t("dlp.fingerprint", { scope: t(SCOPE_LABEL[exception.scope]) })}
													<input
														className="input mono"
														aria-label={t("dlp.exceptionFingerprint", { n: index + 1 })}
														value={exception.fingerprint ?? ""}
														onChange={(event) =>
															updateException(index, {
																...exception,
																fingerprint: event.target.value,
															})
														}
													/>
												</label>
											) : null}
										</div>
									</div>
								))}
							</section>

							<section className="card">
								<h3 style={{ marginTop: 0 }}>
									{validation?.ok ? t("dlp.validatedDoc") : t("dlp.invalidDoc")}
								</h3>
								<p className="muted small">
									{validation?.ok ? t("dlp.validatedHint") : t("dlp.invalidHint")}
								</p>
								<textarea
									className="input mono"
									rows={12}
									readOnly
									aria-label={t("dlp.documentLabel")}
									value={serializeDlpPolicy(validation?.ok ? validation.policy : draft)}
								/>
							</section>
						</fieldset>
					) : null}

					{issues.length > 0 ? (
						<section className="card">
							<div className="notice notice-danger" role="alert" aria-live="assertive">
								<b>{t("dlp.notValid")}</b>
								<ul style={{ margin: "8px 0 0", paddingLeft: 18 }}>
									{issues.map((issue) => (
										<li key={`${issue.path}:${issue.message}`} className="small">
											<span className="mono">{issue.path || "policy"}</span>: {issue.message}
										</li>
									))}
								</ul>
							</div>
						</section>
					) : null}

					{outcome ? (
						<section className="card">
							<div
								className={`notice ${outcome.tone === "error" ? "notice-danger" : ""}`}
								role={outcome.tone === "error" ? "alert" : "status"}
								aria-live="assertive"
							>
								{outcome.message}
							</div>
						</section>
					) : null}

					{teamId && store.kind === "loaded" ? (
						<DlpPolicyHistory
							tenantId={teamId}
							currentVersion={store.version}
							canManage={canManageTeam}
							onRestored={(version, policy) => {
								const restored = validateDlpPolicyDocument(policy);
								if (restored.ok && restored.policy.version === version) {
									setOutcome(null);
									setDraft(restored.policy);
									setStore({ kind: "loaded", version });
								} else {
									setStore({ kind: "unreadable", detail: t("dlp.restoreFailed") });
								}
							}}
						/>
					) : null}
				</>
			)}
		</div>
	);
}

/** AAL2 is obtained by the existing server-verified MFA flow, never by the DLP editor. */
export function DlpStepUpPage() {
	const t = useT();
	const richT = useRichT();
	const [params] = useSearchParams();
	const tenantId = params.get("tenant");
	// Only fixed in-app destinations; never an arbitrary return URL.
	const returnTo = params.get("return");
	const toSettings = returnTo === "settings";
	const toApprovals = returnTo === "approvals";
	const toGovernance = returnTo === "governance";
	if (!tenantId || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(tenantId)) {
		return (
			<div role="alert">
				{richT("dlp.selectTeam", { link: <Link to="/policies">{t("nav.policies")}</Link> })}
			</div>
		);
	}
	return (
		<main className="stack" style={{ maxWidth: 720, margin: "48px auto" }}>
			<EnterpriseAuth tenantId={tenantId} forceMfa>
				<div className="card">
					<h1>{t("dlp.verified")}</h1>
					<p>{t("dlp.verifiedBody")}</p>
					<Link
						className="button"
						to={
							toSettings
								? "/settings"
								: toApprovals
									? "/approvals"
									: toGovernance
										? "/governance/change-control"
										: `/policies?tenant=${encodeURIComponent(tenantId)}`
						}
					>
						{toSettings
							? t("dlp.returnSettings")
							: toApprovals
								? t("dlp.returnApprovals")
								: toGovernance
									? t("dlp.returnGovernance")
									: t("dlp.returnPolicy")}
					</Link>
				</div>
			</EnterpriseAuth>
		</main>
	);
}
