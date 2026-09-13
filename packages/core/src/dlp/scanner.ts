import { createHash } from "node:crypto";
import { z } from "zod";
import {
	type DlpDirection,
	DlpDirectionSchema,
	type DlpException,
	type DlpLabel,
	type DlpMatcher,
	type DlpPolicy,
	DlpPolicySchema,
	type DlpRule,
	type DlpRuleAction,
} from "./policy.js";

export const DlpScanRequestSchema = z
	.object({
		tenantId: z.string().min(1).max(128),
		direction: DlpDirectionSchema,
		content: z.string(),
		contentType: z.string().trim().min(1).max(255),
		scannedAt: z.string().datetime({ offset: true }).optional(),
	})
	.strict();

export type DlpScanRequest = z.infer<typeof DlpScanRequestSchema>;
export type DlpScanAction = "allow" | DlpRuleAction;
export type DlpUnavailableReason =
	| "unsupported_format"
	| "oversize"
	| "malformed_format"
	| "transformation_failed";

export interface DlpFinding {
	ruleId: string;
	labelId: string;
	labelName: string;
	sensitivity: DlpLabel["sensitivity"];
	action: DlpRuleAction;
	start: number;
	end: number;
	/** Tenant- and rule-bound SHA-256; the raw sensitive match is never returned. */
	matchFingerprint: string;
	maskedPreview: string;
}

interface DlpScanResultBase {
	tenantId: string;
	direction: DlpDirection;
	contentType: string;
	byteLength: number;
	contentFingerprint: string;
	action: DlpScanAction;
	findings: DlpFinding[];
	appliedExceptionIds: string[];
}

export interface DlpInspectedResult extends DlpScanResultBase {
	status: "inspected";
	/** Present only when the effective action is redact. */
	transformedContent?: string;
}

export interface DlpUnavailableResult extends DlpScanResultBase {
	status: "unavailable";
	action: "block" | "ask";
	unavailable: {
		reason: DlpUnavailableReason;
		detail: string;
	};
}

export type DlpScanResult = DlpInspectedResult | DlpUnavailableResult;

export class DlpTenantIsolationError extends Error {
	readonly code = "DLP_TENANT_MISMATCH";

	constructor() {
		super("DLP scan tenant does not match the policy tenant");
		this.name = "DlpTenantIsolationError";
	}
}

interface InternalMatch {
	start: number;
	end: number;
	value: string;
}

interface JsonStringToken {
	decoded: string;
	/** Raw indices inside the quotes. */
	rawStart: number;
	rawEnd: number;
	/** Cumulative raw characters added by escapes before each decoded boundary. */
	escapes: Array<{ decodedIndex: number; extraAfter: number }>;
}

interface MatchedFinding {
	finding: DlpFinding;
	rule: DlpRule;
	replacement: string;
}

function sha256(value: string): string {
	return createHash("sha256").update(value, "utf8").digest("hex");
}

export function createDlpContentFingerprint(tenantId: string, content: string): string {
	return sha256(`${tenantId}\0${content}`);
}

export function createDlpMatchFingerprint(
	tenantId: string,
	ruleId: string,
	matchedValue: string,
): string {
	return sha256(`${tenantId}\0${ruleId}\0${matchedValue}`);
}

function normalizedContentType(value: string): string {
	return value.split(";", 1)[0]?.trim().toLowerCase() ?? "";
}

function isJsonContentType(contentType: string): boolean {
	return contentType === "application/json" || contentType.endsWith("+json");
}

/** Validate JSON first, then retain a bounded map from decoded strings to raw spans. */
function jsonStringTokens(content: string): JsonStringToken[] | undefined {
	try {
		JSON.parse(content);
		const tokens: JsonStringToken[] = [];
		for (let index = 0; index < content.length; index++) {
			if (content[index] !== '"') continue;
			const literalStart = index;
			const rawStart = ++index;
			const escapes: JsonStringToken["escapes"] = [];
			let decodedLength = 0;
			let extraAfter = 0;
			while (index < content.length && content[index] !== '"') {
				if (content[index] === "\\") {
					const rawLength = content[index + 1] === "u" ? 6 : 2;
					extraAfter += rawLength - 1;
					escapes.push({ decodedIndex: decodedLength, extraAfter });
					index += rawLength;
				} else {
					index++;
				}
				decodedLength++;
			}
			const decoded: unknown = JSON.parse(content.slice(literalStart, index + 1));
			if (typeof decoded !== "string" || decoded.length !== decodedLength) return undefined;
			tokens.push({ decoded, rawStart, rawEnd: index, escapes });
		}
		return tokens;
	} catch {
		return undefined;
	}
}

function jsonRawBoundary(token: JsonStringToken, decodedIndex: number): number | undefined {
	let low = 0;
	let high = token.escapes.length;
	while (low < high) {
		const middle = (low + high) >>> 1;
		const escape = token.escapes[middle];
		if (!escape) return undefined;
		if (escape.decodedIndex < decodedIndex) low = middle + 1;
		else high = middle;
	}
	const previousEscape = low ? token.escapes[low - 1] : undefined;
	if (low && !previousEscape) return undefined;
	return token.rawStart + decodedIndex + (previousEscape?.extraAfter ?? 0);
}

function supportsContentType(contentType: string, supportedFormats: string[]): boolean {
	return supportedFormats.some((supported) => {
		if (supported.endsWith("/*")) {
			return contentType.startsWith(supported.slice(0, -1));
		}
		return contentType === supported;
	});
}

function escapeRegex(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const WORD_CHARACTER = /[\p{L}\p{N}_]/u;

function isWholeWord(content: string, start: number, end: number): boolean {
	const before = start > 0 ? content[start - 1] : undefined;
	const after = end < content.length ? content[end] : undefined;
	return !(before && WORD_CHARACTER.test(before)) && !(after && WORD_CHARACTER.test(after));
}

function keywordMatches(
	content: string,
	matcher: Extract<DlpMatcher, { type: "keyword" }>,
): InternalMatch[] {
	const flags = matcher.caseSensitive ? "gu" : "giu";
	const matches: InternalMatch[] = [];
	for (const keyword of matcher.values) {
		const expression = new RegExp(escapeRegex(keyword), flags);
		for (const match of content.matchAll(expression)) {
			const start = match.index;
			const value = match[0];
			const end = start + value.length;
			if (!matcher.wholeWord || isWholeWord(content, start, end)) {
				matches.push({ start, end, value });
			}
		}
	}
	return matches;
}

function regexMatches(
	content: string,
	matcher: Extract<DlpMatcher, { type: "regex" }>,
): InternalMatch[] {
	const flags = matcher.flags.includes("g") ? matcher.flags : `${matcher.flags}g`;
	const expression = new RegExp(matcher.pattern, flags);
	return Array.from(content.matchAll(expression), (match) => ({
		start: match.index,
		end: match.index + match[0].length,
		value: match[0],
	}));
}

function matcherMatches(content: string, matcher: DlpMatcher): InternalMatch[] {
	return matcher.type === "keyword"
		? keywordMatches(content, matcher)
		: regexMatches(content, matcher);
}

function deduplicateMatches(matches: InternalMatch[]): InternalMatch[] {
	const byRange = new Map<string, InternalMatch>();
	for (const match of matches) {
		byRange.set(`${match.start}:${match.end}`, match);
	}
	return [...byRange.values()].sort(
		(left, right) => left.start - right.start || left.end - right.end,
	);
}

function ruleMatches(
	content: string,
	rule: DlpRule,
	jsonTokens: JsonStringToken[],
): InternalMatch[] | undefined {
	const matcherResults: InternalMatch[][] = [];
	for (const matcher of rule.matchers) {
		const matches = matcherMatches(content, matcher);
		for (const token of jsonTokens) {
			for (const decodedMatch of matcherMatches(token.decoded, matcher)) {
				if (decodedMatch.start === decodedMatch.end) continue;
				const start = jsonRawBoundary(token, decodedMatch.start);
				const end = jsonRawBoundary(token, decodedMatch.end);
				if (
					start === undefined ||
					end === undefined ||
					start < token.rawStart ||
					end > token.rawEnd ||
					start >= end
				) {
					return undefined;
				}
				matches.push({ start, end, value: decodedMatch.value });
			}
		}
		matcherResults.push(matches);
	}
	if (rule.matchMode === "all" && matcherResults.some((matches) => matches.length === 0)) {
		return [];
	}
	return deduplicateMatches(matcherResults.flat());
}

function maskedPreview(value: string): string {
	const characterCount = [...value].length;
	return "*".repeat(Math.min(12, characterCount));
}

function isActive(exception: DlpException, scannedAt: Date): boolean {
	return (
		Date.parse(exception.expiresAt) > scannedAt.getTime() &&
		(exception.createdAt === undefined || Date.parse(exception.createdAt) <= scannedAt.getTime())
	);
}

function matchingException(
	exceptions: DlpException[],
	ruleId: string,
	contentFingerprint: string,
	matchFingerprint: string,
	scannedAt: Date,
): DlpException | undefined {
	return exceptions.find((exception) => {
		if (exception.ruleId !== ruleId || !isActive(exception, scannedAt)) return false;
		if (exception.scope === "rule") return true;
		if (exception.scope === "content") return exception.fingerprint === contentFingerprint;
		return exception.fingerprint === matchFingerprint;
	});
}

const ACTION_RANK: Record<DlpScanAction, number> = {
	allow: 0,
	redact: 1,
	ask: 2,
	block: 3,
};

function effectiveAction(findings: DlpFinding[]): DlpScanAction {
	return findings.reduce<DlpScanAction>(
		(current, finding) =>
			ACTION_RANK[finding.action] > ACTION_RANK[current] ? finding.action : current,
		"allow",
	);
}

function redact(content: string, matched: MatchedFinding[]): string {
	const spans: Array<{ start: number; end: number; winner: MatchedFinding }> = [];
	const candidates = [...matched].sort(
		(left, right) =>
			left.finding.start - right.finding.start ||
			right.finding.end - left.finding.end ||
			right.rule.priority - left.rule.priority,
	);

	for (const candidate of candidates) {
		const current = spans[spans.length - 1];
		if (current && candidate.finding.start < current.end) {
			// Cover the union: discarding a lower-priority overlap can expose its suffix.
			current.end = Math.max(current.end, candidate.finding.end);
			if (
				candidate.rule.priority > current.winner.rule.priority ||
				(candidate.rule.priority === current.winner.rule.priority &&
					(candidate.finding.start < current.winner.finding.start ||
						(candidate.finding.start === current.winner.finding.start &&
							candidate.finding.end > current.winner.finding.end)))
			) {
				current.winner = candidate;
			}
		} else {
			spans.push({ start: candidate.finding.start, end: candidate.finding.end, winner: candidate });
		}
	}

	let transformed = content;
	for (const span of spans.reverse()) {
		transformed = `${transformed.slice(0, span.start)}${span.winner.replacement}${transformed.slice(span.end)}`;
	}
	return transformed;
}

/**
 * Scans either agent input or model/tool output against one tenant's DLP policy.
 * Invalid policy data throws; uninspectable payloads return an explicit
 * fail-closed unavailable state.
 */
export function scanDlpContent(
	policyInput: DlpPolicy,
	requestInput: DlpScanRequest,
): DlpScanResult {
	const policy = DlpPolicySchema.parse(policyInput);
	const request = DlpScanRequestSchema.parse(requestInput);
	if (request.tenantId !== policy.tenantId) throw new DlpTenantIsolationError();

	const contentType = normalizedContentType(request.contentType);
	const byteLength = new TextEncoder().encode(request.content).byteLength;
	const contentFingerprint = createDlpContentFingerprint(request.tenantId, request.content);
	const unavailableBase: Omit<DlpUnavailableResult, "status" | "unavailable"> = {
		tenantId: request.tenantId,
		direction: request.direction,
		contentType,
		byteLength,
		contentFingerprint,
		action: policy.unavailableAction,
		findings: [],
		appliedExceptionIds: [],
	};

	if (!supportsContentType(contentType, policy.supportedFormats)) {
		return {
			...unavailableBase,
			status: "unavailable",
			unavailable: {
				reason: "unsupported_format",
				detail: `content type ${contentType || "(empty)"} is not configured for inspection`,
			},
		};
	}

	if (byteLength > policy.maxContentBytes) {
		return {
			...unavailableBase,
			status: "unavailable",
			unavailable: {
				reason: "oversize",
				detail: `content is ${byteLength} bytes; inspection limit is ${policy.maxContentBytes} bytes`,
			},
		};
	}
	const jsonContent = isJsonContentType(contentType);
	const jsonTokens = jsonContent ? jsonStringTokens(request.content) : [];
	if (!jsonTokens) {
		return {
			...unavailableBase,
			status: "unavailable",
			unavailable: {
				reason: "malformed_format",
				detail: "JSON content is invalid or cannot be mapped for inspection",
			},
		};
	}

	const scannedAt = new Date(request.scannedAt ?? Date.now());
	const labels = new Map(policy.labels.map((label) => [label.id, label]));
	const matchedFindings: MatchedFinding[] = [];
	const appliedExceptionIds = new Set<string>();

	const rules = policy.rules
		.filter((rule) => rule.enabled && rule.directions.includes(request.direction))
		.sort((left, right) => right.priority - left.priority || left.id.localeCompare(right.id));

	for (const rule of rules) {
		const label = labels.get(rule.labelId);
		if (!label) continue;
		const matches = ruleMatches(request.content, rule, jsonTokens);
		if (!matches) {
			return {
				...unavailableBase,
				status: "unavailable",
				unavailable: {
					reason: "malformed_format",
					detail: "JSON match could not be mapped to raw content",
				},
			};
		}
		for (const match of matches) {
			const matchFingerprint = createDlpMatchFingerprint(request.tenantId, rule.id, match.value);
			const exception = matchingException(
				policy.exceptions,
				rule.id,
				contentFingerprint,
				matchFingerprint,
				scannedAt,
			);
			if (exception) {
				appliedExceptionIds.add(exception.id);
				continue;
			}

			matchedFindings.push({
				finding: {
					ruleId: rule.id,
					labelId: label.id,
					labelName: label.name,
					sensitivity: label.sensitivity,
					action: rule.action,
					start: match.start,
					end: match.end,
					matchFingerprint,
					maskedPreview: maskedPreview(match.value),
				},
				rule,
				replacement: rule.replacement ?? label.redactionToken,
			});
		}
	}

	const findings = matchedFindings.map(({ finding }) => finding);
	const action = effectiveAction(findings);
	const base: DlpInspectedResult = {
		status: "inspected",
		tenantId: request.tenantId,
		direction: request.direction,
		contentType,
		byteLength,
		contentFingerprint,
		action,
		findings,
		appliedExceptionIds: [...appliedExceptionIds].sort(),
	};
	if (action === "redact") {
		const transformed = redact(request.content, matchedFindings);
		if (jsonContent) {
			try {
				JSON.parse(transformed);
			} catch {
				return {
					...unavailableBase,
					status: "unavailable",
					unavailable: {
						reason: "transformation_failed",
						detail: "Redacted JSON could not be validated",
					},
				};
			}
		}
		base.transformedContent = transformed;
	}
	return base;
}

export function scanDlpInput(
	policy: DlpPolicy,
	request: Omit<DlpScanRequest, "direction">,
): DlpScanResult {
	return scanDlpContent(policy, { ...request, direction: "input" });
}

export function scanDlpOutput(
	policy: DlpPolicy,
	request: Omit<DlpScanRequest, "direction">,
): DlpScanResult {
	return scanDlpContent(policy, { ...request, direction: "output" });
}
