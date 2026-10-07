import { createHash } from "node:crypto";
import { z } from "zod";
import {
	type DlpDetector,
	type DlpDirection,
	DlpDirectionSchema,
	type DlpException,
	type DlpLabel,
	type DlpMatcher,
	type DlpPolicy,
	DlpPolicySchema,
	type DlpRule,
	type DlpRuleAction,
	isDlpExceptionActive,
	pruneExpiredExceptions,
} from "./policy.js";
import {
	detectorForKey,
	isPlausibleDetectorValue,
	privacyDetectorPlaceholder,
	scanPrivacyDetectors,
} from "./privacy-detectors.js";

export const DlpScanRequestSchema = z
	.object({
		tenantId: z.string().min(1).max(128),
		direction: DlpDirectionSchema,
		content: z.string(),
		contentType: z.string().trim().min(1).max(255),
		scannedAt: z.string().datetime({ offset: true }).optional(),
		/**
		 * `display` (default) keeps the configured placeholders, e.g. `[REDACTED]`.
		 * `shell_inert` is for content that will be executed as a rewritten tool
		 * input: every replacement becomes a `REDACTED_<TYPE>` word (see
		 * {@link shellInertRedactionToken}).
		 */
		replacementStyle: z.enum(["display", "shell_inert"]).optional(),
	})
	.strict();

/**
 * Replacement token for text a tool will execute. A display placeholder such
 * as `[REDACTED]` or `[TC_KIMLIK]` is a shell glob (`rm ./tmp/[REDACTED]`
 * removes every file named `R`, `E`, `D`, `A`, `C` or `T`), and an operator
 * token may carry spaces, quotes or a leading dash. The inert form keeps only
 * `[A-Za-z0-9_]` and always starts with `REDACTED`, so it is one literal word
 * in a shell, a path, a URL or a query string.
 */
export function shellInertRedactionToken(token: string): string {
	const word = token.replace(/[^A-Za-z0-9_]+/g, "_").replace(/^_+|_+$/g, "");
	if (!word) return "REDACTED";
	return /^REDACTED(?:_|$)/.test(word) ? word : `REDACTED_${word}`;
}

export type DlpScanRequest = z.infer<typeof DlpScanRequestSchema>;
export type DlpScanAction = "allow" | DlpRuleAction;
export type DlpUnavailableReason =
	| "unsupported_format"
	| "oversize"
	| "malformed_format"
	| "transformation_failed"
	/** A built-in detector could not inspect all of the content (input limit, malformed field). */
	| "incomplete_inspection";

export interface DlpFinding {
	ruleId: string;
	labelId: string;
	labelName: string;
	sensitivity: DlpLabel["sensitivity"];
	action: DlpRuleAction;
	/** Built-in detector that produced the match; absent for keyword/regex matchers. */
	detector?: DlpDetector;
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
	detector?: DlpDetector;
	/** A JSON number/literal outside any string: its replacement must be a JSON string. */
	jsonLiteral?: boolean;
}

/** Why a rule's matches could not be produced; both fail closed as unavailable. */
type RuleMatchFailure = "unmapped" | "incomplete";

type DetectorMatcher = Extract<DlpMatcher, { type: "detector" }>;

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

function matcherMatches(
	content: string,
	matcher: Exclude<DlpMatcher, DetectorMatcher>,
): InternalMatch[] {
	return matcher.type === "keyword"
		? keywordMatches(content, matcher)
		: regexMatches(content, matcher);
}

/**
 * Map a half-open span inside a decoded JSON string back to raw content offsets.
 * Returns undefined when the span cannot be mapped inside the string literal.
 */
function jsonRawSpan(
	token: JsonStringToken,
	start: number,
	end: number,
): { start: number; end: number } | undefined {
	const rawStart = jsonRawBoundary(token, start);
	const rawEnd = jsonRawBoundary(token, end);
	if (
		rawStart === undefined ||
		rawEnd === undefined ||
		rawStart < token.rawStart ||
		rawEnd > token.rawEnd ||
		rawStart >= rawEnd
	) {
		return undefined;
	}
	return { start: rawStart, end: rawEnd };
}

/**
 * Content-level inputs shared by every detector matcher in one scan. `jsonTokens` is
 * undefined for non-JSON content; rules sharing a detector set reuse one scan.
 */
interface DetectorScanContext {
	content: string;
	jsonTokens: JsonStringToken[] | undefined;
	cache: Map<string, InternalMatch[] | RuleMatchFailure>;
}

function detectorMatches(
	matcher: DetectorMatcher,
	context: DetectorScanContext,
): InternalMatch[] | RuleMatchFailure {
	const key = [...matcher.detectors].sort().join(",");
	let result = context.cache.get(key);
	if (result === undefined) {
		result = context.jsonTokens
			? jsonDetectorMatches(context.content, matcher.detectors, context.jsonTokens)
			: textDetectorMatches(context.content, matcher.detectors);
		context.cache.set(key, result);
	}
	return result;
}

function textDetectorMatches(
	content: string,
	detectors: readonly DlpDetector[],
): InternalMatch[] | RuleMatchFailure {
	const scan = scanPrivacyDetectors(content, detectors);
	if (scan.incomplete) return "incomplete";
	return scan.matches.map((match) => ({
		start: match.start,
		end: match.end,
		value: content.slice(match.start, match.end),
		detector: match.detector,
	}));
}

/**
 * Separates JSON scan segments. No privacy rule crosses a NUL (it is neither `\s`, a
 * letter, a digit nor a field delimiter), so a label in one string never claims text
 * from the next and an unquoted field value stops at its own string.
 */
const JSON_SEGMENT_SEPARATOR = "\n\u0000\n";

interface JsonScanSegment {
	start: number;
	end: number;
	/** Absent for the skeleton segment, whose offsets are raw content offsets. */
	token?: JsonStringToken;
}

/**
 * JSON-aware detector scan. Each decoded string is its own segment (labels and values
 * never bleed across string boundaries or into JSON structure), numbers and literals are
 * scanned in a skeleton with every string blanked, and a sensitive key such as `tckn`,
 * `iban` or `password` marks its whole string or number value. Every span is mapped back
 * to raw content offsets; a span that cannot be mapped fails the inspection.
 */
function jsonDetectorMatches(
	content: string,
	detectors: readonly DlpDetector[],
	tokens: JsonStringToken[],
): InternalMatch[] | RuleMatchFailure {
	const skeleton: string[] = [];
	let position = 0;
	for (const token of tokens) {
		// Blank the literal including its quotes so offsets stay raw offsets.
		skeleton.push(content.slice(position, token.rawStart - 1));
		skeleton.push(" ".repeat(token.rawEnd - token.rawStart + 2));
		position = token.rawEnd + 1;
	}
	skeleton.push(content.slice(position));

	const parts = [skeleton.join("")];
	const segments: JsonScanSegment[] = [{ start: 0, end: content.length }];
	let offset = content.length;
	for (const token of tokens) {
		offset += JSON_SEGMENT_SEPARATOR.length;
		parts.push(token.decoded);
		segments.push({ start: offset, end: offset + token.decoded.length, token });
		offset += token.decoded.length;
	}
	const combined = parts.join(JSON_SEGMENT_SEPARATOR);
	const scan = scanPrivacyDetectors(combined, detectors);
	if (scan.incomplete) return "incomplete";

	const matches: InternalMatch[] = [];
	for (const match of scan.matches) {
		for (const segment of overlappingSegments(segments, match.start, match.end)) {
			// Clip to each segment: over-redacting both parts is safe, spanning is not.
			const start = Math.max(match.start, segment.start) - segment.start;
			const end = Math.min(match.end, segment.end) - segment.start;
			if (start >= end) continue;
			if (!segment.token) {
				const value = content.slice(start, end);
				matches.push({ start, end, value, detector: match.detector, jsonLiteral: true });
				continue;
			}
			const span = jsonRawSpan(segment.token, start, end);
			if (!span) return "unmapped";
			matches.push({
				...span,
				value: segment.token.decoded.slice(start, end),
				detector: match.detector,
			});
		}
	}
	matches.push(...jsonKeyedMatches(content, detectors, tokens));
	return matches;
}

function overlappingSegments(
	segments: JsonScanSegment[],
	start: number,
	end: number,
): JsonScanSegment[] {
	let low = 0;
	let high = segments.length;
	while (low < high) {
		const middle = (low + high) >>> 1;
		if ((segments[middle]?.end ?? 0) <= start) low = middle + 1;
		else high = middle;
	}
	const overlapping: JsonScanSegment[] = [];
	for (let index = low; index < segments.length; index++) {
		const segment = segments[index];
		if (!segment || segment.start >= end) break;
		overlapping.push(segment);
	}
	return overlapping;
}

const JSON_NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

function skipJsonWhitespace(content: string, index: number): number {
	let position = index;
	while (position < content.length && /[ \t\r\n]/.test(content[position] ?? "")) position++;
	return position;
}

/** Whole string or number values of object keys that name a sensitive field. */
function jsonKeyedMatches(
	content: string,
	detectors: readonly DlpDetector[],
	tokens: JsonStringToken[],
): InternalMatch[] {
	const matches: InternalMatch[] = [];
	for (const [index, token] of tokens.entries()) {
		const colon = skipJsonWhitespace(content, token.rawEnd + 1);
		if (content[colon] !== ":") continue;
		const detector = detectorForKey(token.decoded, detectors);
		if (!detector) continue;
		const valueStart = skipJsonWhitespace(content, colon + 1);
		const next = tokens[index + 1];
		if (content[valueStart] === '"' && next?.rawStart === valueStart + 1) {
			if (next.rawEnd > next.rawStart && isPlausibleDetectorValue(detector, next.decoded)) {
				matches.push({ start: next.rawStart, end: next.rawEnd, value: next.decoded, detector });
			}
			continue;
		}
		JSON_NUMBER.lastIndex = valueStart;
		const number = JSON_NUMBER.exec(content)?.[0];
		if (number && isPlausibleDetectorValue(detector, number)) {
			matches.push({
				start: valueStart,
				end: valueStart + number.length,
				value: number,
				detector,
				jsonLiteral: true,
			});
		}
	}
	return matches;
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
	detectorContext: DetectorScanContext,
): InternalMatch[] | RuleMatchFailure {
	const matcherResults: InternalMatch[][] = [];
	for (const matcher of rule.matchers) {
		if (matcher.type === "detector") {
			const matches = detectorMatches(matcher, detectorContext);
			if (typeof matches === "string") return matches;
			matcherResults.push(matches);
			continue;
		}
		const matches = matcherMatches(content, matcher);
		for (const token of jsonTokens) {
			for (const decodedMatch of matcherMatches(token.decoded, matcher)) {
				if (decodedMatch.start === decodedMatch.end) continue;
				const span = jsonRawSpan(token, decodedMatch.start, decodedMatch.end);
				if (!span) return "unmapped";
				matches.push({ ...span, value: decodedMatch.value });
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

function matchingException(
	exceptions: DlpException[],
	ruleId: string,
	contentFingerprint: string,
	matchFingerprint: string,
	scannedAt: Date,
): DlpException | undefined {
	return exceptions.find((exception) => {
		if (exception.ruleId !== ruleId || !isDlpExceptionActive(exception, scannedAt)) return false;
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

	// Spans are sorted and disjoint: build the output in one pass instead of
	// re-copying the whole content once per span.
	const chunks: string[] = [];
	let position = 0;
	for (const span of spans) {
		chunks.push(content.slice(position, span.start), span.winner.replacement);
		position = span.end;
	}
	chunks.push(content.slice(position));
	return chunks.join("");
}

/**
 * An explicit rule replacement wins; detector matches otherwise get a constant type
 * placeholder such as [TC_KIMLIK]; else the label token. A JSON number replaced in
 * place becomes a JSON string so the redacted document stays valid. The
 * `shell_inert` style rewrites whichever token applies to its inert form.
 */
function replacementFor(
	rule: DlpRule,
	label: DlpLabel,
	match: InternalMatch,
	style: DlpScanRequest["replacementStyle"],
): string {
	const token =
		rule.replacement ??
		(match.detector ? privacyDetectorPlaceholder(match.detector) : label.redactionToken);
	const replacement = style === "shell_inert" ? shellInertRedactionToken(token) : token;
	return match.jsonLiteral ? JSON.stringify(replacement) : replacement;
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
	const validatedPolicy = DlpPolicySchema.parse(policyInput);
	const request = DlpScanRequestSchema.parse(requestInput);
	if (request.tenantId !== validatedPolicy.tenantId) throw new DlpTenantIsolationError();

	// Prune before anything is matched: an exception that is expired at the scan
	// instant must never suppress a finding. Pruning and matching share this one
	// instant, so the list the matcher consults is already free of dead records
	// and the two decisions cannot disagree about time.
	const scannedAt = new Date(request.scannedAt ?? Date.now());
	const policy = pruneExpiredExceptions(validatedPolicy, scannedAt);

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

	const labels = new Map(policy.labels.map((label) => [label.id, label]));
	const matchedFindings: MatchedFinding[] = [];
	const appliedExceptionIds = new Set<string>();
	const detectorContext: DetectorScanContext = {
		content: request.content,
		jsonTokens: jsonContent ? jsonTokens : undefined,
		cache: new Map(),
	};

	const rules = policy.rules
		.filter((rule) => rule.enabled && rule.directions.includes(request.direction))
		.sort((left, right) => right.priority - left.priority || left.id.localeCompare(right.id));

	for (const rule of rules) {
		const label = labels.get(rule.labelId);
		if (!label) continue;
		const matches = ruleMatches(request.content, rule, jsonTokens, detectorContext);
		if (matches === "unmapped") {
			return {
				...unavailableBase,
				status: "unavailable",
				unavailable: {
					reason: "malformed_format",
					detail: "JSON match could not be mapped to raw content",
				},
			};
		}
		if (matches === "incomplete") {
			// Detector findings would only be a lower bound: never report that as clean.
			return {
				...unavailableBase,
				status: "unavailable",
				unavailable: {
					reason: "incomplete_inspection",
					detail: "built-in detectors could not inspect all of the content",
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
					...(match.detector ? { detector: match.detector } : {}),
					start: match.start,
					end: match.end,
					matchFingerprint,
					maskedPreview: maskedPreview(match.value),
				},
				rule,
				replacement: replacementFor(rule, label, match, request.replacementStyle),
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
