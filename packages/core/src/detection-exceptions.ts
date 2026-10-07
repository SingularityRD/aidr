/**
 * Time-limited detection exceptions, created only by an operator.
 *
 * An exception lifts ONE detection rule (by rule id, optionally narrowed to one
 * exact artifact) for ONE subject — a user, an agent, or a repository — until it
 * expires. Expiry is mandatory and bounded ({@link DETECTION_EXCEPTION_MAX_TTL_MS});
 * an expired exception is simply ignored, so it lifts automatically with no sweep.
 * Every time an exception changes a decision the use is audited.
 *
 * Two sources, both operator-only:
 *
 * - **Local** (`aidr exception add`, interactive confirmation): stored in
 *   `~/.singularity-aidr/detection-exceptions.json`, each record HMAC-signed with
 *   the operator approval key (OS vault by default), and revocations kept in the
 *   same vault ledger as approval spends, so neither a hand-edited record nor a
 *   restored copy of the file is honoured.
 * - **Managed** (dashboard, owner/admin + MFA, audited): delivered inside the
 *   Ed25519-signed runtime policy (`detection_exceptions` bound through the
 *   envelope's `detection_exceptions_sha256`); see `remote-policy.ts`.
 *
 * Self-defense and canary rules can never be excepted, whatever a record says:
 * an exception there would let the agent reach the approval machinery itself.
 */

import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { lstat } from "node:fs/promises";
import { userInfo } from "node:os";
import { dirname, join, resolve } from "node:path";
import { z } from "zod";
import { AIDR_DIR, resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import {
	isOperatorRevoked,
	OperatorApprovalError,
	type OperatorApprovalStoreOptions,
	recordOperatorRevocation,
	signOperatorRecord,
	verifyOperatorRecord,
	withOperatorFileLock,
} from "./operator-approvals.js";
import type { AgentRuntime, HeuristicMatch, Logger } from "./types.js";
import { nullLogger } from "./types.js";

/** Longest lifetime of an exception. */
export const DETECTION_EXCEPTION_MAX_TTL_MS = 30 * 24 * 60 * 60 * 1000;
/** Shortest lifetime of an exception. */
export const DETECTION_EXCEPTION_MIN_TTL_MS = 5 * 60 * 1000;
/** Most exceptions kept (local store) or accepted (signed policy). */
export const DETECTION_EXCEPTION_MAX_ENTRIES = 500;
/** Ledger domain of revoked local exceptions. */
export const DETECTION_EXCEPTION_REVOCATION_DOMAIN = "detection-exception-revoked";

const MAX_STORE_BYTES = 1024 * 1024;
const CLOCK_SKEW_MS = 5 * 60 * 1000;
const RULE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$/;
const EXCEPTION_ID = /^[A-Za-z0-9][A-Za-z0-9-]{7,63}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

/** Rule categories and id prefixes no exception can ever lift. */
const PROTECTED_CATEGORIES = new Set(["self_defense"]);
const PROTECTED_PREFIXES = ["CLT-SELF-", "CLT-CANARY-"];

export type DetectionExceptionSubjectKind = "user" | "agent" | "repo";

export interface DetectionExceptionSubject {
	kind: DetectionExceptionSubjectKind;
	/** OS account name / agent runtime or id / repository root path or remote. */
	value: string;
}

export interface DetectionException {
	id: string;
	ruleId: string;
	/** Narrows the exception to one exact artifact; null covers every artifact of the rule. */
	artifactSha256: string | null;
	subject: DetectionExceptionSubject;
	createdAt: string;
	expiresAt: string;
	createdBy: string;
	reason: string;
	source: "local" | "managed";
}

export class DetectionExceptionError extends Error {
	constructor(
		readonly code:
			| "protected_rule"
			| "invalid_rule_id"
			| "invalid_subject"
			| "invalid_ttl"
			| "invalid_reason"
			| "not_found"
			| "store_full"
			| "unavailable",
		message: string,
	) {
		super(message);
		this.name = "DetectionExceptionError";
	}
}

// ── Wire / disk shape (snake_case) ─────────────────────────────────────

const SubjectKindSchema = z.enum(["user", "agent", "repo"]);

/** One exception as the control plane signs it and as the local store keeps it (minus `mac`). */
export const DetectionExceptionWireSchema = z
	.object({
		id: z.string().regex(EXCEPTION_ID),
		rule_id: z.string().regex(RULE_ID),
		artifact_sha256: z.string().regex(DIGEST).nullable(),
		subject_kind: SubjectKindSchema,
		subject_value: z.string().min(1).max(512),
		created_at: z.string().regex(ISO),
		expires_at: z.string().regex(ISO),
		created_by: z.string().min(1).max(200),
		reason: z.string().min(1).max(500),
	})
	.strict();

const LocalRecordSchema = DetectionExceptionWireSchema.extend({
	mac: z.string().regex(DIGEST),
}).strict();

export type DetectionExceptionWire = z.infer<typeof DetectionExceptionWireSchema>;
type LocalRecord = z.infer<typeof LocalRecordSchema>;

function fromWire(record: DetectionExceptionWire, source: "local" | "managed"): DetectionException {
	return {
		id: record.id,
		ruleId: record.rule_id,
		artifactSha256: record.artifact_sha256,
		subject: { kind: record.subject_kind, value: record.subject_value },
		createdAt: record.created_at,
		expiresAt: record.expires_at,
		createdBy: record.created_by,
		reason: record.reason,
		source,
	};
}

/** Whether a wire record has a sane, bounded validity window (independent of now). */
function windowValid(record: DetectionExceptionWire): boolean {
	const created = Date.parse(record.created_at);
	const expires = Date.parse(record.expires_at);
	return (
		Number.isFinite(created) &&
		Number.isFinite(expires) &&
		expires > created &&
		expires - created <= DETECTION_EXCEPTION_MAX_TTL_MS
	);
}

/**
 * Parse exceptions from a signed policy body field. Anything malformed, over
 * the size bound, or naming a protected rule makes the WHOLE list unusable:
 * returning nothing only removes exceptions, which is the safe direction.
 */
export function parseSignedDetectionExceptions(value: unknown): DetectionException[] | null {
	if (!Array.isArray(value) || value.length > DETECTION_EXCEPTION_MAX_ENTRIES) return null;
	const out: DetectionException[] = [];
	for (const item of value) {
		const parsed = DetectionExceptionWireSchema.safeParse(item);
		if (!parsed.success || !windowValid(parsed.data) || isProtectedRule(parsed.data.rule_id)) {
			return null;
		}
		out.push(fromWire(parsed.data, "managed"));
	}
	return out;
}

// ── Protection and matching ──────────────────────────────────────────────

/** Self-defense and canary rules: never excepted. */
export function isProtectedRule(ruleId: string, category?: string): boolean {
	if (category && PROTECTED_CATEGORIES.has(category)) return true;
	const upper = ruleId.toUpperCase();
	return PROTECTED_PREFIXES.some((prefix) => upper.startsWith(prefix));
}

/** Digest of one exact artifact value (command, URL, path...). Only the digest is stored. */
export function detectionExceptionArtifactDigest(value: string): string {
	return createHash("sha256").update(`aidr-detection-exception-artifact\n${value}`).digest("hex");
}

/** Who and where this tool call runs, for subject matching. */
export interface DetectionExceptionSubjectContext {
	/** Local OS account name. */
	user?: string;
	/** Agent runtime of the connector (`claude-code`, `cursor`, ...). */
	agent?: string;
	/** Git repository of the working directory. */
	repo?: { root?: string; remote?: string };
}

function samePath(a: string, b: string): boolean {
	const na = resolve(a).replace(/[\\/]+$/, "");
	const nb = resolve(b).replace(/[\\/]+$/, "");
	return process.platform === "win32" ? na.toLowerCase() === nb.toLowerCase() : na === nb;
}

/** `git@github.com:org/repo.git`, `https://github.com/org/repo` → `github.com/org/repo`. */
export function normalizeRepoRemote(value: string): string {
	let v = value.trim().toLowerCase();
	v = v.replace(/^[a-z+]+:\/\//, "");
	v = v.replace(/^[^@/]+@/, "");
	v = v.replace(/^([^/:]+):(?!\d+\/)/, "$1/");
	v = v.replace(/^([^/:]+):\d+\//, "$1/");
	return v.replace(/\.git$/, "").replace(/\/+$/, "");
}

function looksLikePath(value: string): boolean {
	return /^([a-zA-Z]:[\\/]|[\\/]|~)/.test(value);
}

/** Whether `subject` names this call. Managed user/agent subjects were bound to this principal by the signed control plane. */
export function subjectMatches(
	exception: Pick<DetectionException, "subject" | "source">,
	ctx: DetectionExceptionSubjectContext,
): boolean {
	const { kind, value } = exception.subject;
	if (kind === "repo") {
		if (!ctx.repo) return false;
		if (looksLikePath(value)) return !!ctx.repo.root && samePath(resolvePath(value), ctx.repo.root);
		return !!ctx.repo.remote && normalizeRepoRemote(value) === normalizeRepoRemote(ctx.repo.remote);
	}
	if (exception.source === "managed") return true;
	if (kind === "user") {
		return !!ctx.user && ctx.user.toLowerCase() === value.trim().toLowerCase();
	}
	return !!ctx.agent && ctx.agent === value.trim();
}

/** The nearest `.git` above `start`, and its `origin` remote when readable. Best effort. */
export function findGitRepository(start: string): { root?: string; remote?: string } | undefined {
	let dir = resolve(start);
	for (let depth = 0; depth < 64; depth++) {
		const dotGit = join(dir, ".git");
		if (existsSync(dotGit)) {
			return { root: dir, remote: readOriginRemote(dotGit) };
		}
		const parent = dirname(dir);
		if (parent === dir) return undefined;
		dir = parent;
	}
	return undefined;
}

function readOriginRemote(dotGit: string): string | undefined {
	try {
		let gitDir = dotGit;
		if (statSync(dotGit).isFile()) {
			const pointer = /^gitdir:\s*(.+)$/m.exec(readFileSync(dotGit, "utf8"));
			if (!pointer?.[1]) return undefined;
			gitDir = resolve(dirname(dotGit), pointer[1].trim());
		}
		const config = readFileSync(join(gitDir, "config"), "utf8").slice(0, 64 * 1024);
		const section = /\[remote "origin"\]([^[]*)/.exec(config);
		return section?.[1] ? /^\s*url\s*=\s*(.+)$/m.exec(section[1])?.[1]?.trim() : undefined;
	} catch {
		return undefined;
	}
}

/** Subject context of a tool call. Never throws. */
export function resolveDetectionExceptionSubjectContext(
	agentRuntime: AgentRuntime | undefined,
	workingDirectory: string | undefined,
): DetectionExceptionSubjectContext {
	let user: string | undefined;
	try {
		user = userInfo().username || undefined;
	} catch {
		user = undefined;
	}
	let repo: DetectionExceptionSubjectContext["repo"];
	try {
		repo = findGitRepository(workingDirectory ?? process.cwd());
	} catch {
		repo = undefined;
	}
	return { user, agent: agentRuntime, repo };
}

/** Whether `exception` is in force at `now` (unexpired, not issued in the future). */
export function exceptionActive(exception: DetectionException, now: number): boolean {
	const created = Date.parse(exception.createdAt);
	const expires = Date.parse(exception.expiresAt);
	return (
		Number.isFinite(created) &&
		Number.isFinite(expires) &&
		created <= now + CLOCK_SKEW_MS &&
		now < expires &&
		expires - created <= DETECTION_EXCEPTION_MAX_TTL_MS
	);
}

/** One exception that removed one rule match from a decision. */
export interface AppliedDetectionException {
	exception: DetectionException;
	ruleId: string;
	artifact: string;
}

/**
 * Drop the rule matches an active exception covers for exactly this subject.
 * A protected rule's match is always kept.
 */
export function applyDetectionExceptions(
	matches: readonly HeuristicMatch[],
	exceptions: readonly DetectionException[],
	ctx: DetectionExceptionSubjectContext,
	now: number,
): { kept: HeuristicMatch[]; applied: AppliedDetectionException[] } {
	const kept: HeuristicMatch[] = [];
	const applied: AppliedDetectionException[] = [];
	for (const match of matches) {
		const exception = isProtectedRule(match.threat.id, match.threat.category)
			? undefined
			: exceptions.find(
					(e) =>
						e.ruleId === match.threat.id &&
						exceptionActive(e, now) &&
						(e.artifactSha256 === null ||
							e.artifactSha256 === detectionExceptionArtifactDigest(match.artifact)) &&
						subjectMatches(e, ctx),
				);
		if (exception) applied.push({ exception, ruleId: match.threat.id, artifact: match.artifact });
		else kept.push(match);
	}
	return { kept, applied };
}

// ── Local store (operator CLI) ─────────────────────────────────────────

export interface DetectionExceptionStoreOptions {
	/** Store file; defaults to `~/.singularity-aidr/detection-exceptions.json`. */
	path?: string;
	/** The operator approval key and ledger the records are signed and revoked with. */
	approvals?: OperatorApprovalStoreOptions;
	now?: () => number;
	logger?: Logger;
}

export function detectionExceptionStorePath(options: DetectionExceptionStoreOptions = {}): string {
	return options.path ?? join(resolvePath(AIDR_DIR), "detection-exceptions.json");
}

function nowMs(options: DetectionExceptionStoreOptions): number {
	return options.now ? options.now() : Date.now();
}

async function readRecords(path: string): Promise<LocalRecord[]> {
	let info: Awaited<ReturnType<typeof lstat>>;
	try {
		info = await lstat(path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
		throw error;
	}
	// A symlink, a non-file or an oversized file holds nothing that can verify.
	if (info.isSymbolicLink() || !info.isFile() || info.size > MAX_STORE_BYTES) return [];
	let raw: unknown;
	try {
		raw = JSON.parse(await getFileContent(path));
	} catch {
		return [];
	}
	const list = (raw as { exceptions?: unknown } | null)?.exceptions;
	if (!Array.isArray(list)) return [];
	const out: LocalRecord[] = [];
	for (const entry of list) {
		const parsed = LocalRecordSchema.safeParse(entry);
		if (parsed.success) out.push(parsed.data);
	}
	return out;
}

async function writeRecords(path: string, records: LocalRecord[], now: number): Promise<void> {
	const alive = records.filter((r) => Date.parse(r.expires_at) > now);
	await atomicWriteJson(path, { version: 1, exceptions: alive }, { mode: 0o600 });
}

export interface AddDetectionExceptionInput {
	ruleId: string;
	/** Exact artifact value (command, URL, file path) to narrow the exception to; only its digest is kept. */
	artifact?: string;
	subject: DetectionExceptionSubject;
	ttlMs: number;
	reason: string;
	/** Who confirmed it (OS account and confirmation mode). */
	createdBy: string;
}

function validateInput(input: AddDetectionExceptionInput): void {
	if (!RULE_ID.test(input.ruleId)) {
		throw new DetectionExceptionError("invalid_rule_id", "A rule id looks like CLT-CMD-001.");
	}
	if (isProtectedRule(input.ruleId)) {
		throw new DetectionExceptionError(
			"protected_rule",
			`${input.ruleId} is a self-defense rule; it cannot be excepted.`,
		);
	}
	const value = input.subject.value.trim();
	if (!SubjectKindSchema.safeParse(input.subject.kind).success || !value || value.length > 512) {
		throw new DetectionExceptionError(
			"invalid_subject",
			"The subject must be --user <name>, --agent <runtime> or --repo <path|remote>.",
		);
	}
	if (
		!Number.isFinite(input.ttlMs) ||
		input.ttlMs < DETECTION_EXCEPTION_MIN_TTL_MS ||
		input.ttlMs > DETECTION_EXCEPTION_MAX_TTL_MS
	) {
		throw new DetectionExceptionError(
			"invalid_ttl",
			"An exception must expire between 5 minutes and 30 days from now.",
		);
	}
	const reason = input.reason.trim();
	if (!reason || reason.length > 500) {
		throw new DetectionExceptionError("invalid_reason", "A reason (1-500 characters) is required.");
	}
}

/**
 * Create a local exception. OPERATOR ONLY — reach it from the TTY-confirmed
 * `aidr exception add`, never from a connector or an agent-callable tool.
 * Throws {@link DetectionExceptionError} or {@link OperatorApprovalError} (no key
 * / ledger: exceptions are disabled, fail closed).
 */
export async function addDetectionException(
	input: AddDetectionExceptionInput,
	options: DetectionExceptionStoreOptions = {},
): Promise<DetectionException> {
	validateInput(input);
	const path = detectionExceptionStorePath(options);
	return withOperatorFileLock(path, async () => {
		const now = nowMs(options);
		const records = (await readRecords(path)).filter((r) => Date.parse(r.expires_at) > now);
		if (records.length >= DETECTION_EXCEPTION_MAX_ENTRIES) {
			throw new DetectionExceptionError(
				"store_full",
				"Too many active exceptions; remove some first.",
			);
		}
		const unsigned: DetectionExceptionWire = {
			id: randomBytes(16).toString("hex"),
			rule_id: input.ruleId,
			artifact_sha256: input.artifact ? detectionExceptionArtifactDigest(input.artifact) : null,
			subject_kind: input.subject.kind,
			subject_value: input.subject.value.trim(),
			created_at: new Date(now).toISOString(),
			expires_at: new Date(now + input.ttlMs).toISOString(),
			created_by: input.createdBy.slice(0, 200) || "unknown",
			reason: input.reason.trim(),
		};
		const record: LocalRecord = {
			...unsigned,
			mac: signOperatorRecord("detection-exception", unsigned, options.approvals),
		};
		await writeRecords(path, [...records, record], now);
		return fromWire(unsigned, "local");
	});
}

export interface ListedDetectionException extends DetectionException {
	/** HMAC verified under the operator key (false: edited, or key changed — never honoured). */
	verified: boolean;
	expired: boolean;
}

/** Local exceptions, newest first; expired ones only with `includeExpired`. */
export async function listDetectionExceptions(
	options: DetectionExceptionStoreOptions = {},
	listOptions: { includeExpired?: boolean } = {},
): Promise<ListedDetectionException[]> {
	const now = nowMs(options);
	const records = await readRecords(detectionExceptionStorePath(options));
	return records
		.map((r) => {
			const { mac: _mac, ...wire } = r;
			return {
				...fromWire(wire, "local"),
				verified: verifyOperatorRecord("detection-exception", r, options.approvals),
				expired: Date.parse(r.expires_at) <= now,
			};
		})
		.filter((r) => listOptions.includeExpired || !r.expired)
		.sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
}

/**
 * Revoke a local exception: the revocation goes into the OS-vault ledger first
 * (so a restored copy of the file cannot bring it back), then the record is
 * removed. OPERATOR ONLY.
 */
export async function removeDetectionException(
	id: string,
	options: DetectionExceptionStoreOptions = {},
): Promise<DetectionException> {
	const path = detectionExceptionStorePath(options);
	return withOperatorFileLock(path, async () => {
		const now = nowMs(options);
		const records = await readRecords(path);
		const record = records.find((r) => r.id === id);
		if (!record) {
			throw new DetectionExceptionError("not_found", "No local exception has this id.");
		}
		const revoked = await recordOperatorRevocation(
			DETECTION_EXCEPTION_REVOCATION_DOMAIN,
			record.id,
			Date.parse(record.expires_at),
			options.approvals,
		);
		if (revoked === "unavailable") {
			throw new DetectionExceptionError(
				"unavailable",
				"The revocation could not be recorded in the operator ledger; nothing was removed.",
			);
		}
		await writeRecords(
			path,
			records.filter((r) => r.id !== id),
			now,
		);
		const { mac: _mac, ...wire } = record;
		return fromWire(wire, "local");
	});
}

/**
 * Local exceptions that could lift one of `ruleIds` right now: verified under
 * the operator key and not revoked in the ledger. The key and the ledger are only
 * touched when a candidate exists, so an install without exceptions pays one
 * missing-file check. Never throws: an unverifiable store yields nothing.
 */
export async function loadUsableLocalExceptions(
	ruleIds: ReadonlySet<string>,
	options: DetectionExceptionStoreOptions = {},
): Promise<DetectionException[]> {
	const logger = options.logger ?? nullLogger;
	try {
		const now = nowMs(options);
		const candidates = (await readRecords(detectionExceptionStorePath(options))).filter(
			(r) => ruleIds.has(r.rule_id) && Date.parse(r.expires_at) > now,
		);
		const usable: DetectionException[] = [];
		for (const record of candidates) {
			if (!verifyOperatorRecord("detection-exception", record, options.approvals)) {
				logger.warn("Detection exception failed verification and was ignored", {
					id: record.id,
				});
				continue;
			}
			if (isOperatorRevoked(DETECTION_EXCEPTION_REVOCATION_DOMAIN, record.id, options.approvals)) {
				continue;
			}
			const { mac: _mac, ...wire } = record;
			usable.push(fromWire(wire, "local"));
		}
		return usable;
	} catch (error) {
		logger.warn("Local detection exceptions unavailable; none applied", {
			error: error instanceof OperatorApprovalError ? error.code : String(error),
		});
		return [];
	}
}
