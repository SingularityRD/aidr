/**
 * Append-only incident evidence receipts (T25 / OBS-02, RSP-05).
 *
 * The existing incident store already keeps a hash-chained revision log, and
 * the response auditor keeps a signed chain with a head checkpoint. What was
 * missing was a receipt that:
 *
 *   - binds the *release candidate*, policy revision, device, actor and
 *     incident into one verifiable record, so an event can be traced from the
 *     decision back to the exact build and policy that made it;
 *   - survives offline collection and clock skew, because agent hosts are not
 *     guaranteed to have a trustworthy clock or a live control plane;
 *   - reports a *gap* instead of a clean result when part of the history is
 *     missing, duplicated with conflicting content, or unreachable;
 *   - refuses to claim external custody while the archive is local. A local key
 *     and a local directory are not independent evidence storage.
 *
 * Nothing here performs I/O, so the same functions run inside the agent, the
 * control plane and the test suite. Ordering is by a Lamport-style logical
 * clock, not by the host wall clock: a device whose clock is wrong still
 * produces a deterministic, verifiable order.
 */

export const EVIDENCE_RECEIPT_VERSION = 1;

/** Wall-clock and logical components of a receipt timestamp. */
export interface EvidenceClock {
	/** Host wall clock, ISO-8601 UTC. Untrusted; used only as a tie-breaker. */
	wallClockUtc: string;
	/** Monotonic per-device counter. The authoritative ordering key. */
	logicalCounter: number;
	/** Last observed skew against the control plane, in ms, when known. */
	observedSkewMs: number | null;
}

export interface EvidenceBinding {
	/** Release candidate digest the agent is running. */
	candidateDigest: string;
	/** Policy revision in force when the decision was made. */
	policyRevision: string;
	/** Stable device identity (installation id), never a hostname. */
	deviceId: string;
	/** Actor reflected as a non-reversible reference, never a raw identity. */
	actorRef: string;
	/** Incident this receipt belongs to. */
	incidentId: string;
	/** Optional response action this receipt documents. */
	actionId: string | null;
}

export interface EvidenceReceiptV1 {
	version: typeof EVIDENCE_RECEIPT_VERSION;
	receiptId: string;
	binding: EvidenceBinding;
	clock: EvidenceClock;
	/** Hash of the previous receipt in this device's chain, or GENESIS. */
	previousHash: string;
	/** Digest over `receiptHashInput(this)` - never over the hash itself. */
	receiptHash: string;
	/** Classification of what the payload contains, for retention routing. */
	dataClass: "decision" | "response" | "telemetry" | "audit";
	/** Redacted, bounded payload. Contents are never raw prompts or secrets. */
	payloadSummary: string;
	/**
	 * Always false for a locally produced receipt. Set true only by an archive
	 * adapter that has returned proof of custody for this exact digest.
	 */
	externallyAnchored: false;
}

export const EVIDENCE_GENESIS_HASH = "0".repeat(64);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/;
const REF = /^[A-Za-z0-9._:@/-]{1,200}$/;

export type EvidenceParseResult<T> = { ok: true; value: T } | { ok: false; error: string };

function fail<T>(error: string): EvidenceParseResult<T> {
	return { ok: false, error };
}

function accept<T>(value: T): EvidenceParseResult<T> {
	return { ok: true, value };
}

function parseIso(value: unknown, requireCanonicalUtc = false): string | null {
	if (typeof value !== "string" || !/(?:Z|[+-]\d{2}:\d{2})$/.test(value)) return null;
	const parsed = Date.parse(value);
	if (!Number.isFinite(parsed) || parsed <= 0) return null;
	const normalized = new Date(parsed).toISOString();
	return requireCanonicalUtc && value !== normalized ? null : normalized;
}

function parseBinding(value: unknown): EvidenceParseResult<EvidenceBinding> {
	if (!value || typeof value !== "object" || Array.isArray(value)) return fail("invalid_binding");
	const raw = value as Record<string, unknown>;
	if (typeof raw.candidateDigest !== "string" || !HASH.test(raw.candidateDigest)) {
		return fail("invalid_candidate_digest");
	}
	for (const key of ["policyRevision", "deviceId", "actorRef", "incidentId"] as const) {
		if (typeof raw[key] !== "string" || !REF.test(raw[key] as string)) return fail(`invalid_${key}`);
	}
	if (raw.actionId !== null && (typeof raw.actionId !== "string" || !REF.test(raw.actionId))) {
		return fail("invalid_action_id");
	}
	return accept({
		candidateDigest: raw.candidateDigest,
		policyRevision: raw.policyRevision as string,
		deviceId: raw.deviceId as string,
		actorRef: raw.actorRef as string,
		incidentId: raw.incidentId as string,
		actionId: (raw.actionId as string | null) ?? null,
	});
}

function parseClock(value: unknown): EvidenceParseResult<EvidenceClock> {
	if (!value || typeof value !== "object" || Array.isArray(value)) return fail("invalid_clock");
	const raw = value as Record<string, unknown>;
	const wallClockUtc = parseIso(raw.wallClockUtc, true);
	if (!wallClockUtc) return fail("invalid_wall_clock");
	if (!Number.isSafeInteger(raw.logicalCounter) || (raw.logicalCounter as number) < 0) {
		return fail("invalid_logical_counter");
	}
	if (
		raw.observedSkewMs !== null &&
		(!Number.isSafeInteger(raw.observedSkewMs) || Math.abs(raw.observedSkewMs as number) > 86_400_000)
	) {
		return fail("invalid_observed_skew");
	}
	return accept({
		wallClockUtc,
		logicalCounter: raw.logicalCounter as number,
		observedSkewMs: (raw.observedSkewMs as number | null) ?? null,
	});
}

export function parseEvidenceReceipt(value: unknown): EvidenceParseResult<EvidenceReceiptV1> {
	if (!value || typeof value !== "object" || Array.isArray(value)) return fail("invalid_receipt");
	const raw = value as Record<string, unknown>;
	if (raw.version !== EVIDENCE_RECEIPT_VERSION) return fail("unsupported_version");
	if (typeof raw.receiptId !== "string" || !UUID.test(raw.receiptId)) return fail("invalid_receipt_id");
	const binding = parseBinding(raw.binding);
	if (!binding.ok) return fail(binding.error);
	const clock = parseClock(raw.clock);
	if (!clock.ok) return fail(clock.error);
	if (typeof raw.previousHash !== "string" || !HASH.test(raw.previousHash)) {
		return fail("invalid_previous_hash");
	}
	if (typeof raw.receiptHash !== "string" || !HASH.test(raw.receiptHash)) return fail("invalid_receipt_hash");
	if (!["decision", "response", "telemetry", "audit"].includes(String(raw.dataClass))) {
		return fail("invalid_data_class");
	}
	if (typeof raw.payloadSummary !== "string" || raw.payloadSummary.length > 4096) {
		return fail("invalid_payload_summary");
	}
	if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(raw.payloadSummary)) {
		return fail("invalid_payload_summary");
	}
	if (raw.externallyAnchored !== false) return fail("external_anchor_not_permitted_here");
	return accept({
		version: EVIDENCE_RECEIPT_VERSION,
		receiptId: raw.receiptId,
		binding: binding.value,
		clock: clock.value,
		previousHash: raw.previousHash,
		receiptHash: raw.receiptHash,
		dataClass: raw.dataClass as EvidenceReceiptV1["dataClass"],
		payloadSummary: raw.payloadSummary,
		externallyAnchored: false,
	});
}

/**
 * Canonical digest input. Field order is fixed and every bound field is
 * included, so a receipt cannot be re-pointed at another candidate, policy,
 * device, incident or action without changing its digest.
 */
export function evidenceReceiptHashInput(
	receipt: Omit<EvidenceReceiptV1, "receiptHash">,
): string {
	const b = receipt.binding;
	return [
		`aidr.evidence.receipt.v${EVIDENCE_RECEIPT_VERSION}`,
		receipt.receiptId,
		b.candidateDigest,
		b.policyRevision,
		b.deviceId,
		b.actorRef,
		b.incidentId,
		b.actionId ?? "-",
		receipt.clock.wallClockUtc,
		String(receipt.clock.logicalCounter),
		receipt.clock.observedSkewMs === null ? "-" : String(receipt.clock.observedSkewMs),
		receipt.previousHash,
		receipt.dataClass,
		receipt.payloadSummary,
		String(receipt.externallyAnchored),
	].join("\n");
}

export interface EvidenceHashContext {
	hash: (value: string) => string;
}

export function evidenceReceiptHash(
	receipt: Omit<EvidenceReceiptV1, "receiptHash">,
	context: EvidenceHashContext,
): string {
	return context.hash(evidenceReceiptHashInput(receipt));
}

export interface EvidenceVerifyResult {
	status: "intact" | "tampered" | "unavailable";
	reason: string;
}

/** Verify a single receipt's integrity binding. Anything but `intact` is fail-closed. */
export function verifyEvidenceReceipt(
	value: unknown,
	context: EvidenceHashContext,
): EvidenceVerifyResult {
	const parsed = parseEvidenceReceipt(value);
	if (!parsed.ok) return { status: "unavailable", reason: parsed.error };
	const { receiptHash, ...bound } = parsed.value;
	try {
		const expected = evidenceReceiptHash(bound, context);
		return expected === receiptHash
			? { status: "intact", reason: "receipt_hash_matches" }
			: { status: "tampered", reason: "receipt_hash_mismatch" };
	} catch {
		return { status: "unavailable", reason: "hash_unavailable" };
	}
}

/**
 * Compare two clocks for deterministic ordering.
 *
 * The logical counter is authoritative: a device that was offline and comes
 * back with a wrong wall clock still orders after everything it had already
 * produced. The wall clock is only a tie-breaker between counters, and the
 * receipt id breaks an exact tie so the order never depends on input order.
 */
export function compareEvidenceClock(a: EvidenceClock, b: EvidenceClock): number {
	if (a.logicalCounter !== b.logicalCounter) return a.logicalCounter - b.logicalCounter;
	const aTime = Date.parse(a.wallClockUtc);
	const bTime = Date.parse(b.wallClockUtc);
	if (aTime !== bTime) return aTime < bTime ? -1 : 1;
	return 0;
}

export interface EvidenceChainFinding {
	code: string;
	receiptId?: string;
	detail?: string;
}

export interface EvidenceChainVerification {
	valid: boolean;
	checked: number;
	/** The chain head, present only when the chain verified. */
	head: { receiptId: string; receiptHash: string; logicalCounter: number } | null;
	findings: EvidenceChainFinding[];
	/** Receipt identities and hashes in the verified chain, for truncation comparison. */
	verifiedReceipts: Array<{ receiptId: string; receiptHash: string; logicalCounter: number }>;
	/** Devices seen in the chain, with their highest logical counter. */
	devices: Array<{ deviceId: string; maxLogicalCounter: number; receipts: number }>;
	/** Largest observed clock skew among receipts that reported one. */
	maxObservedSkewMs: number | null;
}

/**
 * Verify a set of receipts for one incident.
 *
 * Findings are additive and never suppressed: a chain with a missing link, a
 * replayed id whose content changed, a candidate/policy mismatch inside one
 * incident, or an unverifiable digest all leave `valid: false` and name the
 * reason. Silence is never success.
 */
export function verifyEvidenceChain(
	receipts: readonly unknown[],
	context: EvidenceHashContext,
): EvidenceChainVerification {
	const result: EvidenceChainVerification = {
		valid: false,
		checked: 0,
		head: null,
		findings: [],
		verifiedReceipts: [],
		devices: [],
		maxObservedSkewMs: null,
	};
	const parsedReceipts: EvidenceReceiptV1[] = [];
	for (const entry of receipts) {
		const parsed = parseEvidenceReceipt(entry);
		if (!parsed.ok) {
			result.findings.push({ code: "receipt_unreadable", detail: parsed.error });
			continue;
		}
		parsedReceipts.push(parsed.value);
	}
	result.checked = parsedReceipts.length;
	if (parsedReceipts.length === 0) {
		result.findings.push({ code: "no_receipts" });
		return result;
	}

	// One incident must be one (candidate, policy) context. A receipt from a
	// different build or policy inside the same incident is a provenance break,
	// not a newer revision.
	const first = parsedReceipts[0] as EvidenceReceiptV1;
	for (const receipt of parsedReceipts) {
		if (receipt.binding.incidentId !== first.binding.incidentId) {
			result.findings.push({ code: "incident_mismatch", receiptId: receipt.receiptId });
		}
		if (receipt.binding.candidateDigest !== first.binding.candidateDigest) {
			result.findings.push({ code: "candidate_digest_mismatch", receiptId: receipt.receiptId });
		}
		if (receipt.binding.policyRevision !== first.binding.policyRevision) {
			result.findings.push({ code: "policy_revision_mismatch", receiptId: receipt.receiptId });
		}
		if (receipt.clock.observedSkewMs !== null) {
			const observed = Math.abs(receipt.clock.observedSkewMs);
			result.maxObservedSkewMs =
				result.maxObservedSkewMs === null ? observed : Math.max(result.maxObservedSkewMs, observed);
		}
	}

	// Deduplicate by receipt id. An identical replay is a no-op; a replay whose
	// content differs from the already-accepted receipt of the same id is a
	// conflict and invalidates the chain rather than quietly winning.
	const byId = new Map<string, EvidenceReceiptV1>();
	const unique: EvidenceReceiptV1[] = [];
	for (const receipt of parsedReceipts) {
		const existing = byId.get(receipt.receiptId);
		if (existing) {
			if (existing.receiptHash !== receipt.receiptHash) {
				result.findings.push({ code: "duplicate_receipt_conflict", receiptId: receipt.receiptId });
			}
			continue;
		}
		byId.set(receipt.receiptId, receipt);
		unique.push(receipt);
	}

	unique.sort((a, b) => {
		const byClock = compareEvidenceClock(a.clock, b.clock);
		if (byClock !== 0) return byClock;
		return a.receiptId < b.receiptId ? -1 : a.receiptId > b.receiptId ? 1 : 0;
	});
	result.verifiedReceipts = unique.map((receipt) => ({
		receiptId: receipt.receiptId,
		receiptHash: receipt.receiptHash,
		logicalCounter: receipt.clock.logicalCounter,
	}));

	let expectedPrevious = EVIDENCE_GENESIS_HASH;
	for (const receipt of unique) {
		const verification = verifyEvidenceReceipt(receipt, context);
		if (verification.status !== "intact") {
			result.findings.push({
				code: verification.status === "tampered" ? "receipt_hash_mismatch" : "receipt_hash_unavailable",
				receiptId: receipt.receiptId,
			});
		}
		if (receipt.previousHash !== expectedPrevious) {
			result.findings.push({
				code: "chain_link_mismatch",
				receiptId: receipt.receiptId,
				detail: `expected ${expectedPrevious.slice(0, 12)}…`,
			});
		}
		expectedPrevious = receipt.receiptHash;
	}

	const devices = new Map<string, { maxLogicalCounter: number; receipts: number }>();
	for (const receipt of unique) {
		const entry = devices.get(receipt.binding.deviceId) ?? { maxLogicalCounter: 0, receipts: 0 };
		entry.maxLogicalCounter = Math.max(entry.maxLogicalCounter, receipt.clock.logicalCounter);
		entry.receipts += 1;
		devices.set(receipt.binding.deviceId, entry);
	}
	result.devices = [...devices.entries()]
		.map(([deviceId, value]) => ({ deviceId, ...value }))
		.sort((a, b) => (a.deviceId < b.deviceId ? -1 : 1));

	result.valid = result.findings.length === 0;
	const head = unique[unique.length - 1] as EvidenceReceiptV1;
	if (result.valid) {
		result.head = {
			receiptId: head.receiptId,
			receiptHash: head.receiptHash,
			logicalCounter: head.clock.logicalCounter,
		};
	}
	return result;
}

/**
 * Detect that a previously observed head is no longer present in the chain.
 *
 * A hash chain cannot detect that its own tail was removed. Comparing the
 * persisted head against a verified chain is the cheapest honest signal; the
 * result is explicitly local-only until an archive adapter holds the digest.
 */
export function detectEvidenceTruncation(
	previousHead: { receiptId: string; receiptHash: string; logicalCounter: number } | null,
	verification: EvidenceChainVerification,
): { truncated: boolean; reason: string } {
	if (!previousHead) return { truncated: false, reason: "no_previous_head" };
	if (!verification.valid || !verification.head) {
		return { truncated: false, reason: "chain_not_verifiable" };
	}
	if (verification.head.receiptHash === previousHead.receiptHash) {
		return { truncated: false, reason: "head_unchanged" };
	}
	if (verification.head.logicalCounter < previousHead.logicalCounter) {
		return { truncated: true, reason: "logical_counter_regressed" };
	}
	const previousPresent = verification.verifiedReceipts.some(
		(receipt) => receipt.receiptId === previousHead.receiptId && receipt.receiptHash === previousHead.receiptHash,
	);
	if (!previousPresent) return { truncated: true, reason: "previous_head_missing_or_replaced" };
	return { truncated: false, reason: "head_advanced" };
}

/**
 * Append a receipt to a chain, filling in `previousHash` and `receiptHash`.
 *
 * The caller supplies the binding, clock, classification and payload summary;
 * this function refuses to append anything it cannot hash, so a chain never
 * contains an unverifiable link.
 */
export function appendEvidenceReceipt(
	input: {
		receiptId: string;
		binding: EvidenceBinding;
		clock: EvidenceClock;
		dataClass: EvidenceReceiptV1["dataClass"];
		payloadSummary: string;
	},
	chainHead: { receiptHash: string } | null,
	context: EvidenceHashContext,
): EvidenceParseResult<EvidenceReceiptV1> {
	const bound: Omit<EvidenceReceiptV1, "receiptHash"> = {
		version: EVIDENCE_RECEIPT_VERSION,
		receiptId: input.receiptId,
		binding: input.binding,
		clock: input.clock,
		previousHash: chainHead?.receiptHash ?? EVIDENCE_GENESIS_HASH,
		dataClass: input.dataClass,
		payloadSummary: input.payloadSummary,
		externallyAnchored: false,
	};
	let receiptHash: string;
	try {
		receiptHash = evidenceReceiptHash(bound, context);
	} catch {
		return fail("hash_unavailable");
	}
	const candidate: EvidenceReceiptV1 = { ...bound, receiptHash };
	return parseEvidenceReceipt(candidate);
}

/*
 * ── External archive custody ───────────────────────────────────────────────
 *
 * A local key and a local directory are not independent evidence storage: an
 * operator with host access can rewrite both. The adapter below is the only
 * place that may ever assert custody, and it asserts nothing without proof.
 */

export interface EvidenceArchiveRequest {
	incidentId: string;
	candidateDigest: string;
	headReceiptHash: string;
	headReceiptId: string;
	/** Full receipt chain, so the archive can verify independently. */
	receipts: readonly EvidenceReceiptV1[];
}

function validateArchiveRequest(request: EvidenceArchiveRequest, context: EvidenceHashContext): string | null {
	if (!HASH.test(request.headReceiptHash)) return "invalid_head_hash";
	if (!HASH.test(request.candidateDigest)) return "invalid_candidate_digest";
	if (!REF.test(request.incidentId)) return "invalid_incident_id";
	if (!UUID.test(request.headReceiptId) || !Array.isArray(request.receipts) || request.receipts.length === 0) {
		return "invalid_receipt_chain";
	}
	let previousHash = EVIDENCE_GENESIS_HASH;
	let head: EvidenceReceiptV1 | null = null;
	let policyRevision: string | null = null;
	const receiptIds = new Set<string>();
	for (const value of request.receipts) {
		const parsed = parseEvidenceReceipt(value);
		if (!parsed.ok) return "invalid_receipt_chain";
		const receipt = parsed.value;
		if (verifyEvidenceReceipt(receipt, context).status !== "intact") return "receipt_integrity_unverified";
		if (receiptIds.has(receipt.receiptId)) return "duplicate_receipt_id";
		receiptIds.add(receipt.receiptId);
		if (
			receipt.binding.incidentId !== request.incidentId ||
			receipt.binding.candidateDigest !== request.candidateDigest ||
			(policyRevision !== null && receipt.binding.policyRevision !== policyRevision) ||
			receipt.previousHash !== previousHash
		) return "receipt_chain_binding_mismatch";
		policyRevision = receipt.binding.policyRevision;
		previousHash = receipt.receiptHash;
		head = receipt;
	}
	if (!head || head.receiptId !== request.headReceiptId || head.receiptHash !== request.headReceiptHash) {
		return "archive_head_mismatch";
	}
	return null;
}

export type EvidenceArchiveResult =
	| {
			status: "anchored";
			/** Digest the archive reports it stored. Must equal the submitted head. */
			anchoredReceiptHash: string;
			/** Opaque archive reference (a receipt id, object key or ticket). */
			reference: string;
			/** ISO timestamp the archive itself reports. */
			anchoredAtUtc: string;
	  }
	| { status: "unavailable"; reason: string }
	| { status: "rejected"; reason: string };

export interface EvidenceArchiveSink {
	readonly id: string;
	anchor(request: EvidenceArchiveRequest): Promise<EvidenceArchiveResult>;
}

export interface EvidenceAnchorOutcome {
	/**
	 * `anchored` only when the archive returned proof for this exact digest.
	 * Every other path is `unanchored`, which callers must surface as an open
	 * evidence gap rather than treating the local copy as custody.
	 */
	status: "anchored" | "unanchored";
	reference: string | null;
	anchoredAtUtc: string | null;
	reason: string;
}

/**
 * Anchor an evidence head, fail-closed.
 *
 * The adapter must return the *same* digest that was submitted. A different
 * digest, a missing reference, a malformed timestamp, a thrown error or a
 * timeout all become `unanchored` with a machine-readable reason. There is
 * deliberately no fallback to a local write, because a local write is what the
 * caller already has.
 */
export async function anchorEvidenceHead(
	sink: EvidenceArchiveSink | null,
	request: EvidenceArchiveRequest,
	context: EvidenceHashContext,
	options: { timeoutMs?: number; now?: () => number } = {},
): Promise<EvidenceAnchorOutcome> {
	if (!sink) return { status: "unanchored", reference: null, anchoredAtUtc: null, reason: "no_archive_sink" };
	const requestFailure = validateArchiveRequest(request, context);
	if (requestFailure) {
		return { status: "unanchored", reference: null, anchoredAtUtc: null, reason: requestFailure };
	}
	const timeoutMs = options.timeoutMs ?? 15_000;
	const now = options.now ?? Date.now;
	let result: EvidenceArchiveResult;
	const started = now();
	try {
		result = await Promise.race([
			sink.anchor(request),
			new Promise<EvidenceArchiveResult>((resolve) =>
				setTimeout(() => resolve({ status: "unavailable", reason: "archive_timeout" }), timeoutMs),
			),
		]);
	} catch (error) {
		return {
			status: "unanchored",
			reference: null,
			anchoredAtUtc: null,
			reason: `archive_error:${error instanceof Error ? error.name : "unknown"}`,
		};
	}
	if (result.status === "unavailable") {
		return { status: "unanchored", reference: null, anchoredAtUtc: null, reason: result.reason };
	}
	if (result.status === "rejected") {
		return { status: "unanchored", reference: null, anchoredAtUtc: null, reason: `rejected:${result.reason}` };
	}
	if (result.anchoredReceiptHash !== request.headReceiptHash) {
		return {
			status: "unanchored",
			reference: null,
			anchoredAtUtc: null,
			reason: "archive_digest_mismatch",
		};
	}
	if (typeof result.reference !== "string" || result.reference.trim() === "" || result.reference.length > 512) {
		return { status: "unanchored", reference: null, anchoredAtUtc: null, reason: "archive_reference_invalid" };
	}
	const anchoredAt = parseIso(result.anchoredAtUtc);
	if (!anchoredAt) {
		return { status: "unanchored", reference: null, anchoredAtUtc: null, reason: "archive_timestamp_invalid" };
	}
	// An archive that answers only after the caller's budget elapsed is not proof
	// of a timely anchor: the caller cannot distinguish "stored" from "stored
	// just before it gave up", and a retry may already be racing it.
	if (now() - started > timeoutMs) {
		return { status: "unanchored", reference: null, anchoredAtUtc: null, reason: "archive_timeout_exceeded" };
	}
	return {
		status: "anchored",
		reference: result.reference.trim(),
		anchoredAtUtc: anchoredAt,
		reason: "archive_confirmed_digest",
	};
}
