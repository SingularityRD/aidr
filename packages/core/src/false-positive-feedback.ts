/**
 * Versioned operator false-positive feedback (MKT-05).
 *
 * An analyst must be able to move from an incident to its reason, the covered
 * host, the observed side effect and a *reversible* policy revision — and an
 * operator verdict of "this was a false positive" has to be auditable, because
 * it is the input that suppresses a detection. Today an override is a boolean on
 * a log line: nothing binds it to the incident and the policy revision it
 * judges, and nothing stops it from being rewritten afterwards.
 *
 * This module records that verdict as an append-only, versioned record:
 *
 *   - **Bound.** Every record names the incident, the policy revision in force,
 *     the actor, the device and the release candidate. A verdict cannot be
 *     re-pointed at another revision.
 *   - **Versioned and append-only.** Versions increase monotonically per
 *     (incident, policy revision) and the version is derived deterministically
 *     from the binding, so a replay after a policy rollback lands on the same
 *     version instead of forking history.
 *   - **Idempotent, but not silently overwritten.** The identical resubmission
 *     is a duplicate `no-op`. A *different* verdict for the same incident and
 *     revision is refused with `conflicting_feedback_submission` rather than
 *     overwriting what the operator already said.
 *   - **Tamper-evident.** Records are hash-chained; verifying the store names
 *     the record that broke, and a deleted tail is detected against the
 *     recorded sequence high-water mark.
 *
 * Nothing here performs I/O, and nothing here suppresses a detection by itself:
 * it produces the auditable record a policy revision can be derived from.
 */

import { createHash } from "node:crypto";

export const FALSE_POSITIVE_FEEDBACK_SCHEMA_VERSION = 1;

export type FalsePositiveFeedbackKind = "false_positive" | "confirmed";

/** Bounded, machine-readable reasons. Free text lives in `rationale`. */
export type FalsePositiveReasonCode =
	| "benign_automation"
	| "benign_maintenance"
	| "expected_egress"
	| "expected_file_write"
	| "legitimate_mcp_tool"
	| "developer_test"
	| "environment_specific"
	| "insufficient_context"
	| "policy_too_strict"
	| "other";

export type FalsePositiveFeedbackOrigin =
	| "runtime_verdict"
	| "plugin_scan_finding"
	| "explicit_incident"
	| "operator_review";

/**
 * The record identity a submission is bound to. Deliberately mirrors
 * `EvidenceBinding` for incident/policy/device/actor, so feedback, evidence
 * receipts and policy revisions can be joined without a translation table.
 */
export interface FalsePositiveFeedbackBinding {
	/** Policy revision the feedback judges; the reversible unit. */
	policyRevision: string;
	/** Incident the feedback refers to. */
	incidentId: string;
	/** Release candidate digest in force when the verdict was made. */
	candidateDigest: string;
	/** Stable device identity (installation id), never a hostname. */
	deviceId: string;
	/** Actor reflected as a non-reversible reference, never a raw identity. */
	actorRef: string;
}

export interface FalsePositiveFeedbackInput {
	tenantId: string;
	binding: FalsePositiveFeedbackBinding;
	feedback: FalsePositiveFeedbackKind;
	reasonCode: FalsePositiveReasonCode;
	/** Bounded operator rationale. Redacted; never a raw prompt or secret. */
	rationale: string;
	origin: FalsePositiveFeedbackOrigin;
	/** Side effect the analyst observed, as a bounded reference. */
	observedSideEffect?: string;
}

export interface FalsePositiveFeedbackRecordInput extends FalsePositiveFeedbackInput {
	/** 1-based sequence within this (incident, policy revision) binding. */
	sequence: number;
}

export interface FalsePositiveFeedbackRecordV1 extends FalsePositiveFeedbackRecordInput {
	version: typeof FALSE_POSITIVE_FEEDBACK_SCHEMA_VERSION;
	/** Deterministic, opaque id derived from the binding and sequence. */
	feedbackId: string;
	/** Hash of the previous record on this binding, or FALSE_POSITIVE_GENESIS_HASH. */
	previousHash: string;
	/** Digest over `falsePositiveFeedbackHashInput(this)` — never over itself. */
	recordHash: string;
}

export const FALSE_POSITIVE_GENESIS_HASH = "0".repeat(64);

export interface FalsePositiveFeedbackStore {
	schemaVersion: typeof FALSE_POSITIVE_FEEDBACK_SCHEMA_VERSION;
	tenantId: string;
	/** Every accepted record, ordered. Append-only: nothing is ever replaced. */
	records: FalsePositiveFeedbackRecordV1[];
	/** Highest sequence accepted per binding key, for tail-truncation detection. */
	maxSequenceByBinding: Record<string, number>;
}

export type FalsePositiveFeedbackOutcomeStatus = "appended" | "duplicate" | "refused";

export interface FalsePositiveFeedbackOutcome {
	status: FalsePositiveFeedbackOutcomeStatus;
	/** `true` only when the store changed. */
	changed: boolean;
	/** Version of the record this submission resolves to, when accepted. */
	version: number | null;
	/** Machine-readable reason; `no-op_replay` for a duplicate. */
	reason: string;
	record: FalsePositiveFeedbackRecordV1 | null;
}

export interface FalsePositiveFeedbackFoldResult {
	store: FalsePositiveFeedbackStore;
	outcomes: FalsePositiveFeedbackOutcome[];
	accepted: number;
	duplicates: number;
	refused: number;
}

export interface HasherContext {
	hash: (value: string) => string;
}

/** SHA-256 context for callers that do not already have one. */
export function createSha256HasherContext(): HasherContext {
	return { hash: (value: string) => createHash("sha256").update(value).digest("hex") };
}

export type FalsePositiveParseResult<T> = { ok: true; value: T } | { ok: false; error: string };

function accept<T>(value: T): FalsePositiveParseResult<T> {
	return { ok: true, value };
}

function fail<T>(error: string): FalsePositiveParseResult<T> {
	return { ok: false, error };
}

const REF = /^[A-Za-z0-9._:@/-]{1,200}$/;
const HASH = /^[0-9a-f]{64}$/;
const TENANT = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const FEEDBACK = new Set<string>(["false_positive", "confirmed"]);
const REASONS = new Set<string>([
	"benign_automation",
	"benign_maintenance",
	"expected_egress",
	"expected_file_write",
	"legitimate_mcp_tool",
	"developer_test",
	"environment_specific",
	"insufficient_context",
	"policy_too_strict",
	"other",
]);
const ORIGINS = new Set<string>([
	"runtime_verdict",
	"plugin_scan_finding",
	"explicit_incident",
	"operator_review",
]);

/** Store key for one feedback target. Both halves are required, never inherited. */
export function falsePositiveBindingKey(binding: FalsePositiveFeedbackBinding): string {
	return JSON.stringify([binding.incidentId, binding.policyRevision]);
}

function bindingKeyOf(record: FalsePositiveFeedbackRecordInput): string {
	return JSON.stringify([record.binding.incidentId, record.binding.policyRevision]);
}

/**
 * Canonical digest input for a record. Fixed field order, and every bound field
 * plus the sequence is included, so a record cannot be re-pointed at another
 * incident, revision, actor, device or verdict without changing its digest.
 */
export function falsePositiveFeedbackHashInput(
	record: Omit<FalsePositiveFeedbackRecordV1, "recordHash">,
): string {
	const b = record.binding;
	return [
		`aidr.false-positive-feedback.v${FALSE_POSITIVE_FEEDBACK_SCHEMA_VERSION}`,
		record.tenantId,
		String(record.sequence),
		b.policyRevision,
		b.incidentId,
		b.candidateDigest,
		b.deviceId,
		b.actorRef,
		record.feedback,
		record.reasonCode,
		record.rationale,
		record.origin,
		record.observedSideEffect ?? "-",
		record.previousHash,
	].join("\n");
}

export function falsePositiveFeedbackHash(
	record: Omit<FalsePositiveFeedbackRecordV1, "recordHash">,
	context: HasherContext,
): string {
	return context.hash(falsePositiveFeedbackHashInput(record));
}

/**
 * Content digest of a submission, excluding the sequence: two submissions with
 * the same digest are the same operator statement, which is what makes an exact
 * replay a no-op and a changed one a conflict.
 */
export function falsePositiveFeedbackSubmissionDigest(
	input: FalsePositiveFeedbackInput,
	context: HasherContext,
): string {
	const b = input.binding;
	return context.hash(
		[
			"aidr.false-positive-feedback.submission.v1",
			input.tenantId,
			b.policyRevision,
			b.incidentId,
			b.candidateDigest,
			b.deviceId,
			b.actorRef,
			input.feedback,
			input.reasonCode,
			input.rationale,
			input.origin,
			input.observedSideEffect ?? "-",
		].join("\n"),
	);
}

/** Deterministic, opaque feedback id: the same statement always has the same id. */
export function falsePositiveFeedbackId(
	input: FalsePositiveFeedbackInput,
	sequence: number,
	context: HasherContext,
): string {
	if (!Number.isSafeInteger(sequence) || sequence < 1) throw new Error("feedback_sequence_invalid");
	const digest = context.hash(
		["aidr.false-positive-feedback.id.v1", falsePositiveFeedbackSubmissionDigest(input, context), String(sequence)].join(
			"\n",
		),
	);
	return `fpfb_${digest}`;
}

function parseBinding(value: unknown): FalsePositiveParseResult<FalsePositiveFeedbackBinding> {
	if (!value || typeof value !== "object" || Array.isArray(value)) return fail("invalid_binding");
	const raw = value as Record<string, unknown>;
	if (typeof raw.policyRevision !== "string" || !REF.test(raw.policyRevision)) {
		return fail("invalid_policy_revision");
	}
	if (typeof raw.incidentId !== "string" || !REF.test(raw.incidentId)) return fail("invalid_incident_id");
	if (typeof raw.candidateDigest !== "string" || !HASH.test(raw.candidateDigest)) {
		return fail("invalid_candidate_digest");
	}
	if (typeof raw.deviceId !== "string" || !REF.test(raw.deviceId)) return fail("invalid_device_id");
	if (typeof raw.actorRef !== "string" || !REF.test(raw.actorRef)) return fail("invalid_actor_ref");
	return accept({
		policyRevision: raw.policyRevision,
		incidentId: raw.incidentId,
		candidateDigest: raw.candidateDigest,
		deviceId: raw.deviceId,
		actorRef: raw.actorRef,
	});
}

function parseInput(value: unknown): FalsePositiveParseResult<FalsePositiveFeedbackInput> {
	if (!value || typeof value !== "object" || Array.isArray(value)) return fail("not_an_object");
	const raw = value as Record<string, unknown>;
	if (typeof raw.tenantId !== "string" || !TENANT.test(raw.tenantId)) return fail("invalid_tenant_id");
	const binding = parseBinding(raw.binding);
	if (!binding.ok) return fail(binding.error);
	if (typeof raw.feedback !== "string" || !FEEDBACK.has(raw.feedback)) return fail("invalid_feedback");
	if (typeof raw.reasonCode !== "string" || !REASONS.has(raw.reasonCode)) return fail("invalid_reason_code");
	if (typeof raw.rationale !== "string" || raw.rationale.length > 2000) return fail("invalid_rationale");
	if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(raw.rationale)) return fail("invalid_rationale");
	if (typeof raw.origin !== "string" || !ORIGINS.has(raw.origin)) return fail("invalid_origin");
	if (
		raw.observedSideEffect !== undefined &&
		(typeof raw.observedSideEffect !== "string" || !REF.test(raw.observedSideEffect))
	) {
		return fail("invalid_observed_side_effect");
	}
	return accept({
		tenantId: raw.tenantId,
		binding: binding.value,
		feedback: raw.feedback as FalsePositiveFeedbackKind,
		reasonCode: raw.reasonCode as FalsePositiveReasonCode,
		rationale: raw.rationale,
		origin: raw.origin as FalsePositiveFeedbackOrigin,
		...(raw.observedSideEffect === undefined
			? {}
			: { observedSideEffect: raw.observedSideEffect as string }),
	});
}

/** Validate a persisted record, including that no field was dropped or retyped. */
export function parseFalsePositiveFeedbackRecord(
	value: unknown,
): FalsePositiveParseResult<FalsePositiveFeedbackRecordV1> {
	if (!value || typeof value !== "object" || Array.isArray(value)) return fail("not_a_record");
	const raw = value as Record<string, unknown>;
	if (raw.version !== FALSE_POSITIVE_FEEDBACK_SCHEMA_VERSION) return fail("unsupported_version");
	if (!Number.isSafeInteger(raw.sequence) || (raw.sequence as number) < 1) return fail("invalid_sequence");
	if (typeof raw.feedbackId !== "string" || !/^fpfb_[0-9a-f]{64}$/.test(raw.feedbackId)) {
		return fail("invalid_feedback_id");
	}
	if (typeof raw.previousHash !== "string" || !HASH.test(raw.previousHash)) {
		return fail("invalid_previous_hash");
	}
	if (typeof raw.recordHash !== "string" || !HASH.test(raw.recordHash)) {
		return fail("invalid_record_hash");
	}
	const input = parseInput({
		tenantId: raw.tenantId,
		binding: raw.binding,
		feedback: raw.feedback,
		reasonCode: raw.reasonCode,
		rationale: raw.rationale,
		origin: raw.origin,
		...(raw.observedSideEffect === undefined ? {} : { observedSideEffect: raw.observedSideEffect }),
	});
	if (!input.ok) return fail(input.error);
	return accept({
		version: FALSE_POSITIVE_FEEDBACK_SCHEMA_VERSION,
		feedbackId: raw.feedbackId,
		sequence: raw.sequence as number,
		previousHash: raw.previousHash,
		recordHash: raw.recordHash,
		...input.value,
	});
}

/** Empty store for one tenant. A store is always tenant-scoped. */
export function createFalsePositiveFeedbackStore(tenantId: string): FalsePositiveFeedbackStore {
	if (!TENANT.test(tenantId)) throw new Error("feedback_tenant_id_invalid");
	return {
		schemaVersion: FALSE_POSITIVE_FEEDBACK_SCHEMA_VERSION,
		tenantId,
		records: [],
		maxSequenceByBinding: {},
	};
}

function validateStore(store: FalsePositiveFeedbackStore): FalsePositiveFeedbackStore {
	if (!store || typeof store !== "object") throw new Error("feedback_store_invalid");
	if (store.schemaVersion !== FALSE_POSITIVE_FEEDBACK_SCHEMA_VERSION) {
		throw new Error("feedback_store_schema_mismatch");
	}
	if (!TENANT.test(store.tenantId)) throw new Error("feedback_store_tenant_invalid");
	if (!Array.isArray(store.records)) throw new Error("feedback_store_records_invalid");
	return store;
}

function headFor(store: FalsePositiveFeedbackStore, key: string): FalsePositiveFeedbackRecordV1 | null {
	for (let index = store.records.length - 1; index >= 0; index -= 1) {
		const record = store.records[index];
		if (record && bindingKeyOf(record) === key) return record;
	}
	return null;
}

/**
 * Apply one operator feedback submission to a store.
 *
 * An exact replay changes nothing. A submission whose content differs from the
 * latest verdict for the same (incident, policy revision) is refused — the
 * operator's earlier statement is not overwritten. A submission for a binding
 * the caller does not own, or a cross-tenant record, is refused before any
 * mutation.
 */
export function recordFalsePositiveFeedback(
	store: FalsePositiveFeedbackStore,
	submission: unknown,
	context: HasherContext,
): { store: FalsePositiveFeedbackStore; outcome: FalsePositiveFeedbackOutcome } {
	validateStore(store);
	const parsed = parseInput(submission);
	if (!parsed.ok) {
		return {
			store,
			outcome: {
				status: "refused",
				changed: false,
				version: null,
				reason: parsed.error,
				record: null,
			},
		};
	}
	const input = parsed.value;
	if (input.tenantId !== store.tenantId) {
		return {
			store,
			outcome: {
				status: "refused",
				changed: false,
				version: null,
				reason: "cross_tenant_feedback",
				record: null,
			},
		};
	}

	const key = falsePositiveBindingKey(input.binding);
	const submissionDigest = falsePositiveFeedbackSubmissionDigest(input, context);
	const head = headFor(store, key);
	const headDigest = head
		? falsePositiveFeedbackSubmissionDigest(
				{
					tenantId: head.tenantId,
					binding: head.binding,
					feedback: head.feedback,
					reasonCode: head.reasonCode,
					rationale: head.rationale,
					origin: head.origin,
					...(head.observedSideEffect === undefined
						? {}
						: { observedSideEffect: head.observedSideEffect }),
				},
				context,
			)
		: null;

	if (head && headDigest === submissionDigest) {
		// Same actor, same verdict, same rationale: nothing new to record.
		return {
			store,
			outcome: {
				status: "duplicate",
				changed: false,
				version: head.sequence,
				reason: "no-op_replay",
				record: head,
			},
		};
	}
	if (head) {
		// A different verdict for the same incident and revision is a conflict.
		// Refusing is the only honest option: overwriting would erase what the
		// operator already attested and hide the disagreement.
		return {
			store,
			outcome: {
				status: "refused",
				changed: false,
				version: null,
				reason: "conflicting_feedback_submission",
				record: null,
			},
		};
	}

	const previousSequence = store.maxSequenceByBinding[key] ?? 0;
	if (previousSequence !== 0) {
		// The high-water mark says this binding already had records that are no
		// longer present: the store was truncated. Appending would hide it.
		return {
			store,
			outcome: {
				status: "refused",
				changed: false,
				version: null,
				reason: "store_tail_truncated",
				record: null,
			},
		};
	}
	// Version 1 for this binding. A binding that already has a verdict was
	// handled above (identical -> duplicate, different -> refused), so history is
	// never rewritten and a rejected resubmission cannot bump the version.
	const sequence = 1;
	const bound: Omit<FalsePositiveFeedbackRecordV1, "recordHash"> = {
		version: FALSE_POSITIVE_FEEDBACK_SCHEMA_VERSION,
		feedbackId: falsePositiveFeedbackId(input, sequence, context),
		sequence,
		previousHash: FALSE_POSITIVE_GENESIS_HASH,
		...input,
	};
	let recordHash: string;
	try {
		recordHash = falsePositiveFeedbackHash(bound, context);
	} catch {
		return {
			store,
			outcome: {
				status: "refused",
				changed: false,
				version: null,
				reason: "hash_unavailable",
				record: null,
			},
		};
	}
	const record: FalsePositiveFeedbackRecordV1 = { ...bound, recordHash };
	return {
		store: {
			...store,
			records: [...store.records, record],
			maxSequenceByBinding: { ...store.maxSequenceByBinding, [key]: sequence },
		},
		outcome: {
			status: "appended",
			changed: true,
			version: sequence,
			reason: "appended",
			record,
		},
	};
}

/**
 * Fold a batch of submissions.
 *
 * Submission order is preserved because a conflict is defined against the
 * *previous* verdict: the same batch applied in the same order yields the same
 * store, and an exact replay appended to an existing store is a no-op.
 */
export function foldFalsePositiveFeedback(
	store: FalsePositiveFeedbackStore,
	submissions: readonly unknown[],
	context: HasherContext,
): FalsePositiveFeedbackFoldResult {
	let current = store;
	const outcomes: FalsePositiveFeedbackOutcome[] = [];
	let accepted = 0;
	let duplicates = 0;
	let refused = 0;
	for (const submission of submissions) {
		const result = recordFalsePositiveFeedback(current, submission, context);
		current = result.store;
		outcomes.push(result.outcome);
		if (result.outcome.status === "appended") accepted += 1;
		else if (result.outcome.status === "duplicate") duplicates += 1;
		else refused += 1;
	}
	return { store: current, outcomes, accepted, duplicates, refused };
}

export interface FalsePositiveFeedbackState {
	incidentId: string;
	policyRevision: string;
	version: number;
	feedback: FalsePositiveFeedbackKind;
	reasonCode: FalsePositiveReasonCode;
	rationale: string;
	actorRef: string;
	feedbackId: string;
	recordHash: string;
}

/**
 * Current verdict for one incident and policy revision, or `null` when no
 * operator has judged it. `null` is "unjudged", never "confirmed".
 */
export function falsePositiveFeedbackState(
	store: FalsePositiveFeedbackStore,
	incidentId: string,
	policyRevision: string,
): FalsePositiveFeedbackState | null {
	validateStore(store);
	const key = falsePositiveBindingKey({ incidentId, policyRevision } as FalsePositiveFeedbackBinding);
	const head = headFor(store, key);
	if (!head) return null;
	return {
		incidentId: head.binding.incidentId,
		policyRevision: head.binding.policyRevision,
		version: head.sequence,
		feedback: head.feedback,
		reasonCode: head.reasonCode,
		rationale: head.rationale,
		actorRef: head.binding.actorRef,
		feedbackId: head.feedbackId,
		recordHash: head.recordHash,
	};
}

/** Every record for one incident, oldest first. */
export function falsePositiveFeedbackHistory(
	store: FalsePositiveFeedbackStore,
	incidentId: string,
): FalsePositiveFeedbackRecordV1[] {
	validateStore(store);
	return store.records.filter((record) => record.binding.incidentId === incidentId);
}

export interface FalsePositiveRateByRevision {
	policyRevision: string;
	falsePositive: number;
	confirmed: number;
	/** `falsePositive / (falsePositive + confirmed)`, or `null` when unjudged. */
	rate: number | null;
}

/**
 * Judged counts per policy revision. An unjudged revision reports `null`, not
 * a zero rate: "nobody looked" and "no false positives" are different results.
 */
export function falsePositiveRateByPolicyRevision(
	store: FalsePositiveFeedbackStore,
): FalsePositiveRateByRevision[] {
	validateStore(store);
	const byRevision = new Map<string, FalsePositiveFeedbackRecordV1>();
	for (const record of store.records) byRevision.set(record.binding.policyRevision, record);
	const out: FalsePositiveRateByRevision[] = [];
	for (const record of byRevision.values()) {
		let falsePositive = 0;
		let confirmed = 0;
		for (const candidate of store.records) {
			if (candidate.binding.policyRevision !== record.binding.policyRevision) continue;
			if (candidate.feedback === "false_positive") falsePositive += 1;
			else confirmed += 1;
		}
		const judged = falsePositive + confirmed;
		out.push({
			policyRevision: record.binding.policyRevision,
			falsePositive,
			confirmed,
			rate: judged === 0 ? null : falsePositive / judged,
		});
	}
	return out.sort((a, b) =>
		a.policyRevision < b.policyRevision ? -1 : a.policyRevision > b.policyRevision ? 1 : 0,
	);
}

export interface FalsePositiveStoreFinding {
	code:
		| "record_unreadable"
		| "record_hash_mismatch"
		| "chain_link_mismatch"
		| "sequence_regressed"
		| "tenant_mismatch"
		| "tail_truncated"
		| "feedback_id_mismatch";
	feedbackId?: string;
	detail?: string;
}

export interface FalsePositiveStoreVerification {
	valid: boolean;
	checked: number;
	findings: FalsePositiveStoreFinding[];
}

/** The submission a persisted record asserts, so its content can be re-digested. */
function submissionOf(record: FalsePositiveFeedbackRecordV1): FalsePositiveFeedbackInput {
	return {
		tenantId: record.tenantId,
		binding: record.binding,
		feedback: record.feedback,
		reasonCode: record.reasonCode,
		rationale: record.rationale,
		origin: record.origin,
		...(record.observedSideEffect === undefined
			? {}
			: { observedSideEffect: record.observedSideEffect }),
	};
}

/**
 * Verify one record against its predecessor on the same binding.
 *
 * Every check is additive: a record can be wrong in more than one way, and the
 * caller needs all of the reasons rather than the first one found.
 */
function verifyFeedbackRecord(
	record: FalsePositiveFeedbackRecordV1,
	previous: FalsePositiveFeedbackRecordV1 | null,
	storeTenantId: string,
	context: HasherContext,
	findings: FalsePositiveStoreFinding[],
): void {
	if (record.tenantId !== storeTenantId) {
		findings.push({ code: "tenant_mismatch", feedbackId: record.feedbackId });
		return;
	}
	const expectedSequence = (previous?.sequence ?? 0) + 1;
	if (record.sequence !== expectedSequence) {
		findings.push({
			code: "sequence_regressed",
			feedbackId: record.feedbackId,
			...(record.sequence > expectedSequence ? { detail: `expected_sequence:${expectedSequence}` } : {}),
		});
	}
	const expectedPreviousHash = previous ? previous.recordHash : FALSE_POSITIVE_GENESIS_HASH;
	if (record.previousHash !== expectedPreviousHash) {
		findings.push({ code: "chain_link_mismatch", feedbackId: record.feedbackId });
	}
	if (
		falsePositiveFeedbackId(submissionOf(record), record.sequence, context) !== record.feedbackId
	) {
		findings.push({ code: "feedback_id_mismatch", feedbackId: record.feedbackId });
	}
	const { recordHash, ...bound } = record;
	try {
		if (falsePositiveFeedbackHash(bound, context) !== recordHash) {
			findings.push({ code: "record_hash_mismatch", feedbackId: record.feedbackId });
		}
	} catch {
		findings.push({ code: "record_unreadable", feedbackId: record.feedbackId, detail: "hash_unavailable" });
	}
}

/**
 * Verify the append-only chain.
 *
 * Any mismatch leaves `valid: false` and names the record: a rewritten verdict, a
 * removed link, a regressed sequence or a deleted tail is never returned as
 * intact.
 */
export function verifyFalsePositiveFeedbackStore(
	store: FalsePositiveFeedbackStore,
	context: HasherContext,
): FalsePositiveStoreVerification {
	const findings: FalsePositiveStoreFinding[] = [];
	if (!store || store.schemaVersion !== FALSE_POSITIVE_FEEDBACK_SCHEMA_VERSION) {
		return { valid: false, checked: 0, findings: [{ code: "record_unreadable", detail: "store_invalid" }] };
	}
	const ordered = [...store.records].sort((a, b) => a.sequence - b.sequence);
	const headByBinding = new Map<string, FalsePositiveFeedbackRecordV1>();
	for (const entry of ordered) {
		const parsed = parseFalsePositiveFeedbackRecord(entry);
		if (!parsed.ok) {
			findings.push({ code: "record_unreadable", detail: parsed.error });
			continue;
		}
		const record = parsed.value;
		const key = bindingKeyOf(record);
		verifyFeedbackRecord(record, headByBinding.get(key) ?? null, store.tenantId, context, findings);
		headByBinding.set(key, record);
	}

	// A high-water mark above the surviving head means records were removed.
	for (const [key, maxSequence] of Object.entries(store.maxSequenceByBinding ?? {})) {
		const head = headByBinding.get(key);
		if (!head) {
			findings.push({ code: "tail_truncated", detail: `binding_without_records:${key}` });
			continue;
		}
		if (head.sequence < maxSequence) {
			findings.push({
				code: "tail_truncated",
				feedbackId: head.feedbackId,
				detail: `recorded_max:${maxSequence}`,
			});
		}
	}

	return { valid: findings.length === 0, checked: ordered.length, findings };
}

/** Canonical JSON for a store, so two equal folds serialize identically. */
export function canonicalFalsePositiveFeedbackJson(store: FalsePositiveFeedbackStore): string {
	const ordered = [...store.records].sort((a, b) =>
		a.sequence === b.sequence
			? a.feedbackId < b.feedbackId
				? -1
				: 1
			: a.sequence - b.sequence,
	);
	return JSON.stringify({
		schemaVersion: store.schemaVersion,
		tenantId: store.tenantId,
		records: ordered.map((record) => ({
			version: record.version,
			feedbackId: record.feedbackId,
			sequence: record.sequence,
			previousHash: record.previousHash,
			recordHash: record.recordHash,
			tenantId: record.tenantId,
			binding: record.binding,
			feedback: record.feedback,
			reasonCode: record.reasonCode,
			rationale: record.rationale,
			origin: record.origin,
			observedSideEffect: record.observedSideEffect ?? null,
		})),
		maxSequenceByBinding: Object.fromEntries(
			Object.entries(store.maxSequenceByBinding).sort(([a], [b]) => (a < b ? -1 : 1)),
		),
	});
}
