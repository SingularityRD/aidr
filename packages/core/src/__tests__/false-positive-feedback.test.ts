import { describe, expect, it } from "vitest";
import {
	canonicalFalsePositiveFeedbackJson,
	createFalsePositiveFeedbackStore,
	createSha256HasherContext,
	FALSE_POSITIVE_GENESIS_HASH,
	type FalsePositiveFeedbackBinding,
	type FalsePositiveFeedbackInput,
	type FalsePositiveFeedbackStore,
	falsePositiveFeedbackHistory,
	falsePositiveFeedbackState,
	falsePositiveRateByPolicyRevision,
	foldFalsePositiveFeedback,
	recordFalsePositiveFeedback,
	verifyFalsePositiveFeedbackStore,
} from "../false-positive-feedback.js";

const hash = createSha256HasherContext();
const TENANT = "tenant-a";
const OTHER_TENANT = "tenant-b";
const CANDIDATE = "d".repeat(64);

function binding(
	overrides: Partial<FalsePositiveFeedbackBinding> = {},
): FalsePositiveFeedbackBinding {
	return {
		policyRevision: "pol-rev-7",
		incidentId: "inc-1",
		candidateDigest: CANDIDATE,
		deviceId: "installation-1111",
		actorRef: "actor:analyst-1",
		...overrides,
	};
}

function submission(
	overrides: Partial<FalsePositiveFeedbackInput> = {},
): FalsePositiveFeedbackInput {
	return {
		tenantId: TENANT,
		binding: binding(),
		feedback: "false_positive",
		reasonCode: "benign_automation",
		rationale: "Scheduled backup task, expected egress to the internal mirror.",
		origin: "operator_review",
		observedSideEffect: "outbound-tcp:443",
		...overrides,
	};
}

function record(store: FalsePositiveFeedbackStore, input: FalsePositiveFeedbackInput) {
	return recordFalsePositiveFeedback(store, input, hash);
}

describe("false-positive feedback binding", () => {
	it("binds the verdict to the incident, policy revision, actor, device and candidate", () => {
		const empty = createFalsePositiveFeedbackStore(TENANT);
		const { store, outcome } = record(empty, submission());
		expect(outcome.status).toBe("appended");
		expect(outcome.version).toBe(1);
		const entry = store.records[0];
		expect(entry?.binding.policyRevision).toBe("pol-rev-7");
		expect(entry?.binding.incidentId).toBe("inc-1");
		expect(entry?.binding.actorRef).toBe("actor:analyst-1");
		expect(entry?.binding.deviceId).toBe("installation-1111");
		expect(entry?.binding.candidateDigest).toBe(CANDIDATE);
		expect(entry?.previousHash).toBe(FALSE_POSITIVE_GENESIS_HASH);
		expect(entry?.feedbackId).toMatch(/^fpfb_[0-9a-f]{64}$/);
		expect(verifyFalsePositiveFeedbackStore(store, hash)).toEqual({
			valid: true,
			checked: 1,
			findings: [],
		});
	});

	it("keeps separate versions for separate incident+revision bindings", () => {
		const first = record(createFalsePositiveFeedbackStore(TENANT), submission());
		const second = record(
			first.store,
			submission({ binding: binding({ policyRevision: "pol-rev-8" }) }),
		);
		expect(second.outcome.version).toBe(1);
		expect(second.store.records).toHaveLength(2);
		expect(
			second.store.records.every((entry) => entry.previousHash === FALSE_POSITIVE_GENESIS_HASH),
		).toBe(true);
		expect(verifyFalsePositiveFeedbackStore(second.store, hash).valid).toBe(true);
	});

	it("reports an unjudged binding as null, never as confirmed", () => {
		const empty = createFalsePositiveFeedbackStore(TENANT);
		expect(falsePositiveFeedbackState(empty, "inc-1", "pol-rev-7")).toBeNull();
		const { store } = record(empty, submission());
		expect(falsePositiveFeedbackState(store, "inc-1", "pol-rev-7")).toMatchObject({
			version: 1,
			feedback: "false_positive",
			reasonCode: "benign_automation",
		});
		expect(falsePositiveFeedbackState(store, "inc-1", "pol-rev-8")).toBeNull();
		expect(falsePositiveFeedbackState(store, "inc-2", "pol-rev-7")).toBeNull();
	});

	it("refuses a cross-tenant record without mutating the store", () => {
		const { store } = record(createFalsePositiveFeedbackStore(TENANT), submission());
		const refused = recordFalsePositiveFeedback(
			store,
			submission({ tenantId: OTHER_TENANT }),
			hash,
		);
		expect(refused.outcome).toMatchObject({
			status: "refused",
			changed: false,
			reason: "cross_tenant_feedback",
		});
		expect(refused.store).toBe(store);
	});

	it("refuses a malformed submission and names the field", () => {
		const empty = createFalsePositiveFeedbackStore(TENANT);
		const cases: Array<[unknown, string]> = [
			[submission({ reasonCode: "because" as never }), "invalid_reason_code"],
			[submission({ feedback: "maybe" as never }), "invalid_feedback"],
			[
				submission({ binding: binding({ policyRevision: "has spaces" }) }),
				"invalid_policy_revision",
			],
			[submission({ rationale: "x".repeat(2001) }), "invalid_rationale"],
			[null, "not_an_object"],
		];
		for (const [input, reason] of cases) {
			const result = recordFalsePositiveFeedback(empty, input, hash);
			expect(result.outcome.status, reason).toBe("refused");
			expect(result.outcome.reason).toBe(reason);
			expect(result.store.records).toEqual([]);
		}
	});
});

describe("false-positive feedback idempotency and conflict", () => {
	it("treats an identical resubmission as a no-op instead of a new version", () => {
		const first = record(createFalsePositiveFeedbackStore(TENANT), submission());
		const replay = record(first.store, submission());
		expect(replay.outcome).toMatchObject({
			status: "duplicate",
			changed: false,
			version: 1,
			reason: "no-op_replay",
		});
		expect(replay.store.records).toHaveLength(1);
		expect(replay.store).toBe(first.store);
	});

	it("is order-independent for a batch: the same submission set folds to the same store", () => {
		const input = submission();
		const single = foldFalsePositiveFeedback(
			createFalsePositiveFeedbackStore(TENANT),
			[input],
			hash,
		);
		const replayed = foldFalsePositiveFeedback(
			createFalsePositiveFeedbackStore(TENANT),
			[input, input, input],
			hash,
		);
		expect(replayed.accepted).toBe(1);
		expect(replayed.duplicates).toBe(2);
		expect(replayed.refused).toBe(0);
		expect(canonicalFalsePositiveFeedbackJson(replayed.store)).toBe(
			canonicalFalsePositiveFeedbackJson(single.store),
		);
	});

	it("refuses a conflicting resubmission for the same incident and revision instead of overwriting", () => {
		const first = record(createFalsePositiveFeedbackStore(TENANT), submission());
		const conflicting = record(
			first.store,
			submission({ feedback: "confirmed", reasonCode: "other", rationale: "Actually malicious." }),
		);
		expect(conflicting.outcome).toEqual({
			status: "refused",
			changed: false,
			version: null,
			reason: "conflicting_feedback_submission",
			record: null,
		});
		expect(conflicting.store).toBe(first.store);
		// The operator's original verdict is still the current one and is intact.
		expect(falsePositiveFeedbackState(conflicting.store, "inc-1", "pol-rev-7")?.feedback).toBe(
			"false_positive",
		);
		expect(conflicting.store.records).toHaveLength(1);
		expect(verifyFalsePositiveFeedbackStore(conflicting.store, hash).valid).toBe(true);
	});

	it("refuses a conflicting verdict that differs only in rationale", () => {
		const first = record(createFalsePositiveFeedbackStore(TENANT), submission());
		const conflicting = record(
			first.store,
			submission({ rationale: "A different justification." }),
		);
		expect(conflicting.outcome.reason).toBe("conflicting_feedback_submission");
	});

	it("versions each submission separately while the store is append-only", () => {
		const benign = record(createFalsePositiveFeedbackStore(TENANT), submission());
		const twin = record(
			benign.store,
			submission({
				binding: binding({ incidentId: "inc-2" }),
				feedback: "confirmed",
				reasonCode: "other",
				rationale: "Confirmed malicious write.",
			}),
		);
		expect(twin.outcome.status).toBe("appended");
		expect(twin.store.records.map((entry) => entry.sequence)).toEqual([1, 1]);
		expect(falsePositiveFeedbackHistory(twin.store, "inc-1")).toHaveLength(1);
		expect(falsePositiveFeedbackHistory(twin.store, "inc-2")).toHaveLength(1);
		expect(verifyFalsePositiveFeedbackStore(twin.store, hash).valid).toBe(true);
	});
});

describe("false-positive feedback store integrity", () => {
	it("detects a rewritten verdict", () => {
		const { store } = record(createFalsePositiveFeedbackStore(TENANT), submission());
		const tampered: FalsePositiveFeedbackStore = {
			...store,
			records: store.records.map((entry) => ({ ...entry, feedback: "confirmed" as const })),
		};
		const verification = verifyFalsePositiveFeedbackStore(tampered, hash);
		expect(verification.valid).toBe(false);
		expect(verification.findings.map((finding) => finding.code)).toContain("record_hash_mismatch");
	});

	it("detects a rewritten binding: a verdict re-pointed at another revision", () => {
		const { store } = record(createFalsePositiveFeedbackStore(TENANT), submission());
		const repointed: FalsePositiveFeedbackStore = {
			...store,
			records: store.records.map((entry) => ({
				...entry,
				binding: { ...entry.binding, policyRevision: "pol-rev-99" },
			})),
		};
		const verification = verifyFalsePositiveFeedbackStore(repointed, hash);
		expect(verification.valid).toBe(false);
		expect(verification.findings.map((finding) => finding.code)).toContain("record_hash_mismatch");
		expect(verification.findings.map((finding) => finding.code)).toContain("feedback_id_mismatch");
	});

	it("detects a removed tail against the recorded sequence high-water mark", () => {
		const { store } = record(createFalsePositiveFeedbackStore(TENANT), submission());
		const empty: FalsePositiveFeedbackStore = {
			...store,
			records: [],
		};
		const verification = verifyFalsePositiveFeedbackStore(empty, hash);
		expect(verification.valid).toBe(false);
		expect(verification.findings.map((finding) => finding.code)).toContain("tail_truncated");
	});

	it("refuses to append once the store was truncated instead of hiding the gap", () => {
		const { store } = record(createFalsePositiveFeedbackStore(TENANT), submission());
		const truncated: FalsePositiveFeedbackStore = { ...store, records: [] };
		const next = recordFalsePositiveFeedback(truncated, submission(), hash);
		expect(next.outcome).toMatchObject({
			status: "refused",
			changed: false,
			reason: "store_tail_truncated",
		});
		expect(next.store.records).toEqual([]);
	});

	it("reports an empty store as valid-but-empty and an unreadable store as invalid", () => {
		expect(
			verifyFalsePositiveFeedbackStore(createFalsePositiveFeedbackStore(TENANT), hash),
		).toEqual({
			valid: true,
			checked: 0,
			findings: [],
		});
		expect(
			verifyFalsePositiveFeedbackStore(
				{ schemaVersion: 9 } as unknown as FalsePositiveFeedbackStore,
				hash,
			).valid,
		).toBe(false);
	});

	it("detects a record that was moved to another tenant while the store scope stays put", () => {
		const { store } = record(createFalsePositiveFeedbackStore(TENANT), submission());
		const moved: FalsePositiveFeedbackStore = {
			...store,
			records: store.records.map((entry) => ({ ...entry, tenantId: OTHER_TENANT })),
		};
		const verification = verifyFalsePositiveFeedbackStore(moved, hash);
		// This is a cross-tenant record inside a single-tenant store: exactly the
		// merge the graph and the store both refuse.
		expect(verification.valid).toBe(false);
		expect(verification.findings).toContainEqual({
			code: "tenant_mismatch",
			feedbackId: store.records[0]?.feedbackId,
		});
	});
});

describe("false-positive rate by policy revision", () => {
	it("reports a rate per revision and null for an unjudged one", () => {
		const first = record(createFalsePositiveFeedbackStore(TENANT), submission());
		const second = record(
			first.store,
			submission({
				binding: binding({ policyRevision: "pol-rev-8" }),
				feedback: "confirmed",
				reasonCode: "other",
			}),
		);
		expect(falsePositiveRateByPolicyRevision(second.store)).toEqual([
			{ policyRevision: "pol-rev-7", falsePositive: 1, confirmed: 0, rate: 1 },
			{ policyRevision: "pol-rev-8", falsePositive: 0, confirmed: 1, rate: 0 },
		]);
		expect(falsePositiveRateByPolicyRevision(createFalsePositiveFeedbackStore(TENANT))).toEqual([]);
		expect(falsePositiveRateByPolicyRevision(first.store)[0]?.rate).toBe(1);
	});
});
