import { createHash, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	appendEvidenceReceipt,
	anchorEvidenceHead,
	compareEvidenceClock,
	detectEvidenceTruncation,
	EVIDENCE_GENESIS_HASH,
	type EvidenceArchiveResult,
	type EvidenceArchiveSink,
	type EvidenceBinding,
	type EvidenceChainVerification,
	type EvidenceClock,
	type EvidenceHashContext,
	type EvidenceReceiptV1,
	parseEvidenceReceipt,
	verifyEvidenceChain,
	verifyEvidenceReceipt,
} from "../incidents/evidence-receipt.js";

/** Mirror of the production hasher; the module is hasher-agnostic by design. */
const hashContext: EvidenceHashContext = {
	hash: (value: string) => createHash("sha256").update(value).digest("hex"),
};

const CANDIDATE = "a".repeat(64);
const OTHER_CANDIDATE = "b".repeat(64);

function binding(overrides: Partial<EvidenceBinding> = {}): EvidenceBinding {
	return {
		candidateDigest: CANDIDATE,
		policyRevision: "rev-42",
		deviceId: "installation-1111",
		actorRef: "actor:opaque-1",
		incidentId: "incident-1",
		actionId: null,
		...overrides,
	};
}

function clock(logicalCounter: number, wallClockUtc = "2026-09-13T00:00:00.000Z", skew: number | null = null): EvidenceClock {
	return { wallClockUtc, logicalCounter, observedSkewMs: skew };
}

function buildChain(
	count: number,
	options: { binding?: Partial<EvidenceBinding>; payloads?: string[] } = {},
): EvidenceReceiptV1[] {
	const chain: EvidenceReceiptV1[] = [];
	for (let index = 0; index < count; index += 1) {
		const appended = appendEvidenceReceipt(
			{
				receiptId: randomUUID(),
				binding: binding(options.binding),
				clock: clock(index, `2026-09-13T00:00:0${index}.000Z`),
				dataClass: "decision",
				payloadSummary: options.payloads?.[index] ?? `decision-${index}`,
			},
			chain.at(-1) ?? null,
			hashContext,
		);
		if (!appended.ok) throw new Error(`fixture chain failed: ${appended.error}`);
		chain.push(appended.value);
	}
	return chain;
}

describe("evidence receipt integrity", () => {
	it("binds candidate, policy, device, actor, incident and action into one digest", () => {
		const [receipt] = buildChain(1);
		expect(receipt?.receiptHash).toMatch(/^[0-9a-f]{64}$/);
		expect(receipt?.previousHash).toBe(EVIDENCE_GENESIS_HASH);
		expect(verifyEvidenceReceipt(receipt, hashContext)).toEqual({
			status: "intact",
			reason: "receipt_hash_matches",
		});
	});

	it("reports tampered for every bound identity field a holder could rewrite", () => {
		const [receipt] = buildChain(1);
		const mutations: Array<Partial<EvidenceReceiptV1>> = [
			{ binding: binding({ candidateDigest: OTHER_CANDIDATE }) },
			{ binding: binding({ policyRevision: "rev-43" }) },
			{ binding: binding({ deviceId: "installation-9999" }) },
			{ binding: binding({ actorRef: "actor:attacker" }) },
			{ binding: binding({ incidentId: "incident-2" }) },
			{ binding: binding({ actionId: "action-9" }) },
			{ clock: clock(1, "2026-09-13T00:00:00.000Z") },
			{ clock: clock(0, "2026-09-14T00:00:00.000Z") },
			{ clock: clock(0, "2026-09-13T00:00:00.000Z", -3_600_000) },
			{ previousHash: "c".repeat(64) },
			{ dataClass: "audit" },
			{ payloadSummary: "rewritten" },
		];
		for (const mutation of mutations) {
			const mutated = { ...(receipt as EvidenceReceiptV1), ...mutation } as EvidenceReceiptV1;
			const result = verifyEvidenceReceipt(mutated, hashContext);
			expect(result.status, JSON.stringify(mutation)).not.toBe("intact");
		}
	});

	it("reports unavailable, never intact, for unreadable or malformed input", () => {
		for (const broken of [null, {}, [], { version: 2 }, "receipt", { receiptId: "not-a-uuid" }]) {
			expect(verifyEvidenceReceipt(broken, hashContext).status).toBe("unavailable");
		}
		expect(verifyEvidenceReceipt(undefined, hashContext).status).toBe("unavailable");
	});

	it("refuses an input that claims external anchoring and refuses an oversized payload", () => {
		const [receipt] = buildChain(1);
		expect(parseEvidenceReceipt({ ...receipt, externallyAnchored: true })).toEqual({
			ok: false,
			error: "external_anchor_not_permitted_here",
		});
		expect(
			parseEvidenceReceipt({ ...receipt, payloadSummary: "x".repeat(4097) }),
		).toEqual({ ok: false, error: "invalid_payload_summary" });
	});

	it("refuses to append a receipt it cannot hash", () => {
		const result = appendEvidenceReceipt(
			{
				receiptId: randomUUID(),
				binding: binding(),
				clock: clock(0),
				dataClass: "decision",
				payloadSummary: "x",
			},
			null,
			{
				hash: () => {
					throw new Error("hasher down");
				},
			},
		);
		expect(result).toEqual({ ok: false, error: "hash_unavailable" });
	});
});

describe("evidence chain verification", () => {
	it("verifies an intact single-device chain and reports its head", () => {
		const chain = buildChain(4);
		const verification = verifyEvidenceChain(chain, hashContext);
		expect(verification.valid).toBe(true);
		expect(verification.findings).toEqual([]);
		expect(verification.checked).toBe(4);
		expect(verification.head?.receiptHash).toBe(chain.at(-1)?.receiptHash);
		expect(verification.devices).toEqual([
			{ deviceId: "installation-1111", maxLogicalCounter: 3, receipts: 4 },
		]);
	});

	it("is order-independent and replay-tolerant for identical receipts", () => {
		const chain = buildChain(3);
		const reordered = [chain[2], chain[0], chain[1], chain[1]] as EvidenceReceiptV1[];
		expect(verifyEvidenceChain(reordered, hashContext).valid).toBe(true);
	});

	it("fails closed on a removed link, a rewritten receipt and a conflicting replay", () => {
		const chain = buildChain(3);
		const withoutMiddle = [chain[0], chain[2]] as EvidenceReceiptV1[];
		const gap = verifyEvidenceChain(withoutMiddle, hashContext);
		expect(gap.valid).toBe(false);
		expect(gap.findings.map((finding) => finding.code)).toContain("chain_link_mismatch");

		const rewritten = [{ ...(chain[0] as EvidenceReceiptV1), payloadSummary: "rewritten" }, chain[1], chain[2]];
		const tampered = verifyEvidenceChain(rewritten, hashContext);
		expect(tampered.valid).toBe(false);
		expect(tampered.findings.map((finding) => finding.code)).toContain("receipt_hash_mismatch");

		const conflictingReplay = [
			...(chain as EvidenceReceiptV1[]),
			{ ...(chain[1] as EvidenceReceiptV1), receiptHash: "d".repeat(64) },
		];
		const conflict = verifyEvidenceChain(conflictingReplay, hashContext);
		expect(conflict.valid).toBe(false);
		expect(conflict.findings.map((finding) => finding.code)).toContain("duplicate_receipt_conflict");
		expect(conflict.head).toBeNull();
	});

	it("fails closed on an empty chain and on an unreadable receipt", () => {
		expect(verifyEvidenceChain([], hashContext)).toMatchObject({
			valid: false,
			checked: 0,
			head: null,
		});
		const unreadable = verifyEvidenceChain([{ nonsense: true }], hashContext);
		expect(unreadable.valid).toBe(false);
		expect(unreadable.findings[0]?.code).toBe("receipt_unreadable");
	});

	it("flags a candidate or policy change inside one incident as a provenance break", () => {
		const chain = buildChain(2);
		const second = appendEvidenceReceipt(
			{
				receiptId: randomUUID(),
				binding: binding({ candidateDigest: OTHER_CANDIDATE }),
				clock: clock(1, "2026-09-13T00:00:01.000Z"),
				dataClass: "decision",
				payloadSummary: "decision-1",
			},
			chain[0] as EvidenceReceiptV1,
			hashContext,
		);
		expect(second.ok).toBe(true);
		if (!second.ok) return;
		const verification = verifyEvidenceChain([chain[0] as EvidenceReceiptV1, second.value], hashContext);
		expect(verification.valid).toBe(false);
		expect(verification.findings.map((finding) => finding.code)).toContain("candidate_digest_mismatch");
		expect(verification.head).toBeNull();
	});

	it("orders by logical counter so a wrong wall clock cannot reorder history", () => {
		const chain = buildChain(2);
		const offline = appendEvidenceReceipt(
			{
				receiptId: randomUUID(),
				binding: binding(),
				// The device was offline, its clock drifted backwards, but its
				// logical counter still advances past what it already produced.
				clock: clock(2, "2026-09-12T23:00:00.000Z", 3_600_000),
				dataClass: "decision",
				payloadSummary: "after-offline",
			},
			chain[1] as EvidenceReceiptV1,
			hashContext,
		);
		expect(offline.ok).toBe(true);
		if (!offline.ok) return;
		const verification = verifyEvidenceChain([...chain, offline.value], hashContext);
		expect(verification.valid).toBe(true);
		expect(verification.head?.logicalCounter).toBe(2);
		expect(verification.maxObservedSkewMs).toBe(3_600_000);
	});

	it("compares clocks deterministically for ties and skew", () => {
		expect(compareEvidenceClock(clock(1), clock(2))).toBeLessThan(0);
		expect(compareEvidenceClock(clock(1, "2026-09-13T01:00:00.000Z"), clock(1, "2026-09-13T00:00:00.000Z"))).toBe(1);
		expect(compareEvidenceClock(clock(1), clock(1))).toBe(0);
	});

	it("detects a truncated tail against a previously observed head", () => {
		const chain = buildChain(3);
		const full = verifyEvidenceChain(chain, hashContext);
		expect(detectEvidenceTruncation(full.head, full)).toEqual({ truncated: false, reason: "head_unchanged" });

		const truncated = verifyEvidenceChain(chain.slice(0, 2), hashContext);
		const detection = detectEvidenceTruncation(full.head, truncated);
		expect(detection.truncated).toBe(true);
		expect(detection.reason).toBe("logical_counter_regressed");

		expect(detectEvidenceTruncation(null, full)).toEqual({ truncated: false, reason: "no_previous_head" });
		const broken: EvidenceChainVerification = { ...full, valid: false, head: null };
		expect(detectEvidenceTruncation(full.head, broken).reason).toBe("chain_not_verifiable");

		const replacement = verifyEvidenceChain(buildChain(4), hashContext);
		expect(detectEvidenceTruncation(full.head, replacement)).toEqual({
			truncated: true,
			reason: "previous_head_missing_or_replaced",
		});
	});

	it("rejects timezone-less wall clocks before producing an unverifiable receipt", () => {
		const result = appendEvidenceReceipt(
			{
				receiptId: randomUUID(),
				binding: binding(),
				clock: clock(1, "2026-09-13T00:00:00"),
				dataClass: "decision",
				payloadSummary: "decision",
			},
			null,
			hashContext,
		);
		expect(result).toMatchObject({ ok: false, error: "invalid_wall_clock" });
	});

	it("surfaces a multi-device chain rather than averaging the devices together", () => {
		const first = buildChain(2);
		const otherDevice = appendEvidenceReceipt(
			{
				receiptId: randomUUID(),
				binding: binding({ deviceId: "installation-2222" }),
				clock: clock(5, "2026-09-13T05:00:00.000Z"),
				dataClass: "decision",
				payloadSummary: "second-device",
			},
			first[1] as EvidenceReceiptV1,
			hashContext,
		);
		expect(otherDevice.ok).toBe(true);
		if (!otherDevice.ok) return;
		const verification = verifyEvidenceChain([...first, otherDevice.value], hashContext);
		expect(verification.valid).toBe(true);
		expect(verification.devices).toEqual([
			{ deviceId: "installation-1111", maxLogicalCounter: 1, receipts: 2 },
			{ deviceId: "installation-2222", maxLogicalCounter: 5, receipts: 1 },
		]);
	});
});

describe("external archive custody (fail-closed)", () => {
	const chain = buildChain(2);
	const head = chain[1] as EvidenceReceiptV1;
	const request = {
		incidentId: head.binding.incidentId,
		candidateDigest: head.binding.candidateDigest,
		headReceiptHash: head.receiptHash,
		headReceiptId: head.receiptId,
		receipts: chain,
	};

	function sink(result: EvidenceArchiveResult | (() => Promise<EvidenceArchiveResult>)): EvidenceArchiveSink {
		return {
			id: "test-archive",
			anchor: typeof result === "function" ? result : async () => result,
		};
	}

	it("anchors only when the archive confirms this exact digest with a reference and time", async () => {
		const outcome = await anchorEvidenceHead(
			sink({
				status: "anchored",
				anchoredReceiptHash: head.receiptHash,
				reference: "archive/incident-1/receipt-1",
				anchoredAtUtc: "2026-09-13T00:00:10.000Z",
			}),
			request,
			hashContext,
		);
		expect(outcome).toEqual({
			status: "anchored",
			reference: "archive/incident-1/receipt-1",
			anchoredAtUtc: "2026-09-13T00:00:10.000Z",
			reason: "archive_confirmed_digest",
		});
	});

	it("stays unanchored when the archive is absent, unavailable, rejects or errors", async () => {
		expect((await anchorEvidenceHead(null, request, hashContext)).reason).toBe("no_archive_sink");
		expect((await anchorEvidenceHead(sink({ status: "unavailable", reason: "s3_down" }), request, hashContext)).status).toBe(
			"unanchored",
		);
		expect((await anchorEvidenceHead(sink({ status: "rejected", reason: "quota" }), request, hashContext)).reason).toBe(
			"rejected:quota",
		);
		const throwing = sink(async () => {
			throw new Error("network");
		});
		const thrown = await anchorEvidenceHead(throwing, request, hashContext);
		expect(thrown.status).toBe("unanchored");
		expect(thrown.reason).toMatch(/^archive_error:/);
	});

	it("refuses proof for a different digest, a missing reference or a bad timestamp", async () => {
		const wrongDigest = await anchorEvidenceHead(
			sink({
				status: "anchored",
				anchoredReceiptHash: "e".repeat(64),
				reference: "ref",
				anchoredAtUtc: "2026-09-13T00:00:10.000Z",
			}),
			request,
			hashContext,
		);
		expect(wrongDigest.reason).toBe("archive_digest_mismatch");

		const noReference = await anchorEvidenceHead(
			sink({
				status: "anchored",
				anchoredReceiptHash: head.receiptHash,
				reference: "   ",
				anchoredAtUtc: "2026-09-13T00:00:10.000Z",
			}),
			request,
			hashContext,
		);
		expect(noReference.reason).toBe("archive_reference_invalid");

		const badTime = await anchorEvidenceHead(
			sink({
				status: "anchored",
				anchoredReceiptHash: head.receiptHash,
				reference: "ref",
				anchoredAtUtc: "not-a-time",
			}),
			request,
			hashContext,
		);
		expect(badTime.reason).toBe("archive_timestamp_invalid");
	});

	it("does not treat a late response as a successful anchor", async () => {
		let nowMs = 0;
		const late = sink(async () => ({
			status: "anchored",
			anchoredReceiptHash: head.receiptHash,
			reference: "ref",
			anchoredAtUtc: "2026-09-13T00:00:10.000Z",
		}));
		const outcome = await anchorEvidenceHead(late, request, hashContext, {
			timeoutMs: 50,
			now: () => {
				const value = nowMs;
				nowMs += 100;
				return value;
			},
		});
		expect(outcome.status).toBe("unanchored");
		expect(outcome.reason).toBe("archive_timeout_exceeded");
	});

	it("times out rather than waiting forever on a hung archive", async () => {
		const hung = sink(() => new Promise<EvidenceArchiveResult>(() => undefined));
		const outcome = await anchorEvidenceHead(hung, request, hashContext, { timeoutMs: 20 });
		expect(outcome).toEqual({
			status: "unanchored",
			reference: null,
			anchoredAtUtc: null,
			reason: "archive_timeout",
		});
	});

	it("rejects an invalid head digest before contacting any archive", async () => {
		let called = false;
		const spy = sink(async () => {
			called = true;
			return { status: "unavailable", reason: "unused" };
		});
		const outcome = await anchorEvidenceHead(spy, { ...request, headReceiptHash: "nope" }, hashContext);
		expect(outcome.reason).toBe("invalid_head_hash");
		expect(called).toBe(false);
	});

	it("rejects empty or mismatched archive receipt chains before calling the sink", async () => {
		let called = false;
		const spy = sink(async () => {
			called = true;
			return {
				status: "anchored",
				anchoredReceiptHash: request.headReceiptHash,
				reference: "ref",
				anchoredAtUtc: "2026-09-13T00:00:10.000Z",
			};
		});
		const empty = await anchorEvidenceHead(spy, { ...request, receipts: [] }, hashContext);
		expect(empty.reason).toBe("invalid_receipt_chain");
		const wrongIncident = await anchorEvidenceHead(spy, { ...request, incidentId: "other-incident" }, hashContext);
		expect(wrongIncident.reason).toBe("receipt_chain_binding_mismatch");
		const wrongHead = await anchorEvidenceHead(spy, { ...request, headReceiptId: randomUUID() }, hashContext);
		expect(wrongHead.reason).toBe("archive_head_mismatch");
		expect(called).toBe(false);
	});

	it("does not send a tampered chain to an archive that echoes the claimed head", async () => {
		let called = false;
		const spy = sink(async () => {
			called = true;
			return {
				status: "anchored",
				anchoredReceiptHash: request.headReceiptHash,
				reference: "ref",
				anchoredAtUtc: "2026-09-13T00:00:10.000Z",
			};
		});
		const altered = { ...(chain[0] as EvidenceReceiptV1), payloadSummary: "forged" };
		const outcome = await anchorEvidenceHead(spy, { ...request, receipts: [altered, head] }, hashContext);
		expect(outcome).toMatchObject({ status: "unanchored", reason: "receipt_integrity_unverified" });
		expect(called).toBe(false);
	});

	it("refuses a validly hashed policy switch within one incident", async () => {
		const changed = appendEvidenceReceipt(
			{
				receiptId: randomUUID(),
				binding: binding({ policyRevision: "rev-43" }),
				clock: clock(1, "2026-09-13T00:00:01.000Z"),
				dataClass: "decision",
				payloadSummary: "changed-policy",
			},
			chain[0] as EvidenceReceiptV1,
			hashContext,
		);
		if (!changed.ok) throw new Error(changed.error);
		let called = false;
		const spy = sink(async () => {
			called = true;
			return { status: "unavailable", reason: "unused" };
		});
		const outcome = await anchorEvidenceHead(
			spy,
			{
				...request,
				headReceiptHash: changed.value.receiptHash,
				headReceiptId: changed.value.receiptId,
				receipts: [chain[0] as EvidenceReceiptV1, changed.value],
			},
			hashContext,
		);
		expect(outcome).toMatchObject({ status: "unanchored", reason: "receipt_chain_binding_mismatch" });
		expect(called).toBe(false);
	});
});
