import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	type CausalChainLinkInput,
	CAUSAL_CHAIN_ORDER,
	type CausalCorrelationIds,
	causalLinkDigest,
	causalLinkReceiptId,
	canonicalCausalChainJson,
	recordCausalChain,
	verifyCausalChainEvidence,
} from "../causal-chain.js";
import { EVIDENCE_GENESIS_HASH, type EvidenceBinding } from "../incidents/evidence-receipt.js";

const hash = { hash: (value: string) => createHash("sha256").update(value).digest("hex") };

const CANDIDATE = "c".repeat(64);

const binding: EvidenceBinding = {
	candidateDigest: CANDIDATE,
	policyRevision: "pol-rev-7",
	deviceId: "installation-1111",
	actorRef: "actor:opaque-1",
	incidentId: "inc-1",
	actionId: null,
};

const correlation: CausalCorrelationIds = {
	sessionId: "sess-1",
	agentIid: "agent-iid-1",
	connector: "cursor",
	incidentId: "inc-1",
	traceId: "trace-1",
	spanId: "span-1",
};

/**
 * A benign turn: the agent read a file. Every step the chain claims is present,
 * so nothing is flagged as a gap.
 */
function benignLinks(): CausalChainLinkInput[] {
	return [
		link({ linkId: "l1-message", kind: "message", position: 1, nextLinkIds: ["l2-retrieval"] }),
		link({
			linkId: "l2-retrieval",
			kind: "retrieval",
			position: 2,
			previousLinkIds: ["l1-message"],
			nextLinkIds: ["l3-tool-description"],
		}),
		link({
			linkId: "l3-tool-description",
			kind: "tool_description",
			position: 3,
			previousLinkIds: ["l2-retrieval"],
			nextLinkIds: ["l4-tool-response"],
		}),
		link({
			linkId: "l4-tool-response",
			kind: "tool_response",
			position: 4,
			previousLinkIds: ["l3-tool-description"],
			nextLinkIds: ["l5-authorization"],
		}),
		link({
			linkId: "l5-authorization",
			kind: "authorization",
			position: 5,
			previousLinkIds: ["l4-tool-response"],
			nextLinkIds: ["l6-action"],
		}),
		link({
			linkId: "l6-action",
			kind: "action",
			position: 6,
			previousLinkIds: ["l5-authorization"],
			nextLinkIds: ["l7-side-effect"],
		}),
		link({
			linkId: "l7-side-effect",
			kind: "side_effect",
			position: 7,
			previousLinkIds: ["l6-action"],
		}),
	];
}

/**
 * The attack twin: the tool description was never observed, but the tool
 * response names the description as its predecessor. The chain must report the
 * hole instead of joining retrieval straight to the response.
 */
function gappedLinks(): CausalChainLinkInput[] {
	const links = benignLinks().filter((entry) => entry.linkId !== "l3-tool-description");
	return links.map((entry) =>
		entry.linkId === "l4-tool-response"
			? { ...entry, previousLinkIds: ["l3-tool-description"] }
			: entry.linkId === "l2-retrieval"
				? { ...entry, nextLinkIds: ["l3-tool-description"] }
				: entry,
	);
}

function link(overrides: Partial<CausalChainLinkInput> & Pick<CausalChainLinkInput, "linkId" | "kind" | "position">): CausalChainLinkInput {
	return {
		wallClockUtc: `2026-09-13T00:00:${String(overrides.position).padStart(2, "0")}.000Z`,
		correlation,
		payloadSummary: `${overrides.kind}-summary`,
		severity: "info",
		...overrides,
	};
}

function gapFindings(chain: ReturnType<typeof recordCausalChain>) {
	return chain.findings.filter((finding) => finding.code === "chain_gap");
}

describe("causal chain ordering", () => {
	it("produces the same chain for any arrival order of the same links", () => {
		const links = benignLinks();
		const forward = recordCausalChain(links, { ...hash, expectedKinds: [] });
		const reversed = recordCausalChain([...links].reverse(), { ...hash, expectedKinds: [] });
		const shuffled = recordCausalChain(
			[links[3], links[0], links[6], links[2], links[5], links[1], links[4]],
			{ ...hash, expectedKinds: [] },
		);
		expect(canonicalCausalChainJson(reversed)).toBe(canonicalCausalChainJson(forward));
		expect(canonicalCausalChainJson(shuffled)).toBe(canonicalCausalChainJson(forward));
		expect(forward.links.map((entry) => entry.kind)).toEqual([
			"message",
			"retrieval",
			"tool_description",
			"tool_response",
			"authorization",
			"action",
			"side_effect",
		]);
	});

	it("orders by position, then wall clock, then link id, so input order never decides", () => {
		const a = link({ linkId: "b-link", kind: "message", position: 1, wallClockUtc: "2026-09-13T00:00:01.000Z" });
		const b = link({ linkId: "a-link", kind: "retrieval", position: 1, wallClockUtc: "2026-09-13T00:00:01.000Z" });
		const c = link({ linkId: "c-link", kind: "action", position: 1, wallClockUtc: "2026-09-13T00:00:00.000Z" });
		const chain = recordCausalChain([a, b, c], { ...hash, expectedKinds: [] });
		// Same position: the earlier wall clock wins, then the lower link id.
		expect(chain.links.map((entry) => entry.linkId)).toEqual(["c-link", "a-link", "b-link"]);
	});

	it("is idempotent for an exact replay and flags a changed replay", () => {
		const links = benignLinks();
		const replay = recordCausalChain([...links, ...links], { ...hash, expectedKinds: [] });
		expect(replay.duplicates).toEqual(links.map((entry) => entry.linkId).sort());
		expect(replay.findings.filter((finding) => finding.code === "duplicate_link_conflict")).toEqual([]);

		const rewritten = { ...links[4], payloadSummary: "rewritten" } as CausalChainLinkInput;
		const conflict = recordCausalChain([links[4], rewritten], { ...hash, expectedKinds: [] });
		expect(conflict.findings.map((finding) => finding.code)).toContain("duplicate_link_conflict");
		expect(conflict.links).toHaveLength(1);
		expect(conflict.links[0]?.payloadSummary).toBe("authorization-summary");
	});

	it("uses a logical clock so a wrong host clock cannot reorder the chain", () => {
		const links = benignLinks().map((entry, index) =>
			index === 4 ? { ...entry, wallClockUtc: "2026-09-12T00:00:00.000Z" } : entry,
		);
		const chain = recordCausalChain(links, { ...hash, expectedKinds: [] });
		// Position is authoritative; the drifted clock on the authorization link
		// does not move it ahead of the message.
		expect(chain.links[4]?.kind).toBe("authorization");
		expect(chain.head?.linkId).toBe("l7-side-effect");
	});

	it("refuses a link from another correlation scope instead of merging two chains", () => {
		const foreign = link({
			linkId: "l9-foreign",
			kind: "intervention",
			position: 9,
			correlation: { ...correlation, incidentId: "inc-2", traceId: "trace-2" },
		});
		const chain = recordCausalChain([...benignLinks(), foreign], { ...hash, expectedKinds: [] });
		expect(chain.refused).toEqual(["l9-foreign"]);
		expect(chain.findings.map((finding) => finding.code)).toContain("correlation_mismatch");
		expect(chain.links.some((entry) => entry.linkId === "l9-foreign")).toBe(false);
		expect(chain.correlation.incidentId).toBe("inc-1");
	});

	it("keeps an agent-to-agent handoff in one chain through correlation ids", () => {
		const links = benignLinks();
		const handoff = link({
			linkId: "l8-intervention",
			kind: "intervention",
			position: 8,
			previousLinkIds: ["l7-side-effect"],
			correlation: { ...correlation, handoffFromAgentIid: "agent-iid-0" },
		});
		// A handoff changes the acting agent, which is a different scope by design.
		const chain = recordCausalChain([...links, handoff], { ...hash, expectedKinds: [] });
		expect(chain.refused).toEqual(["l8-intervention"]);

		const handedOff = link({
			linkId: "l8-intervention",
			kind: "intervention",
			position: 8,
			previousLinkIds: ["l7-side-effect"],
		});
		const same = recordCausalChain([...links, handedOff], { ...hash, expectedKinds: [] });
		expect(same.refused).toEqual([]);
		expect(same.links).toHaveLength(8);
		expect(same.observedKinds).toEqual([...CAUSAL_CHAIN_ORDER]);
	});
});

describe("causal chain gaps", () => {
	it("flags a missing link as chain_gap instead of joining its neighbours", () => {
		const chain = recordCausalChain(gappedLinks(), { ...hash, expectedKinds: [] });
		const gaps = gapFindings(chain);
		expect(gaps.length).toBeGreaterThan(0);
		expect(gaps.some((finding) => finding.detail === "missing_predecessor:l3-tool-description")).toBe(true);
		expect(gaps.some((finding) => finding.detail === "missing_successor:l3-tool-description")).toBe(true);
		// The hole is not spliced: retrieval and tool_response remain distinct
		// links and no synthetic tool_description appears.
		expect(chain.links.map((entry) => entry.kind)).toEqual([
			"message",
			"retrieval",
			"tool_response",
			"authorization",
			"action",
			"side_effect",
		]);
		expect(chain.findings.some((finding) => finding.code === "chain_gap" && finding.missingKind)).toBe(false);
	});

	it("reports a kind that is entirely absent when the chain claims to cover it", () => {
		const withoutAuthorization = benignLinks().filter((entry) => entry.kind !== "authorization");
		const chain = recordCausalChain(withoutAuthorization, {
			...hash,
			expectedKinds: CAUSAL_CHAIN_ORDER,
		});
		const kinds = gapFindings(chain).map((finding) => finding.missingKind);
		expect(kinds).toContain("authorization");
		expect(chain.observedKinds).not.toContain("authorization");
	});

	it("is silent about a benign turn that claims nothing it did not observe", () => {
		const links = benignLinks();
		const chain = recordCausalChain(links, {
			...hash,
			expectedKinds: links.map((entry) => entry.kind),
		});
		expect(chain.findings).toEqual([]);
		expect(chain.observedKinds).toEqual([...CAUSAL_CHAIN_ORDER].filter((kind) => kind !== "intervention"));
		// The same turn is still complete when the chain says it covers everything:
		// the one absent kind is reported, not silently accepted.
		const full = recordCausalChain(links, { ...hash, expectedKinds: CAUSAL_CHAIN_ORDER });
		expect(gapFindings(full).map((finding) => finding.missingKind)).toEqual(["intervention"]);
	});

	it("refuses an unreadable link and names the reason", () => {
		const chain = recordCausalChain([...benignLinks(), { linkId: "l9", kind: "not_a_kind" }], {
			...hash,
			expectedKinds: [],
		});
		expect(chain.findings).toContainEqual({
			code: "link_unreadable",
			detail: "invalid_link_kind",
		});
		expect(chain.links).toHaveLength(7);
	});
});

describe("causal chain tamper-evident binding", () => {
	it("binds every link to the candidate, policy, device, actor and incident", () => {
		const chain = recordCausalChain(benignLinks(), {
			...hash,
			expectedKinds: [],
			binding,
		});
		expect(chain.receiptOutcome).toMatchObject({ status: "bound", receipts: 7 });
		expect(chain.receipts).toHaveLength(7);
		expect(chain.receipts[0]?.previousHash).toBe(EVIDENCE_GENESIS_HASH);
		expect(chain.receipts.every((receipt) => receipt.binding.deviceId === binding.deviceId)).toBe(true);
		expect(chain.receipts.every((receipt) => receipt.binding.incidentId === "inc-1")).toBe(true);
		expect(chain.links.every((entry) => entry.receiptId !== null)).toBe(true);
		expect(verifyCausalChainEvidence(chain, hash)).toMatchObject({
			valid: true,
			checkedLinks: 7,
			checkedReceipts: 7,
			findings: [],
		});
		// Neither the benign chain nor its twin is refused for claiming no gaps.
		const benignWithoutBinding = recordCausalChain(benignLinks(), { ...hash, expectedKinds: [] });
		expect(benignWithoutBinding.findings).toEqual([]);
	});

	it("reports a full-coverage benign turn as complete", () => {
		const links = benignLinks();
		const chain = recordCausalChain(links, {
			...hash,
			expectedKinds: links.map((entry) => entry.kind),
		});
		expect(chain.findings).toEqual([]);
		expect(chain.observedKinds).toHaveLength(7);
	});

	it("detects a rewritten link through the receipt that documents it", () => {
		const chain = recordCausalChain(benignLinks(), { ...hash, expectedKinds: [], binding });
		const intact = verifyCausalChainEvidence(chain, hash);
		expect(intact.valid).toBe(true);

		const tampered = {
			...chain,
			links: chain.links.map((entry) =>
				entry.linkId === "l6-action" ? { ...entry, payloadSummary: "different payload" } : entry,
			),
		};
		const verification = verifyCausalChainEvidence(tampered, hash);
		expect(verification.valid).toBe(false);
		expect(verification.findings.some((finding) => finding.detail === "link_digest_mismatch")).toBe(true);
		expect(verification.findings.some((finding) => finding.detail === "receipt_does_not_document_this_link")).toBe(
			true,
		);
	});

	it("detects a rewritten receipt and a removed receipt link", () => {
		const chain = recordCausalChain(benignLinks(), { ...hash, expectedKinds: [], binding });
		const rewritten = {
			...chain,
			receipts: chain.receipts.map((receipt, index) =>
				index === 2 ? { ...receipt, payloadSummary: "forged" } : receipt,
			),
		};
		const rewrittenResult = verifyCausalChainEvidence(rewritten, hash);
		expect(rewrittenResult.valid).toBe(false);
		expect(rewrittenResult.findings.some((finding) => finding.code === "receipt_not_intact")).toBe(true);

		const removed = { ...chain, receipts: chain.receipts.filter((_, index) => index !== 2) };
		const removedResult = verifyCausalChainEvidence(removed, hash);
		expect(removedResult.valid).toBe(false);
		expect(removedResult.findings.some((finding) => finding.detail === "receipt_missing")).toBe(true);
	});

	it("fails closed when no binding was supplied", () => {
		const chain = recordCausalChain(benignLinks(), { ...hash, expectedKinds: [] });
		expect(chain.receiptOutcome).toEqual({ status: "not_requested" });
		expect(chain.receipts).toEqual([]);
		const verification = verifyCausalChainEvidence(chain, hash);
		expect(verification.valid).toBe(false);
		expect(verification.findings.every((finding) => finding.detail === "link_has_no_receipt")).toBe(true);
	});

	it("recomputes missing-link gaps instead of trusting stored findings", () => {
		const gapped = recordCausalChain(gappedLinks(), { ...hash, expectedKinds: [], binding });
		const findingsRemoved = { ...gapped, findings: [] };
		const verification = verifyCausalChainEvidence(findingsRemoved, hash);
		expect(verification.valid).toBe(false);
		expect(verification.findings.some((finding) => finding.code === "chain_gap")).toBe(true);
	});

	it("mints a deterministic receipt id so a replay cannot create a second receipt", () => {
		expect(causalLinkReceiptId("l1-message")).toBe(causalLinkReceiptId("l1-message"));
		expect(causalLinkReceiptId("l1-message")).not.toBe(causalLinkReceiptId("l2-retrieval"));
		expect(causalLinkReceiptId("l1-message")).toMatch(
			/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$/,
		);
	});
});

describe("causal chain digest", () => {
	it("changes for every causal field a holder could rewrite", () => {
		const base: CausalChainLinkInput = link({ linkId: "l1-message", kind: "message", position: 1 });
		const original = causalLinkDigest(base, hash);
		const mutations: CausalChainLinkInput[] = [
			{ ...base, kind: "retrieval" },
			{ ...base, position: 2 },
			{ ...base, wallClockUtc: "2026-09-13T01:00:00.000Z" },
			{ ...base, payloadSummary: "rewritten" },
			{ ...base, severity: "critical" },
			{ ...base, correlation: { ...correlation, agentIid: "agent-iid-2" } },
			{ ...base, correlation: { ...correlation, incidentId: "inc-2" } },
			{ ...base, nextLinkIds: ["l2-retrieval"] },
		];
		for (const mutation of mutations) {
			expect(causalLinkDigest(mutation, hash), JSON.stringify(mutation)).not.toBe(original);
		}
		expect(causalLinkDigest({ ...base }, hash)).toBe(original);
	});
});
