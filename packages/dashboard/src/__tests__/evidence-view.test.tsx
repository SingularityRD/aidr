// @vitest-environment jsdom

// Regression guards for the evidence view (packages/dashboard/src/enterprise/evidence-view.tsx).
//
// The incident correlation and the evidence-chain status are computed by the
// core and carried in the audit payload, but no dashboard surface rendered
// them: the audit table showed one flat row per record. These tests pin the
// properties the view exists for:
//
//   - records are grouped by the correlation id their payload carries, and the
//     response steps — including a rollback — are shown in order under the
//     incident that owns them;
//   - an unanchored chain head is reported as unanchored, with the core's own
//     reason, and nothing implies archive custody, while an anchored head shows
//     the archive's own reference and time;
//   - the per-device clock panel reports counters, reports a skew that no
//     record observed as *not reported* rather than as a synchronised clock,
//     and never presents an unverifiable chain as verified.

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import {
	type EvidenceAuditRow,
	type EvidenceChainVerification,
	EvidenceView,
	correlationScopeOf,
} from "../enterprise/evidence-view";

const T0 = Date.parse("2026-09-13T00:00:00.000Z");

const VERDICT_ROW: EvidenceAuditRow = {
	id: "row-1",
	action: "runtime_verdict",
	timestampMs: T0,
	payload: { incident_id: "inc_alpha", decision: "deny", tool_name: "bash" },
};

/** The chain the core's `verifyEvidenceChain` returns for one intact device. */
const VERIFIED_CHAIN: EvidenceChainVerification = {
	valid: true,
	checked: 4,
	head: { receiptId: "receipt-4", receiptHash: "a".repeat(64), logicalCounter: 9 },
	findings: [],
	devices: [{ deviceId: "installation-1111", maxLogicalCounter: 9, receipts: 4 }],
	maxObservedSkewMs: null,
};

describe("evidence view", () => {
	afterEach(cleanup);

	it("resolves the correlation id the audit payload carries, incident scope first", () => {
		expect(correlationScopeOf({ session_id: "session-1", incident_id: "inc_alpha" })).toEqual({
			kind: "incident",
			id: "inc_alpha",
		});
		expect(correlationScopeOf({ sessionId: "session-1" })).toEqual({
			kind: "session",
			id: "session-1",
		});
		// No id at all stays uncorrelated rather than joining a neighbour.
		expect(correlationScopeOf({ tool_name: "bash", verdict: "deny" })).toBeNull();
	});

	it("groups a multi-step response under one incident and shows its rollback", () => {
		const rows: EvidenceAuditRow[] = [
			VERDICT_ROW,
			{
				id: "row-2",
				action: "response_action",
				timestampMs: T0 + 1_000,
				payload: {
					incident_id: "inc_alpha",
					session_id: "session-1",
					actions: [
						{
							action: "snapshot",
							outcome: "success",
							target: "/workspace/app.py",
							snapshot_id: "snap-1",
						},
					],
				},
			},
			{
				id: "row-3",
				action: "response_action",
				timestampMs: T0 + 2_000,
				payload: {
					incident_id: "inc_alpha",
					actions: [
						{
							action: "rollback",
							outcome: "success",
							target: "/workspace/app.py",
							snapshot_id: "snap-1",
						},
					],
				},
			},
			{
				id: "row-4",
				action: "runtime_verdict",
				timestampMs: T0 + 3_000,
				payload: { incident_id: "inc_beta", decision: "ask", tool_name: "WebFetch" },
			},
		];

		render(<EvidenceView rows={rows} />);

		// Three records name inc_alpha, and they are one group, not three rows.
		expect(screen.getAllByText("inc_alpha")).toHaveLength(1);
		expect(screen.getAllByText("inc_beta")).toHaveLength(1);
		expect(screen.getByText(/3 record\(s\), 2 response step\(s\)/)).toBeInTheDocument();

		const steps = within(
			screen.getByRole("list", { name: /Response steps for inc_alpha/ }),
		).getAllByRole("listitem");
		expect(steps).toHaveLength(2);
		expect(steps[0]).toHaveTextContent("Snapshot");
		expect(steps[1]).toHaveTextContent("Rollback");
		// A rollback is rendered as the restore it is, naming its target — not as
		// another snapshot, which would tell the operator the opposite.
		expect(screen.getByText("Rollback")).toBeInTheDocument();
		expect(screen.getByText(/restored \/workspace\/app\.py/)).toBeInTheDocument();
		// The unrelated incident keeps its own group.
		expect(screen.getAllByRole("list")).toHaveLength(1);
	});

	it.each([
		["incident_id", "Incident", "inc_shared"],
		["session_id", "Session", "unknown"],
	] as const)("keeps matching %s values separate across agents", (scopeKey, label, id) => {
		const rows: EvidenceAuditRow[] = [
			{
				id: "agent-a-row",
				action: "runtime_verdict",
				timestampMs: T0,
				agentId: "agent-a",
				payload: { [scopeKey]: id, decision: "deny" },
			},
			{
				id: "agent-b-row",
				action: "runtime_verdict",
				timestampMs: T0,
				agentId: "agent-b",
				payload: { [scopeKey]: id, decision: "allow" },
			},
		];

		render(<EvidenceView rows={rows} />);

		const groups = screen
			.getAllByRole("region")
			.filter((group) => group.getAttribute("aria-label")?.startsWith(`${label} ${id}, agent`));
		expect(groups).toHaveLength(2);
		const agentA = groups.find((group) => within(group).queryByText(/agent agent-a/));
		const agentB = groups.find((group) => within(group).queryByText(/agent agent-b/));
		expect(agentA).toBeDefined();
		expect(agentB).toBeDefined();
		if (!agentA || !agentB) return;
		expect(within(agentA).getByText("Deny")).toBeInTheDocument();
		expect(within(agentA).queryByText("Allow")).not.toBeInTheDocument();
		expect(within(agentB).getByText("Allow")).toBeInTheDocument();
		expect(within(agentB).queryByText("Deny")).not.toBeInTheDocument();
	});

	it("reports an unanchored chain head instead of implying custody", () => {
		render(
			<EvidenceView
				rows={[VERDICT_ROW]}
				anchor={{
					status: "unanchored",
					reference: null,
					anchoredAtUtc: null,
					reason: "no_archive_sink",
				}}
			/>,
		);

		expect(screen.getByText("Unanchored")).toBeInTheDocument();
		// The core's own reason is shown verbatim, not rewritten into a nicer one.
		expect(screen.getByText("no_archive_sink")).toBeInTheDocument();
		expect(screen.getByText(/the records shown here are local records/i)).toBeInTheDocument();
		expect(screen.queryByText("Anchored")).not.toBeInTheDocument();
		expect(screen.queryByText(/custody/i)).not.toBeInTheDocument();
		expect(screen.queryByText(/archive reference/i)).not.toBeInTheDocument();
		// The status changes when the caller finishes anchoring, so it is announced.
		expect(screen.getAllByRole("status").length).toBeGreaterThan(0);
	});

	it("renders an anchored chain head with the archive's reference and time", () => {
		render(
			<EvidenceView
				rows={[VERDICT_ROW]}
				anchor={{
					status: "anchored",
					reference: "archive/incident-1/head",
					anchoredAtUtc: "2026-09-13T00:00:10.000Z",
					reason: "archive_confirmed_digest",
				}}
			/>,
		);

		expect(screen.getByText("Anchored")).toBeInTheDocument();
		expect(screen.getByText("archive/incident-1/head")).toBeInTheDocument();
		expect(screen.getByText("2026-09-13T00:00:10.000Z")).toBeInTheDocument();
		expect(screen.queryByText("Unanchored")).not.toBeInTheDocument();
	});

	it("shows per-device logical counters and reports an unreported skew as unreported", () => {
		render(<EvidenceView rows={[VERDICT_ROW]} chain={VERIFIED_CHAIN} />);

		expect(screen.getByText("installation-1111")).toBeInTheDocument();
		expect(screen.getByText("9")).toBeInTheDocument();
		expect(screen.getByText(/Chain verified: 4 record\(s\) checked; head receipt-4/)).toBeInTheDocument();
		expect(screen.getByText(/not reported by any record/)).toBeInTheDocument();
		expect(screen.queryByText(/in sync/i)).not.toBeInTheDocument();
		expect(screen.queryByText(/0 ms/)).not.toBeInTheDocument();
	});

	it("never presents an unverifiable chain as verified", () => {
		render(
			<EvidenceView
				rows={[VERDICT_ROW]}
				chain={{
					valid: false,
					checked: 3,
					head: null,
					findings: [{ code: "chain_link_mismatch", receiptId: "receipt-2" }],
					devices: [{ deviceId: "installation-1111", maxLogicalCounter: 5, receipts: 3 }],
					maxObservedSkewMs: 3_600_000,
				}}
			/>,
		);

		expect(screen.getByText(/Chain not verifiable: 1 finding\(s\)/)).toBeInTheDocument();
		expect(screen.getByText(/chain_link_mismatch/)).toBeInTheDocument();
		expect(screen.queryByText(/Chain verified/)).not.toBeInTheDocument();
		// A skew that was observed is reported as the number it was.
		expect(screen.getByText(/Largest observed clock skew: 3600000 ms/)).toBeInTheDocument();
	});
});
