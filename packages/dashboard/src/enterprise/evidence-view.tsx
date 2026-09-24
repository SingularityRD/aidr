/**
 * Evidence view — the incident-correlation and evidence-chain half of the audit
 * surface.
 *
 * The flat audit table renders one row per record, which loses the one thing the
 * stored payload already carries: the correlation id that ties a multi-step
 * response — including its rollback — to the incident that triggered it. This
 * view groups that id within the producing agent, renders response steps in the
 * order they happened, and reports the receipt clock state per device.
 *
 * Two rules from the core's `incidents/evidence-receipt.ts` are load-bearing:
 *
 *   - the per-device logical counter, not the host wall clock, is the
 *     authoritative order, and a skew that no record reported is reported as
 *     *not reported* — never smoothed into "in sync";
 *   - a chain head is `anchored` only when an archive returned proof for that
 *     exact digest. With no `EvidenceArchiveSink` configured the core answers
 *     `unanchored` (`no_archive_sink`), and this view says exactly that: the
 *     receipts shown are local records, not archive custody.
 *
 * The dashboard package deliberately does not depend on `@singularityrd/aidr-core`,
 * so the types below mirror the `EvidenceClock`, `EvidenceChainVerification` and
 * `EvidenceAnchorOutcome` values that module produces, and the caller passes in
 * what the core computed. Nothing here verifies, upgrades or recomputes a
 * status, and no status is inferred from message text.
 */

import { useMemo } from "react";

/* ── Status unions ────────────────────────────────────────────────────────
 *
 * Every status is a closed union rendered through a total map. The dashboard
 * learned this the hard way (`enterprise/auth.tsx`): a
 * `status.includes("Failed") || status.includes("error")` check styled every
 * other failure — including a missing backend — as a neutral, success-looking
 * notice. Nothing below inspects a message string.
 */

type EvidenceDecision = "allow" | "ask" | "deny" | "unrecorded";

type EvidenceResponseAction =
	| "block"
	| "contain"
	| "quarantine"
	| "notify"
	| "snapshot"
	| "rollback"
	| "unrecorded";

type EvidenceResponseOutcome = "success" | "failure" | "skipped" | "unavailable" | "unrecorded";

type EvidenceAnchorStatus = "anchored" | "unanchored";

const DECISION_VALUES: readonly string[] = ["allow", "ask", "deny"];
const RESPONSE_ACTION_VALUES: readonly string[] = [
	"block",
	"contain",
	"quarantine",
	"notify",
	"snapshot",
	"rollback",
];
const RESPONSE_OUTCOME_VALUES: readonly string[] = ["success", "failure", "skipped", "unavailable"];

const DECISION_LABEL: Record<EvidenceDecision, string> = {
	allow: "Allow",
	ask: "Ask",
	deny: "Deny",
	unrecorded: "Decision not recorded",
};

const DECISION_CLASS: Record<EvidenceDecision, string> = {
	allow: "badge badge-allow",
	ask: "badge badge-ask",
	deny: "badge badge-deny",
	unrecorded: "badge badge-neutral",
};

/** Strongest decision wins when one incident holds several verdicts. */
const DECISION_RANK: Record<EvidenceDecision, number> = {
	deny: 3,
	ask: 2,
	allow: 1,
	unrecorded: 0,
};

const RESPONSE_ACTION_LABEL: Record<EvidenceResponseAction, string> = {
	block: "Block",
	contain: "Contain",
	quarantine: "Quarantine",
	notify: "Notify",
	snapshot: "Snapshot",
	rollback: "Rollback",
	unrecorded: "Response not recorded",
};

const RESPONSE_ACTION_CLASS: Record<EvidenceResponseAction, string> = {
	block: "badge badge-deny",
	contain: "badge badge-error",
	quarantine: "badge badge-warning",
	notify: "badge badge-info",
	snapshot: "badge badge-neutral",
	rollback: "badge badge-high",
	unrecorded: "badge badge-neutral",
};

const RESPONSE_OUTCOME_LABEL: Record<EvidenceResponseOutcome, string> = {
	success: "Success",
	failure: "Failed",
	skipped: "Skipped",
	unavailable: "Unavailable",
	unrecorded: "Outcome not recorded",
};

const RESPONSE_OUTCOME_CLASS: Record<EvidenceResponseOutcome, string> = {
	success: "badge badge-success",
	failure: "badge badge-error",
	skipped: "badge badge-neutral",
	unavailable: "badge badge-warning",
	unrecorded: "badge badge-neutral",
};

/* ── Mirrors of the core's evidence-receipt types ─────────────────────────── */

/** Mirror of the core's `EvidenceClock`. */
interface EvidenceClock {
	/** Host wall clock, ISO-8601 UTC. Untrusted; used only as a tie-breaker. */
	wallClockUtc: string;
	/** Monotonic per-device counter. The authoritative ordering key. */
	logicalCounter: number;
	/** Last observed skew against the control plane, in ms, when known. */
	observedSkewMs: number | null;
}

/** Mirror of the device summary inside the core's `EvidenceChainVerification`. */
interface EvidenceDeviceClock {
	deviceId: string;
	maxLogicalCounter: number;
	receipts: number;
}

/** Mirror of the core's `EvidenceChainVerification`. */
export interface EvidenceChainVerification {
	valid: boolean;
	checked: number;
	/** The chain head, present only when the chain verified. */
	head: { receiptId: string; receiptHash: string; logicalCounter: number } | null;
	findings: readonly { code: string; receiptId?: string; detail?: string }[];
	devices: readonly EvidenceDeviceClock[];
	/** Largest observed clock skew among receipts that reported one. */
	maxObservedSkewMs: number | null;
}

/** Mirror of the core's `EvidenceAnchorOutcome`. */
interface EvidenceAnchorOutcome {
	/** `anchored` only when an archive returned proof for this exact digest. */
	status: EvidenceAnchorStatus;
	reference: string | null;
	anchoredAtUtc: string | null;
	reason: string;
}

/* ── Input rows ─────────────────────────────────────────────────────────── */

/**
 * One audit record. `payload` is the stored payload verbatim: the correlation
 * id, the response steps and the receipt clock are read from it, never from a
 * pre-digested copy that could disagree with the record it came from.
 */
export interface EvidenceAuditRow {
	id: string;
	/** The record's kind or action, e.g. `runtime_verdict` or `response_action`. */
	action: string;
	/** Epoch milliseconds the record was written. */
	timestampMs: number;
	/** Actor that produced the record, when the store carries one. */
	actor?: string;
	/** Agent that produced the record, when the store carries one. */
	agentId?: string;
	payload: Readonly<Record<string, unknown>>;
}

export interface EvidenceViewProps {
	/** Audit records to group and render. */
	rows: readonly EvidenceAuditRow[];
	/** Result of the core's `verifyEvidenceChain`, when the caller has one. */
	chain?: EvidenceChainVerification | null;
	/** Result of the core's `anchorEvidenceHead`. Absent renders `unanchored`. */
	anchor?: EvidenceAnchorOutcome | null;
	/** True while the caller is still loading rows. */
	isLoading?: boolean;
	/** Caller-side load failure. The view never invents a clean result. */
	error?: string | null;
}

/* ── Payload readers ────────────────────────────────────────────────────── */

function asRecord(value: unknown): Record<string, unknown> | null {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
	return value as Record<string, unknown>;
}

function asString(value: unknown): string | null {
	return typeof value === "string" && value.length > 0 ? value : null;
}

function fromUnion<T extends string>(value: unknown, allowed: readonly string[], missing: T): T {
	return typeof value === "string" && allowed.includes(value) ? (value as T) : missing;
}

function readDecision(payload: Readonly<Record<string, unknown>>): EvidenceDecision {
	const raw = asString(payload.decision) ?? asString(payload.verdict);
	return fromUnion(raw, DECISION_VALUES, "unrecorded");
}

/**
 * Read the receipt clock a payload carries, in either shape the pipeline emits:
 * the receipt's nested `clock` object, or flattened `logical_counter` /
 * `observed_skew_ms` fields. An incomplete clock is treated as absent rather
 * than guessed at.
 */
function readClock(payload: Readonly<Record<string, unknown>>): EvidenceClock | null {
	const nested = asRecord(payload.clock);
	const source = nested ?? payload;
	const counter = source.logicalCounter ?? source.logical_counter;
	const wallClockUtc = asString(source.wallClockUtc) ?? asString(source.wall_clock_utc);
	if (!Number.isSafeInteger(counter) || (counter as number) < 0 || wallClockUtc === null) return null;
	const skew = source.observedSkewMs ?? source.observed_skew_ms;
	return {
		wallClockUtc,
		logicalCounter: counter as number,
		observedSkewMs: Number.isSafeInteger(skew) ? (skew as number) : null,
	};
}

/** Device identity as the receipt binding carries it; never inferred from a hostname. */
function readDeviceId(payload: Readonly<Record<string, unknown>>): string | null {
	const binding = asRecord(payload.binding);
	return (
		asString(payload.device_id) ??
		asString(payload.deviceId) ??
		(binding ? (asString(binding.deviceId) ?? asString(binding.device_id)) : null)
	);
}

/** Correlation id keys, in the order the pipeline emits them. */
const INCIDENT_ID_KEYS = ["incident_id", "incidentId", "correlation_id", "correlationId"] as const;
const SESSION_ID_KEYS = ["session_id", "sessionId"] as const;

export interface EvidenceCorrelationScope {
	kind: "incident" | "session";
	id: string;
}

/**
 * The correlation the payload already carries. An incident-scoped id wins: a row
 * that names its incident belongs to it whatever session produced it. A row that
 * only names a session is grouped as session-scoped and labelled as such, and a
 * row with neither is reported as uncorrelated instead of being merged into a
 * neighbouring incident.
 */
export function correlationScopeOf(
	payload: Readonly<Record<string, unknown>>,
): EvidenceCorrelationScope | null {
	for (const key of INCIDENT_ID_KEYS) {
		const id = asString(payload[key]);
		if (id) return { kind: "incident", id };
	}
	for (const key of SESSION_ID_KEYS) {
		const id = asString(payload[key]);
		if (id) return { kind: "session", id };
	}
	return null;
}

/* ── Derived models ─────────────────────────────────────────────────────── */

interface ResponseStep {
	observedAtMs: number;
	action: EvidenceResponseAction;
	outcome: EvidenceResponseOutcome;
	target: string | null;
	snapshotId: string | null;
	reason: string | null;
}

interface EvidenceIncidentGroup {
	key: string;
	scope: EvidenceCorrelationScope | null;
	rows: EvidenceAuditRow[];
	steps: ResponseStep[];
	decision: EvidenceDecision;
	firstObservedAtMs: number;
	lastObservedAtMs: number;
}

function byObservedAt(a: { timestampMs: number; id: string }, b: { timestampMs: number; id: string }): number {
	return a.timestampMs - b.timestampMs || a.id.localeCompare(b.id);
}

function parseStep(value: unknown, observedAtMs: number): ResponseStep | null {
	const raw = asRecord(value);
	if (!raw) return null;
	return {
		observedAtMs,
		action: fromUnion(asString(raw.action), RESPONSE_ACTION_VALUES, "unrecorded"),
		outcome: fromUnion(asString(raw.outcome), RESPONSE_OUTCOME_VALUES, "unrecorded"),
		target: asString(raw.target),
		snapshotId: asString(raw.snapshot_id) ?? asString(raw.snapshotId),
		reason: asString(raw.reason) ?? asString(raw.detail),
	};
}

/**
 * The response steps a payload carries: an `actions` array, or a single step
 * flattened onto the record. A step that cannot be read at all is reported as
 * `unrecorded` rather than dropped, so a response never silently disappears.
 */
function parseSteps(row: EvidenceAuditRow): ResponseStep[] {
	const actions = row.payload.actions;
	if (Array.isArray(actions)) {
		const steps: ResponseStep[] = [];
		for (const entry of actions) {
			const step = parseStep(entry, row.timestampMs);
			if (step) steps.push(step);
		}
		return steps;
	}
	if (typeof row.payload.action === "string") {
		const step = parseStep(row.payload, row.timestampMs);
		if (step) return [step];
	}
	return [];
}

function groupIncidents(rows: readonly EvidenceAuditRow[]): EvidenceIncidentGroup[] {
	const groups = new Map<string, EvidenceIncidentGroup>();
	for (const row of rows) {
		const scope = correlationScopeOf(row.payload);
		const key = JSON.stringify([row.agentId ?? null, scope?.kind ?? null, scope?.id ?? null]);
		const group = groups.get(key) ?? {
			key,
			scope,
			rows: [],
			steps: [],
			decision: "unrecorded" as EvidenceDecision,
			firstObservedAtMs: row.timestampMs,
			lastObservedAtMs: row.timestampMs,
		};
		group.rows.push(row);
		group.steps.push(...parseSteps(row));
		const decision = readDecision(row.payload);
		if (DECISION_RANK[decision] > DECISION_RANK[group.decision]) group.decision = decision;
		groups.set(key, group);
	}

	for (const group of groups.values()) {
		group.rows.sort(byObservedAt);
		group.steps.sort((a, b) => a.observedAtMs - b.observedAtMs);
		const first = group.rows[0];
		const last = group.rows[group.rows.length - 1];
		if (first) group.firstObservedAtMs = first.timestampMs;
		if (last) group.lastObservedAtMs = last.timestampMs;
	}

	// Newest activity first; the uncorrelated bucket always sorts last so it can
	// never be mistaken for an incident.
	return [...groups.values()].sort((a, b) => {
		if (a.scope === null || b.scope === null) {
			if (a.scope === null && b.scope === null) return 0;
			return a.scope === null ? 1 : -1;
		}
		return b.lastObservedAtMs - a.lastObservedAtMs || a.key.localeCompare(b.key);
	});
}

interface ClockSummary {
	source: "chain" | "rows";
	devices: EvidenceDeviceClock[];
	maxObservedSkewMs: number | null;
	/** Rows that carry a clock but no device id; never attributed to an invented device. */
	unattributedClockRows: number;
}

/** Same aggregation the core's `verifyEvidenceChain` performs over receipts. */
function clockSummaryOf(rows: readonly EvidenceAuditRow[]): ClockSummary {
	const devices = new Map<string, { maxLogicalCounter: number; receipts: number }>();
	let maxObservedSkewMs: number | null = null;
	let unattributedClockRows = 0;
	for (const row of rows) {
		const clock = readClock(row.payload);
		if (!clock) continue;
		if (clock.observedSkewMs !== null) {
			const observed = Math.abs(clock.observedSkewMs);
			maxObservedSkewMs =
				maxObservedSkewMs === null ? observed : Math.max(maxObservedSkewMs, observed);
		}
		const deviceId = readDeviceId(row.payload);
		if (deviceId === null) {
			unattributedClockRows += 1;
			continue;
		}
		const entry = devices.get(deviceId) ?? { maxLogicalCounter: 0, receipts: 0 };
		entry.maxLogicalCounter = Math.max(entry.maxLogicalCounter, clock.logicalCounter);
		entry.receipts += 1;
		devices.set(deviceId, entry);
	}
	return {
		source: "rows",
		devices: [...devices.entries()]
			.map(([deviceId, value]) => ({ deviceId, ...value }))
			.sort((a, b) => (a.deviceId < b.deviceId ? -1 : a.deviceId > b.deviceId ? 1 : 0)),
		maxObservedSkewMs,
		unattributedClockRows,
	};
}

function formatObserved(ms: number): string {
	return Number.isFinite(ms) ? new Date(ms).toLocaleString() : "time not recorded";
}

/* ── Panels ─────────────────────────────────────────────────────────────── */

/**
 * Anchored versus unanchored. `anchored` is an archive's own assertion for the
 * submitted digest; everything else is an open evidence gap, and the only thing
 * this panel may say about a local chain is that it is local.
 */
function AnchorPanel({ anchor }: { anchor: EvidenceAnchorOutcome | null }) {
	const anchored = anchor?.status === "anchored";
	return (
		<div className="notice" role="status" aria-live="polite">
			<span className={anchored ? "badge badge-success" : "badge badge-warning"}>
				{anchored ? "Anchored" : "Unanchored"}
			</span>
			{anchored && anchor ? (
				<span>
					{" "}
					Archive reference <span className="mono">{anchor.reference ?? "reference not reported"}</span>{" "}
					at <span className="mono">{anchor.anchoredAtUtc ?? "time not reported"}</span>.
				</span>
			) : (
				<span>
					{" "}
					No archive returned proof for this chain head, so the records shown here are local
					records.{" "}
					{anchor ? (
						<span className="mono">{anchor.reason}</span>
					) : (
						<span>No anchor result was supplied.</span>
					)}
				</span>
			)}
		</div>
	);
}

function ClockPanel({
	summary,
	chain,
	isLoading,
}: {
	summary: ClockSummary;
	chain: EvidenceChainVerification | null;
	isLoading: boolean;
}) {
	return (
		<div style={{ marginTop: 14 }}>
			<h3 style={{ margin: 0, fontSize: "var(--text-base)" }}>Device clocks</h3>
			<p className="muted small">
				Ordering is by the per-device logical counter, never by the host wall clock. A skew no
				record reported is shown as not reported.
			</p>

			{isLoading ? (
				<p className="muted" role="status" aria-live="polite">
					Loading evidence records…
				</p>
			) : null}

			{summary.devices.length === 0 ? (
				<p className="muted" role="status" aria-live="polite">
					No device logical clock is recorded in these rows.
					{summary.source === "rows"
						? " Wall-clock time is the only ordering available for them."
						: ""}
				</p>
			) : (
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>Device</th>
								<th>Highest logical counter</th>
								<th>Records</th>
							</tr>
						</thead>
						<tbody>
							{summary.devices.map((device) => (
								<tr key={device.deviceId}>
									<td className="mono">{device.deviceId}</td>
									<td className="mono">{device.maxLogicalCounter}</td>
									<td className="mono">{device.receipts}</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}

			<p className="muted small" role="status" aria-live="polite">
				Largest observed clock skew:{" "}
				{summary.maxObservedSkewMs === null
					? "not reported by any record"
					: `${summary.maxObservedSkewMs} ms`}
			</p>

			{summary.unattributedClockRows > 0 ? (
				<p className="muted small" role="status" aria-live="polite">
					{summary.unattributedClockRows} record(s) carry a logical clock but no device id, so they
					are not attributed to a device.
				</p>
			) : null}

			<p className="muted small" role="status" aria-live="polite">
				{chain === null
					? "No receipt-chain verification was supplied for these rows; the counters above are read straight from the records."
					: chain.valid && chain.head
						? `Chain verified: ${chain.checked} record(s) checked; head ${chain.head.receiptId} at logical counter ${chain.head.logicalCounter}.`
						: `Chain not verifiable: ${chain.findings.length} finding(s) reported (${chain.findings
								.map((finding) => finding.code)
								.join(", ")}).`}
			</p>
		</div>
	);
}

function describeStep(step: ResponseStep): string {
	const target = step.target ?? "target not recorded";
	const snapshot = step.snapshotId ? ` (snapshot ${step.snapshotId})` : "";
	const reason = step.reason ? ` — ${step.reason}` : "";
	if (step.action === "rollback") return `restored ${target}${snapshot}${reason}`;
	if (step.action === "snapshot") return `preserved ${target}${snapshot}${reason}`;
	return `${target}${snapshot}${reason}`;
}

function StepItem({ step }: { step: ResponseStep }) {
	return (
		<li className="row" style={{ gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
			<span className={RESPONSE_ACTION_CLASS[step.action]}>{RESPONSE_ACTION_LABEL[step.action]}</span>
			<span className="mono" style={{ fontSize: 12 }}>
				{describeStep(step)}
			</span>
			<span className={RESPONSE_OUTCOME_CLASS[step.outcome]}>
				{RESPONSE_OUTCOME_LABEL[step.outcome]}
			</span>
			<span className="muted small">{formatObserved(step.observedAtMs)}</span>
		</li>
	);
}

function IncidentGroup({ group }: { group: EvidenceIncidentGroup }) {
	const scope = group.scope;
	const heading = scope ? (scope.kind === "incident" ? "Incident " : "Session ") : "Uncorrelated — ";
	const agents = [
		...new Set(group.rows.map((row) => row.agentId).filter((id): id is string => Boolean(id))),
	].sort();
	const agentLabel = agents.length > 0 ? `agent ${agents.join(", ")}` : "agent not recorded";
	const listLabel = scope
		? `Response steps for ${scope.id} on ${agentLabel}`
		: `Response steps for uncorrelated records on ${agentLabel}`;
	const observed =
		group.firstObservedAtMs === group.lastObservedAtMs
			? formatObserved(group.firstObservedAtMs)
			: `${formatObserved(group.firstObservedAtMs)} to ${formatObserved(group.lastObservedAtMs)}`;
	// Provenance per record, not an identity graph: the agent ids the records
	// themselves name, and nothing inferred from them.

	return (
		<section className="card" aria-label={`${heading}${scope ? scope.id : "records"}, ${agentLabel}`}>
			<div className="row space-between" style={{ alignItems: "baseline" }}>
				<h3 style={{ margin: 0, fontSize: "var(--text-base)" }}>
					{heading}
					<span className="mono">{scope ? scope.id : "no correlation id in payload"}</span>
				</h3>
				<span className={DECISION_CLASS[group.decision]}>{DECISION_LABEL[group.decision]}</span>
			</div>
			<p className="muted small">
				{group.rows.length} record(s), {group.steps.length} response step(s) — observed {observed}
				{agents.length > 0 ? ` · agent ${agents.join(", ")}` : ""}
			</p>
			{group.steps.length > 0 ? (
				<ol aria-label={listLabel} style={{ margin: 0, paddingLeft: 18 }}>
					{group.steps.map((step, index) => (
						<StepItem key={`${step.observedAtMs}-${index}-${step.action}`} step={step} />
					))}
				</ol>
			) : (
				<p className="muted small">
					No response step is recorded in this payload. That is the absence of a step here, not
					evidence that no response was taken elsewhere.
				</p>
			)}
		</section>
	);
}

/* ── View ───────────────────────────────────────────────────────────────── */

export function EvidenceView({
	rows,
	chain = null,
	anchor = null,
	isLoading = false,
	error = null,
}: EvidenceViewProps) {
	const incidents = useMemo(() => groupIncidents(rows), [rows]);
	const rowSummary = useMemo(() => clockSummaryOf(rows), [rows]);
	const summary = useMemo<ClockSummary>(
		() =>
			chain
				? {
						source: "chain",
						devices: [...chain.devices],
						maxObservedSkewMs: chain.maxObservedSkewMs,
						unattributedClockRows: rowSummary.unattributedClockRows,
					}
				: rowSummary,
		[chain, rowSummary],
	);

	return (
		<div className="stack">
			<div className="card">
				<h2 style={{ margin: 0 }}>Evidence chain</h2>
				<p className="muted small">
					Grouped by the agent attached to each record and its payload correlation id. Response steps
					are shown in the order they were observed, including any rollback.
				</p>
				<AnchorPanel anchor={anchor} />
				<ClockPanel summary={summary} chain={chain} isLoading={isLoading} />
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}
			</div>

			{incidents.length === 0
				? error === null && (
						<div className="card">
							<p className="muted">
								{isLoading ? "Loading evidence records…" : "No audit records were supplied."}
							</p>
						</div>
					)
				: incidents.map((group) => <IncidentGroup key={group.key} group={group} />)}
		</div>
	);
}
