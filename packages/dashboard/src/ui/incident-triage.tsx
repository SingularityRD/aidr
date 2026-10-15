import { type FormEvent, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import type { TeamMember } from "../enterprise/team-provider";
import { useT } from "../i18n/I18nProvider";
import { stepUpPath } from "../lib/ai-governance";
import {
	effectiveStatus,
	exceptionPrefillPath,
	INCIDENT_NOTE_MAX,
	INCIDENT_SNOOZE_MAX_DAYS,
	isSnoozed,
	TRIAGE_STATUS_LABEL,
	TRIAGE_STATUSES,
	type TriageDraft,
	type TriageHistoryRow,
	type TriageRow,
	type TriageStatus,
	triageDraftProblem,
	triageErrorMessage,
	triageHistory,
	updateTriage,
} from "../lib/incidents";

const TRIAGE_BADGE: Readonly<Record<TriageStatus, string>> = {
	open: "badge badge-deny",
	acknowledged: "badge badge-ask",
	resolved: "badge badge-info",
	false_positive: "badge badge-neutral",
};

export type TriageFilter = "active" | "snoozed" | "closed" | "all";
export const TRIAGE_FILTERS: readonly TriageFilter[] = ["active", "snoozed", "closed", "all"];

function isoDay(ms: number): string {
	return new Date(ms).toISOString().slice(0, 10);
}

function memberLabel(members: TeamMember[], userId: string | null): string {
	if (!userId) return "—";
	const member = members.find((m) => m.user_id === userId);
	return member?.email || `${userId.slice(0, 8)}…`;
}

/** Status, owner and the manage button of one incident row. */
export function TriageCells(props: {
	eventId: number;
	row: TriageRow | undefined;
	nowMs: number;
	members: TeamMember[];
	canTriage: boolean;
	onManage: (eventId: number) => void;
}) {
	const t = useT();
	const status = effectiveStatus(props.row);
	const snoozedUntil = isSnoozed(props.row, props.nowMs) ? props.row?.snoozedUntil : null;
	return (
		<>
			<td>
				<span className={TRIAGE_BADGE[status]}>{t(TRIAGE_STATUS_LABEL[status])}</span>
				{snoozedUntil ? (
					<div className="muted small">
						{t("inc.snoozedUntil", { date: snoozedUntil.slice(0, 10) })}
					</div>
				) : null}
			</td>
			<td>
				<TriageOwner members={props.members} userId={props.row?.ownerUserId ?? null} />
			</td>
			<td>
				<button
					className="button button-secondary button-sm"
					type="button"
					aria-label={t("inc.manageLabel", { id: props.eventId })}
					onClick={() => props.onManage(props.eventId)}
				>
					{props.canTriage ? t("inc.manage") : t("inc.details")}
				</button>
			</td>
		</>
	);
}

function TriageOwner({ members, userId }: { members: TeamMember[]; userId: string | null }) {
	const t = useT();
	return userId ? (
		<span>{memberLabel(members, userId)}</span>
	) : (
		<span className="muted">{t("inc.unassigned")}</span>
	);
}

interface PanelProps {
	tenantId: string;
	eventId: number;
	agentId: string;
	summary: string;
	ruleId: unknown;
	triage: TriageRow | undefined;
	canTriage: boolean;
	members: TeamMember[];
	onClose: () => void;
	onSaved: (row: TriageRow) => void;
}

/** Triage form, false-positive exception hand-off and audit trail of one incident. */
export function TriagePanel(props: PanelProps) {
	const { tenantId, eventId, triage, canTriage, members } = props;
	const t = useT();
	const [draft, setDraft] = useState<TriageDraft>(() => ({
		status: triage?.status ?? "open",
		ownerUserId: triage?.ownerUserId ?? "",
		note: triage?.resolutionNote ?? "",
		snoozeUntil: triage?.snoozedUntil ? triage.snoozedUntil.slice(0, 10) : "",
	}));
	const [busy, setBusy] = useState(false);
	const [notice, setNotice] = useState<{
		tone: "ok" | "error";
		text: string;
		stepUp?: boolean;
	} | null>(null);
	const [history, setHistory] = useState<TriageHistoryRow[] | null>(null);
	const [historyError, setHistoryError] = useState(false);
	const [tick, setTick] = useState(0);

	useEffect(() => {
		let cancelled = false;
		void triageHistory(tenantId, eventId).then((result) => {
			if (cancelled) return;
			if (result.ok) {
				setHistory(result.value);
				setHistoryError(false);
			} else setHistoryError(true);
		});
		return () => {
			cancelled = true;
		};
		// `tick` re-reads the history after a save.
	}, [tenantId, eventId, tick]);

	const exceptionPath =
		canTriage && triage?.status === "false_positive"
			? exceptionPrefillPath({
					ruleId: props.ruleId,
					agentId: props.agentId,
					note: triage.resolutionNote,
				})
			: null;

	async function submit(event: FormEvent) {
		event.preventDefault();
		const problem = triageDraftProblem(draft, Date.now(), t);
		if (problem) {
			setNotice({ tone: "error", text: problem });
			return;
		}
		setBusy(true);
		const result = await updateTriage(tenantId, eventId, triage?.version ?? 0, draft);
		setBusy(false);
		if (!result.ok) {
			setNotice({
				tone: "error",
				text: triageErrorMessage(result.error, t),
				stepUp: result.error === "mfa_required",
			});
			return;
		}
		setNotice({
			tone: "ok",
			text: t("inc.saved", { status: t(TRIAGE_STATUS_LABEL[result.value.status]) }),
		});
		props.onSaved(result.value);
		setTick((value) => value + 1);
	}

	return (
		<section className="card" aria-labelledby={`incident-${eventId}-triage`}>
			<div className="row space-between" style={{ alignItems: "flex-start" }}>
				<div>
					<h2 id={`incident-${eventId}-triage`}>{t("inc.panelTitle")}</h2>
					<p className="mono small">{props.summary}</p>
				</div>
				<button className="button button-secondary button-sm" type="button" onClick={props.onClose}>
					{t("inc.close")}
				</button>
			</div>
			{notice ? (
				<div
					className={notice.tone === "ok" ? "notice" : "notice notice-error"}
					role={notice.tone === "ok" ? "status" : "alert"}
				>
					{notice.text}{" "}
					{notice.stepUp ? <Link to={stepUpPath(tenantId)}>{t("inc.verifyNow")}</Link> : null}
				</div>
			) : null}
			{canTriage ? (
				<TriageForm
					draft={draft}
					setDraft={setDraft}
					members={members}
					busy={busy}
					onSubmit={submit}
				/>
			) : (
				<p className="muted small">{t("inc.readOnly")}</p>
			)}
			{exceptionPath ? (
				<p>
					<Link className="button button-secondary button-sm" to={exceptionPath}>
						{t("inc.createException")}
					</Link>{" "}
					<span className="muted small">{t("inc.createExceptionHint")}</span>
				</p>
			) : null}
			<h3>{t("inc.history")}</h3>
			<TriageHistoryList history={history} failed={historyError} members={members} />
		</section>
	);
}

/** Status, owner, note and snooze of one incident (owners and admins). */
function TriageForm(props: {
	draft: TriageDraft;
	setDraft: (draft: TriageDraft) => void;
	members: TeamMember[];
	busy: boolean;
	onSubmit: (event: FormEvent) => void;
}) {
	const t = useT();
	const { draft, setDraft, busy } = props;
	const assignable = props.members.filter((m) => m.role !== "viewer");
	const now = Date.now();
	const closing = draft.status === "resolved" || draft.status === "false_positive";
	return (
		<form onSubmit={props.onSubmit} aria-label={t("inc.formLabel")}>
			<label>
				{t("inc.col.status")}
				<select
					value={draft.status}
					onChange={(e) => {
						const status = e.target.value as TriageStatus;
						setDraft({
							...draft,
							status,
							snoozeUntil:
								status === "resolved" || status === "false_positive" ? "" : draft.snoozeUntil,
						});
					}}
				>
					{TRIAGE_STATUSES.map((status) => (
						<option key={status} value={status}>
							{t(TRIAGE_STATUS_LABEL[status])}
						</option>
					))}
				</select>
			</label>
			<label>
				{t("inc.col.owner")}
				<select
					value={draft.ownerUserId}
					onChange={(e) => setDraft({ ...draft, ownerUserId: e.target.value })}
				>
					<option value="">{t("inc.unassigned")}</option>
					{assignable.map((m) => (
						<option key={m.user_id} value={m.user_id}>
							{m.email || m.user_id}
						</option>
					))}
				</select>
			</label>
			<label>
				{closing ? t("inc.noteRequired") : t("inc.note")}
				<textarea
					value={draft.note}
					maxLength={INCIDENT_NOTE_MAX}
					onChange={(e) => setDraft({ ...draft, note: e.target.value })}
					required={closing}
				/>
			</label>
			{closing ? null : (
				<label>
					{t("inc.snoozeUntil", { days: INCIDENT_SNOOZE_MAX_DAYS })}
					<input
						type="date"
						value={draft.snoozeUntil}
						min={isoDay(now + 86_400_000)}
						max={isoDay(now + INCIDENT_SNOOZE_MAX_DAYS * 86_400_000)}
						onChange={(e) => setDraft({ ...draft, snoozeUntil: e.target.value })}
					/>
				</label>
			)}
			{draft.status === "false_positive" ? <p className="muted small">{t("inc.fpHint")}</p> : null}
			<button className="button" type="submit" disabled={busy}>
				{t("inc.save")}
			</button>
		</form>
	);
}

/** The append-only audit trail of one incident's triage. */
function TriageHistoryList(props: {
	history: TriageHistoryRow[] | null;
	failed: boolean;
	members: TeamMember[];
}) {
	const t = useT();
	const { history, members } = props;
	if (props.failed) {
		return (
			<div className="notice notice-error" role="alert">
				{t("inc.err.unavailable")}
			</div>
		);
	}
	if (history === null) return <div role="status">{t("inc.loadingHistory")}</div>;
	if (history.length === 0) return <p className="muted small">{t("inc.noHistory")}</p>;
	const line = (row: TriageHistoryRow) =>
		[
			t("inc.historyLine", {
				actor: memberLabel(members, row.actorUserId),
				from: row.fromStatus ? t(TRIAGE_STATUS_LABEL[row.fromStatus]) : t("inc.untriaged"),
				to: t(TRIAGE_STATUS_LABEL[row.toStatus]),
				owner: row.toOwnerUserId ? memberLabel(members, row.toOwnerUserId) : t("inc.unassigned"),
			}),
			row.snoozedUntil ? t("inc.snoozedUntil", { date: row.snoozedUntil.slice(0, 10) }) : null,
			row.selfClosure ? t("inc.selfClosure") : null,
		]
			.filter(Boolean)
			.join(" · ");
	return (
		<ul className="small" aria-label={t("inc.history")}>
			{history.map((row) => (
				<li key={row.id}>
					<span className="mono">{new Date(row.createdAt).toLocaleString()}</span> · {line(row)}
					{row.note ? <div className="muted">{row.note}</div> : null}
				</li>
			))}
		</ul>
	);
}
