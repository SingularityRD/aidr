import { type FormEvent, useCallback, useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import { useRichT, useT } from "../../i18n/I18nProvider";
import { stepUpPath } from "../../lib/ai-governance";
import {
	createDetectionException,
	DETECTION_EXCEPTION_MAX_DAYS,
	type DetectionExceptionRow,
	draftFromQuery,
	draftProblem,
	type ExceptionDraft,
	exceptionErrorMessage,
	exceptionState,
	listDetectionExceptions,
	revokeDetectionException,
	SUBJECT_KINDS,
	SUBJECT_LABEL,
	type SubjectKind,
} from "../../lib/detection-exceptions";

type Load =
	| { kind: "loading" }
	| { kind: "error"; code: string }
	| { kind: "ready"; rows: DetectionExceptionRow[] };

const STATE_BADGE = {
	active: "badge badge-ask",
	expired: "badge badge-info",
	revoked: "badge badge-info",
} as const;

const STATE_LABEL = {
	active: "dex.state.active",
	expired: "dex.state.expired",
	revoked: "dex.state.revoked",
} as const satisfies Record<keyof typeof STATE_BADGE, DashboardMessageKey>;

function isoDay(ms: number): string {
	return new Date(ms).toISOString().slice(0, 10);
}

/** Time-limited detection exceptions: owners and admins only (AAL2 on the server). */
export function DetectionExceptionsPage() {
	const t = useT();
	const { currentTeam, currentRole, isLoading, roleResolved } = useTeam();
	if (isLoading || (currentTeam && !roleResolved)) {
		return <div role="status">{t("gsc.resolving")}</div>;
	}
	if (!currentTeam) return <div role="alert">{t("dex.selectTeam")}</div>;
	if (currentRole !== "owner" && currentRole !== "admin") {
		return (
			<section className="card">
				<h1>{t("dex.title")}</h1>
				<div className="notice" role="alert">
					{t("dex.err.forbidden")}
				</div>
			</section>
		);
	}
	return <TenantDetectionExceptions key={currentTeam.id} tenantId={currentTeam.id} />;
}

function TenantDetectionExceptions({ tenantId }: { tenantId: string }) {
	const t = useT();
	const richT = useRichT();
	const { members } = useTeam();
	const [load, setLoad] = useState<Load>({ kind: "loading" });
	const [tick, setTick] = useState(0);
	const [notice, setNotice] = useState<{
		tone: "ok" | "error";
		text: string;
		stepUp?: boolean;
	} | null>(null);
	const [busy, setBusy] = useState(false);
	const location = useLocation();
	const [prefilled] = useState(() => new URLSearchParams(location.search).has("rule"));
	const [draft, setDraft] = useState<ExceptionDraft>(() =>
		draftFromQuery(location.search, Date.now()),
	);

	useEffect(() => {
		let cancelled = false;
		void listDetectionExceptions(tenantId).then((result) => {
			if (cancelled) return;
			setLoad(
				result.ok ? { kind: "ready", rows: result.value } : { kind: "error", code: result.error },
			);
		});
		return () => {
			cancelled = true;
		};
	}, [tenantId, tick]);

	const report = useCallback(
		(code: string) => {
			setNotice({
				tone: "error",
				text: exceptionErrorMessage(code, t),
				stepUp: code === "mfa_required",
			});
		},
		[t],
	);

	const submit = useCallback(
		async (event: FormEvent) => {
			event.preventDefault();
			const problem = draftProblem(draft, Date.now(), t);
			if (problem) {
				setNotice({ tone: "error", text: problem });
				return;
			}
			setBusy(true);
			const result = await createDetectionException(tenantId, draft);
			setBusy(false);
			if (!result.ok) {
				report(result.error);
				return;
			}
			setNotice({
				tone: "ok",
				text: t("dex.added", { rule: draft.ruleId.trim(), date: draft.endDate }),
			});
			setDraft((previous) => ({ ...previous, ruleId: "", reason: "", artifactSha256: "" }));
			setTick((value) => value + 1);
		},
		[draft, tenantId, report, t],
	);

	const revoke = useCallback(
		async (row: DetectionExceptionRow) => {
			const reason = window.prompt(t("dex.revokePrompt", { rule: row.ruleId }));
			if (!reason?.trim()) return;
			setBusy(true);
			const result = await revokeDetectionException(tenantId, row.id, reason);
			setBusy(false);
			if (!result.ok) {
				report(result.error);
				return;
			}
			setNotice({ tone: "ok", text: t("dex.revoked", { rule: row.ruleId }) });
			setTick((value) => value + 1);
		},
		[tenantId, report, t],
	);

	const memberEmail = (userId: string) =>
		members.find((m) => m.user_id === userId)?.email ?? userId;
	const now = Date.now();

	return (
		<section className="card">
			<h1>{t("dex.title")}</h1>
			<p>{t("dex.lead", { days: DETECTION_EXCEPTION_MAX_DAYS })}</p>

			{notice ? (
				<div
					className={notice.tone === "ok" ? "notice" : "notice notice-error"}
					role={notice.tone === "ok" ? "status" : "alert"}
				>
					{notice.text}{" "}
					{notice.stepUp ? <Link to={stepUpPath(tenantId)}>{t("dex.verifyNow")}</Link> : null}
				</div>
			) : null}

			<form onSubmit={submit} aria-label={t("dex.addLabel")}>
				<h2>{t("dex.addTitle")}</h2>
				{prefilled ? (
					<div className="notice" role="status">
						{t("dex.prefilled")}
					</div>
				) : null}
				<label>
					{t("dex.ruleId")}
					<input
						value={draft.ruleId}
						onChange={(e) => setDraft({ ...draft, ruleId: e.target.value })}
						// i18n-exempt: sample rule id
						placeholder="CLT-CMD-011"
						maxLength={100}
						required
					/>
				</label>
				<label>
					{t("dex.appliesTo")}
					<select
						value={draft.subjectKind}
						onChange={(e) =>
							setDraft({ ...draft, subjectKind: e.target.value as SubjectKind, subject: "" })
						}
					>
						{SUBJECT_KINDS.map((kind) => (
							<option key={kind} value={kind}>
								{t(SUBJECT_LABEL[kind])}
							</option>
						))}
					</select>
				</label>
				{draft.subjectKind === "user" ? (
					<label>
						{t("dex.member")}
						<select
							value={draft.subject}
							onChange={(e) => setDraft({ ...draft, subject: e.target.value })}
							required
						>
							<option value="">{t("dex.chooseMember")}</option>
							{members.map((m) => (
								<option key={m.user_id} value={m.user_id}>
									{m.email || m.user_id}
								</option>
							))}
						</select>
					</label>
				) : (
					<label>
						{draft.subjectKind === "agent" ? t("dex.agentId") : t("dex.repo")}
						<input
							value={draft.subject}
							onChange={(e) => setDraft({ ...draft, subject: e.target.value })}
							maxLength={512}
							required
						/>
					</label>
				)}
				<label>
					{t("dex.endsOn")}
					<input
						type="date"
						value={draft.endDate}
						min={isoDay(now + 86_400_000)}
						max={isoDay(now + DETECTION_EXCEPTION_MAX_DAYS * 86_400_000)}
						onChange={(e) => setDraft({ ...draft, endDate: e.target.value })}
						required
					/>
				</label>
				<label>
					{t("dex.reason")}
					<textarea
						value={draft.reason}
						onChange={(e) => setDraft({ ...draft, reason: e.target.value })}
						maxLength={500}
						required
					/>
				</label>
				<label>
					{richT("dex.artifact", { command: <code>aidr exception</code> })}
					<input
						value={draft.artifactSha256}
						onChange={(e) => setDraft({ ...draft, artifactSha256: e.target.value })}
						maxLength={64}
					/>
				</label>
				<button className="button" type="submit" disabled={busy}>
					{t("dex.add")}
				</button>
			</form>

			<h2>{t("dex.list")}</h2>
			{load.kind === "loading" ? <div role="status">{t("dex.loading")}</div> : null}
			{load.kind === "error" ? (
				<div className="notice notice-error" role="alert">
					{exceptionErrorMessage(load.code, t)}{" "}
					{load.code === "mfa_required" ? (
						<Link to={stepUpPath(tenantId)}>{t("dex.verifyNow")}</Link>
					) : null}
				</div>
			) : null}
			{load.kind === "ready" && load.rows.length === 0 ? <p>{t("dex.empty")}</p> : null}
			{load.kind === "ready" && load.rows.length > 0 ? (
				<table>
					<thead>
						<tr>
							<th>{t("dex.col.rule")}</th>
							<th>{t("dex.appliesTo")}</th>
							<th>{t("dex.col.ends")}</th>
							<th>{t("dex.col.state")}</th>
							<th>{t("dex.reason")}</th>
							<th />
						</tr>
					</thead>
					<tbody>
						{load.rows.map((row) => {
							const state = exceptionState(row, now);
							return (
								<tr key={row.id}>
									<td>
										<code>{row.ruleId}</code>
										{row.artifactSha256 ? (
											<div>{t("dex.oneArtifact", { digest: row.artifactSha256.slice(0, 12) })}</div>
										) : null}
									</td>
									<td>
										{t(SUBJECT_LABEL[row.subjectKind])}:{" "}
										{row.subjectKind === "user" ? memberEmail(row.subject) : row.subject}
									</td>
									<td>{new Date(row.expiresAt).toLocaleString()}</td>
									<td>
										<span className={STATE_BADGE[state]}>{t(STATE_LABEL[state])}</span>
									</td>
									<td>{row.reason}</td>
									<td>
										{state === "active" ? (
											<button
												className="button button-sm"
												type="button"
												disabled={busy}
												onClick={() => void revoke(row)}
											>
												{t("dex.revoke")}
											</button>
										) : null}
									</td>
								</tr>
							);
						})}
					</tbody>
				</table>
			) : null}
		</section>
	);
}
