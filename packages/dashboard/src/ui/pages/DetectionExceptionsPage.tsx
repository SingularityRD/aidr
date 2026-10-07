import { type FormEvent, useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import { stepUpPath } from "../../lib/ai-governance";
import {
	createDetectionException,
	DETECTION_EXCEPTION_MAX_DAYS,
	type DetectionExceptionRow,
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

function isoDay(ms: number): string {
	return new Date(ms).toISOString().slice(0, 10);
}

/** Time-limited detection exceptions: owners and admins only (AAL2 on the server). */
export function DetectionExceptionsPage() {
	const { currentTeam, currentRole, isLoading, roleResolved } = useTeam();
	if (isLoading || (currentTeam && !roleResolved)) {
		return <div role="status">Resolving the managed tenant…</div>;
	}
	if (!currentTeam) return <div role="alert">Select a team to manage detection exceptions.</div>;
	if (currentRole !== "owner" && currentRole !== "admin") {
		return (
			<section className="card">
				<h1>Detection exceptions</h1>
				<div className="notice" role="alert">
					Only workspace owners and admins can manage detection exceptions.
				</div>
			</section>
		);
	}
	return <TenantDetectionExceptions key={currentTeam.id} tenantId={currentTeam.id} />;
}

function TenantDetectionExceptions({ tenantId }: { tenantId: string }) {
	const { members } = useTeam();
	const [load, setLoad] = useState<Load>({ kind: "loading" });
	const [tick, setTick] = useState(0);
	const [notice, setNotice] = useState<{
		tone: "ok" | "error";
		text: string;
		stepUp?: boolean;
	} | null>(null);
	const [busy, setBusy] = useState(false);
	const [draft, setDraft] = useState<ExceptionDraft>(() => ({
		ruleId: "",
		subjectKind: "user",
		subject: "",
		endDate: isoDay(Date.now() + 7 * 86_400_000),
		reason: "",
		artifactSha256: "",
	}));

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

	const report = useCallback((code: string) => {
		setNotice({
			tone: "error",
			text: exceptionErrorMessage(code),
			stepUp: code === "mfa_required",
		});
	}, []);

	const submit = useCallback(
		async (event: FormEvent) => {
			event.preventDefault();
			const problem = draftProblem(draft, Date.now());
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
				text: `Exception added for ${draft.ruleId.trim()} until ${draft.endDate}.`,
			});
			setDraft((previous) => ({ ...previous, ruleId: "", reason: "", artifactSha256: "" }));
			setTick((value) => value + 1);
		},
		[draft, tenantId, report],
	);

	const revoke = useCallback(
		async (row: DetectionExceptionRow) => {
			const reason = window.prompt(`Why revoke the exception for ${row.ruleId}?`);
			if (!reason?.trim()) return;
			setBusy(true);
			const result = await revokeDetectionException(tenantId, row.id, reason);
			setBusy(false);
			if (!result.ok) {
				report(result.error);
				return;
			}
			setNotice({ tone: "ok", text: `Exception for ${row.ruleId} revoked.` });
			setTick((value) => value + 1);
		},
		[tenantId, report],
	);

	const memberEmail = (userId: string) =>
		members.find((m) => m.user_id === userId)?.email ?? userId;
	const now = Date.now();

	return (
		<section className="card">
			<h1>Detection exceptions</h1>
			<p>
				Lift one detection rule for one member, agent or repository until an end date at most{" "}
				{DETECTION_EXCEPTION_MAX_DAYS} days ahead; it lifts itself when it expires. Connectors
				receive exceptions only inside the signed runtime policy, apply them to exactly that rule
				and subject, and audit every use. Self-defense rules can never be excepted. Every change
				requires multi-factor verification and is recorded in the audit log.
			</p>

			{notice ? (
				<div
					className={notice.tone === "ok" ? "notice" : "notice notice-error"}
					role={notice.tone === "ok" ? "status" : "alert"}
				>
					{notice.text} {notice.stepUp ? <Link to={stepUpPath(tenantId)}>Verify now</Link> : null}
				</div>
			) : null}

			<form onSubmit={submit} aria-label="Add a detection exception">
				<h2>Add an exception</h2>
				<label>
					Rule id
					<input
						value={draft.ruleId}
						onChange={(e) => setDraft({ ...draft, ruleId: e.target.value })}
						placeholder="CLT-CMD-011"
						maxLength={100}
						required
					/>
				</label>
				<label>
					Applies to
					<select
						value={draft.subjectKind}
						onChange={(e) =>
							setDraft({ ...draft, subjectKind: e.target.value as SubjectKind, subject: "" })
						}
					>
						{SUBJECT_KINDS.map((kind) => (
							<option key={kind} value={kind}>
								{SUBJECT_LABEL[kind]}
							</option>
						))}
					</select>
				</label>
				{draft.subjectKind === "user" ? (
					<label>
						Member
						<select
							value={draft.subject}
							onChange={(e) => setDraft({ ...draft, subject: e.target.value })}
							required
						>
							<option value="">Choose a member…</option>
							{members.map((m) => (
								<option key={m.user_id} value={m.user_id}>
									{m.email || m.user_id}
								</option>
							))}
						</select>
					</label>
				) : (
					<label>
						{draft.subjectKind === "agent"
							? "Agent id"
							: "Repository (origin remote, e.g. github.com/acme/app)"}
						<input
							value={draft.subject}
							onChange={(e) => setDraft({ ...draft, subject: e.target.value })}
							maxLength={512}
							required
						/>
					</label>
				)}
				<label>
					Ends on (UTC)
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
					Reason
					<textarea
						value={draft.reason}
						onChange={(e) => setDraft({ ...draft, reason: e.target.value })}
						maxLength={500}
						required
					/>
				</label>
				<label>
					Only this artifact (optional SHA-256 from <code>aidr exception</code> or the audit log)
					<input
						value={draft.artifactSha256}
						onChange={(e) => setDraft({ ...draft, artifactSha256: e.target.value })}
						maxLength={64}
					/>
				</label>
				<button className="button" type="submit" disabled={busy}>
					Add exception
				</button>
			</form>

			<h2>Exceptions</h2>
			{load.kind === "loading" ? <div role="status">Loading exceptions…</div> : null}
			{load.kind === "error" ? (
				<div className="notice notice-error" role="alert">
					{exceptionErrorMessage(load.code)}{" "}
					{load.code === "mfa_required" ? <Link to={stepUpPath(tenantId)}>Verify now</Link> : null}
				</div>
			) : null}
			{load.kind === "ready" && load.rows.length === 0 ? <p>No detection exceptions yet.</p> : null}
			{load.kind === "ready" && load.rows.length > 0 ? (
				<table>
					<thead>
						<tr>
							<th>Rule</th>
							<th>Applies to</th>
							<th>Ends</th>
							<th>State</th>
							<th>Reason</th>
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
											<div>one artifact ({row.artifactSha256.slice(0, 12)}…)</div>
										) : null}
									</td>
									<td>
										{SUBJECT_LABEL[row.subjectKind]}:{" "}
										{row.subjectKind === "user" ? memberEmail(row.subject) : row.subject}
									</td>
									<td>{new Date(row.expiresAt).toLocaleString()}</td>
									<td>
										<span className={STATE_BADGE[state]}>{state}</span>
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
												Revoke
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
