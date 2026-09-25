import { useCallback, useEffect, useState } from "react";
import { useTeam } from "../../enterprise/team-provider";
import {
	type ChangeKind,
	governanceAction,
	governanceErrorMessage,
	type PolicyChangeRequest,
	pendingPolicyChangeNotice,
	REASON_MAX,
} from "../../lib/ai-governance";
import { diffDocuments, diffStats } from "../../lib/json-diff";
import { supabase } from "../../lib/supabase";
import {
	DiffView,
	formatTime,
	GovernanceTabs,
	memberLabel,
	type Notice,
	NoticeBanner,
	ReasonField,
	useGovernanceData,
	validText,
} from "../governance/common";

const KIND_LABEL: Record<ChangeKind, string> = {
	runtime_publish: "Publish runtime policy",
	runtime_publish_document: "Publish compiled policy YAML",
	runtime_restore: "Roll back runtime policy",
	runtime_stage: "Stage runtime policy for selected agents",
	runtime_rollout: "Ordered canary rollout",
	dlp_publish: "Save DLP policy",
	disable_four_eyes: "Turn off four-eyes change control",
};

interface ChangeDetail {
	proposed: Record<string, unknown>;
	current: { version: number; policy: unknown } | null;
}

function PendingChange({
	change,
	tenantId,
	own,
	canDecide,
	busy,
	requester,
	onDecide,
	onCancel,
	onNotice,
}: {
	change: PolicyChangeRequest;
	tenantId: string;
	own: boolean;
	canDecide: boolean;
	busy: boolean;
	requester: string;
	onDecide: (decision: "approve" | "reject", reason: string) => void;
	onCancel: () => void;
	onNotice: (notice: Notice) => void;
}) {
	const [detail, setDetail] = useState<ChangeDetail | null>(null);
	const [loading, setLoading] = useState(false);
	const [reason, setReason] = useState("");
	async function loadDetail() {
		setLoading(true);
		const result = await governanceAction(tenantId, "policy_change_detail", {
			request_id: change.id,
		});
		setLoading(false);
		if (!result.ok) {
			onNotice({
				tone: "error",
				message: governanceErrorMessage(result.error),
				code: result.error,
			});
			return;
		}
		const proposed = result.value.proposed;
		const current = result.value.current;
		if (!proposed || typeof proposed !== "object") {
			onNotice({ tone: "error", message: governanceErrorMessage("governance_unavailable") });
			return;
		}
		setDetail({
			proposed: proposed as Record<string, unknown>,
			current: (current as ChangeDetail["current"]) ?? null,
		});
	}
	const lines = detail
		? diffDocuments(detail.current?.policy ?? null, detail.proposed.policy ?? null)
		: null;
	const stats = lines ? diffStats(lines) : null;
	return (
		<li className="card" data-testid="change-pending">
			<h3 style={{ margin: 0 }}>{KIND_LABEL[change.changeKind]}</h3>
			<p className="small">
				Filed by {requester} on {formatTime(change.createdAt)} against version {change.baseVersion}
				{change.targetVersion !== null ? ` (restores revision ${change.targetVersion})` : ""};
				expires {formatTime(change.expiresAt)}.
			</p>
			<p className="muted small mono">sha256 {change.payloadSha256.slice(0, 16)}…</p>
			{change.changeKind !== "disable_four_eyes" ? (
				detail ? (
					<>
						<p className="small">
							Current version {detail.current?.version ?? 0} → proposed: {stats?.added ?? 0} line(s)
							added, {stats?.removed ?? 0} removed.
							{Array.isArray(detail.proposed.agent_ids)
								? ` Targets ${detail.proposed.agent_ids.length} agent(s).`
								: ""}
							{Array.isArray(detail.proposed.rings)
								? ` ${detail.proposed.rings.length} rollout ring(s).`
								: ""}
						</p>
						{lines ? (
							<DiffView lines={lines} label={`Diff for ${KIND_LABEL[change.changeKind]}`} />
						) : null}
					</>
				) : canDecide ? (
					<button
						className="button button-secondary button-sm"
						type="button"
						disabled={loading}
						onClick={() => void loadDetail()}
					>
						{loading ? "Loading…" : "Review diff"}
					</button>
				) : null
			) : null}
			{own ? (
				<div className="row" style={{ gap: 8, marginTop: 8 }}>
					<span className="muted small">
						You filed this change, so another owner or administrator must approve it.
					</span>
					<button
						className="button button-secondary button-sm"
						type="button"
						disabled={busy}
						onClick={onCancel}
					>
						Withdraw
					</button>
				</div>
			) : canDecide ? (
				<div className="stack" style={{ gap: 6, maxWidth: 560, marginTop: 8 }}>
					<ReasonField id={`change-${change.id}`} value={reason} onChange={setReason} />
					<div className="row" style={{ gap: 8 }}>
						<button
							className="button"
							type="button"
							disabled={
								busy ||
								!validText(reason, REASON_MAX) ||
								(change.changeKind !== "disable_four_eyes" && !detail)
							}
							onClick={() => onDecide("approve", reason.trim())}
						>
							Approve and apply
						</button>
						<button
							className="button button-danger"
							type="button"
							disabled={busy || !validText(reason, REASON_MAX)}
							onClick={() => onDecide("reject", reason.trim())}
						>
							Reject
						</button>
					</div>
					{change.changeKind !== "disable_four_eyes" && !detail ? (
						<p className="muted small">Review the diff before approving.</p>
					) : null}
				</div>
			) : (
				<p className="muted small">Owners and administrators decide policy changes.</p>
			)}
		</li>
	);
}

type Revision = { version: number; policy: Record<string, unknown>; created_at: string };

function RevisionHistory({
	tenantId,
	canManage,
	onNotice,
}: {
	tenantId: string;
	canManage: boolean;
	onNotice: (notice: Notice) => void;
}) {
	const [revisions, setRevisions] = useState<Revision[] | null>(null);
	const [current, setCurrent] = useState<number | null>(null);
	const [open, setOpen] = useState<number | null>(null);
	const [busy, setBusy] = useState(false);
	const load = useCallback(async () => {
		try {
			const [history, read] = await Promise.all([
				supabase.functions.invoke("policy-management", {
					body: { action: "history", tenant_id: tenantId },
				}),
				supabase.functions.invoke("policy-management", {
					body: { action: "read", tenant_id: tenantId },
				}),
			]);
			if (
				history.error ||
				read.error ||
				history.data?.ok !== true ||
				!Array.isArray(history.data.revisions) ||
				read.data?.ok !== true ||
				!Number.isSafeInteger(read.data.version)
			)
				throw new Error("history");
			setRevisions(history.data.revisions as Revision[]);
			setCurrent(read.data.version as number);
		} catch {
			setRevisions(null);
			onNotice({ tone: "error", message: "Runtime policy history could not be loaded." });
		}
	}, [tenantId, onNotice]);
	useEffect(() => {
		void load();
	}, [load]);
	async function rollback(version: number) {
		if (current === null) return;
		setBusy(true);
		try {
			const { data, error } = await supabase.functions.invoke("policy-management", {
				body: {
					action: "restore",
					tenant_id: tenantId,
					expected_version: current,
					target_version: version,
				},
			});
			if (error) throw error;
			const pending = pendingPolicyChangeNotice(data);
			if (pending)
				onNotice({ tone: "success", message: `Rollback to revision ${version} filed. ${pending}` });
			else if (data?.ok === true && Number.isSafeInteger(data.version))
				onNotice({
					tone: "success",
					message: `Revision ${version} republished as version ${data.version}.`,
				});
			else throw new Error("rollback");
			await load();
		} catch {
			onNotice({
				tone: "error",
				message:
					"The rollback was not confirmed. Refresh if another administrator changed the policy.",
			});
		} finally {
			setBusy(false);
		}
	}
	if (!revisions) return <p className="muted small">No runtime policy history available.</p>;
	if (revisions.length === 0)
		return <p className="muted small">No runtime policy has been published yet.</p>;
	return (
		<ul
			className="stack"
			style={{ listStyle: "none", padding: 0, margin: 0 }}
			data-testid="revision-history"
		>
			{revisions.map((revision, index) => {
				const previous = revisions[index + 1];
				return (
					<li key={revision.version} className="stack" style={{ gap: 4 }}>
						<div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
							<span>
								Version {revision.version}
								{revision.version === current ? " (published)" : ""} ·{" "}
								{formatTime(revision.created_at)}
							</span>
							<button
								className="button button-secondary button-sm"
								type="button"
								onClick={() => setOpen(open === revision.version ? null : revision.version)}
							>
								{open === revision.version
									? "Hide diff"
									: previous
										? `Diff vs version ${previous.version}`
										: "Show content"}
							</button>
							{canManage && revision.version !== current ? (
								<button
									className="button button-sm"
									type="button"
									disabled={busy}
									onClick={() => void rollback(revision.version)}
								>
									Roll back to version {revision.version}
								</button>
							) : null}
						</div>
						{open === revision.version ? (
							<DiffView
								lines={diffDocuments(previous?.policy ?? null, revision.policy)}
								label={`Diff of version ${revision.version}`}
							/>
						) : null}
					</li>
				);
			})}
		</ul>
	);
}

export function GovernanceChangeControlPage() {
	const { currentTeam, currentRole, roleResolved, members, currentUserId } = useTeam();
	const tenantId = currentTeam?.id ?? null;
	const { data, error, reload } = useGovernanceData(tenantId, 15_000);
	const [notice, setNotice] = useState<Notice | null>(null);
	const [busy, setBusy] = useState(false);
	const [reviewDays, setReviewDays] = useState("");
	const canManage = roleResolved && (currentRole === "owner" || currentRole === "admin");

	useEffect(() => {
		setNotice(null);
	}, [tenantId]);
	useEffect(() => {
		if (data) setReviewDays(String(data.settings.defaultReviewDays));
	}, [data]);

	async function run(
		action: string,
		payload: Record<string, unknown>,
		success: (value: Record<string, unknown>) => string,
	) {
		if (!tenantId) return;
		setBusy(true);
		setNotice(null);
		const result = await governanceAction(tenantId, action, payload);
		setBusy(false);
		if (!result.ok) {
			setNotice({
				tone: "error",
				message: governanceErrorMessage(result.error),
				code: result.error,
			});
			return;
		}
		setNotice({ tone: "success", message: success(result.value) });
		await reload();
	}

	if (!currentTeam || !tenantId)
		return <div role="alert">Select a team to view change control.</div>;
	const pending = data?.changes.filter((change) => change.status === "pending") ?? [];
	const closed = data?.changes.filter((change) => change.status !== "pending") ?? [];
	const fourEyes = data?.settings.policyFourEyes ?? false;
	const disablePending = pending.some((change) => change.changeKind === "disable_four_eyes");
	const reviewerCandidates = members.filter((member) => member.role === "member");
	const daysValid =
		/^\d{2,3}$/.test(reviewDays) && Number(reviewDays) >= 30 && Number(reviewDays) <= 730;

	return (
		<div className="stack">
			<div className="card">
				<p className="eyebrow">AI governance</p>
				<h1>Policy change control</h1>
				<p className="muted" style={{ maxWidth: 820 }}>
					With four-eyes on, publishing runtime or DLP policy — including rollbacks, staged and
					canary rollouts — files a change request that a second owner or administrator must approve
					after reviewing the diff. The database refuses any publication that is not such an
					approval, and nobody can approve their own change.
				</p>
				<GovernanceTabs />
			</div>
			{notice ? <NoticeBanner notice={notice} tenantId={tenantId} /> : null}
			{error ? (
				<div className="notice notice-danger" role="alert">
					{governanceErrorMessage(error)}
				</div>
			) : null}
			{!data && !error ? <div role="status">Loading change control…</div> : null}
			{data ? (
				<>
					<section className="card stack" aria-labelledby="four-eyes-heading">
						<h2 id="four-eyes-heading">Settings</h2>
						<p>
							Four-eyes change control is{" "}
							<b data-testid="four-eyes-state">{fourEyes ? "on" : "off"}</b>.
							{disablePending ? " A request to turn it off is waiting for a second approver." : ""}
						</p>
						{canManage ? (
							<div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
								{fourEyes ? (
									<button
										className="button button-secondary"
										type="button"
										disabled={busy || disablePending}
										onClick={() =>
											void run(
												"update_settings",
												{ policy_four_eyes: false },
												() =>
													"Request to turn off four-eyes filed; another owner or administrator must approve it.",
											)
										}
									>
										Request to turn off four-eyes
									</button>
								) : (
									<button
										className="button"
										type="button"
										disabled={busy}
										onClick={() =>
											void run(
												"update_settings",
												{ policy_four_eyes: true },
												() => "Four-eyes change control is on.",
											)
										}
									>
										Turn on four-eyes
									</button>
								)}
								<label className="label" htmlFor="review-days">
									Review interval (days)
								</label>
								<input
									id="review-days"
									className="input"
									style={{ maxWidth: 100 }}
									inputMode="numeric"
									value={reviewDays}
									onChange={(event) => setReviewDays(event.target.value)}
								/>
								<button
									className="button button-secondary"
									type="button"
									disabled={
										busy || !daysValid || Number(reviewDays) === data.settings.defaultReviewDays
									}
									onClick={() =>
										void run(
											"update_settings",
											{ default_review_days: Number(reviewDays) },
											() => "Review interval saved.",
										)
									}
								>
									Save interval
								</button>
							</div>
						) : (
							<p className="muted small">Only owners and administrators change these settings.</p>
						)}
						<h3>Designated AI governance reviewers</h3>
						<p className="muted small">
							Members you designate can decide intake requests and record periodic reviews (at
							AAL2). They cannot lift a ban or restriction, decide exceptions or approve policy
							changes.
						</p>
						{reviewerCandidates.length === 0 ? (
							<p className="muted small">No members with the member role.</p>
						) : (
							<ul className="stack" style={{ gap: 4, paddingLeft: 18 }}>
								{reviewerCandidates.map((member) => {
									const designated = data.reviewers.includes(member.user_id);
									return (
										<li key={member.user_id} className="small">
											{member.email || member.user_id}{" "}
											{designated ? <span className="badge badge-success">Reviewer</span> : null}
											{canManage ? (
												<button
													className="button button-ghost button-sm"
													type="button"
													disabled={busy}
													onClick={() =>
														void run(
															"set_reviewer",
															{ user_id: member.user_id, designated: !designated },
															() =>
																designated
																	? "Reviewer designation removed."
																	: "Reviewer designated.",
														)
													}
												>
													{designated ? "Remove" : "Designate"}
												</button>
											) : null}
										</li>
									);
								})}
							</ul>
						)}
					</section>
					<section className="card stack" aria-labelledby="pending-changes">
						<h2 id="pending-changes">Pending changes</h2>
						{pending.length === 0 ? (
							<p className="muted">No changes are waiting for approval.</p>
						) : (
							<ul className="stack" style={{ listStyle: "none", padding: 0, margin: 0 }}>
								{pending.map((change) => (
									<PendingChange
										key={change.id}
										change={change}
										tenantId={tenantId}
										own={change.requestedBy === currentUserId}
										canDecide={canManage}
										busy={busy}
										requester={memberLabel(members, change.requestedBy, currentUserId)}
										onNotice={setNotice}
										onCancel={() =>
											void run(
												"cancel_request",
												{ kind: "policy_change", request_id: change.id },
												() => "Change withdrawn.",
											)
										}
										onDecide={(decision, reason) =>
											void run(
												"decide_policy_change",
												{ request_id: change.id, decision, reason },
												(value) =>
													decision === "reject"
														? "Change rejected; nothing was published."
														: `Change approved and applied${Number.isSafeInteger(value.applied_version) ? ` as version ${value.applied_version}` : ""}.`,
											)
										}
									/>
								))}
							</ul>
						)}
						<h3>Decided changes</h3>
						{closed.length === 0 ? (
							<p className="muted small">None yet.</p>
						) : (
							<div className="table-wrap">
								<table className="table" data-testid="change-history">
									<thead>
										<tr>
											<th scope="col">Change</th>
											<th scope="col">Author</th>
											<th scope="col">Outcome</th>
											<th scope="col">Decided by</th>
											<th scope="col">Applied</th>
											<th scope="col">Reason</th>
										</tr>
									</thead>
									<tbody>
										{closed.map((change) => (
											<tr key={change.id}>
												<td>{KIND_LABEL[change.changeKind]}</td>
												<td>{memberLabel(members, change.requestedBy, currentUserId)}</td>
												<td>
													{change.status}
													{change.outcomeCode ? ` (${change.outcomeCode})` : ""}
												</td>
												<td>
													{memberLabel(members, change.decidedBy, currentUserId)}
													{change.decidedAt ? ` · ${formatTime(change.decidedAt)}` : ""}
												</td>
												<td>{change.appliedVersion ?? "—"}</td>
												<td className="small">{change.decisionReason ?? "—"}</td>
											</tr>
										))}
									</tbody>
								</table>
							</div>
						)}
					</section>
					<section className="card stack" aria-labelledby="history-heading">
						<h2 id="history-heading">Runtime policy history</h2>
						<p className="muted small">
							Every published and staged revision, with a diff against the one before it. Rolling
							back republishes the chosen revision through the normal publication path, so four-eyes
							applies to it too.
						</p>
						<RevisionHistory tenantId={tenantId} canManage={canManage} onNotice={setNotice} />
					</section>
				</>
			) : null}
		</div>
	);
}
