import { useCallback, useEffect, useRef, useState } from "react";
import { useTeam } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import { useRichT, useT } from "../../i18n/I18nProvider";
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
	requestStatus,
	useGovernanceData,
	validText,
} from "../governance/common";

const KIND_LABEL: Record<ChangeKind, DashboardMessageKey> = {
	runtime_publish: "gov.chg.kind.runtimePublish",
	runtime_publish_document: "gov.chg.kind.runtimePublishDocument",
	runtime_restore: "gov.chg.kind.runtimeRestore",
	runtime_stage: "gov.chg.kind.runtimeStage",
	runtime_rollout: "gov.chg.kind.runtimeRollout",
	dlp_publish: "gov.chg.kind.dlpPublish",
	agent_profiles_stage: "gov.chg.kind.agentProfilesStage",
	disable_four_eyes: "gov.chg.kind.disableFourEyes",
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
	const t = useT();
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
				message: governanceErrorMessage(result.error, t),
				code: result.error,
			});
			return;
		}
		const proposed = result.value.proposed;
		const current = result.value.current;
		if (!proposed || typeof proposed !== "object") {
			onNotice({ tone: "error", message: governanceErrorMessage("governance_unavailable", t) });
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
			<h3 style={{ margin: 0 }}>{t(KIND_LABEL[change.changeKind])}</h3>
			<p className="small">
				{t("gov.chg.filed", {
					member: requester,
					time: formatTime(change.createdAt),
					version: change.baseVersion,
					restores:
						change.targetVersion !== null
							? t("gov.chg.restores", { version: change.targetVersion })
							: "",
					expires: formatTime(change.expiresAt),
				})}
			</p>
			<p className="muted small mono">sha256 {change.payloadSha256.slice(0, 16)}…</p>
			{change.changeKind !== "disable_four_eyes" ? (
				detail ? (
					<>
						<p className="small">
							{t("gov.chg.diffSummary", {
								version: detail.current?.version ?? 0,
								added: stats?.added ?? 0,
								removed: stats?.removed ?? 0,
							})}
							{Array.isArray(detail.proposed.agent_ids)
								? t("gov.chg.targets", { count: detail.proposed.agent_ids.length })
								: ""}
							{Array.isArray(detail.proposed.rings)
								? t("gov.chg.rings", { count: detail.proposed.rings.length })
								: ""}
						</p>
						{lines ? (
							<DiffView
								lines={lines}
								label={t("gov.chg.diffFor", { kind: t(KIND_LABEL[change.changeKind]) })}
							/>
						) : null}
					</>
				) : canDecide ? (
					<button
						className="button button-secondary button-sm"
						type="button"
						disabled={loading}
						onClick={() => void loadDetail()}
					>
						{loading ? t("common.loading") : t("gov.chg.reviewDiff")}
					</button>
				) : null
			) : null}
			{own ? (
				<div className="row" style={{ gap: 8, marginTop: 8 }}>
					<span className="muted small">{t("gov.chg.own")}</span>
					<button
						className="button button-secondary button-sm"
						type="button"
						disabled={busy}
						onClick={onCancel}
					>
						{t("gov.chg.withdraw")}
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
							{t("gov.chg.approveApply")}
						</button>
						<button
							className="button button-danger"
							type="button"
							disabled={busy || !validText(reason, REASON_MAX)}
							onClick={() => onDecide("reject", reason.trim())}
						>
							{t("gov.req.reject")}
						</button>
					</div>
					{change.changeKind !== "disable_four_eyes" && !detail ? (
						<p className="muted small">{t("gov.chg.reviewFirst")}</p>
					) : null}
				</div>
			) : (
				<p className="muted small">{t("gov.chg.ownersDecide")}</p>
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
	const t = useT();
	// Read the translator through a ref so a language switch does not refetch.
	const translator = useRef(t);
	translator.current = t;
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
			onNotice({ tone: "error", message: translator.current("gov.chg.historyFailed") });
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
			const pending = pendingPolicyChangeNotice(data, t);
			if (pending)
				onNotice({ tone: "success", message: t("gov.chg.rollbackFiled", { version, pending }) });
			else if (data?.ok === true && Number.isSafeInteger(data.version))
				onNotice({
					tone: "success",
					message: t("gov.chg.republished", { version, next: data.version }),
				});
			else throw new Error("rollback");
			await load();
		} catch {
			onNotice({
				tone: "error",
				message: t("gov.chg.rollbackUnconfirmed"),
			});
		} finally {
			setBusy(false);
		}
	}
	if (!revisions) return <p className="muted small">{t("gov.chg.noHistory")}</p>;
	if (revisions.length === 0) return <p className="muted small">{t("gov.chg.nothingPublished")}</p>;
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
								{t("gov.chg.version", { version: revision.version })}
								{revision.version === current ? t("gov.chg.published") : ""} ·{" "}
								{formatTime(revision.created_at)}
							</span>
							<button
								className="button button-secondary button-sm"
								type="button"
								onClick={() => setOpen(open === revision.version ? null : revision.version)}
							>
								{open === revision.version
									? t("gov.chg.hideDiff")
									: previous
										? t("gov.chg.diffVs", { version: previous.version })
										: t("gov.chg.showContent")}
							</button>
							{canManage && revision.version !== current ? (
								<button
									className="button button-sm"
									type="button"
									disabled={busy}
									onClick={() => void rollback(revision.version)}
								>
									{t("gov.chg.rollBackTo", { version: revision.version })}
								</button>
							) : null}
						</div>
						{open === revision.version ? (
							<DiffView
								lines={diffDocuments(previous?.policy ?? null, revision.policy)}
								label={t("gov.chg.diffOf", { version: revision.version })}
							/>
						) : null}
					</li>
				);
			})}
		</ul>
	);
}

/**
 * Keyed by tenant: switching team remounts the page, so a request or decision
 * still in flight for the previous tenant can never write into the new view.
 */
export function GovernanceChangeControlPage() {
	const { currentTeam } = useTeam();
	return <TenantGovernanceChangeControlPage key={currentTeam?.id ?? "no-tenant"} />;
}

function TenantGovernanceChangeControlPage() {
	const t = useT();
	const richT = useRichT();
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
				message: governanceErrorMessage(result.error, t),
				code: result.error,
			});
			return;
		}
		setNotice({ tone: "success", message: success(result.value) });
		await reload();
	}

	if (!currentTeam || !tenantId) return <div role="alert">{t("gov.chg.selectTeam")}</div>;
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
				<p className="eyebrow">{t("gov.eyebrow")}</p>
				<h1>{t("gov.chg.title")}</h1>
				<p className="muted" style={{ maxWidth: 820 }}>
					{t("gov.chg.lead")}
				</p>
				<GovernanceTabs />
			</div>
			{notice ? <NoticeBanner notice={notice} tenantId={tenantId} /> : null}
			{error ? (
				<div className="notice notice-danger" role="alert">
					{governanceErrorMessage(error, t)}
				</div>
			) : null}
			{!data && !error ? <div role="status">{t("gov.chg.loading")}</div> : null}
			{data ? (
				<>
					<section className="card stack" aria-labelledby="four-eyes-heading">
						<h2 id="four-eyes-heading">{t("gov.chg.settings")}</h2>
						<p>
							{richT("gov.chg.fourEyesIs", {
								state: (
									<b data-testid="four-eyes-state">
										{fourEyes ? t("gov.chg.on") : t("gov.chg.off")}
									</b>
								),
							})}
							{disablePending ? t("gov.chg.disablePending") : ""}
						</p>
						{canManage ? (
							<div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
								{fourEyes ? (
									<button
										className="button button-secondary"
										type="button"
										disabled={busy || disablePending}
										onClick={() =>
											void run("update_settings", { policy_four_eyes: false }, () =>
												t("gov.chg.disableFiled"),
											)
										}
									>
										{t("gov.chg.requestDisable")}
									</button>
								) : (
									<button
										className="button"
										type="button"
										disabled={busy}
										onClick={() =>
											void run("update_settings", { policy_four_eyes: true }, () =>
												t("gov.chg.enabled"),
											)
										}
									>
										{t("gov.chg.enable")}
									</button>
								)}
								<label className="label" htmlFor="review-days">
									{t("gov.chg.reviewInterval")}
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
										void run("update_settings", { default_review_days: Number(reviewDays) }, () =>
											t("gov.chg.intervalSaved"),
										)
									}
								>
									{t("gov.chg.saveInterval")}
								</button>
							</div>
						) : (
							<p className="muted small">{t("gov.chg.settingsReadOnly")}</p>
						)}
						<h3>{t("gov.chg.reviewers")}</h3>
						<p className="muted small">{t("gov.chg.reviewersLead")}</p>
						{reviewerCandidates.length === 0 ? (
							<p className="muted small">{t("gov.chg.noMembers")}</p>
						) : (
							<ul className="stack" style={{ gap: 4, paddingLeft: 18 }}>
								{reviewerCandidates.map((member) => {
									const designated = data.reviewers.includes(member.user_id);
									return (
										<li key={member.user_id} className="small">
											{member.email || member.user_id}{" "}
											{designated ? (
												<span className="badge badge-success">{t("gov.chg.reviewer")}</span>
											) : null}
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
																	? t("gov.chg.reviewerRemoved")
																	: t("gov.chg.reviewerAdded"),
														)
													}
												>
													{designated ? t("gov.chg.remove") : t("gov.chg.designate")}
												</button>
											) : null}
										</li>
									);
								})}
							</ul>
						)}
					</section>
					<section className="card stack" aria-labelledby="pending-changes">
						<h2 id="pending-changes">{t("gov.chg.pending")}</h2>
						{pending.length === 0 ? (
							<p className="muted">{t("gov.chg.noPending")}</p>
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
										requester={memberLabel(members, change.requestedBy, currentUserId, t)}
										onNotice={setNotice}
										onCancel={() =>
											void run(
												"cancel_request",
												{ kind: "policy_change", request_id: change.id },
												() => t("gov.chg.withdrawn"),
											)
										}
										onDecide={(decision, reason) =>
											void run(
												"decide_policy_change",
												{ request_id: change.id, decision, reason },
												(value) =>
													decision === "reject"
														? t("gov.chg.rejected")
														: Number.isSafeInteger(value.applied_version)
															? t("gov.chg.appliedAs", { version: String(value.applied_version) })
															: t("gov.chg.applied"),
											)
										}
									/>
								))}
							</ul>
						)}
						<h3>{t("gov.chg.decided")}</h3>
						{closed.length === 0 ? (
							<p className="muted small">{t("gov.req.noneYet")}</p>
						) : (
							<div className="table-wrap">
								<table className="table" data-testid="change-history">
									<thead>
										<tr>
											<th scope="col">{t("gov.chg.col.change")}</th>
											<th scope="col">{t("gov.chg.col.author")}</th>
											<th scope="col">{t("gov.req.col.outcome")}</th>
											<th scope="col">{t("gov.req.col.decidedBy")}</th>
											<th scope="col">{t("gov.chg.col.applied")}</th>
											<th scope="col">{t("gov.req.col.reason")}</th>
										</tr>
									</thead>
									<tbody>
										{closed.map((change) => (
											<tr key={change.id}>
												<td>{t(KIND_LABEL[change.changeKind])}</td>
												<td>{memberLabel(members, change.requestedBy, currentUserId, t)}</td>
												<td>
													{requestStatus(change.status, t)}
													{change.outcomeCode ? ` (${change.outcomeCode})` : ""}
												</td>
												<td>
													{memberLabel(members, change.decidedBy, currentUserId, t)}
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
						<h2 id="history-heading">{t("gov.chg.history")}</h2>
						<p className="muted small">{t("gov.chg.historyLead")}</p>

						<RevisionHistory tenantId={tenantId} canManage={canManage} onNotice={setNotice} />
					</section>
				</>
			) : null}
		</div>
	);
}
