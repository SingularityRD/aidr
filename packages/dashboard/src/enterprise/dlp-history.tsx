/**
 * DLP policy revision history (Policy → DLP): every saved revision with its
 * counts, a diff between any two revisions, and rollback.
 *
 * Rollback publishes the chosen revision's content as a NEW revision
 * (`restore_dlp_policy`), so history stays append-only, the server
 * re-validates the document with today's schema and clock (an exception that
 * has since expired refuses the rollback), and four-eyes change control
 * applies exactly as it does to a normal save.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { pendingPolicyChangeNotice } from "../lib/ai-governance";
import { diffDocuments, diffStats } from "../lib/json-diff";
import { invokePolicyManagement, policyManagementMessage } from "../lib/policy-management";
import { DiffView } from "../ui/governance/common";

export interface DlpRevisionSummary {
	version: number;
	createdAt: string;
	updatedBy: string | null;
	counts: { labels: number; rules: number; exceptions: number };
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

const whole = (value: unknown) => Number.isSafeInteger(value) && Number(value) >= 0;

/** Strict projection of one `dlp_policy_history` row; null when malformed. */
export function parseDlpRevisionSummary(value: unknown): DlpRevisionSummary | null {
	if (
		!isRecord(value) ||
		!Number.isSafeInteger(value.version) ||
		Number(value.version) < 1 ||
		typeof value.created_at !== "string" ||
		!Number.isFinite(Date.parse(value.created_at)) ||
		!isRecord(value.counts) ||
		!whole(value.counts.labels) ||
		!whole(value.counts.rules) ||
		!whole(value.counts.exceptions)
	)
		return null;
	return {
		version: value.version as number,
		createdAt: value.created_at,
		updatedBy: typeof value.updated_by === "string" ? value.updated_by : null,
		counts: {
			labels: value.counts.labels as number,
			rules: value.counts.rules as number,
			exceptions: value.counts.exceptions as number,
		},
	};
}

type HistoryState =
	| { kind: "loading" }
	| { kind: "error"; message: string }
	| { kind: "ready"; revisions: DlpRevisionSummary[]; nextBefore: number | null };

interface Comparison {
	base: number;
	target: number;
	lines: ReturnType<typeof diffDocuments> | null;
	error: string | null;
}

async function readRevision(
	tenantId: string,
	version: number,
): Promise<{ ok: true; policy: Record<string, unknown> } | { ok: false; message: string }> {
	const result = await invokePolicyManagement(
		{ action: "read_dlp_policy_revision", tenant_id: tenantId, version },
		"dlp_history_unavailable",
	);
	if (!result.ok) return { ok: false, message: policyManagementMessage(result.code) };
	const revision = result.data.revision;
	if (
		!isRecord(revision) ||
		revision.version !== version ||
		!isRecord(revision.policy) ||
		revision.policy.tenantId !== tenantId
	) {
		return { ok: false, message: "The revision could not be verified." };
	}
	return { ok: true, policy: revision.policy };
}

export function DlpPolicyHistory({
	tenantId,
	currentVersion,
	canManage,
	onRestored,
}: {
	tenantId: string;
	currentVersion: number;
	canManage: boolean;
	onRestored: (version: number, policy: unknown) => void;
}) {
	const [history, setHistory] = useState<HistoryState>({ kind: "loading" });
	const [comparison, setComparison] = useState<Comparison | null>(null);
	const [busy, setBusy] = useState(false);
	const [notice, setNotice] = useState<{ tone: "success" | "error"; message: string } | null>(null);
	const [confirming, setConfirming] = useState<number | null>(null);
	// Loaded on request: history reads are AAL2 policy reads, not page chrome.
	const [open, setOpen] = useState(false);

	const load = useCallback(
		// `_version` only ties a reload to the revision it follows.
		async (before?: number, _version?: number) => {
			const result = await invokePolicyManagement(
				{
					action: "dlp_policy_history",
					tenant_id: tenantId,
					...(before ? { before_version: before } : {}),
				},
				"dlp_history_unavailable",
			);
			if (!result.ok) {
				setHistory({ kind: "error", message: policyManagementMessage(result.code) });
				return;
			}
			const rows = Array.isArray(result.data.revisions)
				? result.data.revisions.map(parseDlpRevisionSummary)
				: null;
			const next = result.data.next_before_version;
			if (!rows || rows.some((row) => row === null)) {
				setHistory({ kind: "error", message: "The revision history could not be verified." });
				return;
			}
			setHistory((current) => ({
				kind: "ready",
				revisions: [
					...(before && current.kind === "ready" ? current.revisions : []),
					...(rows as DlpRevisionSummary[]),
				],
				nextBefore: Number.isSafeInteger(next) ? (next as number) : null,
			}));
		},
		[tenantId],
	);

	useEffect(() => {
		setNotice(null);
		setConfirming(null);
		setOpen(false);
	}, [tenantId]);

	// Reload after any save or rollback; the outcome notice stays visible.
	useEffect(() => {
		if (!open) return;
		setHistory({ kind: "loading" });
		setComparison(null);
		void load(undefined, currentVersion);
	}, [open, load, currentVersion]);

	async function compare(base: number, target: number) {
		setComparison({ base, target, lines: null, error: null });
		const [left, right] = await Promise.all([
			readRevision(tenantId, base),
			readRevision(tenantId, target),
		]);
		if (!left.ok || !right.ok) {
			setComparison({
				base,
				target,
				lines: null,
				error: (!left.ok ? left.message : null) ?? (!right.ok ? right.message : "Unavailable"),
			});
			return;
		}
		setComparison({ base, target, lines: diffDocuments(left.policy, right.policy), error: null });
	}

	async function restore(version: number) {
		setBusy(true);
		setNotice(null);
		setConfirming(null);
		const result = await invokePolicyManagement(
			{
				action: "restore_dlp_policy",
				tenant_id: tenantId,
				version,
				expected_version: currentVersion,
			},
			"dlp_policy_publish_failed",
		);
		setBusy(false);
		if (!result.ok) {
			const issues = Array.isArray(result.body?.issues)
				? result.body.issues
						.filter(isRecord)
						.slice(0, 5)
						.map((issue) =>
							`${Array.isArray(issue.path) ? issue.path.join(".") : "policy"}: ${String(issue.message ?? "")}`.slice(
								0,
								200,
							),
						)
				: [];
			setNotice({
				tone: "error",
				message: [policyManagementMessage(result.code), ...issues].join(" "),
			});
			return;
		}
		const pending = pendingPolicyChangeNotice(result.data);
		if (pending) {
			setNotice({
				tone: "success",
				message: `Rollback to version ${version} filed for approval. ${pending}`,
			});
			return;
		}
		const saved = result.data.version;
		if (saved !== currentVersion + 1 || result.data.restored_from !== version) {
			setNotice({ tone: "error", message: "The rollback was not confirmed." });
			return;
		}
		setNotice({
			tone: "success",
			message: `Version ${version} restored as version ${saved}. Not delivered: signed provisioning must distribute it.`,
		});
		onRestored(saved, result.data.policy);
	}

	const stats = useMemo(
		() => (comparison?.lines ? diffStats(comparison.lines) : null),
		[comparison],
	);

	if (!open) {
		return (
			<section
				className="card row"
				style={{ justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}
			>
				<span className="muted small">
					Every saved revision is kept: compare revisions or roll back to an earlier one.
				</span>
				<button type="button" className="btn btn-secondary btn-sm" onClick={() => setOpen(true)}>
					Show revision history
				</button>
			</section>
		);
	}

	return (
		<section className="card stack" aria-labelledby="dlp-history-heading">
			<div>
				<h3 id="dlp-history-heading" style={{ margin: 0 }}>
					Revision history
				</h3>
				<p className="muted small" style={{ margin: "6px 0 0" }}>
					Every saved DLP revision is kept. Compare any revision with the current one, or roll back:
					a rollback saves the earlier content as a new revision after re-validating it, and goes
					through four-eyes approval when that is on.
				</p>
			</div>
			{notice ? (
				<div
					className={`notice ${notice.tone === "error" ? "notice-danger" : ""}`}
					role={notice.tone === "error" ? "alert" : "status"}
				>
					{notice.message}
				</div>
			) : null}
			{history.kind === "loading" ? (
				<p role="status">Loading revisions…</p>
			) : history.kind === "error" ? (
				<p role="alert">{history.message}</p>
			) : history.revisions.length === 0 ? (
				<p className="muted">No DLP revision has been saved yet.</p>
			) : (
				<>
					<div className="table-wrap">
						<table className="table" aria-label="DLP policy revisions">
							<thead>
								<tr>
									<th>Version</th>
									<th>Saved</th>
									<th>Labels</th>
									<th>Rules</th>
									<th>Exceptions</th>
									<th>Actions</th>
								</tr>
							</thead>
							<tbody>
								{history.revisions.map((revision) => {
									const current = revision.version === currentVersion;
									return (
										<tr key={revision.version}>
											<td>
												v{revision.version}
												{current ? (
													<span className="pill" style={{ marginLeft: 6 }}>
														current
													</span>
												) : null}
											</td>
											<td className="small">{new Date(revision.createdAt).toLocaleString()}</td>
											<td>{revision.counts.labels}</td>
											<td>{revision.counts.rules}</td>
											<td>{revision.counts.exceptions}</td>
											<td>
												<div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
													{!current ? (
														<button
															type="button"
															className="btn btn-secondary btn-sm"
															aria-label={`Compare version ${revision.version} with current`}
															onClick={() => void compare(revision.version, currentVersion)}
														>
															Diff vs current
														</button>
													) : null}
													{revision.version > 1 ? (
														<button
															type="button"
															className="btn btn-secondary btn-sm"
															aria-label={`Show changes in version ${revision.version}`}
															onClick={() => void compare(revision.version - 1, revision.version)}
														>
															Changes
														</button>
													) : null}
													{canManage && !current ? (
														confirming === revision.version ? (
															<button
																type="button"
																className="btn btn-danger btn-sm"
																disabled={busy}
																aria-label={`Confirm rollback to version ${revision.version}`}
																onClick={() => void restore(revision.version)}
															>
																Confirm rollback
															</button>
														) : (
															<button
																type="button"
																className="btn btn-secondary btn-sm"
																disabled={busy}
																aria-label={`Roll back to version ${revision.version}`}
																onClick={() => setConfirming(revision.version)}
															>
																Roll back
															</button>
														)
													) : null}
												</div>
											</td>
										</tr>
									);
								})}
							</tbody>
						</table>
					</div>
					{history.nextBefore ? (
						<button
							type="button"
							className="btn btn-secondary btn-sm"
							onClick={() => void load(history.nextBefore ?? undefined)}
						>
							Load older revisions
						</button>
					) : null}
				</>
			)}
			{comparison ? (
				<div className="stack" style={{ gap: 6 }}>
					<b>
						Version {comparison.base} → version {comparison.target}
						{stats ? ` (+${stats.added} / −${stats.removed} lines)` : ""}
					</b>
					{comparison.error ? (
						<p role="alert">{comparison.error}</p>
					) : comparison.lines ? (
						<DiffView
							lines={comparison.lines}
							label={`DLP diff from version ${comparison.base} to version ${comparison.target}`}
						/>
					) : (
						<p role="status">Loading diff…</p>
					)}
				</div>
			) : null}
		</section>
	);
}
