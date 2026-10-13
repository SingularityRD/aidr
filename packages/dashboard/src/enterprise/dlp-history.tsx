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
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { englishT, type Translate, useT } from "../i18n/I18nProvider";
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
	t: Translate = englishT,
): Promise<{ ok: true; policy: Record<string, unknown> } | { ok: false; message: string }> {
	const result = await invokePolicyManagement(
		{ action: "read_dlp_policy_revision", tenant_id: tenantId, version },
		"dlp_history_unavailable",
	);
	if (!result.ok) return { ok: false, message: policyManagementMessage(result.code, t) };
	const revision = result.data.revision;
	if (
		!isRecord(revision) ||
		revision.version !== version ||
		!isRecord(revision.policy) ||
		revision.policy.tenantId !== tenantId
	) {
		return { ok: false, message: t("dh.unverified") };
	}
	return { ok: true, policy: revision.policy };
}

/** Up to five `path: message` validation issues from a refused rollback. */
function validationIssues(body: Record<string, unknown> | null): string[] {
	if (!Array.isArray(body?.issues)) return [];
	return body.issues
		.filter(isRecord)
		.slice(0, 5)
		.map((issue) =>
			`${Array.isArray(issue.path) ? issue.path.join(".") : "policy"}: ${String(issue.message ?? "")}`.slice(
				0,
				200,
			),
		);
}

function RevisionRow({
	revision,
	currentVersion,
	canManage,
	busy,
	confirming,
	onCompare,
	onConfirm,
	onRestore,
}: {
	revision: DlpRevisionSummary;
	currentVersion: number;
	canManage: boolean;
	busy: boolean;
	confirming: boolean;
	onCompare: (base: number, target: number) => void;
	onConfirm: (version: number) => void;
	onRestore: (version: number) => void;
}) {
	const t = useT();
	const current = revision.version === currentVersion;
	return (
		<tr>
			<td>
				v{revision.version}
				{current ? (
					<span className="pill" style={{ marginLeft: 6 }}>
						{t("dh.current")}
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
							aria-label={t("dh.compareLabel", { version: revision.version })}
							onClick={() => onCompare(revision.version, currentVersion)}
						>
							{t("dh.diffCurrent")}
						</button>
					) : null}
					{revision.version > 1 ? (
						<button
							type="button"
							className="btn btn-secondary btn-sm"
							aria-label={t("dh.changesLabel", { version: revision.version })}
							onClick={() => onCompare(revision.version - 1, revision.version)}
						>
							{t("dh.changes")}
						</button>
					) : null}
					{canManage && !current ? (
						confirming ? (
							<button
								type="button"
								className="btn btn-danger btn-sm"
								disabled={busy}
								aria-label={t("dh.confirmLabel", { version: revision.version })}
								onClick={() => onRestore(revision.version)}
							>
								{t("dh.confirm")}
							</button>
						) : (
							<button
								type="button"
								className="btn btn-secondary btn-sm"
								disabled={busy}
								aria-label={t("dh.rollBackLabel", { version: revision.version })}
								onClick={() => onConfirm(revision.version)}
							>
								{t("dh.rollBack")}
							</button>
						)
					) : null}
				</div>
			</td>
		</tr>
	);
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
	const t = useT();
	// The loader reads the translator through a ref so a language switch does not refetch.
	const translator = useRef(t);
	translator.current = t;
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
			const t = translator.current;
			const result = await invokePolicyManagement(
				{
					action: "dlp_policy_history",
					tenant_id: tenantId,
					...(before ? { before_version: before } : {}),
				},
				"dlp_history_unavailable",
			);
			if (!result.ok) {
				setHistory({ kind: "error", message: policyManagementMessage(result.code, t) });
				return;
			}
			const rows = Array.isArray(result.data.revisions)
				? result.data.revisions.map(parseDlpRevisionSummary)
				: null;
			const next = result.data.next_before_version;
			if (!rows || rows.some((row) => row === null)) {
				setHistory({ kind: "error", message: t("dh.historyUnverified") });
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
			readRevision(tenantId, base, t),
			readRevision(tenantId, target, t),
		]);
		if (!left.ok || !right.ok) {
			setComparison({
				base,
				target,
				lines: null,
				error:
					(!left.ok ? left.message : null) ?? (!right.ok ? right.message : t("dh.unavailable")),
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
			setNotice({
				tone: "error",
				message: [policyManagementMessage(result.code, t), ...validationIssues(result.body)].join(
					" ",
				),
			});
			return;
		}
		const pending = pendingPolicyChangeNotice(result.data, t);
		if (pending) {
			setNotice({ tone: "success", message: t("dh.filed", { version, pending }) });
			return;
		}
		const saved = result.data.version;
		if (saved !== currentVersion + 1 || result.data.restored_from !== version) {
			setNotice({ tone: "error", message: t("dh.notConfirmed") });
			return;
		}
		setNotice({
			tone: "success",
			message: t("dh.restored", { version, saved: String(saved) }),
		});
		onRestored(saved, result.data.policy);
	}

	if (!open) {
		return (
			<section
				className="card row"
				style={{ justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}
			>
				<span className="muted small">{t("dh.teaser")}</span>
				<button type="button" className="btn btn-secondary btn-sm" onClick={() => setOpen(true)}>
					{t("dh.show")}
				</button>
			</section>
		);
	}

	return (
		<section className="card stack" aria-labelledby="dlp-history-heading">
			<div>
				<h3 id="dlp-history-heading" style={{ margin: 0 }}>
					{t("dh.title")}
				</h3>
				<p className="muted small" style={{ margin: "6px 0 0" }}>
					{t("dh.lead")}
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
				<p role="status">{t("dh.loading")}</p>
			) : history.kind === "error" ? (
				<p role="alert">{history.message}</p>
			) : history.revisions.length === 0 ? (
				<p className="muted">{t("dh.empty")}</p>
			) : (
				<>
					<div className="table-wrap">
						<table className="table" aria-label={t("dh.tableLabel")}>
							<thead>
								<tr>
									<th>{t("dh.col.version")}</th>
									<th>{t("dh.col.saved")}</th>
									<th>{t("dh.col.labels")}</th>
									<th>{t("dh.col.rules")}</th>
									<th>{t("dh.col.exceptions")}</th>
									<th>{t("dh.col.actions")}</th>
								</tr>
							</thead>
							<tbody>
								{history.revisions.map((revision) => (
									<RevisionRow
										key={revision.version}
										revision={revision}
										currentVersion={currentVersion}
										canManage={canManage}
										busy={busy}
										confirming={confirming === revision.version}
										onCompare={(base, target) => void compare(base, target)}
										onConfirm={setConfirming}
										onRestore={(version) => void restore(version)}
									/>
								))}
							</tbody>
						</table>
					</div>
					{history.nextBefore ? (
						<button
							type="button"
							className="btn btn-secondary btn-sm"
							onClick={() => void load(history.nextBefore ?? undefined)}
						>
							{t("dh.loadOlder")}
						</button>
					) : null}
				</>
			)}
			{comparison ? <ComparisonView comparison={comparison} /> : null}
		</section>
	);
}

function ComparisonView({ comparison }: { comparison: Comparison }) {
	const t = useT();
	const stats = useMemo(
		() => (comparison.lines ? diffStats(comparison.lines) : null),
		[comparison],
	);
	return (
		<div className="stack" style={{ gap: 6 }}>
			<b>
				{t("dh.compareTitle", { base: comparison.base, target: comparison.target })}
				{stats ? t("dh.lines", { added: stats.added, removed: stats.removed }) : ""}
			</b>
			{comparison.error ? (
				<p role="alert">{comparison.error}</p>
			) : comparison.lines ? (
				<DiffView
					lines={comparison.lines}
					label={t("dh.diffLabel", { base: comparison.base, target: comparison.target })}
				/>
			) : (
				<p role="status">{t("dh.loadingDiff")}</p>
			)}
		</div>
	);
}
