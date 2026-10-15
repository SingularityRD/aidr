import { useEffect, useMemo, useState } from "react";
import { type TeamMember, useTeam } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import { type Translate, useT } from "../../i18n/I18nProvider";
import {
	type AiAsset,
	ASSET_STATUSES,
	ASSET_TYPE_LABEL,
	ASSET_TYPES,
	type AssetEvidence,
	type AssetStatus,
	type AssetType,
	CATEGORY_LABEL,
	DATA_CATEGORIES,
	type DataCategory,
	ENFORCEMENT_LABEL,
	enforcementOf,
	governanceAction,
	governanceErrorMessage,
	isReviewOverdue,
	RISK_LABEL,
	RISK_TIERS,
	type RiskTier,
	STATUS_BADGE,
	STATUS_LABEL,
	sourceLabel,
	TEXT_MAX,
} from "../../lib/ai-governance";
import { supabase } from "../../lib/supabase";
import {
	formatDate,
	formatTime,
	GovernanceTabs,
	memberLabel,
	type Notice,
	NoticeBanner,
	useGovernanceData,
	useNow,
	validText,
} from "../governance/common";

interface EnforcementPreview {
	denyServers: string[];
	approvalServers: string[];
	blockedSites: string[];
	runtimePolicyVersion: number;
}

function readPreview(value: Record<string, unknown>): EnforcementPreview | null {
	const overlay = value.connector_overlay as Record<string, unknown> | undefined;
	const browser = value.browser_guard_managed_policy as Record<string, unknown> | undefined;
	const list = (item: unknown) =>
		Array.isArray(item) && item.every((x) => typeof x === "string") ? (item as string[]) : null;
	const deny = list(overlay?.mcp_deny_servers);
	const approval = list(overlay?.mcp_require_approval_servers);
	const sites = list(browser?.blockedSites);
	if (!deny || !approval || !sites || !Number.isSafeInteger(value.runtime_policy_version))
		return null;
	return {
		denyServers: deny,
		approvalServers: approval,
		blockedSites: sites,
		runtimePolicyVersion: value.runtime_policy_version as number,
	};
}

interface AssetDraft {
	assetType: AssetType;
	identifier: string;
	name: string;
	vendor: string;
	ownerUserId: string;
	businessPurpose: string;
	dataCategories: DataCategory[];
	riskTier: RiskTier;
	riskScore: string;
	status: AssetStatus;
	reviewDueAt: string;
}

function draftFrom(asset: AiAsset | null): AssetDraft {
	return {
		assetType: asset?.assetType ?? "mcp_server",
		identifier: asset?.identifier ?? "",
		name: asset?.name ?? "",
		vendor: asset?.vendor ?? "",
		ownerUserId: asset?.ownerUserId ?? "",
		businessPurpose: asset?.businessPurpose ?? "",
		dataCategories: asset?.dataCategories ?? [],
		riskTier: asset?.riskTier ?? "unassessed",
		riskScore:
			asset?.riskScore === null || asset?.riskScore === undefined ? "" : String(asset.riskScore),
		status: asset?.status ?? "proposed",
		reviewDueAt: asset?.reviewDueAt ?? "",
	};
}

/** Only the fields that changed (all fields for a new entry), in RPC vocabulary. */
function fieldsFrom(draft: AssetDraft, asset: AiAsset | null): Record<string, unknown> {
	const score = draft.riskScore.trim() === "" ? null : Number(draft.riskScore);
	const next: Record<string, unknown> = {
		name: draft.name.trim(),
		vendor: draft.vendor.trim() || null,
		owner_user_id: draft.ownerUserId || null,
		business_purpose: draft.businessPurpose.trim() || null,
		data_categories: [...draft.dataCategories].sort(),
		risk_tier: draft.riskTier,
		risk_score: score,
		status: draft.status,
		...(draft.reviewDueAt ? { review_due_at: draft.reviewDueAt } : {}),
	};
	if (!asset) return { asset_type: draft.assetType, identifier: draft.identifier.trim(), ...next };
	const current: Record<string, unknown> = {
		name: asset.name,
		vendor: asset.vendor,
		owner_user_id: asset.ownerUserId,
		business_purpose: asset.businessPurpose,
		data_categories: [...asset.dataCategories].sort(),
		risk_tier: asset.riskTier,
		risk_score: asset.riskScore,
		status: asset.status,
		review_due_at: asset.reviewDueAt,
	};
	return Object.fromEntries(
		Object.entries(next).filter(
			([key, value]) => JSON.stringify(value) !== JSON.stringify(current[key]),
		),
	);
}

function draftProblem(draft: AssetDraft, creating: boolean): DashboardMessageKey | null {
	if (creating && !/^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$/.test(draft.identifier.trim())) {
		return "gov.reg.problem.identifier";
	}
	if (
		creating &&
		draft.assetType === "mcp_server" &&
		!/^[A-Za-z0-9][A-Za-z0-9._:/_-]{0,255}$/.test(draft.identifier.trim())
	) {
		return "gov.reg.problem.mcpIdentifier";
	}
	if (!validText(draft.name, 120)) return "gov.reg.problem.name";
	if (draft.vendor.trim() && !validText(draft.vendor, 120)) return "gov.reg.problem.vendor";
	if (draft.businessPurpose.trim() && !validText(draft.businessPurpose, TEXT_MAX))
		return "gov.reg.problem.purpose";
	if (draft.riskScore.trim() && !/^(100|[1-9]?\d)$/.test(draft.riskScore.trim()))
		return "gov.reg.problem.score";
	if (draft.riskTier === "prohibited" && draft.status !== "banned" && draft.status !== "retired") {
		return "gov.reg.problem.prohibited";
	}
	return null;
}

function AssetForm({
	asset,
	members,
	busy,
	onSubmit,
	onCancel,
}: {
	asset: AiAsset | null;
	members: TeamMember[];
	busy: boolean;
	onSubmit: (fields: Record<string, unknown>) => void;
	onCancel: () => void;
}) {
	const t = useT();
	// The parent keys this form by entry id and version, so a saved or
	// concurrently changed entry remounts it with fresh values.
	const [draft, setDraft] = useState<AssetDraft>(() => draftFrom(asset));
	const creating = asset === null;
	const problem = draftProblem(draft, creating);
	const fields = fieldsFrom(draft, asset);
	const set = <K extends keyof AssetDraft>(key: K, value: AssetDraft[K]) =>
		setDraft((current) => ({ ...current, [key]: value }));
	const prefix = asset ? `asset-${asset.id}` : "asset-new";
	return (
		<form
			className="stack"
			style={{ maxWidth: 760 }}
			onSubmit={(event) => {
				event.preventDefault();
				if (!problem && Object.keys(fields).length > 0) onSubmit(fields);
			}}
		>
			{creating ? (
				<div className="cols">
					<div className="stack" style={{ gap: 4 }}>
						<label className="label" htmlFor={`${prefix}-type`}>
							{t("gov.reg.type")}
						</label>
						<select
							id={`${prefix}-type`}
							className="input"
							value={draft.assetType}
							onChange={(event) => set("assetType", event.target.value as AssetType)}
						>
							{ASSET_TYPES.map((type) => (
								<option key={type} value={type}>
									{t(ASSET_TYPE_LABEL[type])}
								</option>
							))}
						</select>
					</div>
					<div className="stack" style={{ gap: 4 }}>
						<label className="label" htmlFor={`${prefix}-identifier`}>
							{t("gov.reg.identifier")}
						</label>
						<input
							id={`${prefix}-identifier`}
							className="input mono"
							value={draft.identifier}
							maxLength={256}
							placeholder={
								draft.assetType === "mcp_server"
									? "github"
									: draft.assetType === "ai_site"
										? "chatgpt"
										: "claude-code"
							}
							onChange={(event) => set("identifier", event.target.value)}
						/>
					</div>
				</div>
			) : null}
			<div className="cols">
				<div className="stack" style={{ gap: 4 }}>
					<label className="label" htmlFor={`${prefix}-name`}>
						{t("common.name")}
					</label>
					<input
						id={`${prefix}-name`}
						className="input"
						value={draft.name}
						maxLength={120}
						onChange={(event) => set("name", event.target.value)}
					/>
				</div>
				<div className="stack" style={{ gap: 4 }}>
					<label className="label" htmlFor={`${prefix}-vendor`}>
						{t("gov.reg.vendor")}
					</label>
					<input
						id={`${prefix}-vendor`}
						className="input"
						value={draft.vendor}
						maxLength={120}
						onChange={(event) => set("vendor", event.target.value)}
					/>
				</div>
				<div className="stack" style={{ gap: 4 }}>
					<label className="label" htmlFor={`${prefix}-owner`}>
						{t("gov.reg.owner")}
					</label>
					<select
						id={`${prefix}-owner`}
						className="input"
						value={draft.ownerUserId}
						onChange={(event) => set("ownerUserId", event.target.value)}
					>
						<option value="">{t("gov.reg.unassigned")}</option>
						{members.map((member) => (
							<option key={member.user_id} value={member.user_id}>
								{member.email || member.user_id}
							</option>
						))}
					</select>
				</div>
			</div>
			<div className="stack" style={{ gap: 4 }}>
				<label className="label" htmlFor={`${prefix}-purpose`}>
					{t("gov.reg.purpose")}
				</label>
				<textarea
					id={`${prefix}-purpose`}
					className="input"
					rows={2}
					maxLength={TEXT_MAX}
					value={draft.businessPurpose}
					onChange={(event) => set("businessPurpose", event.target.value)}
				/>
			</div>
			<fieldset className="stack" style={{ gap: 4, border: 0, padding: 0, margin: 0 }}>
				<legend className="label">{t("gov.reg.categories")}</legend>
				<div className="row" style={{ gap: 12, flexWrap: "wrap" }}>
					{DATA_CATEGORIES.map((category) => (
						<label key={category} className="row small" style={{ gap: 4 }}>
							<input
								type="checkbox"
								checked={draft.dataCategories.includes(category)}
								onChange={(event) =>
									set(
										"dataCategories",
										event.target.checked
											? [...draft.dataCategories, category]
											: draft.dataCategories.filter((item) => item !== category),
									)
								}
							/>
							{t(CATEGORY_LABEL[category])}
						</label>
					))}
				</div>
			</fieldset>
			<div className="cols">
				<div className="stack" style={{ gap: 4 }}>
					<label className="label" htmlFor={`${prefix}-tier`}>
						{t("gov.reg.tier")}
					</label>
					<select
						id={`${prefix}-tier`}
						className="input"
						value={draft.riskTier}
						onChange={(event) => set("riskTier", event.target.value as RiskTier)}
					>
						{RISK_TIERS.map((tier) => (
							<option key={tier} value={tier}>
								{t(RISK_LABEL[tier])}
							</option>
						))}
					</select>
				</div>
				<div className="stack" style={{ gap: 4 }}>
					<label className="label" htmlFor={`${prefix}-score`}>
						{t("gov.reg.score")}
					</label>
					<input
						id={`${prefix}-score`}
						className="input"
						inputMode="numeric"
						value={draft.riskScore}
						onChange={(event) => set("riskScore", event.target.value)}
					/>
				</div>
				<div className="stack" style={{ gap: 4 }}>
					<label className="label" htmlFor={`${prefix}-status`}>
						{t("common.status")}
					</label>
					<select
						id={`${prefix}-status`}
						className="input"
						value={draft.status}
						onChange={(event) => set("status", event.target.value as AssetStatus)}
					>
						{ASSET_STATUSES.map((status) => (
							<option key={status} value={status}>
								{t(STATUS_LABEL[status])}
							</option>
						))}
					</select>
				</div>
				<div className="stack" style={{ gap: 4 }}>
					<label className="label" htmlFor={`${prefix}-review`}>
						{t("gov.reg.nextReview")}
					</label>
					<input
						id={`${prefix}-review`}
						className="input"
						type="date"
						value={draft.reviewDueAt}
						onChange={(event) => set("reviewDueAt", event.target.value)}
					/>
				</div>
			</div>
			<p className="muted small">
				{t("gov.reg.effectOf", {
					effect: t(
						ENFORCEMENT_LABEL[
							enforcementOf({
								assetType: draft.assetType,
								identifier: draft.identifier.trim(),
								status: draft.status,
							})
						],
					),
				})}
			</p>
			{problem ? (
				<p className="small" role="alert">
					{t(problem)}
				</p>
			) : null}
			<div className="row" style={{ gap: 8 }}>
				<button
					className="button"
					type="submit"
					disabled={busy || problem !== null || Object.keys(fields).length === 0}
				>
					{creating ? t("gov.reg.add") : t("gov.reg.save")}
				</button>
				<button
					className="button button-secondary"
					type="button"
					disabled={busy}
					onClick={onCancel}
				>
					{t("common.cancel")}
				</button>
			</div>
		</form>
	);
}

interface Suggestion {
	kind: AssetEvidence["kind"];
	ref: string;
	date: string;
	severity?: string;
}

function suggestionLabel(item: Suggestion, t: Translate): string {
	return item.kind === "posture_finding"
		? t("gov.reg.findingSuggestion", { severity: item.severity ?? "", date: item.date })
		: t("gov.reg.incidentSuggestion", { id: item.ref, date: item.date });
}

function EvidencePanel({
	asset,
	evidence,
	canManage,
	busy,
	tenantId,
	onLink,
}: {
	asset: AiAsset;
	evidence: AssetEvidence[];
	canManage: boolean;
	busy: boolean;
	tenantId: string;
	onLink: (kind: string, ref: string, link: boolean) => void;
}) {
	const t = useT();
	const [suggestions, setSuggestions] = useState<Suggestion[]>([]);
	// A failed lookup must not look like "nothing to suggest".
	const [suggestionsUnavailable, setSuggestionsUnavailable] = useState(false);
	// Suggestions store data; labels are built at render time in the viewer's language.
	useEffect(() => {
		if (!canManage) return;
		let cancelled = false;
		void (async () => {
			try {
				const [findings, incidents] = await Promise.all([
					asset.assetType === "mcp_server"
						? supabase
								.from("posture_findings")
								.select("id,severity,observed_at")
								.eq("tenant_id", tenantId)
								.eq("mcp_server_name", asset.identifier)
								.order("observed_at", { ascending: false })
								.limit(10)
						: Promise.resolve({ data: [], error: null }),
					supabase
						.from("events")
						.select("id,created_at")
						.eq("tenant_id", tenantId)
						.eq("type", "incident")
						.order("created_at", { ascending: false })
						.limit(10),
				]);
				if (cancelled) return;
				if (
					findings.error ||
					incidents.error ||
					!Array.isArray(findings.data) ||
					!Array.isArray(incidents.data)
				) {
					setSuggestions([]);
					setSuggestionsUnavailable(true);
					return;
				}
				setSuggestionsUnavailable(false);
				setSuggestions([
					...(findings.data as Array<{ id: number; severity: string; observed_at: string }>).map(
						(row) => ({
							kind: "posture_finding" as const,
							ref: String(row.id),
							severity: row.severity,
							date: formatDate(row.observed_at),
						}),
					),
					...(incidents.data as Array<{ id: number; created_at: string }>).map((row) => ({
						kind: "incident" as const,
						ref: String(row.id),
						date: formatDate(row.created_at),
					})),
				]);
			} catch {
				if (!cancelled) {
					setSuggestions([]);
					setSuggestionsUnavailable(true);
				}
			}
		})();
		return () => {
			cancelled = true;
		};
	}, [asset.assetType, asset.identifier, canManage, tenantId]);
	const unlinked = suggestions.filter(
		(item) => !evidence.some((linked) => linked.kind === item.kind && linked.ref === item.ref),
	);
	return (
		<div className="stack" style={{ gap: 6 }}>
			<h3 style={{ margin: 0 }}>{t("gov.reg.evidence")}</h3>
			{evidence.length === 0 ? (
				<p className="muted small">{t("gov.reg.noEvidence")}</p>
			) : (
				<ul className="stack" style={{ gap: 4, paddingLeft: 18, margin: 0 }}>
					{evidence.map((item) => (
						<li key={item.id} className="small">
							<span className="mono">{item.label}</span>{" "}
							<span className="muted">
								{t("gov.reg.linkedOn", { date: formatDate(item.linkedAt) })}
							</span>
							{canManage ? (
								<button
									className="button button-ghost button-sm"
									type="button"
									disabled={busy}
									onClick={() => onLink(item.kind, item.ref, false)}
								>
									{t("gov.reg.unlink")}
								</button>
							) : null}
						</li>
					))}
				</ul>
			)}
			{canManage && suggestionsUnavailable ? (
				<p className="muted small" role="status" style={{ margin: 0 }}>
					{t("gov.reg.suggestionsUnavailable")}
				</p>
			) : null}
			{canManage && unlinked.length > 0 ? (
				<div className="stack" style={{ gap: 4 }}>
					<p className="muted small" style={{ margin: 0 }}>
						{t("gov.reg.linkRelated")}
					</p>
					<div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
						{unlinked.map((item) => (
							<button
								key={`${item.kind}:${item.ref}`}
								className="button button-secondary button-sm"
								type="button"
								disabled={busy}
								onClick={() => onLink(item.kind, item.ref, true)}
							>
								+ {suggestionLabel(item, t)}
							</button>
						))}
					</div>
				</div>
			) : null}
		</div>
	);
}

function EnforcementCard({ tenantId }: { tenantId: string }) {
	const t = useT();
	const [preview, setPreview] = useState<EnforcementPreview | null>(null);
	// The error code; the message is rendered in the viewer's language.
	const [error, setError] = useState<string | null>(null);
	const [refresh, setRefresh] = useState(0);
	useEffect(() => {
		let cancelled = false;
		void governanceAction(tenantId, "enforcement_preview").then((result) => {
			if (cancelled) return;
			if (!result.ok) {
				setError(result.error);
				return;
			}
			const parsed = readPreview(result.value);
			setPreview(parsed);
			setError(parsed ? null : "governance_unavailable");
		});
		return () => {
			cancelled = true;
		};
	}, [tenantId, refresh]);
	const managed = JSON.stringify({ blockedSites: preview?.blockedSites ?? [] }, null, 2);
	return (
		<section className="card stack" aria-labelledby="enforcement-heading">
			<div className="panel-head">
				<h2 id="enforcement-heading">{t("gov.reg.enforces")}</h2>
				<button
					className="button button-secondary button-sm"
					type="button"
					onClick={() => setRefresh((value) => value + 1)}
				>
					{t("common.refresh")}
				</button>
			</div>
			<p className="muted small">{t("gov.reg.enforcesLead")}</p>
			{error ? <p role="alert">{governanceErrorMessage(error, t)}</p> : null}
			{preview ? (
				<>
					{preview.runtimePolicyVersion === 0 &&
					(preview.denyServers.length > 0 || preview.approvalServers.length > 0) ? (
						<div className="notice notice-warning" role="status">
							{t("gov.reg.noRuntimePolicy")}
						</div>
					) : null}
					<dl className="kv">
						<dt>{t("gov.reg.mcpBlocked")}</dt>
						<dd className="mono">{preview.denyServers.join(", ") || t("gov.none")}</dd>
						<dt>{t("gov.reg.mcpApproval")}</dt>
						<dd className="mono">{preview.approvalServers.join(", ") || t("gov.none")}</dd>
					</dl>
					<p className="small" style={{ marginBottom: 4 }}>
						{t("gov.reg.browserPolicy")}
					</p>
					<pre className="approval-summary" data-testid="browser-guard-managed-policy">
						{managed}
					</pre>
				</>
			) : null}
		</section>
	);
}

/**
 * Keyed by tenant: switching team remounts the page, so a request or decision
 * still in flight for the previous tenant can never write into the new view.
 */
export function GovernanceRegisterPage() {
	const { currentTeam } = useTeam();
	return <TenantGovernanceRegisterPage key={currentTeam?.id ?? "no-tenant"} />;
}

function TenantGovernanceRegisterPage() {
	const t = useT();
	const { currentTeam, currentRole, roleResolved, members, currentUserId } = useTeam();
	const tenantId = currentTeam?.id ?? null;
	const { data, error, reload } = useGovernanceData(tenantId);
	const now = useNow();
	const canManage = roleResolved && (currentRole === "owner" || currentRole === "admin");
	const isReviewer = Boolean(data?.reviewers.includes(currentUserId));
	const canReview = canManage || (roleResolved && currentRole === "member" && isReviewer);
	const [notice, setNotice] = useState<Notice | null>(null);
	const [busy, setBusy] = useState(false);
	const [selectedId, setSelectedId] = useState<string | null>(null);
	const [creating, setCreating] = useState(false);
	const [search, setSearch] = useState("");
	const [typeFilter, setTypeFilter] = useState<AssetType | "all">("all");
	const [statusFilter, setStatusFilter] = useState<AssetStatus | "all">("all");
	const [overdueOnly, setOverdueOnly] = useState(false);

	useEffect(() => {
		setSelectedId(null);
		setCreating(false);
		setNotice(null);
	}, [tenantId]);

	const assets = data?.assets ?? [];
	const overdue = useMemo(
		() => assets.filter((asset) => isReviewOverdue(asset, now)),
		[assets, now],
	);
	const filtered = useMemo(() => {
		const needle = search.trim().toLowerCase();
		return assets.filter(
			(asset) =>
				(typeFilter === "all" || asset.assetType === typeFilter) &&
				(statusFilter === "all" || asset.status === statusFilter) &&
				(!overdueOnly || isReviewOverdue(asset, now)) &&
				(!needle ||
					asset.name.toLowerCase().includes(needle) ||
					asset.identifier.toLowerCase().includes(needle) ||
					(asset.vendor ?? "").toLowerCase().includes(needle)),
		);
	}, [assets, typeFilter, statusFilter, overdueOnly, search, now]);
	const selected = assets.find((asset) => asset.id === selectedId) ?? null;
	const pendingIntake = data?.intake.filter((request) => request.status === "pending").length ?? 0;

	async function run(action: string, payload: Record<string, unknown>, success: string) {
		// `success` is already translated by the caller.
		if (!tenantId) return false;
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
			return false;
		}
		setNotice({ tone: "success", message: success });
		await reload();
		return true;
	}

	if (!currentTeam || !tenantId) return <div role="alert">{t("gov.reg.selectTeam")}</div>;

	return (
		<div className="stack">
			<div className="card">
				<p className="eyebrow">{t("gov.eyebrow")}</p>
				<h1>{t("gov.reg.title")}</h1>
				<p className="muted" style={{ maxWidth: 820 }}>
					{t("gov.reg.lead")}
				</p>
				<GovernanceTabs />
			</div>
			{notice ? <NoticeBanner notice={notice} tenantId={tenantId} /> : null}
			{error ? (
				<div className="notice notice-danger" role="alert">
					{governanceErrorMessage(error, t)}
				</div>
			) : null}
			{!data && !error ? <div role="status">{t("gov.reg.loading")}</div> : null}
			{data && (data.truncated.assets || data.truncated.evidence) ? (
				<div className="notice notice-warning" role="note" data-testid="register-truncated">
					{data.truncated.assets
						? t("gov.reg.truncatedAssets", { count: assets.length.toLocaleString() })
						: null}
					{data.truncated.assets && data.truncated.evidence ? " " : null}
					{data.truncated.evidence
						? t("gov.reg.truncatedEvidence", { count: data.evidence.length.toLocaleString() })
						: null}
				</div>
			) : null}
			{data ? (
				<>
					<div className="grid">
						<div className="card stat-card">
							<span className="stat-label">{t("gov.reg.stat.systems")}</span>
							<span className="stat-value">{assets.length}</span>
						</div>
						<div className="card stat-card">
							<span className="stat-label">{t("gov.reg.stat.approved")}</span>
							<span className="stat-value">
								{assets.filter((a) => a.status === "approved").length}
							</span>
						</div>
						<div className="card stat-card">
							<span className="stat-label">{t("gov.reg.stat.restricted")}</span>
							<span className="stat-value">
								{assets.filter((a) => a.status === "restricted" || a.status === "banned").length}
							</span>
						</div>
						<div className="card stat-card">
							<span className="stat-label">{t("gov.reg.stat.overdue")}</span>
							<span className="stat-value" data-testid="overdue-count">
								{overdue.length}
							</span>
						</div>
						<div className="card stat-card">
							<span className="stat-label">{t("gov.reg.stat.intake")}</span>
							<span className="stat-value">{pendingIntake}</span>
						</div>
					</div>
					{overdue.length > 0 ? (
						<div className="notice notice-warning" role="status" data-testid="overdue-reviews">
							<b>
								{overdue.length === 1
									? t("gov.reg.overdueOne")
									: t("gov.reg.overdueMany", { count: overdue.length })}
							</b>
							<div className="muted small" style={{ marginTop: 6 }}>
								{overdue
									.slice(0, 8)
									.map((asset) =>
										t("gov.reg.due", { name: asset.name, date: asset.reviewDueAt ?? "—" }),
									)
									.join(" · ")}
								{overdue.length > 8 ? t("gov.reg.andMore", { count: overdue.length - 8 }) : ""}
							</div>
							<button
								className="button button-secondary button-sm"
								type="button"
								style={{ marginTop: 8 }}
								onClick={() => setOverdueOnly(true)}
							>
								{t("gov.reg.showOverdue")}
							</button>
						</div>
					) : null}
					<section className="card stack">
						<div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
							<input
								className="input"
								aria-label={t("gov.reg.search")}
								placeholder={t("gov.reg.searchPlaceholder")}
								value={search}
								onChange={(event) => setSearch(event.target.value)}
								style={{ maxWidth: 280 }}
							/>
							<select
								className="input"
								aria-label={t("gov.reg.filterType")}
								value={typeFilter}
								style={{ maxWidth: 220 }}
								onChange={(event) => setTypeFilter(event.target.value as AssetType | "all")}
							>
								<option value="all">{t("gov.reg.allTypes")}</option>
								{ASSET_TYPES.map((type) => (
									<option key={type} value={type}>
										{t(ASSET_TYPE_LABEL[type])}
									</option>
								))}
							</select>
							<select
								className="input"
								aria-label={t("gov.reg.filterStatus")}
								value={statusFilter}
								style={{ maxWidth: 180 }}
								onChange={(event) => setStatusFilter(event.target.value as AssetStatus | "all")}
							>
								<option value="all">{t("gov.reg.allStatuses")}</option>
								{ASSET_STATUSES.map((status) => (
									<option key={status} value={status}>
										{t(STATUS_LABEL[status])}
									</option>
								))}
							</select>
							<label className="row small" style={{ gap: 4 }}>
								<input
									type="checkbox"
									checked={overdueOnly}
									onChange={(event) => setOverdueOnly(event.target.checked)}
								/>
								{t("gov.reg.overdueOnly")}
							</label>
							{canManage ? (
								<>
									<button
										className="button button-secondary button-sm"
										type="button"
										disabled={busy}
										onClick={() => void run("import_candidates", {}, t("gov.reg.imported"))}
									>
										{t("gov.reg.import")}
									</button>
									<button
										className="button button-sm"
										type="button"
										disabled={busy}
										onClick={() => {
											setCreating(true);
											setSelectedId(null);
										}}
									>
										{t("gov.reg.addSystem")}
									</button>
								</>
							) : null}
						</div>
						{creating && canManage ? (
							<div className="card">
								<h2>{t("gov.reg.addTitle")}</h2>
								<AssetForm
									asset={null}
									members={members}
									busy={busy}
									onCancel={() => setCreating(false)}
									onSubmit={(fields) =>
										void run("upsert_asset", { fields }, t("gov.reg.added")).then(
											(ok) => ok && setCreating(false),
										)
									}
								/>
							</div>
						) : null}
						{assets.length === 0 ? (
							<p className="muted">
								{t("gov.reg.empty")}
								{canManage ? t("gov.reg.emptyManage") : t("gov.reg.emptyMember")}
							</p>
						) : (
							<div className="table-wrap">
								<table className="table" data-testid="asset-register">
									<thead>
										<tr>
											<th scope="col">{t("gov.reg.col.system")}</th>
											<th scope="col">{t("gov.reg.type")}</th>
											<th scope="col">{t("common.status")}</th>
											<th scope="col">{t("gov.reg.col.risk")}</th>
											<th scope="col">{t("gov.reg.owner")}</th>
											<th scope="col">{t("gov.reg.col.data")}</th>
											<th scope="col">{t("gov.reg.nextReview")}</th>
											<th scope="col">{t("gov.reg.col.source")}</th>
											<th scope="col">
												<span className="sr-only">{t("gov.reg.col.actions")}</span>
											</th>
										</tr>
									</thead>
									<tbody>
										{filtered.map((asset) => (
											<tr key={asset.id}>
												<td>
													<div>{asset.name}</div>
													<div className="mono muted small">{asset.identifier}</div>
												</td>
												<td>{t(ASSET_TYPE_LABEL[asset.assetType])}</td>
												<td>
													<span className={STATUS_BADGE[asset.status]}>
														{t(STATUS_LABEL[asset.status])}
													</span>
												</td>
												<td>
													{t(RISK_LABEL[asset.riskTier])}
													{asset.riskScore !== null ? ` · ${asset.riskScore}` : ""}
												</td>
												<td>{memberLabel(members, asset.ownerUserId, currentUserId, t)}</td>
												<td className="small">
													{asset.dataCategories.map((c) => t(CATEGORY_LABEL[c])).join(", ") || "—"}
												</td>
												<td>
													{asset.reviewDueAt ?? "—"}
													{isReviewOverdue(asset, now) ? (
														<span className="badge badge-warning" style={{ marginLeft: 6 }}>
															{t("gov.reg.overdue")}
														</span>
													) : null}
												</td>
												<td className="small">{sourceLabel(asset.source, t)}</td>
												<td>
													<button
														className="button button-secondary button-sm"
														type="button"
														onClick={() => {
															setSelectedId(asset.id);
															setCreating(false);
														}}
													>
														{t("gov.reg.open")}
													</button>
												</td>
											</tr>
										))}
										{filtered.length === 0 ? (
											<tr>
												<td colSpan={9}>{t("gov.reg.noMatch")}</td>
											</tr>
										) : null}
									</tbody>
								</table>
							</div>
						)}
					</section>
					{selected ? (
						<section
							className="card stack"
							aria-label={t("gov.reg.entry", { name: selected.name })}
						>
							<div className="panel-head">
								<h2>{selected.name}</h2>
								<button
									className="button button-ghost button-sm"
									type="button"
									onClick={() => setSelectedId(null)}
								>
									{t("gov.reg.close")}
								</button>
							</div>
							<dl className="kv">
								<dt>{t("gov.reg.identifier")}</dt>
								<dd className="mono">{selected.identifier}</dd>
								<dt>{t("gov.reg.effect")}</dt>
								<dd>{t(ENFORCEMENT_LABEL[enforcementOf(selected)])}</dd>
								<dt>{t("gov.reg.observed")}</dt>
								<dd>
									{selected.firstObservedAt
										? `${formatDate(selected.firstObservedAt)} – ${formatDate(selected.lastObservedAt)}`
										: t("gov.reg.notObserved")}
								</dd>
								<dt>{t("gov.reg.lastReview")}</dt>
								<dd>
									{selected.lastReviewedAt
										? t("gov.reg.reviewedBy", {
												time: formatTime(selected.lastReviewedAt),
												member: memberLabel(members, selected.lastReviewedBy, currentUserId, t),
											})
										: t("gov.never")}
								</dd>
								<dt>{t("gov.reg.purpose")}</dt>
								<dd>{selected.businessPurpose ?? "—"}</dd>
							</dl>
							{canReview && selected.status !== "retired" ? (
								<div>
									<button
										className="button button-secondary button-sm"
										type="button"
										disabled={busy}
										onClick={() =>
											void run(
												"review_asset",
												{ asset_id: selected.id },
												t("gov.reg.reviewRecorded", { name: selected.name }),
											)
										}
									>
										{t("gov.reg.markReviewed")}
									</button>
									<span className="muted small" style={{ marginLeft: 8 }}>
										{t("gov.reg.markReviewedHint")}
									</span>
								</div>
							) : null}
							{canManage ? (
								<AssetForm
									key={`${selected.id}:${selected.version}`}
									asset={selected}
									members={members}
									busy={busy}
									onCancel={() => setSelectedId(null)}
									onSubmit={(fields) =>
										void run(
											"upsert_asset",
											{ asset_id: selected.id, expected_version: selected.version, fields },
											t("gov.reg.updated", { name: selected.name }),
										)
									}
								/>
							) : (
								<p className="muted small">{t("gov.reg.readOnly")}</p>
							)}
							<EvidencePanel
								asset={selected}
								evidence={data.evidence.filter((item) => item.assetId === selected.id)}
								canManage={canManage}
								busy={busy}
								tenantId={tenantId}
								onLink={(kind, ref, link) =>
									void run(
										"link_evidence",
										{ asset_id: selected.id, kind, ref, link },
										link ? t("gov.reg.evidenceLinked") : t("gov.reg.evidenceUnlinked"),
									)
								}
							/>
						</section>
					) : null}
					<EnforcementCard tenantId={tenantId} />
				</>
			) : null}
		</div>
	);
}
