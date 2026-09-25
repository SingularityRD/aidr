import { useEffect, useMemo, useState } from "react";
import { type TeamMember, useTeam } from "../../enterprise/team-provider";
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
	SOURCE_LABEL,
	STATUS_BADGE,
	STATUS_LABEL,
	TEXT_MAX,
} from "../../lib/governance";
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

function draftProblem(draft: AssetDraft, creating: boolean): string | null {
	if (creating && !/^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$/.test(draft.identifier.trim())) {
		return "Identifier: letters, digits and . _ : / @ + - only (for MCP servers, the server name used in tool calls).";
	}
	if (
		creating &&
		draft.assetType === "mcp_server" &&
		!/^[A-Za-z0-9][A-Za-z0-9._:/_-]{0,255}$/.test(draft.identifier.trim())
	) {
		return "MCP server identifiers may not contain @ or +.";
	}
	if (!validText(draft.name, 120)) return "Enter a name of up to 120 characters.";
	if (draft.vendor.trim() && !validText(draft.vendor, 120))
		return "Vendor must be up to 120 characters.";
	if (draft.businessPurpose.trim() && !validText(draft.businessPurpose, TEXT_MAX))
		return "Business purpose must be up to 1000 characters.";
	if (draft.riskScore.trim() && !/^(100|[1-9]?\d)$/.test(draft.riskScore.trim()))
		return "Risk score must be a whole number from 0 to 100.";
	if (draft.riskTier === "prohibited" && draft.status !== "banned" && draft.status !== "retired") {
		return "A prohibited-tier system must be banned or retired.";
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
							Type
						</label>
						<select
							id={`${prefix}-type`}
							className="input"
							value={draft.assetType}
							onChange={(event) => set("assetType", event.target.value as AssetType)}
						>
							{ASSET_TYPES.map((type) => (
								<option key={type} value={type}>
									{ASSET_TYPE_LABEL[type]}
								</option>
							))}
						</select>
					</div>
					<div className="stack" style={{ gap: 4 }}>
						<label className="label" htmlFor={`${prefix}-identifier`}>
							Identifier
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
						Name
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
						Vendor
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
						Owner
					</label>
					<select
						id={`${prefix}-owner`}
						className="input"
						value={draft.ownerUserId}
						onChange={(event) => set("ownerUserId", event.target.value)}
					>
						<option value="">Unassigned</option>
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
					Business purpose
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
				<legend className="label">Data categories processed</legend>
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
							{CATEGORY_LABEL[category]}
						</label>
					))}
				</div>
			</fieldset>
			<div className="cols">
				<div className="stack" style={{ gap: 4 }}>
					<label className="label" htmlFor={`${prefix}-tier`}>
						Risk tier (EU AI Act style)
					</label>
					<select
						id={`${prefix}-tier`}
						className="input"
						value={draft.riskTier}
						onChange={(event) => set("riskTier", event.target.value as RiskTier)}
					>
						{RISK_TIERS.map((tier) => (
							<option key={tier} value={tier}>
								{RISK_LABEL[tier]}
							</option>
						))}
					</select>
				</div>
				<div className="stack" style={{ gap: 4 }}>
					<label className="label" htmlFor={`${prefix}-score`}>
						Internal risk score (0–100)
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
						Status
					</label>
					<select
						id={`${prefix}-status`}
						className="input"
						value={draft.status}
						onChange={(event) => set("status", event.target.value as AssetStatus)}
					>
						{ASSET_STATUSES.map((status) => (
							<option key={status} value={status}>
								{STATUS_LABEL[status]}
							</option>
						))}
					</select>
				</div>
				<div className="stack" style={{ gap: 4 }}>
					<label className="label" htmlFor={`${prefix}-review`}>
						Next review
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
				Effect of this status:{" "}
				{
					ENFORCEMENT_LABEL[
						enforcementOf({
							assetType: draft.assetType,
							identifier: draft.identifier.trim(),
							status: draft.status,
						})
					]
				}
				.
			</p>
			{problem ? (
				<p className="small" role="alert">
					{problem}
				</p>
			) : null}
			<div className="row" style={{ gap: 8 }}>
				<button
					className="button"
					type="submit"
					disabled={busy || problem !== null || Object.keys(fields).length === 0}
				>
					{creating ? "Add to register" : "Save changes"}
				</button>
				<button
					className="button button-secondary"
					type="button"
					disabled={busy}
					onClick={onCancel}
				>
					Cancel
				</button>
			</div>
		</form>
	);
}

interface Suggestion {
	kind: AssetEvidence["kind"];
	ref: string;
	label: string;
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
	const [suggestions, setSuggestions] = useState<Suggestion[]>([]);
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
				if (cancelled || findings.error || incidents.error) return;
				setSuggestions([
					...(
						(findings.data ?? []) as Array<{ id: number; severity: string; observed_at: string }>
					).map((row) => ({
						kind: "posture_finding" as const,
						ref: String(row.id),
						label: `MCP inventory finding · ${row.severity} · ${formatDate(row.observed_at)}`,
					})),
					...((incidents.data ?? []) as Array<{ id: number; created_at: string }>).map((row) => ({
						kind: "incident" as const,
						ref: String(row.id),
						label: `Incident #${row.id} · ${formatDate(row.created_at)}`,
					})),
				]);
			} catch {
				if (!cancelled) setSuggestions([]);
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
			<h3 style={{ margin: 0 }}>Linked evidence</h3>
			{evidence.length === 0 ? (
				<p className="muted small">No findings or incidents linked yet.</p>
			) : (
				<ul className="stack" style={{ gap: 4, paddingLeft: 18, margin: 0 }}>
					{evidence.map((item) => (
						<li key={item.id} className="small">
							<span className="mono">{item.label}</span>{" "}
							<span className="muted">(linked {formatDate(item.linkedAt)})</span>
							{canManage ? (
								<button
									className="button button-ghost button-sm"
									type="button"
									disabled={busy}
									onClick={() => onLink(item.kind, item.ref, false)}
								>
									Unlink
								</button>
							) : null}
						</li>
					))}
				</ul>
			)}
			{canManage && unlinked.length > 0 ? (
				<div className="stack" style={{ gap: 4 }}>
					<p className="muted small" style={{ margin: 0 }}>
						Link related evidence:
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
								+ {item.label}
							</button>
						))}
					</div>
				</div>
			) : null}
		</div>
	);
}

function EnforcementCard({ tenantId }: { tenantId: string }) {
	const [preview, setPreview] = useState<EnforcementPreview | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [refresh, setRefresh] = useState(0);
	useEffect(() => {
		let cancelled = false;
		void governanceAction(tenantId, "enforcement_preview").then((result) => {
			if (cancelled) return;
			if (!result.ok) {
				setError(governanceErrorMessage(result.error));
				return;
			}
			const parsed = readPreview(result.value);
			setPreview(parsed);
			setError(parsed ? null : governanceErrorMessage("governance_unavailable"));
		});
		return () => {
			cancelled = true;
		};
	}, [tenantId, refresh]);
	const managed = JSON.stringify({ blockedSites: preview?.blockedSites ?? [] }, null, 2);
	return (
		<section className="card stack" aria-labelledby="enforcement-heading">
			<div className="panel-head">
				<h2 id="enforcement-heading">What the register enforces</h2>
				<button
					className="button button-secondary button-sm"
					type="button"
					onClick={() => setRefresh((value) => value + 1)}
				>
					Refresh
				</button>
			</div>
			<p className="muted small">
				The register only ever adds restrictions on top of your published runtime policy. Banned MCP
				servers are blocked and restricted ones require approval on every managed connector at its
				next policy refresh; an approved exception lifts that for its scope until it expires. Coding
				agents and model services are recorded only.
			</p>
			{error ? <p role="alert">{error}</p> : null}
			{preview ? (
				<>
					{preview.runtimePolicyVersion === 0 &&
					(preview.denyServers.length > 0 || preview.approvalServers.length > 0) ? (
						<div className="notice notice-warning" role="status">
							No runtime policy is published for this workspace yet, so connectors do not receive
							these MCP restrictions. Publish a runtime policy under Policies to deliver them.
						</div>
					) : null}
					<dl className="kv">
						<dt>MCP servers blocked (tenant-wide)</dt>
						<dd className="mono">{preview.denyServers.join(", ") || "None"}</dd>
						<dt>MCP servers requiring approval</dt>
						<dd className="mono">{preview.approvalServers.join(", ") || "None"}</dd>
					</dl>
					<p className="small" style={{ marginBottom: 4 }}>
						Browser Guard managed policy for banned AI chat sites. The control plane does not push
						browser policy: deploy this through your browser management (Chrome/Edge policy for the
						extension).
					</p>
					<pre className="approval-summary" data-testid="browser-guard-managed-policy">
						{managed}
					</pre>
				</>
			) : null}
		</section>
	);
}

export function GovernanceRegisterPage() {
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
		if (!tenantId) return false;
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
			return false;
		}
		setNotice({ tone: "success", message: success });
		await reload();
		return true;
	}

	if (!currentTeam || !tenantId)
		return <div role="alert">Select a team to view the AI asset register.</div>;

	return (
		<div className="stack">
			<div className="card">
				<p className="eyebrow">AI governance</p>
				<h1>AI asset register</h1>
				<p className="muted" style={{ maxWidth: 820 }}>
					One register of the AI systems in use in this workspace — coding agents and connectors,
					MCP servers, AI chat sites and SaaS tools, models and AI services — with owner, business
					purpose, data categories, risk tier, status and review date. Entries come from what AIDR
					already observes (enrolled agents, MCP inventory, Browser Guard site counts, discovery)
					and from manual entries and approved intake requests.
				</p>
				<GovernanceTabs />
			</div>
			{notice ? <NoticeBanner notice={notice} tenantId={tenantId} /> : null}
			{error ? (
				<div className="notice notice-danger" role="alert">
					{governanceErrorMessage(error)}
				</div>
			) : null}
			{!data && !error ? <div role="status">Loading the register…</div> : null}
			{data ? (
				<>
					<div className="grid">
						<div className="card stat-card">
							<span className="stat-label">AI systems</span>
							<span className="stat-value">{assets.length}</span>
						</div>
						<div className="card stat-card">
							<span className="stat-label">Approved</span>
							<span className="stat-value">
								{assets.filter((a) => a.status === "approved").length}
							</span>
						</div>
						<div className="card stat-card">
							<span className="stat-label">Restricted or banned</span>
							<span className="stat-value">
								{assets.filter((a) => a.status === "restricted" || a.status === "banned").length}
							</span>
						</div>
						<div className="card stat-card">
							<span className="stat-label">Reviews overdue</span>
							<span className="stat-value" data-testid="overdue-count">
								{overdue.length}
							</span>
						</div>
						<div className="card stat-card">
							<span className="stat-label">Pending intake</span>
							<span className="stat-value">{pendingIntake}</span>
						</div>
					</div>
					{overdue.length > 0 ? (
						<div className="notice notice-warning" role="status" data-testid="overdue-reviews">
							<b>
								{overdue.length === 1 ? "1 AI system is" : `${overdue.length} AI systems are`} past
								the review date.
							</b>
							<div className="muted small" style={{ marginTop: 6 }}>
								{overdue
									.slice(0, 8)
									.map((asset) => `${asset.name} (due ${asset.reviewDueAt})`)
									.join(" · ")}
								{overdue.length > 8 ? ` · and ${overdue.length - 8} more` : ""}
							</div>
							<button
								className="button button-secondary button-sm"
								type="button"
								style={{ marginTop: 8 }}
								onClick={() => setOverdueOnly(true)}
							>
								Show overdue only
							</button>
						</div>
					) : null}
					<section className="card stack">
						<div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
							<input
								className="input"
								aria-label="Search the register"
								placeholder="Search name, identifier or vendor"
								value={search}
								onChange={(event) => setSearch(event.target.value)}
								style={{ maxWidth: 280 }}
							/>
							<select
								className="input"
								aria-label="Filter by type"
								value={typeFilter}
								style={{ maxWidth: 220 }}
								onChange={(event) => setTypeFilter(event.target.value as AssetType | "all")}
							>
								<option value="all">All types</option>
								{ASSET_TYPES.map((type) => (
									<option key={type} value={type}>
										{ASSET_TYPE_LABEL[type]}
									</option>
								))}
							</select>
							<select
								className="input"
								aria-label="Filter by status"
								value={statusFilter}
								style={{ maxWidth: 180 }}
								onChange={(event) => setStatusFilter(event.target.value as AssetStatus | "all")}
							>
								<option value="all">All statuses</option>
								{ASSET_STATUSES.map((status) => (
									<option key={status} value={status}>
										{STATUS_LABEL[status]}
									</option>
								))}
							</select>
							<label className="row small" style={{ gap: 4 }}>
								<input
									type="checkbox"
									checked={overdueOnly}
									onChange={(event) => setOverdueOnly(event.target.checked)}
								/>
								Overdue reviews only
							</label>
							{canManage ? (
								<>
									<button
										className="button button-secondary button-sm"
										type="button"
										disabled={busy}
										onClick={() =>
											void run(
												"import_candidates",
												{},
												"Observed AI systems imported as proposed entries.",
											)
										}
									>
										Import observed AI systems
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
										Add AI system
									</button>
								</>
							) : null}
						</div>
						{creating && canManage ? (
							<div className="card">
								<h2>Add an AI system</h2>
								<AssetForm
									asset={null}
									members={members}
									busy={busy}
									onCancel={() => setCreating(false)}
									onSubmit={(fields) =>
										void run("upsert_asset", { fields }, "Added to the register.").then(
											(ok) => ok && setCreating(false),
										)
									}
								/>
							</div>
						) : null}
						{assets.length === 0 ? (
							<p className="muted">
								The register is empty.
								{canManage
									? " Import the AI systems AIDR has observed, or add one manually."
									: " Ask an owner or administrator to populate it, or file an intake request."}
							</p>
						) : (
							<div className="table-wrap">
								<table className="table" data-testid="asset-register">
									<thead>
										<tr>
											<th scope="col">AI system</th>
											<th scope="col">Type</th>
											<th scope="col">Status</th>
											<th scope="col">Risk</th>
											<th scope="col">Owner</th>
											<th scope="col">Data</th>
											<th scope="col">Next review</th>
											<th scope="col">Source</th>
											<th scope="col">
												<span className="sr-only">Actions</span>
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
												<td>{ASSET_TYPE_LABEL[asset.assetType]}</td>
												<td>
													<span className={STATUS_BADGE[asset.status]}>
														{STATUS_LABEL[asset.status]}
													</span>
												</td>
												<td>
													{RISK_LABEL[asset.riskTier]}
													{asset.riskScore !== null ? ` · ${asset.riskScore}` : ""}
												</td>
												<td>{memberLabel(members, asset.ownerUserId, currentUserId)}</td>
												<td className="small">
													{asset.dataCategories.map((c) => CATEGORY_LABEL[c]).join(", ") || "—"}
												</td>
												<td>
													{asset.reviewDueAt ?? "—"}
													{isReviewOverdue(asset, now) ? (
														<span className="badge badge-warning" style={{ marginLeft: 6 }}>
															Overdue
														</span>
													) : null}
												</td>
												<td className="small">{SOURCE_LABEL[asset.source] ?? asset.source}</td>
												<td>
													<button
														className="button button-secondary button-sm"
														type="button"
														onClick={() => {
															setSelectedId(asset.id);
															setCreating(false);
														}}
													>
														Open
													</button>
												</td>
											</tr>
										))}
										{filtered.length === 0 ? (
											<tr>
												<td colSpan={9}>No AI systems match the filters.</td>
											</tr>
										) : null}
									</tbody>
								</table>
							</div>
						)}
					</section>
					{selected ? (
						<section className="card stack" aria-label={`Register entry ${selected.name}`}>
							<div className="panel-head">
								<h2>{selected.name}</h2>
								<button
									className="button button-ghost button-sm"
									type="button"
									onClick={() => setSelectedId(null)}
								>
									Close
								</button>
							</div>
							<dl className="kv">
								<dt>Identifier</dt>
								<dd className="mono">{selected.identifier}</dd>
								<dt>Effect</dt>
								<dd>{ENFORCEMENT_LABEL[enforcementOf(selected)]}</dd>
								<dt>Observed</dt>
								<dd>
									{selected.firstObservedAt
										? `${formatDate(selected.firstObservedAt)} – ${formatDate(selected.lastObservedAt)}`
										: "Not observed by AIDR"}
								</dd>
								<dt>Last review</dt>
								<dd>
									{selected.lastReviewedAt
										? `${formatTime(selected.lastReviewedAt)} by ${memberLabel(members, selected.lastReviewedBy, currentUserId)}`
										: "Never"}
								</dd>
								<dt>Business purpose</dt>
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
												`Review of ${selected.name} recorded.`,
											)
										}
									>
										Mark reviewed
									</button>
									<span className="muted small" style={{ marginLeft: 8 }}>
										Sets the next review date from the workspace review interval.
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
											`${selected.name} updated.`,
										)
									}
								/>
							) : (
								<p className="muted small">
									Only owners and administrators can change register entries. Use Requests &amp;
									exceptions to ask for a change.
								</p>
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
										link ? "Evidence linked." : "Evidence unlinked.",
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
