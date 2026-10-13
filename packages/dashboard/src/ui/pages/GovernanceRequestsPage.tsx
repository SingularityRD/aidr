import { useEffect, useMemo, useState } from "react";
import { useTeam } from "../../enterprise/team-provider";
import { englishT, type Translate, useT } from "../../i18n/I18nProvider";
import {
	type AiAsset,
	ASSET_TYPE_LABEL,
	ASSET_TYPES,
	type AssetType,
	CATEGORY_LABEL,
	DATA_CATEGORIES,
	type DataCategory,
	ENFORCEMENT_LABEL,
	enforcementOf,
	type GovernanceException,
	governanceAction,
	governanceErrorMessage,
	type IntakeRequest,
	REASON_MAX,
	STATUS_LABEL,
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
	ReasonField,
	requestStatus,
	useGovernanceData,
	useNow,
	validText,
} from "../governance/common";

type Run = (action: string, payload: Record<string, unknown>, success: string) => Promise<boolean>;

const DAY_MS = 86_400_000;

function IntakeForm({
	assets,
	busy,
	onSubmit,
}: {
	assets: AiAsset[];
	busy: boolean;
	onSubmit: (fields: Record<string, unknown>) => Promise<boolean>;
}) {
	const t = useT();
	const [assetId, setAssetId] = useState("");
	const [assetType, setAssetType] = useState<AssetType>("mcp_server");
	const [identifier, setIdentifier] = useState("");
	const [name, setName] = useState("");
	const [vendor, setVendor] = useState("");
	const [purpose, setPurpose] = useState("");
	const [categories, setCategories] = useState<DataCategory[]>([]);
	const [requestedStatus, setRequestedStatus] = useState<"approved" | "restricted">("approved");
	const existing = assets.find((asset) => asset.id === assetId) ?? null;
	const problem = !validText(purpose, TEXT_MAX)
		? t("gov.req.problem.purpose")
		: existing
			? null
			: !/^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$/.test(identifier.trim())
				? t("gov.req.problem.identifier")
				: !validText(name, 120)
					? t("gov.req.problem.name")
					: null;
	async function submit() {
		const fields: Record<string, unknown> = {
			business_purpose: purpose.trim(),
			data_categories: categories,
			requested_status: requestedStatus,
			...(existing
				? { asset_id: existing.id }
				: {
						asset_type: assetType,
						identifier: identifier.trim(),
						name: name.trim(),
						...(vendor.trim() ? { vendor: vendor.trim() } : {}),
					}),
		};
		if (await onSubmit(fields)) {
			setAssetId("");
			setIdentifier("");
			setName("");
			setVendor("");
			setPurpose("");
			setCategories([]);
		}
	}
	return (
		<form
			className="stack"
			style={{ maxWidth: 760 }}
			onSubmit={(event) => {
				event.preventDefault();
				if (!problem) void submit();
			}}
		>
			<div className="stack" style={{ gap: 4 }}>
				<label className="label" htmlFor="intake-existing">
					{t("gov.req.aiSystem")}
				</label>
				<select
					id="intake-existing"
					className="input"
					value={assetId}
					onChange={(event) => setAssetId(event.target.value)}
				>
					<option value="">{t("gov.req.notInRegister")}</option>
					{assets
						.filter((asset) => asset.status !== "approved")
						.map((asset) => (
							<option key={asset.id} value={asset.id}>
								{asset.name} ({t(STATUS_LABEL[asset.status])})
							</option>
						))}
				</select>
			</div>
			{existing ? null : (
				<div className="cols">
					<div className="stack" style={{ gap: 4 }}>
						<label className="label" htmlFor="intake-type">
							{t("gov.reg.type")}
						</label>
						<select
							id="intake-type"
							className="input"
							value={assetType}
							onChange={(event) => setAssetType(event.target.value as AssetType)}
						>
							{ASSET_TYPES.map((type) => (
								<option key={type} value={type}>
									{t(ASSET_TYPE_LABEL[type])}
								</option>
							))}
						</select>
					</div>
					<div className="stack" style={{ gap: 4 }}>
						<label className="label" htmlFor="intake-identifier">
							{t("gov.reg.identifier")}
						</label>
						<input
							id="intake-identifier"
							className="input mono"
							value={identifier}
							maxLength={256}
							onChange={(event) => setIdentifier(event.target.value)}
						/>
					</div>
					<div className="stack" style={{ gap: 4 }}>
						<label className="label" htmlFor="intake-name">
							{t("common.name")}
						</label>
						<input
							id="intake-name"
							className="input"
							value={name}
							maxLength={120}
							onChange={(event) => setName(event.target.value)}
						/>
					</div>
					<div className="stack" style={{ gap: 4 }}>
						<label className="label" htmlFor="intake-vendor">
							{t("gov.req.vendorOptional")}
						</label>
						<input
							id="intake-vendor"
							className="input"
							value={vendor}
							maxLength={120}
							onChange={(event) => setVendor(event.target.value)}
						/>
					</div>
				</div>
			)}
			<div className="stack" style={{ gap: 4 }}>
				<label className="label" htmlFor="intake-purpose">
					{t("gov.req.why")}
				</label>
				<textarea
					id="intake-purpose"
					className="input"
					rows={3}
					maxLength={TEXT_MAX}
					value={purpose}
					onChange={(event) => setPurpose(event.target.value)}
				/>
			</div>
			<fieldset className="stack" style={{ gap: 4, border: 0, padding: 0, margin: 0 }}>
				<legend className="label">{t("gov.req.dataProcessed")}</legend>
				<div className="row" style={{ gap: 12, flexWrap: "wrap" }}>
					{DATA_CATEGORIES.map((category) => (
						<label key={category} className="row small" style={{ gap: 4 }}>
							<input
								type="checkbox"
								checked={categories.includes(category)}
								onChange={(event) =>
									setCategories((current) =>
										event.target.checked
											? [...current, category]
											: current.filter((c) => c !== category),
									)
								}
							/>
							{t(CATEGORY_LABEL[category])}
						</label>
					))}
				</div>
			</fieldset>
			<div className="stack" style={{ gap: 4, maxWidth: 320 }}>
				<label className="label" htmlFor="intake-status">
					{t("gov.req.outcome")}
				</label>
				<select
					id="intake-status"
					className="input"
					value={requestedStatus}
					onChange={(event) => setRequestedStatus(event.target.value as "approved" | "restricted")}
				>
					<option value="approved">{t("gov.req.approvedForUse")}</option>
					<option value="restricted">{t("gov.req.restrictedUseLong")}</option>
				</select>
			</div>
			{problem ? <p className="muted small">{problem}</p> : null}
			<div>
				<button className="button" type="submit" disabled={busy || problem !== null}>
					{t("gov.req.submit")}
				</button>
			</div>
		</form>
	);
}

function DecisionForm({
	id,
	busy,
	onDecide,
}: {
	id: string;
	busy: boolean;
	onDecide: (decision: "approve" | "reject", reason: string) => void;
}) {
	const t = useT();
	const [reason, setReason] = useState("");
	const valid = validText(reason, REASON_MAX);
	return (
		<div className="stack" style={{ maxWidth: 560, gap: 6 }}>
			<ReasonField id={`reason-${id}`} value={reason} onChange={setReason} />
			<div className="row" style={{ gap: 8 }}>
				<button
					className="button"
					type="button"
					disabled={busy || !valid}
					onClick={() => onDecide("approve", reason.trim())}
				>
					{t("gov.req.approve")}
				</button>
				<button
					className="button button-danger"
					type="button"
					disabled={busy || !valid}
					onClick={() => onDecide("reject", reason.trim())}
				>
					{t("gov.req.reject")}
				</button>
			</div>
		</div>
	);
}

function IntakeSection({
	intake,
	canDecide,
	currentUserId,
	members,
	busy,
	run,
}: {
	intake: IntakeRequest[];
	canDecide: boolean;
	currentUserId: string;
	members: ReturnType<typeof useTeam>["members"];
	busy: boolean;
	run: Run;
}) {
	const t = useT();
	const pending = intake.filter((request) => request.status === "pending");
	const closed = intake.filter((request) => request.status !== "pending");
	return (
		<section className="card stack" aria-labelledby="intake-queue">
			<h2 id="intake-queue">{t("gov.req.pendingIntake")}</h2>
			{pending.length === 0 ? (
				<p className="muted">{t("gov.req.noPending")}</p>
			) : (
				<ul className="stack" style={{ listStyle: "none", padding: 0, margin: 0 }}>
					{pending.map((request) => {
						const own = request.requestedBy === currentUserId;
						return (
							<li key={request.id} className="card" data-testid="intake-pending">
								<h3 style={{ margin: 0 }}>
									{request.name} <span className="mono muted small">{request.identifier}</span>
								</h3>
								<dl className="kv">
									<dt>{t("gov.reg.type")}</dt>
									<dd>{t(ASSET_TYPE_LABEL[request.assetType])}</dd>
									<dt>{t("gov.req.requested")}</dt>
									<dd>
										{t("gov.req.requestedLine", {
											outcome:
												request.requestedStatus === "approved"
													? t("gov.req.approvedForUse")
													: t("gov.req.restrictedUse"),
											member: memberLabel(members, request.requestedBy, currentUserId, t),
											date: formatDate(request.createdAt),
										})}
									</dd>
									<dt>{t("gov.req.purpose")}</dt>
									<dd>{request.businessPurpose}</dd>
									<dt>{t("gov.reg.col.data")}</dt>
									<dd>
										{request.dataCategories.map((c) => t(CATEGORY_LABEL[c])).join(", ") ||
											t("gov.req.noneDeclared")}
									</dd>
									<dt>{t("gov.req.expires")}</dt>
									<dd>{formatDate(request.expiresAt)}</dd>
								</dl>
								{own ? (
									<div className="row" style={{ gap: 8 }}>
										<span className="muted small">{t("gov.req.ownRequest")}</span>
										<button
											className="button button-secondary button-sm"
											type="button"
											disabled={busy}
											onClick={() =>
												void run(
													"cancel_request",
													{ kind: "intake", request_id: request.id },
													t("gov.req.cancelled"),
												)
											}
										>
											{t("gov.req.cancel")}
										</button>
									</div>
								) : canDecide ? (
									<DecisionForm
										id={request.id}
										busy={busy}
										onDecide={(decision, reason) =>
											void run(
												"decide_intake",
												{ request_id: request.id, decision, reason },
												decision === "approve"
													? t("gov.req.intakeApproved", { name: request.name })
													: t("gov.req.intakeRejected", { name: request.name }),
											)
										}
									/>
								) : (
									<p className="muted small">{t("gov.req.whoDecides")}</p>
								)}
							</li>
						);
					})}
				</ul>
			)}
			<h3>{t("gov.req.decided")}</h3>
			{closed.length === 0 ? (
				<p className="muted small">{t("gov.req.noneYet")}</p>
			) : (
				<div className="table-wrap">
					<table className="table" data-testid="intake-history">
						<thead>
							<tr>
								<th scope="col">{t("gov.req.aiSystem")}</th>
								<th scope="col">{t("gov.req.col.requestedBy")}</th>
								<th scope="col">{t("gov.req.col.outcome")}</th>
								<th scope="col">{t("gov.req.col.decidedBy")}</th>
								<th scope="col">{t("gov.req.col.reason")}</th>
							</tr>
						</thead>
						<tbody>
							{closed.map((request) => (
								<tr key={request.id}>
									<td>
										{request.name} <span className="mono muted small">{request.identifier}</span>
									</td>
									<td>{memberLabel(members, request.requestedBy, currentUserId, t)}</td>
									<td>{requestStatus(request.status, t)}</td>
									<td>
										{memberLabel(members, request.decidedBy, currentUserId, t)}
										{request.decidedAt ? ` · ${formatDate(request.decidedAt)}` : ""}
									</td>
									<td>{request.decisionReason ?? "—"}</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}
		</section>
	);
}

function ExceptionForm({
	assets,
	members,
	agents,
	busy,
	onSubmit,
}: {
	assets: AiAsset[];
	members: ReturnType<typeof useTeam>["members"];
	agents: Array<{ id: string; label: string }>;
	busy: boolean;
	onSubmit: (fields: Record<string, unknown>) => Promise<boolean>;
}) {
	const t = useT();
	const restricted = assets.filter(
		(asset) =>
			(asset.status === "banned" || asset.status === "restricted") &&
			asset.riskTier !== "prohibited",
	);
	const [assetId, setAssetId] = useState("");
	const [scope, setScope] = useState<"tenant" | "members" | "agents">("members");
	const [userIds, setUserIds] = useState<string[]>([]);
	const [agentIds, setAgentIds] = useState<string[]>([]);
	const [justification, setJustification] = useState("");
	const [until, setUntil] = useState("");
	const asset = restricted.find((item) => item.id === assetId) ?? null;
	const expiresAt = until ? new Date(`${until}T23:59:59Z`) : null;
	const problem = !asset
		? t("gov.req.problem.asset")
		: scope === "members" && userIds.length === 0
			? t("gov.req.problem.member")
			: scope === "agents" && agentIds.length === 0
				? t("gov.req.problem.agent")
				: !validText(justification, TEXT_MAX)
					? t("gov.req.problem.justification")
					: !expiresAt ||
							!(expiresAt.getTime() > Date.now() + 3_600_000) ||
							expiresAt.getTime() > Date.now() + 365 * DAY_MS
						? t("gov.req.problem.until")
						: null;
	async function submit() {
		if (!asset || !expiresAt) return;
		const ok = await onSubmit({
			asset_id: asset.id,
			scope_kind: scope,
			...(scope === "members" ? { scope_user_ids: userIds } : {}),
			...(scope === "agents" ? { scope_agent_ids: agentIds } : {}),
			justification: justification.trim(),
			expires_at: expiresAt.toISOString(),
		});
		if (ok) {
			setAssetId("");
			setUserIds([]);
			setAgentIds([]);
			setJustification("");
			setUntil("");
		}
	}
	const toggle = (list: string[], set: (next: string[]) => void, id: string, on: boolean) =>
		set(on ? [...list, id] : list.filter((item) => item !== id));
	return (
		<form
			className="stack"
			style={{ maxWidth: 760 }}
			onSubmit={(event) => {
				event.preventDefault();
				if (!problem) void submit();
			}}
		>
			<div className="cols">
				<div className="stack" style={{ gap: 4 }}>
					<label className="label" htmlFor="exception-asset">
						{t("gov.req.exceptionAsset")}
					</label>
					<select
						id="exception-asset"
						className="input"
						value={assetId}
						onChange={(event) => setAssetId(event.target.value)}
					>
						<option value="">{t("gov.req.choose")}</option>
						{restricted.map((item) => (
							<option key={item.id} value={item.id}>
								{item.name} ({t(STATUS_LABEL[item.status])})
							</option>
						))}
					</select>
				</div>
				<div className="stack" style={{ gap: 4 }}>
					<label className="label" htmlFor="exception-scope">
						{t("gov.req.appliesTo")}
					</label>
					<select
						id="exception-scope"
						className="input"
						value={scope}
						onChange={(event) => setScope(event.target.value as "tenant" | "members" | "agents")}
					>
						<option value="members">{t("gov.req.selectedMembers")}</option>
						<option value="agents">{t("gov.req.selectedAgents")}</option>
						<option value="tenant">{t("gov.req.everyone")}</option>
					</select>
				</div>
				<div className="stack" style={{ gap: 4 }}>
					<label className="label" htmlFor="exception-until">
						{t("gov.req.until")}
					</label>
					<input
						id="exception-until"
						className="input"
						type="date"
						value={until}
						onChange={(event) => setUntil(event.target.value)}
					/>
				</div>
			</div>
			{asset ? (
				<p className="muted small">
					{enforcementOf(asset) === "connector_deny" || enforcementOf(asset) === "connector_ask"
						? t("gov.req.effectConnector")
						: enforcementOf(asset) === "browser_block"
							? t("gov.req.effectBrowser")
							: t("gov.req.effectRecorded", { effect: t(ENFORCEMENT_LABEL[enforcementOf(asset)]) })}
				</p>
			) : null}
			{scope === "members" ? (
				<fieldset className="stack" style={{ gap: 4, border: 0, padding: 0, margin: 0 }}>
					<legend className="label">{t("gov.req.members")}</legend>
					<div className="row" style={{ gap: 12, flexWrap: "wrap" }}>
						{members.map((member) => (
							<label key={member.user_id} className="row small" style={{ gap: 4 }}>
								<input
									type="checkbox"
									checked={userIds.includes(member.user_id)}
									onChange={(event) =>
										toggle(userIds, setUserIds, member.user_id, event.target.checked)
									}
								/>
								{member.email || member.user_id}
							</label>
						))}
					</div>
				</fieldset>
			) : null}
			{scope === "agents" ? (
				<fieldset className="stack" style={{ gap: 4, border: 0, padding: 0, margin: 0 }}>
					<legend className="label">{t("gov.req.agents")}</legend>
					<div className="row" style={{ gap: 12, flexWrap: "wrap" }}>
						{agents.length === 0 ? (
							<span className="muted small">{t("gov.req.noAgents")}</span>
						) : (
							agents.map((agent) => (
								<label key={agent.id} className="row small" style={{ gap: 4 }}>
									<input
										type="checkbox"
										checked={agentIds.includes(agent.id)}
										onChange={(event) =>
											toggle(agentIds, setAgentIds, agent.id, event.target.checked)
										}
									/>
									{agent.label}
								</label>
							))
						)}
					</div>
				</fieldset>
			) : null}
			<div className="stack" style={{ gap: 4 }}>
				<label className="label" htmlFor="exception-justification">
					{t("gov.req.justification")}
				</label>
				<textarea
					id="exception-justification"
					className="input"
					rows={2}
					maxLength={TEXT_MAX}
					value={justification}
					onChange={(event) => setJustification(event.target.value)}
				/>
			</div>
			{problem ? <p className="muted small">{problem}</p> : null}
			<div>
				<button className="button" type="submit" disabled={busy || problem !== null}>
					{t("gov.req.requestException")}
				</button>
			</div>
		</form>
	);
}

function RevokeForm({
	id,
	busy,
	onRevoke,
}: {
	id: string;
	busy: boolean;
	onRevoke: (reason: string) => void;
}) {
	const t = useT();
	const [reason, setReason] = useState("");
	return (
		<div className="stack" style={{ gap: 6, maxWidth: 480 }}>
			<ReasonField
				id={`revoke-${id}`}
				value={reason}
				onChange={setReason}
				label={t("gov.req.revocationReason")}
			/>
			<div>
				<button
					className="button button-danger button-sm"
					type="button"
					disabled={busy || !validText(reason, REASON_MAX)}
					onClick={() => onRevoke(reason.trim())}
				>
					{t("gov.req.revokeNow")}
				</button>
			</div>
		</div>
	);
}

function scopeText(
	exception: GovernanceException,
	members: ReturnType<typeof useTeam>["members"],
	agents: Array<{ id: string; label: string }>,
	currentUserId: string,
	t: Translate = englishT,
): string {
	if (exception.scopeKind === "tenant") return t("gov.req.everyone");
	if (exception.scopeKind === "members")
		return exception.scopeUserIds
			.map((id) => memberLabel(members, id, currentUserId, t))
			.join(", ");
	return exception.scopeAgentIds
		.map((id) => agents.find((agent) => agent.id === id)?.label ?? `${id.slice(0, 8)}…`)
		.join(", ");
}

/**
 * Keyed by tenant: switching team remounts the page, so a request or decision
 * still in flight for the previous tenant can never write into the new view.
 */
export function GovernanceRequestsPage() {
	const { currentTeam } = useTeam();
	return <TenantGovernanceRequestsPage key={currentTeam?.id ?? "no-tenant"} />;
}

function TenantGovernanceRequestsPage() {
	const t = useT();
	const { currentTeam, currentRole, roleResolved, members, currentUserId } = useTeam();
	const tenantId = currentTeam?.id ?? null;
	const { data, error, reload } = useGovernanceData(tenantId);
	const now = useNow(30_000);
	const [notice, setNotice] = useState<Notice | null>(null);
	const [busy, setBusy] = useState(false);
	const [agents, setAgents] = useState<Array<{ id: string; label: string }>>([]);
	const ownerAdmin = roleResolved && (currentRole === "owner" || currentRole === "admin");
	const canRequest = roleResolved && (ownerAdmin || currentRole === "member");
	const canDecideIntake =
		ownerAdmin ||
		(roleResolved && currentRole === "member" && Boolean(data?.reviewers.includes(currentUserId)));

	useEffect(() => {
		setNotice(null);
		// Never offer the previous tenant's (or a failed read's) agents as scope targets.
		setAgents([]);
		if (!tenantId) return;
		let cancelled = false;
		void (async () => {
			try {
				const { data: rows, error: agentsError } = await supabase
					.from("agents")
					.select("id,iid,display_name")
					.eq("tenant_id", tenantId)
					.order("iid", { ascending: true })
					.limit(200);
				if (cancelled) return;
				if (agentsError || !Array.isArray(rows)) {
					setAgents([]);
					return;
				}
				setAgents(
					(rows as Array<{ id: string; iid: string; display_name: string | null }>).map((row) => ({
						id: row.id,
						label: row.display_name || row.iid,
					})),
				);
			} catch {
				if (!cancelled) setAgents([]);
			}
		})();
		return () => {
			cancelled = true;
		};
	}, [tenantId]);

	const assetsById = useMemo(
		() => new Map((data?.assets ?? []).map((asset) => [asset.id, asset])),
		[data],
	);
	const exceptions = data?.exceptions ?? [];
	const pendingExceptions = exceptions.filter((item) => item.status === "pending");
	const activeExceptions = exceptions.filter((item) => item.status === "approved");
	const closedExceptions = exceptions.filter(
		(item) => item.status !== "pending" && item.status !== "approved",
	);

	const run: Run = async (action, payload, success) => {
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
	};

	if (!currentTeam || !tenantId) return <div role="alert">{t("gov.req.selectTeam")}</div>;

	return (
		<div className="stack">
			<div className="card">
				<p className="eyebrow">{t("gov.eyebrow")}</p>
				<h1>{t("gov.tab.requests")}</h1>
				<p className="muted" style={{ maxWidth: 820 }}>
					{t("gov.req.lead")}
				</p>
				<GovernanceTabs />
			</div>
			{notice ? <NoticeBanner notice={notice} tenantId={tenantId} /> : null}
			{error ? (
				<div className="notice notice-danger" role="alert">
					{governanceErrorMessage(error, t)}
				</div>
			) : null}
			{!data && !error ? <div role="status">{t("gov.req.loading")}</div> : null}
			{data ? (
				<>
					{canRequest ? (
						<section className="card stack">
							<h2>{t("gov.req.requestSystem")}</h2>
							<IntakeForm
								assets={data.assets}
								busy={busy}
								onSubmit={(fields) => run("submit_intake", { fields }, t("gov.req.submitted"))}
							/>
						</section>
					) : (
						<p className="muted">{t("gov.req.viewerNote")}</p>
					)}
					<IntakeSection
						intake={data.intake}
						canDecide={canDecideIntake}
						currentUserId={currentUserId}
						members={members}
						busy={busy}
						run={run}
					/>
					<section className="card stack" aria-labelledby="exceptions-heading">
						<h2 id="exceptions-heading">{t("gov.req.exceptions")}</h2>
						{canRequest ? (
							<ExceptionForm
								assets={data.assets}
								members={members}
								agents={agents}
								busy={busy}
								onSubmit={(fields) =>
									run("request_exception", { fields }, t("gov.req.exceptionRequested"))
								}
							/>
						) : null}
						<h3>{t("gov.req.pending")}</h3>
						{pendingExceptions.length === 0 ? (
							<p className="muted small">{t("gov.req.noPendingExceptions")}</p>
						) : (
							<ul className="stack" style={{ listStyle: "none", padding: 0, margin: 0 }}>
								{pendingExceptions.map((item) => {
									const asset = assetsById.get(item.assetId);
									const own = item.requestedBy === currentUserId;
									return (
										<li key={item.id} className="card" data-testid="exception-pending">
											<h4 style={{ margin: 0 }}>
												{t("gov.req.untilDate", {
													name: asset?.name ?? t("gov.req.aiSystem"),
													date: formatDate(item.expiresAt),
												})}
											</h4>
											<p className="small">
												{t("gov.req.requestedBy", {
													scope: scopeText(item, members, agents, currentUserId, t),
													member: memberLabel(members, item.requestedBy, currentUserId, t),
												})}
											</p>
											<p className="small">{item.justification}</p>
											{own ? (
												<button
													className="button button-secondary button-sm"
													type="button"
													disabled={busy}
													onClick={() =>
														void run(
															"cancel_request",
															{ kind: "exception", request_id: item.id },
															t("gov.req.exceptionCancelled"),
														)
													}
												>
													{t("gov.req.cancel")}
												</button>
											) : ownerAdmin ? (
												<DecisionForm
													id={item.id}
													busy={busy}
													onDecide={(decision, reason) =>
														void run(
															"decide_exception",
															{ exception_id: item.id, decision, reason },
															decision === "approve"
																? t("gov.req.exceptionApproved")
																: t("gov.req.exceptionRejected"),
														)
													}
												/>
											) : (
												<p className="muted small">{t("gov.req.ownerDecides")}</p>
											)}
										</li>
									);
								})}
							</ul>
						)}
						<h3>{t("gov.req.active")}</h3>
						{activeExceptions.length === 0 ? (
							<p className="muted small">{t("gov.req.noActive")}</p>
						) : (
							<ul className="stack" style={{ listStyle: "none", padding: 0, margin: 0 }}>
								{activeExceptions.map((item) => {
									const asset = assetsById.get(item.assetId);
									const daysLeft = Math.max(
										0,
										Math.ceil((Date.parse(item.expiresAt) - now) / DAY_MS),
									);
									return (
										<li key={item.id} className="card" data-testid="exception-active">
											<h4 style={{ margin: 0 }}>
												{asset?.name ?? t("gov.req.aiSystem")}{" "}
												<span className="badge badge-warning">
													{daysLeft === 1
														? t("gov.req.dayLeft")
														: t("gov.req.daysLeft", { count: daysLeft })}
												</span>
											</h4>
											<p className="small">
												{t("gov.req.activeLine", {
													scope: scopeText(item, members, agents, currentUserId, t),
													time: formatTime(item.expiresAt),
													member: memberLabel(members, item.decidedBy, currentUserId, t),
												})}
											</p>
											<p className="small">{item.justification}</p>
											{ownerAdmin ? (
												<RevokeForm
													id={item.id}
													busy={busy}
													onRevoke={(reason) =>
														void run(
															"revoke_exception",
															{ exception_id: item.id, reason },
															t("gov.req.exceptionRevoked"),
														)
													}
												/>
											) : null}
										</li>
									);
								})}
							</ul>
						)}
						<h3>{t("gov.req.closed")}</h3>
						{closedExceptions.length === 0 ? (
							<p className="muted small">{t("gov.req.noneYet")}</p>
						) : (
							<div className="table-wrap">
								<table className="table" data-testid="exception-history">
									<thead>
										<tr>
											<th scope="col">{t("gov.req.aiSystem")}</th>
											<th scope="col">{t("gov.req.col.scope")}</th>
											<th scope="col">{t("gov.req.col.outcome")}</th>
											<th scope="col">{t("gov.req.col.ended")}</th>
											<th scope="col">{t("gov.req.col.reason")}</th>
										</tr>
									</thead>
									<tbody>
										{closedExceptions.map((item) => (
											<tr key={item.id}>
												<td>{assetsById.get(item.assetId)?.name ?? t("gov.req.aiSystem")}</td>
												<td className="small">
													{scopeText(item, members, agents, currentUserId, t)}
												</td>
												<td>{requestStatus(item.status, t)}</td>

												<td>{formatDate(item.expiresAt)}</td>
												<td className="small">{item.revokeReason ?? item.decisionReason ?? "—"}</td>
											</tr>
										))}
									</tbody>
								</table>
							</div>
						)}
					</section>
				</>
			) : null}
		</div>
	);
}
