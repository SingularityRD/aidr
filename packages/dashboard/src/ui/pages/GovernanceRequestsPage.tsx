import { useEffect, useMemo, useState } from "react";
import { useTeam } from "../../enterprise/team-provider";
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
} from "../../lib/governance";
import { supabase } from "../../lib/supabase";
import {
	formatDate,
	formatTime,
	GovernanceTabs,
	memberLabel,
	type Notice,
	NoticeBanner,
	ReasonField,
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
		? "Describe the business purpose (up to 1000 characters)."
		: existing
			? null
			: !/^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$/.test(identifier.trim())
				? "Enter an identifier (for an MCP server, the server name used in tool calls)."
				: !validText(name, 120)
					? "Enter a name."
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
					AI system
				</label>
				<select
					id="intake-existing"
					className="input"
					value={assetId}
					onChange={(event) => setAssetId(event.target.value)}
				>
					<option value="">Something not in the register yet</option>
					{assets
						.filter((asset) => asset.status !== "approved")
						.map((asset) => (
							<option key={asset.id} value={asset.id}>
								{asset.name} ({STATUS_LABEL[asset.status]})
							</option>
						))}
				</select>
			</div>
			{existing ? null : (
				<div className="cols">
					<div className="stack" style={{ gap: 4 }}>
						<label className="label" htmlFor="intake-type">
							Type
						</label>
						<select
							id="intake-type"
							className="input"
							value={assetType}
							onChange={(event) => setAssetType(event.target.value as AssetType)}
						>
							{ASSET_TYPES.map((type) => (
								<option key={type} value={type}>
									{ASSET_TYPE_LABEL[type]}
								</option>
							))}
						</select>
					</div>
					<div className="stack" style={{ gap: 4 }}>
						<label className="label" htmlFor="intake-identifier">
							Identifier
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
							Name
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
							Vendor (optional)
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
					Why do you need it? (business purpose)
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
				<legend className="label">Data it will process</legend>
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
							{CATEGORY_LABEL[category]}
						</label>
					))}
				</div>
			</fieldset>
			<div className="stack" style={{ gap: 4, maxWidth: 320 }}>
				<label className="label" htmlFor="intake-status">
					Requested outcome
				</label>
				<select
					id="intake-status"
					className="input"
					value={requestedStatus}
					onChange={(event) => setRequestedStatus(event.target.value as "approved" | "restricted")}
				>
					<option value="approved">Approved for use</option>
					<option value="restricted">Restricted use (each use needs approval)</option>
				</select>
			</div>
			{problem ? <p className="muted small">{problem}</p> : null}
			<div>
				<button className="button" type="submit" disabled={busy || problem !== null}>
					Submit request
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
					Approve
				</button>
				<button
					className="button button-danger"
					type="button"
					disabled={busy || !valid}
					onClick={() => onDecide("reject", reason.trim())}
				>
					Reject
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
	const pending = intake.filter((request) => request.status === "pending");
	const closed = intake.filter((request) => request.status !== "pending");
	return (
		<section className="card stack" aria-labelledby="intake-queue">
			<h2 id="intake-queue">Pending intake requests</h2>
			{pending.length === 0 ? (
				<p className="muted">No pending requests.</p>
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
									<dt>Type</dt>
									<dd>{ASSET_TYPE_LABEL[request.assetType]}</dd>
									<dt>Requested</dt>
									<dd>
										{request.requestedStatus === "approved" ? "Approved for use" : "Restricted use"}{" "}
										by {memberLabel(members, request.requestedBy, currentUserId)} on{" "}
										{formatDate(request.createdAt)}
									</dd>
									<dt>Purpose</dt>
									<dd>{request.businessPurpose}</dd>
									<dt>Data</dt>
									<dd>
										{request.dataCategories.map((c) => CATEGORY_LABEL[c]).join(", ") ||
											"None declared"}
									</dd>
									<dt>Expires</dt>
									<dd>{formatDate(request.expiresAt)}</dd>
								</dl>
								{own ? (
									<div className="row" style={{ gap: 8 }}>
										<span className="muted small">
											You filed this request, so someone else must decide it.
										</span>
										<button
											className="button button-secondary button-sm"
											type="button"
											disabled={busy}
											onClick={() =>
												void run(
													"cancel_request",
													{ kind: "intake", request_id: request.id },
													"Request cancelled.",
												)
											}
										>
											Cancel request
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
													? `${request.name} approved and recorded in the register.`
													: `Request for ${request.name} rejected.`,
											)
										}
									/>
								) : (
									<p className="muted small">
										An owner, administrator or designated AI governance reviewer decides this
										request.
									</p>
								)}
							</li>
						);
					})}
				</ul>
			)}
			<h3>Decided requests</h3>
			{closed.length === 0 ? (
				<p className="muted small">None yet.</p>
			) : (
				<div className="table-wrap">
					<table className="table" data-testid="intake-history">
						<thead>
							<tr>
								<th scope="col">AI system</th>
								<th scope="col">Requested by</th>
								<th scope="col">Outcome</th>
								<th scope="col">Decided by</th>
								<th scope="col">Reason</th>
							</tr>
						</thead>
						<tbody>
							{closed.map((request) => (
								<tr key={request.id}>
									<td>
										{request.name} <span className="mono muted small">{request.identifier}</span>
									</td>
									<td>{memberLabel(members, request.requestedBy, currentUserId)}</td>
									<td>{request.status}</td>
									<td>
										{memberLabel(members, request.decidedBy, currentUserId)}
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
		? "Choose a banned or restricted AI system."
		: scope === "members" && userIds.length === 0
			? "Choose at least one member."
			: scope === "agents" && agentIds.length === 0
				? "Choose at least one agent."
				: !validText(justification, TEXT_MAX)
					? "Give a justification (up to 1000 characters)."
					: !expiresAt ||
							!(expiresAt.getTime() > Date.now() + 3_600_000) ||
							expiresAt.getTime() > Date.now() + 365 * DAY_MS
						? "Choose an end date within the next 365 days."
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
						Banned or restricted AI system
					</label>
					<select
						id="exception-asset"
						className="input"
						value={assetId}
						onChange={(event) => setAssetId(event.target.value)}
					>
						<option value="">Choose…</option>
						{restricted.map((item) => (
							<option key={item.id} value={item.id}>
								{item.name} ({STATUS_LABEL[item.status]})
							</option>
						))}
					</select>
				</div>
				<div className="stack" style={{ gap: 4 }}>
					<label className="label" htmlFor="exception-scope">
						Applies to
					</label>
					<select
						id="exception-scope"
						className="input"
						value={scope}
						onChange={(event) => setScope(event.target.value as "tenant" | "members" | "agents")}
					>
						<option value="members">Selected members</option>
						<option value="agents">Selected agents</option>
						<option value="tenant">Everyone in this workspace</option>
					</select>
				</div>
				<div className="stack" style={{ gap: 4 }}>
					<label className="label" htmlFor="exception-until">
						Until (inclusive, UTC)
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
					Effect:{" "}
					{enforcementOf(asset) === "connector_deny" || enforcementOf(asset) === "connector_ask"
						? "lifts the connector restriction for this scope until the end date"
						: `recorded only (${ENFORCEMENT_LABEL[enforcementOf(asset)]})`}
					.
				</p>
			) : null}
			{scope === "members" ? (
				<fieldset className="stack" style={{ gap: 4, border: 0, padding: 0, margin: 0 }}>
					<legend className="label">Members</legend>
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
					<legend className="label">Agents</legend>
					<div className="row" style={{ gap: 12, flexWrap: "wrap" }}>
						{agents.length === 0 ? (
							<span className="muted small">No enrolled agents.</span>
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
					Justification
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
					Request exception
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
	const [reason, setReason] = useState("");
	return (
		<div className="stack" style={{ gap: 6, maxWidth: 480 }}>
			<ReasonField
				id={`revoke-${id}`}
				value={reason}
				onChange={setReason}
				label="Revocation reason"
			/>
			<div>
				<button
					className="button button-danger button-sm"
					type="button"
					disabled={busy || !validText(reason, REASON_MAX)}
					onClick={() => onRevoke(reason.trim())}
				>
					Revoke now
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
): string {
	if (exception.scopeKind === "tenant") return "Everyone in this workspace";
	if (exception.scopeKind === "members")
		return exception.scopeUserIds.map((id) => memberLabel(members, id, currentUserId)).join(", ");
	return exception.scopeAgentIds
		.map((id) => agents.find((agent) => agent.id === id)?.label ?? `${id.slice(0, 8)}…`)
		.join(", ");
}

export function GovernanceRequestsPage() {
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
				if (cancelled || agentsError || !Array.isArray(rows)) return;
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
				message: governanceErrorMessage(result.error),
				code: result.error,
			});
			return false;
		}
		setNotice({ tone: "success", message: success });
		await reload();
		return true;
	};

	if (!currentTeam || !tenantId)
		return <div role="alert">Select a team to view AI governance requests.</div>;

	return (
		<div className="stack">
			<div className="card">
				<p className="eyebrow">AI governance</p>
				<h1>Requests &amp; exceptions</h1>
				<p className="muted" style={{ maxWidth: 820 }}>
					Anyone in the workspace can ask to use a new AI tool, MCP server or site. Owners,
					administrators and designated AI governance reviewers decide, never the person who asked.
					Exceptions waive a ban or restriction for named members, agents or the whole workspace
					until an end date, and stop applying automatically when it passes.
				</p>
				<GovernanceTabs />
			</div>
			{notice ? <NoticeBanner notice={notice} tenantId={tenantId} /> : null}
			{error ? (
				<div className="notice notice-danger" role="alert">
					{governanceErrorMessage(error)}
				</div>
			) : null}
			{!data && !error ? <div role="status">Loading requests…</div> : null}
			{data ? (
				<>
					{canRequest ? (
						<section className="card stack">
							<h2>Request an AI system</h2>
							<IntakeForm
								assets={data.assets}
								busy={busy}
								onSubmit={(fields) =>
									run("submit_intake", { fields }, "Request submitted for review.")
								}
							/>
						</section>
					) : (
						<p className="muted">Viewers can follow requests but cannot file them.</p>
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
						<h2 id="exceptions-heading">Exceptions</h2>
						{canRequest ? (
							<ExceptionForm
								assets={data.assets}
								members={members}
								agents={agents}
								busy={busy}
								onSubmit={(fields) =>
									run(
										"request_exception",
										{ fields },
										"Exception requested. An owner or administrator must approve it.",
									)
								}
							/>
						) : null}
						<h3>Pending</h3>
						{pendingExceptions.length === 0 ? (
							<p className="muted small">No pending exceptions.</p>
						) : (
							<ul className="stack" style={{ listStyle: "none", padding: 0, margin: 0 }}>
								{pendingExceptions.map((item) => {
									const asset = assetsById.get(item.assetId);
									const own = item.requestedBy === currentUserId;
									return (
										<li key={item.id} className="card" data-testid="exception-pending">
											<h4 style={{ margin: 0 }}>
												{asset?.name ?? "AI system"} until {formatDate(item.expiresAt)}
											</h4>
											<p className="small">
												{scopeText(item, members, agents, currentUserId)} · requested by{" "}
												{memberLabel(members, item.requestedBy, currentUserId)}
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
															"Exception request cancelled.",
														)
													}
												>
													Cancel request
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
																? "Exception approved."
																: "Exception rejected.",
														)
													}
												/>
											) : (
												<p className="muted small">An owner or administrator decides exceptions.</p>
											)}
										</li>
									);
								})}
							</ul>
						)}
						<h3>Active</h3>
						{activeExceptions.length === 0 ? (
							<p className="muted small">No active exceptions.</p>
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
												{asset?.name ?? "AI system"}{" "}
												<span className="badge badge-warning">
													{daysLeft} day{daysLeft === 1 ? "" : "s"} left
												</span>
											</h4>
											<p className="small">
												{scopeText(item, members, agents, currentUserId)} · until{" "}
												{formatTime(item.expiresAt)} · approved by{" "}
												{memberLabel(members, item.decidedBy, currentUserId)}
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
															"Exception revoked.",
														)
													}
												/>
											) : null}
										</li>
									);
								})}
							</ul>
						)}
						<h3>Closed</h3>
						{closedExceptions.length === 0 ? (
							<p className="muted small">None yet.</p>
						) : (
							<div className="table-wrap">
								<table className="table" data-testid="exception-history">
									<thead>
										<tr>
											<th scope="col">AI system</th>
											<th scope="col">Scope</th>
											<th scope="col">Outcome</th>
											<th scope="col">Ended</th>
											<th scope="col">Reason</th>
										</tr>
									</thead>
									<tbody>
										{closedExceptions.map((item) => (
											<tr key={item.id}>
												<td>{assetsById.get(item.assetId)?.name ?? "AI system"}</td>
												<td className="small">{scopeText(item, members, agents, currentUserId)}</td>
												<td>{item.status}</td>
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
