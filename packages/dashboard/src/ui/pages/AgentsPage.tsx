import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import { readErrorMessage } from "../../lib/errors";
import { supabase } from "../../lib/supabase";

type AgentRow = {
	id: string;
	iid: string;
	display_name: string | null;
	agent_runtime: string | null;
	agent_runtime_version: string | null;
	first_seen: string;
	last_seen: string;
};

type SeatUsageRow = {
	included_agents: number;
	extra_agents: number;
	allowed_agents: number;
};

function isAgentRow(value: unknown): value is AgentRow {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
	const row = value as Record<string, unknown>;
	return (
		typeof row.id === "string" &&
		typeof row.iid === "string" &&
		(row.display_name === null || typeof row.display_name === "string") &&
		(row.agent_runtime === null || typeof row.agent_runtime === "string") &&
		(row.agent_runtime_version === null || typeof row.agent_runtime_version === "string") &&
		typeof row.first_seen === "string" &&
		typeof row.last_seen === "string" &&
		Number.isFinite(Date.parse(row.last_seen))
	);
}

function isSeatUsageRow(value: unknown): value is SeatUsageRow {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
	const row = value as Record<string, unknown>;
	return (
		typeof row.included_agents === "number" &&
		Number.isSafeInteger(row.included_agents) &&
		row.included_agents >= 0 &&
		typeof row.extra_agents === "number" &&
		Number.isSafeInteger(row.extra_agents) &&
		row.extra_agents >= 0 &&
		typeof row.allowed_agents === "number" &&
		Number.isSafeInteger(row.allowed_agents) &&
		row.allowed_agents === row.included_agents + row.extra_agents
	);
}

export function AgentsPage() {
	const { currentTeam } = useTeam();
	const tenantId = currentTeam?.id;
	const [agents, setAgents] = useState<AgentRow[] | null>(null);
	const [seatUsage, setSeatUsage] = useState<SeatUsageRow | null>(null);
	const [seatUsageError, setSeatUsageError] = useState<string | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [loadedTenantId, setLoadedTenantId] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;
		let requestId = 0;
		setLoadedTenantId(null);
		setAgents(null);
		setSeatUsage(null);
		setError(null);
		setSeatUsageError(null);
		if (!tenantId) return;
		const activeTenantId = tenantId;

		async function load() {
			const currentRequest = ++requestId;
			try {
				const [agentsRes, seatRes] = await Promise.all([
					supabase
						.from("agents")
						.select("id,iid,display_name,agent_runtime,agent_runtime_version,first_seen,last_seen")
						.eq("tenant_id", activeTenantId)
						.order("last_seen", { ascending: false }),
					supabase
						.from("seat_usage")
						.select("included_agents,extra_agents,allowed_agents")
						.eq("tenant_id", activeTenantId)
						.maybeSingle(),
				]);

				if (cancelled || currentRequest !== requestId) return;
				setLoadedTenantId(activeTenantId);

				if (
					agentsRes.error ||
					!Array.isArray(agentsRes.data) ||
					!agentsRes.data.every(isAgentRow)
				) {
					setAgents(null);
					setError(
						agentsRes.error
							? readErrorMessage(agentsRes.error, "Failed to load agents")
							: "Agent data is unavailable.",
					);
				} else {
					setAgents(agentsRes.data);
					setError(null);
				}

				if (seatRes.error || !isSeatUsageRow(seatRes.data)) {
					setSeatUsage(null);
					setSeatUsageError(
						seatRes.error
							? readErrorMessage(seatRes.error, "Failed to load seat usage")
							: "Seat usage data is unavailable.",
					);
				} else {
					setSeatUsageError(null);
					setSeatUsage(seatRes.data);
				}
			} catch (cause) {
				if (cancelled || currentRequest !== requestId) return;
				setLoadedTenantId(activeTenantId);
				setAgents(null);
				setSeatUsage(null);
				setError(readErrorMessage(cause, "Failed to load agents"));
				setSeatUsageError("Seat usage data is unavailable.");
			}
		}

		void load();
		const t = setInterval(load, 5000);
		return () => {
			cancelled = true;
			clearInterval(t);
		};
	}, [tenantId]);

	const agentsForTeam = loadedTenantId === tenantId ? agents : null;
	const seatUsageForTeam = loadedTenantId === tenantId ? seatUsage : null;
	const allowed = seatUsageForTeam?.allowed_agents ?? null;

	return (
		<div className="stack">
			<div className="card">
				<div className="row space-between" style={{ alignItems: "flex-start", gap: 16 }}>
					<div>
						<h1>Agents</h1>
						<p className="muted">{currentTeam?.name ?? "Select a team to view its agents."}</p>
						<p className="muted">
							Known installations (unique <code>iid</code>). Allowed:{" "}
							<b>{allowed ?? "unavailable"}</b>. Recorded:{" "}
							<b>{agentsForTeam?.length ?? "unavailable"}</b>.
						</p>
					</div>
					<span className="badge badge-neutral">
						{agentsForTeam === null
							? "unavailable"
							: agentsForTeam.length > 0
								? "agents recorded"
								: "no agents"}
					</span>
				</div>
				{loadedTenantId === tenantId && error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}
				{loadedTenantId === tenantId && seatUsageError ? (
					<div className="notice notice-danger" role="alert" aria-live="polite">
						Seat usage data is unavailable; do not infer the allowed-agent limit. {seatUsageError}
					</div>
				) : null}
			</div>

			<div className="card">
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>Name</th>
								<th>Runtime</th>
								<th>Last seen</th>
								<th className="right">
									<span className="sr-only">Actions</span>
								</th>
							</tr>
						</thead>
						<tbody>
							{agentsForTeam?.map((a) => (
								<tr key={a.id}>
									<td>
										<div className="mono">{a.display_name ?? a.iid.slice(0, 12)}</div>
										<div className="muted small">iid: {a.iid}</div>
									</td>
									<td>
										<span className="badge badge-neutral badge-plain">
											{a.agent_runtime ?? "unknown"}
										</span>
										{a.agent_runtime_version ? (
											<span className="muted small"> {a.agent_runtime_version}</span>
										) : null}
									</td>
									<td className="mono">{new Date(a.last_seen).toLocaleString()}</td>
									<td className="right">
										<Link className="button button-secondary button-sm" to={`/agents/${a.id}`}>
											View
										</Link>
									</td>
								</tr>
							))}
							{agentsForTeam === null ? (
								<tr>
									<td colSpan={4} className="muted">
										Agent data is unavailable.
									</td>
								</tr>
							) : agentsForTeam.length === 0 ? (
								<tr>
									<td colSpan={4} className="muted">
										No agents yet. Go to <Link to="/onboarding">Onboarding</Link> to connect your
										first agent.
									</td>
								</tr>
							) : null}
						</tbody>
					</table>
				</div>
			</div>
		</div>
	);
}
