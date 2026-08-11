import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
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

type EntitlementsRow = { included_agents: number; extra_agents: number };

export function AgentsPage() {
	const [agents, setAgents] = useState<AgentRow[]>([]);
	const [entitlements, setEntitlements] = useState<EntitlementsRow | null>(null);
	const [entitlementsError, setEntitlementsError] = useState<string | null>(null);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;

		async function load() {
			setError(null);

			const [agentsRes, entRes] = await Promise.all([
				supabase
					.from("agents")
					.select("id,iid,display_name,agent_runtime,agent_runtime_version,first_seen,last_seen")
					.order("last_seen", { ascending: false }),
				supabase.from("entitlements").select("included_agents,extra_agents").maybeSingle(),
			]);

			if (cancelled) return;

			if (agentsRes.error) setError(agentsRes.error.message);
			else setAgents((agentsRes.data ?? []) as AgentRow[]);

			if (entRes.error) {
				setEntitlements(null);
				setEntitlementsError(entRes.error.message);
			} else {
				setEntitlementsError(null);
				setEntitlements((entRes.data ?? null) as EntitlementsRow | null);
			}
		}

		load();
		const t = setInterval(load, 5000);
		return () => {
			cancelled = true;
			clearInterval(t);
		};
	}, []);

	const allowed = entitlements
		? Number(entitlements.included_agents ?? 1) + Number(entitlements.extra_agents ?? 0)
		: null;

	return (
		<div className="stack">
			<div className="card">
				<div className="row space-between" style={{ alignItems: "flex-start", gap: 16 }}>
					<div>
						<h1>Agents</h1>
						<p className="muted">
							Connected installations (unique <code>iid</code>). Allowed:{" "}
							<b>{allowed ?? "unavailable"}</b>. Current: <b>{agents.length}</b>.
						</p>
					</div>
					<span className={agents.length > 0 ? "badge badge-success" : "badge badge-neutral"}>
						{agents.length > 0 ? "reporting" : "no agents"}
					</span>
				</div>
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}
				{entitlementsError ? (
					<div className="notice notice-danger" role="alert" aria-live="polite">
						Seat entitlement data is unavailable; do not infer the allowed-agent limit.{" "}
						{entitlementsError}
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
							{agents.map((a) => (
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
							{agents.length === 0 ? (
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
