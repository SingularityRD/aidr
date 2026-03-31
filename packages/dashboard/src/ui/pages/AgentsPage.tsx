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

			if (entRes.error) setEntitlements(null);
			else setEntitlements((entRes.data ?? null) as EntitlementsRow | null);
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
		: 1;

	return (
		<div className="stack">
			<div className="card">
				<h1>Agents</h1>
				<p className="muted">
					Connected installations (unique <code>iid</code>). Allowed: <b>{allowed}</b>. Current:{" "}
					<b>{agents.length}</b>.
				</p>
				{error ? <div className="notice notice-danger">{error}</div> : null}
			</div>

			<div className="card">
				<table className="table">
					<thead>
						<tr>
							<th>Name</th>
							<th>Runtime</th>
							<th>Last seen</th>
							<th></th>
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
									{a.agent_runtime ?? "unknown"}
									{a.agent_runtime_version ? (
										<span className="muted"> {a.agent_runtime_version}</span>
									) : null}
								</td>
								<td className="mono">{new Date(a.last_seen).toLocaleString()}</td>
								<td className="right">
									<Link className="button button-secondary" to={`/agents/${a.id}`}>
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
	);
}
