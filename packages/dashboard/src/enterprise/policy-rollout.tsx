import { useCallback, useEffect, useRef, useState } from "react";
import { readErrorMessage } from "../lib/errors";
import { pendingPolicyChangeNotice } from "../lib/ai-governance";
import { supabase } from "../lib/supabase";
import { useTeam } from "./team-provider";

type Agent = {
	id: string;
	iid: string;
	display_name: string | null;
	target_version: number;
	loaded_version: number | null;
	received_at: string | null;
	state: "unknown" | "stale" | "current" | "outdated";
};
type Revision = { version: number; policy: Record<string, unknown>; created_at: string };
type Rollout = {
	status: string;
	version: number | null;
	targeted: number;
	current: number;
	stale: number;
	outdated: number;
	unknown: number;
};
function readRollout(value: unknown): Rollout | null {
	if (!value || typeof value !== "object") return null;
	const data = value as Record<string, unknown>;
	const progress = data.rollout_progress as Record<string, unknown> | null;
	if (data.ok !== true || !progress || typeof progress !== "object" || !["none", "running", "paused", "completed", "cancelled"].includes(String(data.status))) return null;
	for (const key of ["targeted", "current", "stale", "unknown"]) {
		if (!Number.isSafeInteger(progress[key]) || Number(progress[key]) < 0) return null;
	}
	if (progress.outdated !== undefined && (!Number.isSafeInteger(progress.outdated) || Number(progress.outdated) < 0)) return null;
	if (Number(progress.current) + Number(progress.stale) + Number(progress.outdated ?? 0) + Number(progress.unknown) !== Number(progress.targeted)) return null;
	return {
		status: String(data.status),
		version: typeof data.version === "number" && Number.isSafeInteger(data.version) ? data.version : null,
		targeted: Number(progress.targeted), current: Number(progress.current), stale: Number(progress.stale),
		outdated: Number(progress.outdated ?? 0), unknown: Number(progress.unknown),
	};
}
export function PolicyRollout({
	version,
	draft,
	onChanged,
	onReview,
}: {
	version: number | null;
	draft: string;
	onChanged: () => void;
	onReview: (policy: Record<string, unknown>) => void;
}) {
	const { currentTeam, canManageTeam } = useTeam();
	const team = currentTeam?.id;
	const selectedTeam = useRef(team);
	selectedTeam.current = team;
	const [agents, setAgents] = useState<Agent[]>([]);
	const [history, setHistory] = useState<Revision[]>([]);
	const [rollout, setRollout] = useState<Rollout | null>(null);
	const [selected, setSelected] = useState<string[]>([]);
	const [error, setError] = useState("");
	const [notice, setNotice] = useState("");
	const [busy, setBusy] = useState(false);
	const [truncated, setTruncated] = useState(false);
	const [refresh, setRefresh] = useState(0);
	const [agentCursor, setAgentCursor] = useState<string | undefined>();
	const [nextAgent, setNextAgent] = useState<string | null>(null);
	const generation = useRef(0);
	const load = useCallback(async () => {
		if (!team) return;
		const requestGeneration = ++generation.current;
		try {
			const [fleet, revisions, progress] = await Promise.all([
				supabase.functions.invoke("policy-management", {
					body: {
						action: "adoption",
						tenant_id: team,
						...(agentCursor ? { after_agent: agentCursor } : {}),
					},
				}),
				supabase.functions.invoke("policy-management", {
					body: { action: "history", tenant_id: team },
				}),
				supabase.functions.invoke("policy-management", {
					body: { action: "rollout_progress", tenant_id: team },
				}),
			]);
			if (selectedTeam.current !== team || generation.current !== requestGeneration) return;
			if (
				fleet.error ||
				revisions.error ||
				progress.error ||
				fleet.data?.ok !== true ||
				revisions.data?.ok !== true ||
				!Array.isArray(fleet.data.agents) ||
				!Array.isArray(revisions.data.revisions) ||
				!readRollout(progress.data)
			)
				throw new Error("Policy deployment status could not be loaded.");
			setAgents(fleet.data.agents);
			setRollout(readRollout(progress.data));
			setNextAgent(typeof fleet.data.next_agent === "string" ? fleet.data.next_agent : null);
			setHistory(revisions.data.revisions);
			setTruncated(fleet.data.truncated || revisions.data.truncated);
			setError("");
		} catch {
			if (selectedTeam.current === team && generation.current === requestGeneration) {
				setAgents([]);
				setRollout(null);
				setNextAgent(null);
				setHistory([]);
				setError("Policy deployment status could not be loaded. Refresh to retry.");
			}
		}
	}, [team, agentCursor]);
	useEffect(() => {
		setSelected([]);
		setAgents([]);
		setRollout(null);
		setHistory([]);
		setNotice("");
		setBusy(false);
		setAgentCursor(undefined);
		setNextAgent(null);
	}, [team]);
	useEffect(() => {
		void load();
		const timer = setInterval(() => void load(), 30000);
		return () => {
			++generation.current;
			clearInterval(timer);
		};
	}, [load, refresh, version]);

	async function change(action: "stage" | "restore" | "rollout", targetVersion?: number) {
		if (!team || !canManageTeam || version === null || busy) return;
		setBusy(true);
		setError("");
		setNotice("");
		try {
			const body =
				action === "rollout"
					? {
							action, tenant_id: team, expected_version: version,
							expected_revision_version: history[0]?.version, policy: JSON.parse(draft),
							rings: [
								{ ring_order: 1, batches: [{ batch_order: 1, agent_ids: selected.slice(0, 1) }] },
								...(selected.length > 1 ? [{ ring_order: 2, batches: [{ batch_order: 1, agent_ids: selected.slice(1) }] }] : []),
							],
						}
					: action === "stage"
					? {
							action,
							tenant_id: team,
							expected_version: version,
							expected_revision_version: history[0]?.version,
							agent_ids: selected,
							policy: JSON.parse(draft),
						}
					: { action, tenant_id: team, expected_version: version, target_version: targetVersion };
			const result = await supabase.functions.invoke("policy-management", { body });
			if (selectedTeam.current !== team) return;
			const pendingChange = result.error ? null : pendingPolicyChangeNotice(result.data);
			if (pendingChange) {
				setNotice(pendingChange);
				setSelected([]);
				return;
			}
			if (result.error || result.data?.ok !== true)
				throw new Error(
					"Policy change failed. Refresh if another administrator published a version.",
				);
			if (action === "rollout" && (typeof result.data.rollout_id !== "string" || !Number.isSafeInteger(result.data.version)))
				throw new Error("Ordered rollout was not confirmed. Refresh deployment status.");
			setNotice(
				action === "rollout"
					? `Ordered rollout version ${result.data.version} started. Waiting for agent-reported load receipts; host enforcement is not yet proven.`
					: action === "stage"
					? `Version ${result.data.version} assigned to ${result.data.target_count} selected agents. Other agents keep their current target.`
					: `Revision ${targetVersion} republished as version ${result.data.version} for all enrolled agents.`,
			);
			setSelected([]);
			setRefresh((value) => value + 1);
			onChanged();
		} catch (cause) {
			if (selectedTeam.current === team) setError(readErrorMessage(cause, "Policy change failed."));
		} finally {
			if (selectedTeam.current === team) setBusy(false);
		}
	}
	if (!team) return null;
	return (
		<section className="card stack">
			<h2>Policy rollout</h2>
			<p className="muted">
				Select a small group to test the runtime controls above, then publish a reviewed revision to
				everyone. A loading receipt is reported by the agent; it does not prove the host enforced
				every action. Receipts older than five minutes are marked stale.
			</p>
			<p className="muted">
				Ordered rollout plans accept up to 1,667 agents per request and must fit within 64 KB.
				Larger policies or many small batches can lower that limit; split larger fleets into smaller
				plans. This screen stages up to 200 selected agents at a time.
			</p>
			<button
				className="button button-secondary"
				type="button"
				onClick={() => {
					setRefresh((value) => value + 1);
					onChanged();
				}}
			>
				Refresh deployment status
			</button>
			{error && <p role="alert">{error}</p>}
			{rollout && rollout.status !== "none" && (
				<p role="status">
					{`Latest ordered rollout: version ${rollout.version ?? "Unknown"}, ${rollout.status}; agent-reported loads ${rollout.current}/${rollout.targeted} current, ${rollout.stale} stale, ${rollout.outdated} outdated, ${rollout.unknown} unknown. This is not host-enforcement attestation.`}
				</p>
			)}
			{truncated && (
				<p role="status">
					Showing up to 500 agents per page and the latest 100 revisions. Use Next agents to
					continue through the fleet.
				</p>
			)}
			<div className="table-wrap">
				<table className="table">
					<thead>
						<tr>
							<th>Select</th>
							<th>Agent</th>
							<th>Target</th>
							<th>Reported loaded</th>
							<th>Status</th>
						</tr>
					</thead>
					<tbody>
						{agents.map((agent) => (
							<tr key={agent.id}>
								<td>
									<input
										type="checkbox"
										aria-label={`Stage policy for ${agent.display_name || agent.iid}`}
										checked={selected.includes(agent.id)}
										disabled={!canManageTeam || busy}
										onChange={(event) =>
											setSelected((values) =>
												event.target.checked
													? [...values, agent.id]
													: values.filter((id) => id !== agent.id),
											)
										}
									/>
								</td>
								<td>{agent.display_name || agent.iid}</td>
								<td>{agent.target_version || "None"}</td>
								<td>{agent.loaded_version ?? "Unknown"}</td>
								<td>{agent.state}</td>
							</tr>
						))}
						{agents.length === 0 && !error && (
							<tr>
								<td colSpan={5}>No agent loading receipts available.</td>
							</tr>
						)}
					</tbody>
				</table>
			</div>
			<div className="row">
				<button
					className="button button-secondary"
					type="button"
					disabled={!agentCursor || busy}
					onClick={() => {
						setSelected([]);
						setAgentCursor(undefined);
					}}
				>
					First agents
				</button>
				<button
					className="button button-secondary"
					type="button"
					disabled={!nextAgent || busy}
					onClick={() => {
						setSelected([]);
						setAgentCursor(nextAgent ?? undefined);
					}}
				>
					Next agents
				</button>
			</div>
			<button
				className="button"
				type="button"
				disabled={
					!canManageTeam ||
					busy ||
					version === null ||
					history.length === 0 ||
					selected.length === 0 ||
					selected.length > 200
				}
				onClick={() => void change("stage")}
			>
				Stage current draft for {selected.length} selected agents
			</button>
			<button
				className="button button-secondary"
				type="button"
				disabled={!canManageTeam || busy || version === null || history.length === 0 || selected.length === 0 || selected.length > 200}
				onClick={() => void change("rollout")}
			>
				Start ordered canary rollout for {selected.length} selected agents
			</button>
			<p className="muted">The first selected agent is the canary. Remaining selected agents receive this revision only after its fresh load receipt.</p>
			<h3>Revision history and rollback</h3>
			<p className="muted">
				Staging a new policy or republishing a revision cancels any active ordered rollout. Review
				controls before a tenant-wide publish.
			</p>
			{history.map((revision) => (
				<div className="row" key={revision.version}>
					<span>
						Version {revision.version} · {new Date(revision.created_at).toLocaleString()}
					</span>
					<button
						className="button button-secondary"
						type="button"
						disabled={busy}
						onClick={() => onReview(revision.policy)}
					>
						Review version {revision.version}
					</button>
					<button
						className="button"
						type="button"
						disabled={!canManageTeam || busy || version === null}
						onClick={() => void change("restore", revision.version)}
					>
						Publish version {revision.version} to all enrolled agents
					</button>
				</div>
			))}
			{notice && <p role="status">{notice}</p>}
		</section>
	);
}
