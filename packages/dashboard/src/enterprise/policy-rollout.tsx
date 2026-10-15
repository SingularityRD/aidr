import { useCallback, useEffect, useRef, useState } from "react";
import type { DashboardMessageKey } from "../i18n/en";
import { useT } from "../i18n/I18nProvider";
import { pendingPolicyChangeNotice } from "../lib/ai-governance";
import { readErrorMessage } from "../lib/errors";
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
const ROLLOUT_STATUS: Record<string, DashboardMessageKey> = {
	none: "rollout.status.none",
	running: "rollout.status.running",
	paused: "rollout.status.paused",
	completed: "rollout.status.completed",
	cancelled: "rollout.status.cancelled",
};

const AGENT_STATE: Record<Agent["state"], DashboardMessageKey> = {
	unknown: "rollout.state.unknown",
	stale: "rollout.state.stale",
	current: "rollout.state.current",
	outdated: "rollout.state.outdated",
};

function readRollout(value: unknown): Rollout | null {
	if (!value || typeof value !== "object") return null;
	const data = value as Record<string, unknown>;
	const progress = data.rollout_progress as Record<string, unknown> | null;
	if (
		data.ok !== true ||
		!progress ||
		typeof progress !== "object" ||
		!["none", "running", "paused", "completed", "cancelled"].includes(String(data.status))
	)
		return null;
	for (const key of ["targeted", "current", "stale", "unknown"]) {
		if (!Number.isSafeInteger(progress[key]) || Number(progress[key]) < 0) return null;
	}
	if (
		progress.outdated !== undefined &&
		(!Number.isSafeInteger(progress.outdated) || Number(progress.outdated) < 0)
	)
		return null;
	if (
		Number(progress.current) +
			Number(progress.stale) +
			Number(progress.outdated ?? 0) +
			Number(progress.unknown) !==
		Number(progress.targeted)
	)
		return null;
	return {
		status: String(data.status),
		version:
			typeof data.version === "number" && Number.isSafeInteger(data.version) ? data.version : null,
		targeted: Number(progress.targeted),
		current: Number(progress.current),
		stale: Number(progress.stale),
		outdated: Number(progress.outdated ?? 0),
		unknown: Number(progress.unknown),
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
	const t = useT();
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
				throw new Error(t("rollout.loadFailed"));
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
				setError(t("rollout.loadFailedRetry"));
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
							action,
							tenant_id: team,
							expected_version: version,
							expected_revision_version: history[0]?.version,
							policy: JSON.parse(draft),
							rings: [
								{ ring_order: 1, batches: [{ batch_order: 1, agent_ids: selected.slice(0, 1) }] },
								...(selected.length > 1
									? [{ ring_order: 2, batches: [{ batch_order: 1, agent_ids: selected.slice(1) }] }]
									: []),
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
			const pendingChange = result.error ? null : pendingPolicyChangeNotice(result.data, t);
			if (pendingChange) {
				setNotice(pendingChange);
				setSelected([]);
				return;
			}
			if (result.error || result.data?.ok !== true)
				throw new Error(t("rollout.changeFailedRefresh"));
			if (
				action === "rollout" &&
				(typeof result.data.rollout_id !== "string" || !Number.isSafeInteger(result.data.version))
			)
				throw new Error(t("rollout.notConfirmed"));
			setNotice(
				action === "rollout"
					? t("rollout.started", { version: result.data.version })
					: action === "stage"
						? t("rollout.staged", {
								version: result.data.version,
								count: result.data.target_count,
							})
						: t("rollout.restored", {
								revision: targetVersion ?? "",
								version: result.data.version,
							}),
			);
			setSelected([]);
			setRefresh((value) => value + 1);
			// Staging and canary rollout change agent targets, not the published
			// tenant policy. Reloading that policy would discard the reviewed draft.
			if (action === "restore") onChanged();
		} catch (cause) {
			if (selectedTeam.current === team)
				setError(readErrorMessage(cause, t("rollout.changeFailed")));
		} finally {
			if (selectedTeam.current === team) setBusy(false);
		}
	}
	if (!team) return null;
	return (
		<section className="card stack">
			<h2>{t("rollout.title")}</h2>
			<p className="muted">{t("rollout.intro")}</p>
			<p className="muted">{t("rollout.limits")}</p>
			<button
				className="button button-secondary"
				type="button"
				onClick={() => {
					setRefresh((value) => value + 1);
				}}
			>
				{t("rollout.refresh")}
			</button>
			{error && <p role="alert">{error}</p>}
			{rollout && rollout.status !== "none" && (
				<p role="status">
					{t("rollout.latest", {
						version: rollout.version ?? t("rollout.unknownVersion"),
						status: ROLLOUT_STATUS[rollout.status]
							? t(ROLLOUT_STATUS[rollout.status] as DashboardMessageKey)
							: rollout.status,
						current: rollout.current,
						targeted: rollout.targeted,
						stale: rollout.stale,
						outdated: rollout.outdated,
						unknown: rollout.unknown,
					})}
				</p>
			)}
			{truncated && <p role="status">{t("rollout.truncated")}</p>}
			<div className="table-wrap">
				<table className="table">
					<thead>
						<tr>
							<th>{t("rollout.select")}</th>
							<th>{t("rollout.agent")}</th>
							<th>{t("rollout.target")}</th>
							<th>{t("rollout.loaded")}</th>
							<th>{t("common.status")}</th>
						</tr>
					</thead>
					<tbody>
						{agents.map((agent) => (
							<tr key={agent.id}>
								<td>
									<input
										type="checkbox"
										aria-label={t("rollout.stageFor", { name: agent.display_name || agent.iid })}
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
								<td>{agent.target_version || t("rollout.none")}</td>
								<td>{agent.loaded_version ?? t("rollout.unknownVersion")}</td>
								<td>{AGENT_STATE[agent.state] ? t(AGENT_STATE[agent.state]) : agent.state}</td>
							</tr>
						))}
						{agents.length === 0 && !error && (
							<tr>
								<td colSpan={5}>{t("rollout.noReceipts")}</td>
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
					{t("rollout.first")}
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
					{t("rollout.next")}
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
				{t("rollout.stage", { count: selected.length })}
			</button>
			<button
				className="button button-secondary"
				type="button"
				disabled={
					!canManageTeam ||
					busy ||
					version === null ||
					history.length === 0 ||
					selected.length === 0 ||
					selected.length > 200
				}
				onClick={() => void change("rollout")}
			>
				{t("rollout.canary", { count: selected.length })}
			</button>
			<p className="muted">{t("rollout.canaryNote")}</p>
			<h3>{t("rollout.history")}</h3>
			<p className="muted">{t("rollout.historyNote")}</p>
			{history.map((revision) => (
				<div className="row" key={revision.version}>
					<span>
						{t("rollout.revision", {
							version: revision.version,
							time: new Date(revision.created_at).toLocaleString(),
						})}
					</span>
					<button
						className="button button-secondary"
						type="button"
						disabled={busy}
						onClick={() => onReview(revision.policy)}
					>
						{t("rollout.review", { version: revision.version })}
					</button>
					<button
						className="button"
						type="button"
						disabled={!canManageTeam || busy || version === null}
						onClick={() => void change("restore", revision.version)}
					>
						{t("rollout.publishAll", { version: revision.version })}
					</button>
				</div>
			))}
			{notice && <p role="status">{notice}</p>}
		</section>
	);
}
