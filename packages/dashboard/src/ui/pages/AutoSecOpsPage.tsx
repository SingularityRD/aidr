import { useCallback, useEffect, useState } from "react";
import { useTeam } from "../../enterprise/team-provider";
import { supabase } from "../../lib/supabase";

type HealthSnapshot = {
	schema_version?: string;
	team_id?: string;
	state?: string;
	as_of?: string;
	active_agents?: number;
	open_degradations?: number;
	policy_version?: string;
	components?: Array<{ name?: string; state?: string; reason_code?: string }>;
};

type FleetAgent = {
	agent_id?: string;
	agent_name?: string;
	runtime?: string;
	instance_id?: string;
	connector?: string;
	connector_version?: string;
	state?: string;
	health?: string;
	last_event_at?: string;
};

type BridgeResponse = {
	ok?: boolean;
	provider?: string;
	action?: string;
	team_id?: string;
	data?: {
		snapshot?: HealthSnapshot;
		response?: { items?: FleetAgent[]; next_cursor?: string };
		status?: Record<string, unknown>;
	};
};

function asBridgeResponse(value: unknown): BridgeResponse {
	return value && typeof value === "object" && !Array.isArray(value)
		? (value as BridgeResponse)
		: {};
}

function formatTime(value: string | undefined): string {
	if (!value) return "unknown";
	const time = new Date(value);
	return Number.isFinite(time.getTime()) ? time.toLocaleString() : "unknown";
}

function stateClass(state: string | undefined): string {
	if (state === "healthy" || state === "active") return "notice notice-success";
	if (state === "degraded" || state === "idle") return "notice notice-warning";
	return "notice notice-danger";
}

function resultMessage(error: unknown, fallback: string): string {
	if (error && typeof error === "object" && "message" in error) {
		const message = (error as { message?: unknown }).message;
		if (typeof message === "string" && message.trim()) return message;
	}
	return fallback;
}

function readHealthResult(result: { data: unknown; error: unknown }) {
	if (result.error) {
		return {
			value: null,
			message: resultMessage(result.error, "AutoSecOps health is unavailable."),
		};
	}
	const response = asBridgeResponse(result.data);
	if (
		response.ok !== true ||
		response.provider !== "autosecops" ||
		response.action !== "health" ||
		!response.data?.snapshot
	) {
		return { value: null, message: "AutoSecOps health response is invalid." };
	}
	return { value: response.data.snapshot, message: null };
}

function readFleetResult(result: { data: unknown; error: unknown }) {
	if (result.error) {
		return { value: [], message: resultMessage(result.error, "AutoSecOps fleet is unavailable.") };
	}
	const response = asBridgeResponse(result.data);
	if (
		response.ok !== true ||
		response.provider !== "autosecops" ||
		response.action !== "fleet" ||
		!response.data?.response ||
		!Array.isArray(response.data.response.items)
	) {
		return { value: [], message: "AutoSecOps fleet response is invalid." };
	}
	return { value: response.data.response.items, message: null };
}

function useAutoSecOpsRuntime(teamId: string | undefined, teamCount: number, teamLoading: boolean) {
	const [health, setHealth] = useState<HealthSnapshot | null>(null);
	const [fleet, setFleet] = useState<FleetAgent[]>([]);
	const [error, setError] = useState<string | null>(null);
	const [loading, setLoading] = useState(false);
	const [lastLoadedAt, setLastLoadedAt] = useState<string | null>(null);

	const load = useCallback(async () => {
		if (teamLoading || (!teamId && teamCount > 1)) {
			setHealth(null);
			setFleet([]);
			setError(
				!teamLoading && teamCount > 1 ? "Select a team to view its AutoSecOps runtime." : null,
			);
			return;
		}

		setLoading(true);
		setError(null);
		const scope = teamId ? { team_id: teamId } : {};
		let healthResult: { data: unknown; error: unknown };
		let fleetResult: { data: unknown; error: unknown };
		try {
			[healthResult, fleetResult] = await Promise.all([
				supabase.functions.invoke("autosecops-runtime", {
					body: { action: "health", ...scope },
				}),
				supabase.functions.invoke("autosecops-runtime", {
					body: { action: "fleet", ...scope, query: { limit: 100 } },
				}),
			]);
		} catch {
			setHealth(null);
			setFleet([]);
			setError("AutoSecOps bridge is unavailable.");
			setLastLoadedAt(new Date().toISOString());
			setLoading(false);
			return;
		}

		const healthOutcome = readHealthResult(healthResult);
		const fleetOutcome = readFleetResult(fleetResult);
		setHealth(healthOutcome.value);
		setFleet(fleetOutcome.value);
		setError([healthOutcome.message, fleetOutcome.message].filter(Boolean).join(" ") || null);
		setLastLoadedAt(new Date().toISOString());
		setLoading(false);
	}, [teamCount, teamId, teamLoading]);

	useEffect(() => {
		void load();
		const timer = window.setInterval(() => void load(), 15000);
		return () => window.clearInterval(timer);
	}, [load]);

	return { health, fleet, error, loading, lastLoadedAt, load };
}

function TeamSelector({
	teams,
	currentTeamId,
	loading,
	switchTeam,
}: {
	teams: ReturnType<typeof useTeam>["teams"];
	currentTeamId: string | undefined;
	loading: boolean;
	switchTeam: (teamId: string) => void;
}) {
	if (teams.length <= 1) return null;
	return (
		<label className="label" style={{ maxWidth: 420, marginTop: 16 }}>
			AIDR team
			<select
				className="input"
				value={currentTeamId ?? ""}
				onChange={(event) => switchTeam(event.target.value)}
				disabled={loading}
			>
				{teams.map((team) => (
					<option key={team.id} value={team.id}>
						{team.name}
					</option>
				))}
			</select>
		</label>
	);
}

function RuntimeFleet({ fleet, unavailable }: { fleet: FleetAgent[]; unavailable: boolean }) {
	return (
		<div className="card">
			<h2>AutoSecOps runtime fleet</h2>
			<p className="muted">
				Registered Claude Code, Codex, OpenCode, and other AIDR runtime connectors observed by
				AutoSecOps.
			</p>
			<table className="table">
				<thead>
					<tr>
						<th>Agent</th>
						<th>Runtime / connector</th>
						<th>State</th>
						<th>Last event</th>
					</tr>
				</thead>
				<tbody>
					{fleet.map((agent) => (
						<tr key={`${agent.agent_id ?? "agent"}:${agent.instance_id ?? "instance"}`}>
							<td>
								<div className="mono">{agent.agent_name ?? agent.agent_id ?? "unknown"}</div>
								<div className="muted small">{agent.agent_id ?? "unknown id"}</div>
							</td>
							<td>
								<div>{agent.runtime ?? "unknown"}</div>
								<div className="muted small">
									{agent.connector ?? "unknown connector"} {agent.connector_version ?? ""}
								</div>
							</td>
							<td>
								<span className="mono">{agent.state ?? "unknown"}</span>
								<div className="muted small">health: {agent.health ?? "unknown"}</div>
							</td>
							<td className="mono">{formatTime(agent.last_event_at)}</td>
						</tr>
					))}
					{fleet.length === 0 ? (
						<tr>
							<td colSpan={4} className="muted">
								{unavailable
									? "Fleet data is unavailable."
									: "No AutoSecOps runtime agents reported yet."}
							</td>
						</tr>
					) : null}
				</tbody>
			</table>
		</div>
	);
}

function IntegrationBoundary({ health }: { health: HealthSnapshot | null }) {
	const summary = (health?.components ?? []).map(
		(component) => `${component.name ?? "component"}: ${component.state ?? "unknown"}`,
	);
	return (
		<div className="card">
			<h2>Integration boundary</h2>
			<div className="muted">
				<p>AIDR performs local interception, redaction, and fail-closed policy checks.</p>
				<p style={{ marginTop: 6 }}>
					AutoSecOps receives bounded identity, health, event, and decision observations through its
					canonical runtime API. It does not receive raw secrets or model authority.
				</p>
				{summary.length > 0 ? (
					<div className="mono small" style={{ marginTop: 10 }}>
						{summary.join(" · ")}
					</div>
				) : null}
			</div>
		</div>
	);
}

export function AutoSecOpsPage() {
	const { currentTeam, teams, isLoading: teamsLoading, switchTeam } = useTeam();
	const { health, fleet, error, loading, lastLoadedAt, load } = useAutoSecOpsRuntime(
		currentTeam?.id,
		teams.length,
		teamsLoading,
	);

	const healthState = health?.state;
	const integrationState = health
		? healthState === "healthy"
			? "Connected"
			: "Connected with restrictions"
		: error
			? "Unavailable"
			: "Not connected";
	return (
		<div className="stack">
			<div className="card">
				<div className="row space-between" style={{ alignItems: "flex-start", gap: 16 }}>
					<div>
						<div className="pill" style={{ marginBottom: 8 }}>
							AIDR integration
						</div>
						<h1>AutoSecOps</h1>
						<p className="muted" style={{ maxWidth: 760 }}>
							View the AutoSecOps runtime security control plane from AIDR. AIDR remains the local
							enforcement surface; AutoSecOps supplies tenant-scoped central runtime visibility.
						</p>
					</div>
					<div className={stateClass(healthState)} role="status">
						<div className="muted small">Integration</div>
						<b>{integrationState}</b>
					</div>
				</div>

				<TeamSelector
					teams={teams}
					currentTeamId={currentTeam?.id}
					loading={teamsLoading}
					switchTeam={switchTeam}
				/>

				<div className="row" style={{ marginTop: 16 }}>
					<button
						className="button button-secondary"
						type="button"
						onClick={() => void load()}
						disabled={loading}
					>
						{loading ? "Refreshing…" : "Refresh"}
					</button>
					{lastLoadedAt ? (
						<span className="muted small">Updated {formatTime(lastLoadedAt)}</span>
					) : null}
				</div>

				{error ? (
					<div
						className="notice notice-danger"
						role="alert"
						aria-live="assertive"
						style={{ marginTop: 16 }}
					>
						{error}
						<div className="muted small" style={{ marginTop: 6 }}>
							No synthetic or cached AutoSecOps data is shown when the bridge is unavailable.
						</div>
					</div>
				) : null}
			</div>

			<div className="grid">
				<div className="card">
					<div className="muted small">Runtime state</div>
					<div className="mono" style={{ fontSize: 24, marginTop: 6 }}>
						{healthState ?? "unknown"}
					</div>
					<div className="muted small">AutoSecOps observation</div>
				</div>
				<div className="card">
					<div className="muted small">Active agents</div>
					<div className="mono" style={{ fontSize: 24, marginTop: 6 }}>
						{health?.active_agents ?? "unknown"}
					</div>
					<div className="muted small">tenant-scoped runtime sessions</div>
				</div>
				<div className="card">
					<div className="muted small">Open degradations</div>
					<div className="mono" style={{ fontSize: 24, marginTop: 6 }}>
						{health?.open_degradations ?? "unknown"}
					</div>
					<div className="muted small">fail-closed health signal</div>
				</div>
			</div>

			<RuntimeFleet fleet={fleet} unavailable={Boolean(error)} />
			<IntegrationBoundary health={health} />
		</div>
	);
}
