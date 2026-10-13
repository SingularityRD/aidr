import { useCallback, useEffect, useRef, useState } from "react";
import { useTeam } from "../../enterprise/team-provider";
import { englishT, type Translate, useT } from "../../i18n/I18nProvider";
import { readErrorMessage } from "../../lib/errors";
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

function formatTime(value: string | undefined, t: Translate = englishT): string {
	if (!value) return t("common.unknown");
	const time = new Date(value);
	return Number.isFinite(time.getTime()) ? time.toLocaleString() : t("common.unknown");
}

function stateClass(state: string | undefined): string {
	if (state === "healthy" || state === "active") return "notice notice-success";
	if (state === "degraded" || state === "idle") return "notice notice-warning";
	return "notice notice-danger";
}

async function resultMessage(error: unknown, fallback: string, t: Translate): Promise<string> {
	const context =
		error && typeof error === "object" && "context" in error
			? (error as { context?: unknown }).context
			: null;
	if (context instanceof Response && context.status === 503) {
		try {
			const body: unknown = await context.clone().json();
			if (
				body &&
				typeof body === "object" &&
				"error" in body &&
				body.error === "integration_not_configured"
			) {
				return t("aso.notConfigured");
			}
		} catch {
			// An unreadable response must not expose provider details in the UI.
		}
	}
	return readErrorMessage(error, fallback);
}

async function readHealthResult(
	result: { data: unknown; error: unknown },
	teamId: string,
	t: Translate,
) {
	if (result.error) {
		return {
			value: null,
			message: await resultMessage(result.error, t("aso.healthUnavailable"), t),
		};
	}
	const response = asBridgeResponse(result.data);
	if (
		response.ok !== true ||
		response.provider !== "autosecops" ||
		response.action !== "health" ||
		response.team_id !== teamId ||
		!response.data?.snapshot
	) {
		return { value: null, message: t("aso.healthInvalid") };
	}
	return { value: response.data.snapshot, message: null };
}

async function readFleetResult(
	result: { data: unknown; error: unknown },
	teamId: string,
	t: Translate,
) {
	if (result.error) {
		return {
			value: [],
			message: await resultMessage(result.error, t("aso.fleetUnavailable"), t),
		};
	}
	const response = asBridgeResponse(result.data);
	if (
		response.ok !== true ||
		response.provider !== "autosecops" ||
		response.action !== "fleet" ||
		response.team_id !== teamId ||
		!response.data?.response ||
		!Array.isArray(response.data.response.items)
	) {
		return { value: [], message: t("aso.fleetInvalid") };
	}
	return { value: response.data.response.items, message: null };
}

function useAutoSecOpsRuntime(teamId: string | undefined, teamCount: number, teamLoading: boolean) {
	const [health, setHealth] = useState<HealthSnapshot | null>(null);
	const [fleet, setFleet] = useState<FleetAgent[]>([]);
	const [error, setError] = useState<string | null>(null);
	const [loading, setLoading] = useState(false);
	const [lastLoadedAt, setLastLoadedAt] = useState<string | null>(null);
	const [loadedTeamId, setLoadedTeamId] = useState<string | null>(null);
	const requestId = useRef(0);
	// Read the translator through a ref so a language switch does not refetch.
	const translate = useT();
	const translator = useRef(translate);
	translator.current = translate;

	const load = useCallback(async () => {
		const currentRequest = ++requestId.current;
		const t = translator.current;
		if (teamLoading || !teamId) {
			setLoadedTeamId(null);
			setHealth(null);
			setFleet([]);
			setLoading(false);
			setLastLoadedAt(null);
			setError(!teamLoading && teamCount > 1 ? t("aso.selectTeam") : null);
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
			if (currentRequest !== requestId.current) return;
			setLoadedTeamId(teamId);
			setHealth(null);
			setFleet([]);
			setError(t("aso.bridgeUnavailable"));
			setLastLoadedAt(new Date().toISOString());
			setLoading(false);
			return;
		}
		if (currentRequest !== requestId.current) return;

		const [healthOutcome, fleetOutcome] = await Promise.all([
			readHealthResult(healthResult, teamId, t),
			readFleetResult(fleetResult, teamId, t),
		]);
		if (currentRequest !== requestId.current) return;
		setLoadedTeamId(teamId);
		setHealth(healthOutcome.value);
		setFleet(fleetOutcome.value);
		setError(
			[...new Set([healthOutcome.message, fleetOutcome.message].filter(Boolean))].join(" ") || null,
		);
		setLastLoadedAt(new Date().toISOString());
		setLoading(false);
	}, [teamCount, teamId, teamLoading]);

	useEffect(() => {
		void load();
		const timer = window.setInterval(() => void load(), 15000);
		return () => {
			requestId.current++;
			window.clearInterval(timer);
		};
	}, [load]);

	const currentTeamLoaded = teamId !== undefined && loadedTeamId === teamId;
	return {
		health: currentTeamLoaded ? health : null,
		fleet: currentTeamLoaded ? fleet : [],
		error: currentTeamLoaded ? error : null,
		loading,
		lastLoadedAt: currentTeamLoaded ? lastLoadedAt : null,
		load,
	};
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
	const t = useT();
	if (teams.length <= 1) return null;
	return (
		<label className="label" style={{ maxWidth: 420, marginTop: 16 }}>
			{t("aso.team")}
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

function fleetStateBadge(state: string | undefined): string {
	if (state === "active") return "badge badge-success";
	if (state === "idle") return "badge badge-warning";
	if (!state) return "badge badge-neutral";
	return "badge badge-neutral";
}

function RuntimeFleet({ fleet, unavailable }: { fleet: FleetAgent[]; unavailable: boolean }) {
	const t = useT();
	return (
		<div className="card">
			<h2>{t("aso.fleet")}</h2>
			<p className="muted">{t("aso.fleetLead")}</p>
			<div className="table-wrap">
				<table className="table">
					<thead>
						<tr>
							<th>{t("aso.col.agent")}</th>
							<th>{t("aso.col.runtime")}</th>
							<th>{t("aso.col.state")}</th>
							<th>{t("aso.col.lastEvent")}</th>
						</tr>
					</thead>
					<tbody>
						{fleet.map((agent) => (
							<tr key={`${agent.agent_id ?? "agent"}:${agent.instance_id ?? "instance"}`}>
								<td>
									<div className="mono">
										{agent.agent_name ?? agent.agent_id ?? t("common.unknown")}
									</div>
									<div className="muted small">{agent.agent_id ?? t("aso.unknownId")}</div>
								</td>
								<td>
									<div>{agent.runtime ?? t("common.unknown")}</div>
									<div className="muted small">
										{agent.connector ?? t("aso.unknownConnector")} {agent.connector_version ?? ""}
									</div>
								</td>
								<td>
									<span className={fleetStateBadge(agent.state)}>
										{agent.state ?? t("common.unknown")}
									</span>
									<div className="muted small" style={{ marginTop: 4 }}>
										{t("aso.health", { state: agent.health ?? t("common.unknown") })}
									</div>
								</td>
								<td className="mono">{formatTime(agent.last_event_at, t)}</td>
							</tr>
						))}
						{fleet.length === 0 ? (
							<tr>
								<td colSpan={4} className="muted">
									{unavailable ? t("aso.fleetDataUnavailable") : t("aso.noAgents")}
								</td>
							</tr>
						) : null}
					</tbody>
				</table>
			</div>
		</div>
	);
}

function IntegrationBoundary({ health }: { health: HealthSnapshot | null }) {
	const t = useT();
	const summary = (health?.components ?? []).map(
		(component) =>
			`${component.name ?? t("aso.component")}: ${component.state ?? t("common.unknown")}`,
	);
	return (
		<div className="card">
			<h2>{t("aso.boundary")}</h2>
			<div className="muted">
				<p>{t("aso.boundaryLocal")}</p>
				<p style={{ marginTop: 6 }}>{t("aso.boundaryRemote")}</p>
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
	const t = useT();
	const { currentTeam, teams, isLoading: teamsLoading, switchTeam } = useTeam();
	const { health, fleet, error, loading, lastLoadedAt, load } = useAutoSecOpsRuntime(
		currentTeam?.id,
		teams.length,
		teamsLoading,
	);

	const healthState = health?.state;
	const integrationState = health
		? healthState === "healthy"
			? t("aso.connected")
			: t("aso.connectedRestricted")
		: error
			? t("aso.unavailable")
			: t("aso.notConnected");
	return (
		<div className="stack">
			<div className="card">
				<div className="row space-between" style={{ alignItems: "flex-start", gap: 16 }}>
					<div>
						<div className="pill" style={{ marginBottom: 8 }}>
							{t("aso.eyebrow")}
						</div>
						<h1>AutoSecOps</h1>
						<p className="muted" style={{ maxWidth: 760 }}>
							{t("aso.lead")}
						</p>
					</div>
					<div className={stateClass(healthState)} role="status">
						<div className="muted small">{t("aso.integration")}</div>
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
						{loading ? t("aso.refreshing") : t("common.refresh")}
					</button>
					{lastLoadedAt ? (
						<span className="muted small">
							{t("aso.updated", { time: formatTime(lastLoadedAt, t) })}
						</span>
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
							{t("aso.noSynthetic")}
						</div>
					</div>
				) : null}
			</div>

			<div className="grid">
				<div className="card stat-card">
					<div className="stat-label">{t("aso.runtimeState")}</div>
					<div className="stat-value">{healthState ?? t("common.unknown")}</div>
					<div className="stat-hint">{t("aso.runtimeStateHint")}</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">{t("aso.activeAgents")}</div>
					<div className="stat-value">{health?.active_agents ?? t("common.unknown")}</div>
					<div className="stat-hint">{t("aso.activeAgentsHint")}</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">{t("aso.degradations")}</div>
					<div className="stat-value">{health?.open_degradations ?? t("common.unknown")}</div>
					<div className="stat-hint">{t("aso.degradationsHint")}</div>
				</div>
			</div>

			<RuntimeFleet fleet={fleet} unavailable={Boolean(error)} />
			<IntegrationBoundary health={health} />
		</div>
	);
}
