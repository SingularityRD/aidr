import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import { readErrorMessage } from "../../lib/errors";
import { supabase } from "../../lib/supabase";
import { dashboardAgentFreshness } from "../dashboard-freshness";
import { getSession } from "../session";

type AgentRow = {
	id: string;
	iid: string;
	display_name: string | null;
	agent_runtime: string | null;
	last_seen: string | null;
};

type EventRow = {
	id: number;
	type: string;
	created_at: string;
	agent_id: string;
	payload: Record<string, unknown> | null;
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNullableString(value: unknown): value is string | null {
	return value === null || typeof value === "string";
}

function isAgentRow(value: unknown): value is AgentRow {
	return (
		isRecord(value) &&
		typeof value.id === "string" &&
		typeof value.iid === "string" &&
		isNullableString(value.display_name) &&
		isNullableString(value.agent_runtime) &&
		isNullableString(value.last_seen)
	);
}

function isEventRow(value: unknown): value is EventRow {
	return (
		isRecord(value) &&
		typeof value.id === "number" &&
		Number.isFinite(value.id) &&
		typeof value.type === "string" &&
		typeof value.created_at === "string" &&
		Number.isFinite(Date.parse(value.created_at)) &&
		typeof value.agent_id === "string" &&
		(value.payload === null || isRecord(value.payload))
	);
}

function queryRows<T>(result: unknown, isRow: (value: unknown) => value is T): T[] {
	if (isRecord(result) && isRecord(result.error) && typeof result.error.message === "string") {
		throw new Error(readErrorMessage(result.error, "Dashboard query failed."));
	}
	if (
		!isRecord(result) ||
		result.error !== null ||
		!Array.isArray(result.data) ||
		!result.data.every(isRow)
	) {
		throw new Error("Malformed dashboard query response.");
	}
	return result.data;
}

function eventSummary(event: EventRow): string {
	if (event.type === "runtime_verdict") {
		const tool =
			typeof event.payload?.tool_name === "string" ? String(event.payload.tool_name) : "tool";
		const verdict =
			typeof event.payload?.verdict === "string" ? String(event.payload.verdict) : "unknown";
		return `${tool}: ${verdict}`;
	}
	if (event.type === "plugin_scan") {
		const key =
			typeof event.payload?.plugin_key === "string" ? String(event.payload.plugin_key) : "plugin";
		const count = Number(event.payload?.findings_count ?? 0);
		return `${key}: ${count} finding(s)`;
	}
	return "Additional event details are not shown.";
}

function verdictOf(event: EventRow): string | null {
	if (event.type !== "runtime_verdict") return null;
	return typeof event.payload?.verdict === "string" ? String(event.payload.verdict) : null;
}

export function DashboardPage() {
	const { currentTeam, isLoading } = useTeam();
	if (isLoading) return <div role="status">Resolving the managed tenant…</div>;
	if (!currentTeam) return <div role="alert">Select a team to view dashboard.</div>;
	return <TenantDashboardPage key={currentTeam.id} tenantId={currentTeam.id} />;
}

function TenantDashboardPage({ tenantId }: { tenantId: string }) {
	const [email, setEmail] = useState<string | null>(null);
	// null = not loaded / unavailable (fail-closed); [] = a real, empty result.
	const [agents, setAgents] = useState<AgentRow[] | null>(null);
	const [events, setEvents] = useState<EventRow[] | null>(null);
	const [pendingTokens, setPendingTokens] = useState<number | null>(null);
	const [agentError, setAgentError] = useState<string | null>(null);
	const [eventError, setEventError] = useState<string | null>(null);
	const [pendingError, setPendingError] = useState<string | null>(null);
	const [nowMs, setNowMs] = useState(() => Date.now());
	const error = [agentError, eventError, pendingError].filter(Boolean).join(" ");

	useEffect(() => {
		let cancelled = false;
		const timers: ReturnType<typeof setInterval>[] = [];
		const deadlines = new Set<ReturnType<typeof setTimeout>>();

		// Poll sources independently. A read has 15 seconds to settle before it
		// becomes unavailable; late responses cannot overwrite a newer poll.
		function poll<T>(
			read: () => Promise<T>,
			setData: (data: T | null) => void,
			setProblem?: (problem: string | null) => void,
		) {
			let loading = false;
			async function load() {
				if (loading) return;
				loading = true;
				let deadline: ReturnType<typeof setTimeout> | undefined;
				try {
					const timeout = new Promise<never>((_resolve, reject) => {
						deadline = setTimeout(() => reject(new Error("Dashboard query timed out.")), 15_000);
						deadlines.add(deadline);
					});
					const data = await Promise.race([read(), timeout]);
					if (!cancelled) {
						setData(data);
						setProblem?.(null);
					}
				} catch (cause) {
					if (!cancelled) {
						setData(null);
						setProblem?.(readErrorMessage(cause, "Dashboard query failed."));
					}
				} finally {
					if (deadline !== undefined) {
						clearTimeout(deadline);
						deadlines.delete(deadline);
					}
					loading = false;
				}
			}
			void load();
			timers.push(setInterval(() => void load(), 6000));
		}

		poll(
			async () =>
				queryRows(
					await supabase
						.from("agents")
						.select("id,iid,display_name,agent_runtime,last_seen")
						.eq("tenant_id", tenantId)
						.order("last_seen", { ascending: false }),
					isAgentRow,
				),
			setAgents,
			setAgentError,
		);
		poll(
			async () =>
				queryRows(
					await supabase
						.from("events")
						.select("id,type,created_at,agent_id,payload")
						.eq("tenant_id", tenantId)
						.order("created_at", { ascending: false })
						.limit(500),
					isEventRow,
				),
			setEvents,
			setEventError,
		);

		// Outstanding enrollment tokens require pilot approval; unavailable or
		// malformed results must not become a made-up zero.
		poll(async () => {
			const result = await supabase.functions.invoke("enrollment-tokens", {
				method: "GET",
				headers: { "X-AIDR-Tenant-ID": tenantId },
			});
			if (
				!isRecord(result) ||
				result.error !== null ||
				!isRecord(result.data) ||
				result.data.ok !== true ||
				!Array.isArray(result.data.tokens)
			) {
				throw new Error("Enrollment tokens are unavailable.");
			}
			const tokens = result.data.tokens;
			const now = Date.now();
			return tokens.filter((token: unknown) => {
				if (
					!isRecord(token) ||
					!isNullableString(token.consumed_at) ||
					(token.consumed_at !== null && !Number.isFinite(Date.parse(token.consumed_at))) ||
					typeof token.expires_at !== "string" ||
					!Number.isFinite(Date.parse(token.expires_at))
				) {
					throw new Error("Malformed enrollment token.");
				}
				return token.consumed_at === null && Date.parse(token.expires_at) > now;
			}).length;
		}, setPendingTokens, setPendingError);

		async function loadSession() {
			try {
				const session = await getSession();
				if (!cancelled) setEmail(session?.user?.email ?? null);
			} catch {
				if (!cancelled) setEmail(null);
			}
		}

		void loadSession();
		// Age existing evidence even when polls return the same array or hang.
		timers.push(setInterval(() => setNowMs(Date.now()), 1000));
		return () => {
			cancelled = true;
			for (const timer of timers) clearInterval(timer);
			for (const deadline of deadlines) clearTimeout(deadline);
		};
	}, [tenantId]);

	// Counters and rows consume exactly the same clock-based classification.
	const agentSnapshot = useMemo(
		() =>
			(agents ?? []).map((agent) => ({
				agent,
				freshness: dashboardAgentFreshness(agent.last_seen, nowMs),
			})),
		[agents, nowMs],
	);
	const connectedCount = agentSnapshot.filter(({ freshness }) => freshness === "fresh").length;
	const denyCount = useMemo(
		() => (events ?? []).filter((e) => verdictOf(e) === "deny").length,
		[events],
	);
	const askCount = useMemo(
		() => (events ?? []).filter((e) => verdictOf(e) === "ask").length,
		[events],
	);
	const latestHeartbeat = useMemo(() => {
		const stamps = (agents ?? [])
			.map((agent) =>
				typeof agent.last_seen === "string" ? Date.parse(agent.last_seen) : Number.NaN,
			)
			.filter((stamp) => Number.isFinite(stamp) && stamp <= nowMs);
		return stamps.length > 0 ? new Date(Math.max(...stamps)) : null;
	}, [agents, nowMs]);

	const liveAgents = agentSnapshot.slice(0, 5);
	const recentEvents = (events ?? []).slice(0, 6);

	return (
		<div className="stack">
			<section className="card console-hero">
				<div className="console-hero-grid">
					<div>
						<p className="eyebrow">AIDR control plane</p>
						<h1>Review reported agent security decisions in one dashboard.</h1>
						<p className="muted" style={{ marginTop: 8 }}>
							Start with prompt-based onboarding, approve a device code once, then review agent
							check-ins and security events as they are reported.
						</p>
						<div className="row" style={{ marginTop: 16 }}>
							<Link className="button" to="/onboarding">
								Connect agent
							</Link>
							<Link className="button button-secondary" to="/verify">
								Verify code
							</Link>
							<Link className="button button-secondary" to="/settings">
								Privacy settings
							</Link>
						</div>
					</div>
					<div>
						<div className="session-box">
							<div className="muted small">Signed in as</div>
							<div className="mono" style={{ marginTop: 2, overflowWrap: "anywhere" }}>
								{email ?? "unknown"}
							</div>
							<div className="muted small" style={{ marginTop: 10 }}>
								Latest heartbeat
							</div>
							<div className="mono" style={{ marginTop: 2 }}>
								{latestHeartbeat
									? latestHeartbeat.toLocaleString()
									: agents?.length === 0
										? "no agents yet"
										: "unavailable"}
							</div>
						</div>
					</div>
				</div>
				{error ? (
					<div
						className="notice notice-danger"
						role="alert"
						aria-live="assertive"
						style={{ marginTop: 14 }}
					>
						{error}
					</div>
				) : null}
			</section>

			<section className="grid" aria-label="Fleet counters">
				<div className="card stat-card">
					<div className="stat-label">Agents</div>
					<div className="stat-value">{agents === null ? "—" : agents.length}</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">Connected</div>
					<div className="stat-value">{agents === null ? "—" : connectedCount}</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">Pending</div>
					<div className="stat-value">{pendingTokens ?? "—"}</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">Events</div>
					<div className="stat-value">{events === null ? "—" : events.length}</div>
					<div className="stat-hint">latest 500</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">Deny</div>
					<div className="stat-value">{events === null ? "—" : denyCount}</div>
					<div className="stat-hint">latest 500</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">Ask</div>
					<div className="stat-value">{events === null ? "—" : askCount}</div>
					<div className="stat-hint">latest 500</div>
				</div>
			</section>

			<section className="cols">
				<div className="card">
					<div className="panel-head">
						<h2>Live agents</h2>
						<Link className="view-all" to="/agents">
							View all
						</Link>
					</div>
					<p className="muted small">Connected installations and their current health.</p>
					<div className="table-wrap">
						<table className="table">
							<thead>
								<tr>
									<th>Agent</th>
									<th>Runtime</th>
									<th>State</th>
								</tr>
							</thead>
							<tbody>
								{liveAgents.map(({ agent, freshness }) => (
									<tr key={agent.id}>
										<td>
											<Link className="mono" to={`/agents/${agent.id}`}>
												{agent.display_name ?? agent.iid.slice(0, 12)}
											</Link>
										</td>
										<td className="muted">{agent.agent_runtime ?? "unknown"}</td>
										<td>
											<span
												className={`badge ${freshness === "fresh" ? "badge-success" : "badge-neutral"}`}
											>
												{freshness === "fresh" ? "connected" : freshness}
											</span>
										</td>
									</tr>
								))}
								{liveAgents.length === 0 ? (
									<tr>
										<td colSpan={3} className="muted">
											{agents === null ? (
												"Agent data is unavailable right now."
											) : (
												<>
													No agents yet. Use <Link to="/onboarding">Connect</Link> to enroll your
													first runtime.
												</>
											)}
										</td>
									</tr>
								) : null}
							</tbody>
						</table>
					</div>
				</div>

				<div className="card">
					<div className="panel-head">
						<h2>Recent events</h2>
						<Link className="view-all" to="/events">
							View all
						</Link>
					</div>
					<p className="muted small">The latest security events received from your agents.</p>
					<div className="table-wrap">
						<table className="table">
							<thead>
								<tr>
									<th>Time</th>
									<th>Type</th>
									<th>Summary</th>
								</tr>
							</thead>
							<tbody>
								{recentEvents.map((event) => (
									<tr key={event.id}>
										<td className="mono muted">
											{new Date(event.created_at).toLocaleTimeString()}
										</td>
										<td>
											<span className="badge badge-neutral badge-plain mono">{event.type}</span>
										</td>
										<td className="mono">{eventSummary(event)}</td>
									</tr>
								))}
								{recentEvents.length === 0 ? (
									<tr>
										<td colSpan={3} className="muted">
											{events === null
												? "Event data is unavailable right now."
												: "No events recorded yet."}
										</td>
									</tr>
								) : null}
							</tbody>
						</table>
					</div>
				</div>
			</section>
		</div>
	);
}
