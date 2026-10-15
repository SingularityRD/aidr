import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import { useRichT, useT } from "../../i18n/I18nProvider";
import {
	AUTO_RETIRE_MAX_DAYS,
	AUTO_RETIRE_MIN_DAYS,
	lifecycleErrorKey,
	readAutoRetireDays,
	setAutoRetire,
	validAutoRetireDays,
} from "../../lib/agent-lifecycle";
import { readErrorMessage } from "../../lib/errors";
import { supabase } from "../../lib/supabase";
import {
	AGENT_PAGE_SIZE,
	AGENT_SORTS,
	AGENT_STATUS_FILTERS,
	type AgentFilters,
	type AgentHealth,
	agentHealth,
	agentsCsv,
	fileStamp,
	filterAgents,
	readAgentFilters,
	saveFile,
	writeAgentFilters,
} from "../fleet-view";
import { RetireAgentControl } from "../RetireAgentControl";

const STATUS_FILTER_LABEL: Record<AgentFilters["status"], DashboardMessageKey> = {
	all: "agents.filter.statusAll",
	active: "agents.status.active",
	stale: "agents.status.stale",
	retired: "agents.status.retired",
};

const SORT_LABEL: Record<AgentFilters["sort"], DashboardMessageKey> = {
	last_seen_desc: "agents.sort.last_seen_desc",
	last_seen_asc: "agents.sort.last_seen_asc",
	name: "agents.sort.name",
};

const HEALTH_BADGE: Record<AgentHealth, string> = {
	active: "badge-allow",
	stale: "badge-ask",
	retired: "badge-neutral",
};

type AgentRow = {
	id: string;
	iid: string;
	display_name: string | null;
	agent_runtime: string | null;
	agent_runtime_version: string | null;
	first_seen: string;
	last_seen: string;
	retired_at?: string | null;
	retired_reason?: "manual" | "offline" | null;
};

type SeatUsageRow = {
	included_agents: number;
	extra_agents: number;
	allowed_agents: number;
	/** Absent before the agent-retirement migration; never inferred. */
	retired_agents?: number | null;
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
		Number.isFinite(Date.parse(row.last_seen)) &&
		(row.retired_at === undefined ||
			row.retired_at === null ||
			(typeof row.retired_at === "string" && Number.isFinite(Date.parse(row.retired_at)))) &&
		(row.retired_reason === undefined ||
			row.retired_reason === null ||
			row.retired_reason === "manual" ||
			row.retired_reason === "offline")
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
		row.allowed_agents === row.included_agents + row.extra_agents &&
		(row.retired_agents === undefined ||
			row.retired_agents === null ||
			(typeof row.retired_agents === "number" &&
				Number.isSafeInteger(row.retired_agents) &&
				row.retired_agents >= 0))
	);
}

function AutoRetireSettings({ tenantId, canManage }: { tenantId: string; canManage: boolean }) {
	const t = useT();
	const [current, setCurrent] = useState<number | null | undefined>(undefined);
	const [draft, setDraft] = useState("");
	const [busy, setBusy] = useState(false);
	const [message, setMessage] = useState<{ tone: "success" | "error"; text: string } | null>(null);

	useEffect(() => {
		let cancelled = false;
		void readAutoRetireDays(tenantId).then((result) => {
			if (cancelled) return;
			if (result.ok) {
				setCurrent(result.value);
				setDraft(result.value === null ? "" : String(result.value));
			} else setCurrent(undefined);
		});
		return () => {
			cancelled = true;
		};
	}, [tenantId]);

	async function save() {
		setMessage(null);
		const trimmed = draft.trim();
		const days = trimmed === "" ? null : /^\d+$/.test(trimmed) ? Number(trimmed) : Number.NaN;
		if (days !== null && !validAutoRetireDays(days)) {
			setMessage({ tone: "error", text: t("agents.autoRetire.err.days") });
			return;
		}
		setBusy(true);
		const result = await setAutoRetire(tenantId, days);
		setBusy(false);
		if (!result.ok) {
			setMessage({ tone: "error", text: t(lifecycleErrorKey(result.code)) });
			return;
		}
		setCurrent(result.value);
		setMessage({ tone: "success", text: t("agents.autoRetire.saved") });
	}

	return (
		<div className="card">
			<h2>{t("agents.autoRetire.title")}</h2>
			<p className="muted">{t("agents.autoRetire.body")}</p>
			<p className="small" data-auto-retire={current === undefined ? "unknown" : String(current)}>
				{current === undefined
					? t("agents.autoRetire.unavailable")
					: t("agents.autoRetire.current", {
							value:
								current === null
									? t("agents.autoRetire.off")
									: t("agents.autoRetire.daysValue", { days: current }),
						})}
			</p>
			{canManage ? (
				<div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
					<label>
						<span className="small">{t("agents.autoRetire.days")}</span>{" "}
						<input
							className="input"
							type="number"
							inputMode="numeric"
							min={AUTO_RETIRE_MIN_DAYS}
							max={AUTO_RETIRE_MAX_DAYS}
							value={draft}
							disabled={busy || current === undefined}
							onChange={(event) => setDraft(event.currentTarget.value)}
						/>
					</label>
					<button
						className="button button-sm"
						type="button"
						disabled={busy || current === undefined}
						onClick={() => void save()}
					>
						{t("agents.autoRetire.save")}
					</button>
				</div>
			) : (
				<p className="muted small">{t("agents.autoRetire.readOnly")}</p>
			)}
			{message ? (
				<div
					className={`notice ${message.tone === "error" ? "notice-danger" : "notice-success"}`}
					role={message.tone === "error" ? "alert" : "status"}
					style={{ marginTop: 10 }}
				>
					{message.text}
				</div>
			) : null}
		</div>
	);
}

export function AgentsPage() {
	const { currentTeam, canManageTeam } = useTeam();
	const t = useT();
	const richT = useRichT();
	const tenantId = currentTeam?.id;
	const [reloadKey, setReloadKey] = useState(0);
	const reload = useCallback(() => setReloadKey((value) => value + 1), []);
	const [agents, setAgents] = useState<AgentRow[] | null>(null);
	const [seatUsage, setSeatUsage] = useState<SeatUsageRow | null>(null);
	const [seatUsageError, setSeatUsageError] = useState<string | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [loadedTenantId, setLoadedTenantId] = useState<string | null>(null);
	// Clock of the last load; stale classification is relative to it.
	const [now, setNow] = useState(() => Date.now());
	const [searchParams, setSearchParams] = useSearchParams();
	const filterKey = searchParams.toString();
	const filters = useMemo(() => readAgentFilters(new URLSearchParams(filterKey)), [filterKey]);
	const updateFilters = useCallback(
		(change: Partial<AgentFilters>) => {
			setSearchParams(writeAgentFilters({ ...filters, page: 1, ...change }), { replace: true });
		},
		[filters, setSearchParams],
	);

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
						.select(
							"id,iid,display_name,agent_runtime,agent_runtime_version,first_seen,last_seen,retired_at,retired_reason",
						)
						.eq("tenant_id", activeTenantId)
						.order("last_seen", { ascending: false }),
					supabase
						.from("seat_usage")
						.select("included_agents,extra_agents,allowed_agents,retired_agents")
						.eq("tenant_id", activeTenantId)
						.maybeSingle(),
				]);

				if (cancelled || currentRequest !== requestId) return;
				setLoadedTenantId(activeTenantId);
				setNow(Date.now());

				if (
					agentsRes.error ||
					!Array.isArray(agentsRes.data) ||
					!agentsRes.data.every(isAgentRow)
				) {
					setAgents(null);
					setError(
						agentsRes.error
							? readErrorMessage(agentsRes.error, t("agents.loadFailed"))
							: t("agents.unavailable"),
					);
				} else {
					setAgents(agentsRes.data);
					setError(null);
				}

				if (seatRes.error || !isSeatUsageRow(seatRes.data)) {
					setSeatUsage(null);
					setSeatUsageError(
						seatRes.error
							? readErrorMessage(seatRes.error, t("agents.seatsLoadFailed"))
							: t("agents.seatsUnavailable"),
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
				setError(readErrorMessage(cause, t("agents.loadFailed")));
				setSeatUsageError(t("agents.seatsUnavailable"));
			}
		}

		void load();
		const timer = setInterval(load, 5000);
		return () => {
			cancelled = true;
			clearInterval(timer);
		};
	}, [tenantId, reloadKey]);

	const agentsForTeam = loadedTenantId === tenantId ? agents : null;
	const seatUsageForTeam = loadedTenantId === tenantId ? seatUsage : null;
	const allowed = seatUsageForTeam?.allowed_agents ?? null;
	const activeAgents = agentsForTeam?.filter((a) => !a.retired_at) ?? null;
	const staleCount = agentsForTeam?.filter((a) => agentHealth(a, now) === "stale").length ?? 0;
	const runtimes = useMemo(
		() =>
			[
				...new Set(
					(agentsForTeam ?? [])
						.map((a) => a.agent_runtime)
						.filter((value): value is string => typeof value === "string"),
				),
			].sort(),
		[agentsForTeam],
	);
	const matching = useMemo(
		() => (agentsForTeam ? filterAgents(agentsForTeam, filters, now) : null),
		[agentsForTeam, filters, now],
	);
	const pages = Math.max(1, Math.ceil((matching?.length ?? 0) / AGENT_PAGE_SIZE));
	const page = Math.min(filters.page, pages);
	const visible = matching?.slice((page - 1) * AGENT_PAGE_SIZE, page * AGENT_PAGE_SIZE) ?? null;
	const filtered = Boolean(filters.q.trim() || filters.status !== "all" || filters.runtime);

	return (
		<div className="stack">
			<div className="card">
				<div className="row space-between" style={{ alignItems: "flex-start", gap: 16 }}>
					<div>
						<h1>{t("nav.agents")}</h1>
						<p className="muted">{currentTeam?.name ?? t("agents.noTeam")}</p>
						<p className="muted">
							{richT("agents.summary", {
								iid: <code>iid</code>,
								allowed: <b>{allowed ?? t("common.unavailable")}</b>,
								recorded: <b>{activeAgents?.length ?? t("common.unavailable")}</b>,
							})}{" "}
							{typeof seatUsageForTeam?.retired_agents === "number"
								? t("agents.retiredCount", { count: seatUsageForTeam.retired_agents })
								: null}
						</p>
					</div>
					<span className="badge badge-neutral">
						{agentsForTeam === null
							? t("common.unavailable")
							: agentsForTeam.length > 0
								? t("agents.badge.recorded")
								: t("agents.badge.none")}
					</span>
				</div>
				{loadedTenantId === tenantId && error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}
				{loadedTenantId === tenantId && seatUsageError ? (
					<div className="notice notice-danger" role="alert" aria-live="polite">
						{t("agents.seatsWarning")} {seatUsageError}
					</div>
				) : null}
				{staleCount > 0 ? (
					<div className="notice notice-warning" role="status" data-stale-count={staleCount}>
						{t("agents.staleCount", { count: staleCount })}
					</div>
				) : null}
			</div>

			<div className="card">
				<div className="row" style={{ gap: 12, flexWrap: "wrap", alignItems: "flex-end" }}>
					<label>
						<span className="small">{t("agents.filter.search")}</span>{" "}
						<input
							className="input"
							type="search"
							value={filters.q}
							placeholder={t("agents.filter.searchHint")}
							onChange={(event) => updateFilters({ q: event.currentTarget.value })}
						/>
					</label>
					<label>
						<span className="small">{t("agents.status")}</span>{" "}
						<select
							className="input"
							value={filters.status}
							onChange={(event) =>
								updateFilters({ status: event.currentTarget.value as AgentFilters["status"] })
							}
						>
							{AGENT_STATUS_FILTERS.map((status) => (
								<option key={status} value={status}>
									{t(STATUS_FILTER_LABEL[status])}
								</option>
							))}
						</select>
					</label>
					<label>
						<span className="small">{t("agents.runtime")}</span>{" "}
						<select
							className="input"
							value={filters.runtime}
							onChange={(event) => updateFilters({ runtime: event.currentTarget.value })}
						>
							<option value="">{t("agents.filter.runtimeAll")}</option>
							{runtimes.map((runtime) => (
								<option key={runtime} value={runtime}>
									{runtime}
								</option>
							))}
						</select>
					</label>
					<label>
						<span className="small">{t("agents.filter.sort")}</span>{" "}
						<select
							className="input"
							value={filters.sort}
							onChange={(event) =>
								updateFilters({ sort: event.currentTarget.value as AgentFilters["sort"] })
							}
						>
							{AGENT_SORTS.map((sort) => (
								<option key={sort} value={sort}>
									{t(SORT_LABEL[sort])}
								</option>
							))}
						</select>
					</label>
					{filtered ? (
						<button
							className="button button-secondary button-sm"
							type="button"
							onClick={() => setSearchParams(new URLSearchParams(), { replace: true })}
						>
							{t("agents.filter.clear")}
						</button>
					) : null}
					<button
						className="button button-secondary button-sm"
						type="button"
						disabled={!matching || matching.length === 0}
						title={t("agents.export.hint")}
						onClick={() => {
							if (!matching) return;
							saveFile(
								`aidr-agents-${fileStamp(Date.now())}.csv`,
								agentsCsv(matching, now),
								"text/csv;charset=utf-8",
							);
						}}
					>
						{t("agents.export.csv")}
					</button>
				</div>
				{matching ? (
					<p className="muted small" style={{ marginTop: 8 }} data-agent-count={matching.length}>
						{t("agents.filter.shown", {
							shown: matching.length,
							total: agentsForTeam?.length ?? 0,
						})}
					</p>
				) : null}
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>{t("common.name")}</th>
								<th>{t("agents.runtime")}</th>
								<th>{t("agents.status")}</th>
								<th>{t("agents.lastSeen")}</th>
								<th className="right">
									<span className="sr-only">{t("notify.table.actions")}</span>
								</th>
							</tr>
						</thead>
						<tbody>
							{visible?.map((a) => {
								const health = agentHealth(a, now);
								return (
									<tr key={a.id} data-agent-status={health}>
										<td>
											<div className="mono">{a.display_name ?? a.iid.slice(0, 12)}</div>
											<div className="muted small">iid: {a.iid}</div>
										</td>
										<td>
											<span className="badge badge-neutral badge-plain">
												{a.agent_runtime ?? t("common.unknown")}
											</span>
											{a.agent_runtime_version ? (
												<span className="muted small"> {a.agent_runtime_version}</span>
											) : null}
										</td>
										<td>
											<span
												className={`badge ${HEALTH_BADGE[health]}`}
												title={health === "stale" ? t("agents.staleHint") : undefined}
											>
												{health === "retired"
													? a.retired_reason === "offline"
														? t("agents.status.retiredOffline")
														: t("agents.status.retired")
													: health === "stale"
														? t("agents.status.stale")
														: t("agents.status.active")}
											</span>
										</td>
										<td className="mono">{new Date(a.last_seen).toLocaleString()}</td>
										<td className="right">
											<Link className="button button-secondary button-sm" to={`/agents/${a.id}`}>
												{t("agents.view")}
											</Link>{" "}
											{canManageTeam && tenantId && !a.retired_at ? (
												<RetireAgentControl tenantId={tenantId} agentId={a.id} onRetired={reload} />
											) : null}
										</td>
									</tr>
								);
							})}
							{agentsForTeam === null ? (
								<tr>
									<td colSpan={5} className="muted">
										{t("agents.unavailable")}
									</td>
								</tr>
							) : agentsForTeam.length === 0 ? (
								<tr>
									<td colSpan={5} className="muted">
										{richT("agents.empty", {
											link: <Link to="/onboarding">{t("nav.onboarding")}</Link>,
										})}
									</td>
								</tr>
							) : matching && matching.length === 0 ? (
								<tr>
									<td colSpan={5} className="muted">
										{t("agents.filter.none")}
									</td>
								</tr>
							) : null}
						</tbody>
					</table>
				</div>
				{pages > 1 ? (
					<div className="row" style={{ gap: 8, marginTop: 10, alignItems: "center" }}>
						<button
							className="button button-secondary button-sm"
							type="button"
							disabled={page <= 1}
							onClick={() => updateFilters({ page: page - 1 })}
						>
							{t("agents.page.prev")}
						</button>
						<span className="small">{t("agents.page", { page, pages })}</span>
						<button
							className="button button-secondary button-sm"
							type="button"
							disabled={page >= pages}
							onClick={() => updateFilters({ page: page + 1 })}
						>
							{t("agents.page.next")}
						</button>
					</div>
				) : null}
			</div>
			{tenantId ? (
				<AutoRetireSettings key={tenantId} tenantId={tenantId} canManage={canManageTeam} />
			) : null}
		</div>
	);
}
