import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import { readErrorMessage } from "../../lib/errors";
import { supabase, supabaseProjectUrl } from "../../lib/supabase";
import {
	actionBadge,
	entityLabel,
	GUARD_MODES,
	type GuardModeValue,
	managedPolicySnippet,
	PRIVACY_WINDOWS,
	type PrivacyEventRow,
	type PrivacySummary,
	type PrivacyWindow,
	parsePrivacyEventRow,
	parsePrivacySummary,
	siteLabel,
} from "../privacy-guard";

const RECENT_LIMIT = 25;
const REFRESH_MS = 30_000;

type BrowserInstall = { id: string; iid: string; display_name: string | null };

type Read<T> = { ok: true; value: T } | { ok: false; error: string };

const SUMMARY_UNAVAILABLE = "Privacy summary is unavailable.";
const RECENT_UNAVAILABLE = "Recent privacy events are unavailable.";

async function readSummary(
	tenantId: string,
	windowDays: PrivacyWindow,
): Promise<Read<PrivacySummary>> {
	try {
		const { data, error } = await supabase.rpc("privacy_guard_summary", {
			p_tenant_id: tenantId,
			p_days: windowDays,
		});
		if (error) throw new Error(readErrorMessage(error, SUMMARY_UNAVAILABLE));
		return { ok: true, value: parsePrivacySummary(data, windowDays) };
	} catch (cause) {
		return { ok: false, error: readErrorMessage(cause, SUMMARY_UNAVAILABLE) };
	}
}

async function readRecent(tenantId: string): Promise<Read<PrivacyEventRow[]>> {
	try {
		const { data, error } = await supabase
			.from("events")
			.select("id,created_at,agent_id,payload")
			.eq("tenant_id", tenantId)
			.eq("type", "privacy_scan")
			.order("created_at", { ascending: false })
			.limit(RECENT_LIMIT);
		if (error || !Array.isArray(data)) throw new Error(readErrorMessage(error, RECENT_UNAVAILABLE));
		const rows = data.map(parsePrivacyEventRow);
		return { ok: true, value: rows.filter((row): row is PrivacyEventRow => row !== null) };
	} catch (cause) {
		return { ok: false, error: readErrorMessage(cause, RECENT_UNAVAILABLE) };
	}
}

async function readInstalls(tenantId: string): Promise<Map<string, BrowserInstall> | null> {
	try {
		const { data, error } = await supabase
			.from("agents")
			.select("id,iid,display_name")
			.eq("tenant_id", tenantId)
			.eq("agent_runtime", "browser_guard");
		if (error || !Array.isArray(data)) return null;
		return new Map((data as BrowserInstall[]).map((row) => [row.id, row]));
	} catch {
		return null;
	}
}

export function PrivacyGuardPage() {
	const { currentTeam, isLoading } = useTeam();
	if (isLoading) return <div role="status">Resolving the managed tenant…</div>;
	if (!currentTeam) return <div role="alert">Select a team to view Browser Privacy Guard.</div>;
	return <TenantPrivacyGuardPage key={currentTeam.id} tenantId={currentTeam.id} />;
}

function numberText(value: number | undefined): string {
	return value === undefined ? "—" : value.toLocaleString();
}

function TenantPrivacyGuardPage({ tenantId }: { tenantId: string }) {
	const [windowDays, setWindowDays] = useState<PrivacyWindow>(30);
	// null = not loaded yet; a failed read is kept as an error, never as zeros.
	const [summaryRead, setSummaryRead] = useState<Read<PrivacySummary> | null>(null);
	const [recentRead, setRecentRead] = useState<Read<PrivacyEventRow[]> | null>(null);
	const [installs, setInstalls] = useState<Map<string, BrowserInstall>>(new Map());
	const [loaded, setLoaded] = useState(false);
	const [refreshTick, setRefreshTick] = useState(0);

	useEffect(() => {
		let cancelled = false;
		let inFlight = false;

		async function load() {
			if (inFlight) return;
			inFlight = true;
			try {
				const [summaryRead, recentRead, installRead] = await Promise.all([
					readSummary(tenantId, windowDays),
					readRecent(tenantId),
					readInstalls(tenantId),
				]);
				if (cancelled) return;
				setSummaryRead(summaryRead);
				setRecentRead(recentRead);
				// Install names are cosmetic: a failed read falls back to the agent ID.
				if (installRead) setInstalls(installRead);
			} finally {
				inFlight = false;
				if (!cancelled) setLoaded(true);
			}
		}

		void load();
		const timer = setInterval(() => void load(), REFRESH_MS);
		return () => {
			cancelled = true;
			clearInterval(timer);
		};
		// refreshTick re-runs the read on demand.
	}, [tenantId, windowDays, refreshTick]);

	const summary = summaryRead?.ok ? summaryRead.value : null;
	const recent = recentRead?.ok ? recentRead.value : null;
	const error = [summaryRead, recentRead]
		.map((read) => (read && !read.ok ? read.error : null))
		.filter(Boolean)
		.join(" ");
	const totals = summary?.totals;

	return (
		<div className="stack">
			<section className="card">
				<div className="row space-between" style={{ alignItems: "flex-start" }}>
					<div>
						<p className="eyebrow">Browser Guard</p>
						<h1>Browser Privacy Guard</h1>
						<p className="muted">
							Sensitive data your browser installs masked, warned about or blocked before it reached
							AI chat products. Only counts are reported: no prompt text, masked text, matched
							values or page addresses leave the browser.
						</p>
					</div>
					<div className="row" role="group" aria-label="Reporting window">
						{PRIVACY_WINDOWS.map((days) => (
							<button
								key={days}
								type="button"
								className={`button button-sm${days === windowDays ? "" : " button-secondary"}`}
								aria-pressed={days === windowDays}
								onClick={() => {
									setSummaryRead(null);
									setWindowDays(days);
								}}
							>
								{days} days
							</button>
						))}
						<button
							type="button"
							className="button button-secondary button-sm"
							onClick={() => setRefreshTick((tick) => tick + 1)}
						>
							Refresh
						</button>
					</div>
				</div>
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}
			</section>

			<section className="grid" aria-label="Browser privacy counters">
				<div className="card stat-card">
					<div className="stat-label">Prompts protected</div>
					<div className="stat-value">{numberText(totals?.promptsProtected)}</div>
					<div className="stat-hint">masked, warned or blocked · {windowDays} days</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">Items masked</div>
					<div className="stat-value">{numberText(totals?.itemsMasked)}</div>
					<div className="stat-hint">values replaced by placeholders</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">Blocked sends</div>
					<div className="stat-value">{numberText(totals?.blockedSends)}</div>
					<div className="stat-hint">stopped before submission</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">Active browser installs</div>
					<div className="stat-value">{numberText(summary?.installs.active)}</div>
					<div className="stat-hint">
						{summary
							? `of ${summary.installs.enrolled.toLocaleString()} enrolled`
							: "enrolled installs"}
					</div>
				</div>
			</section>

			<section className="cols">
				<BreakdownCard
					title="By entity type"
					description="Detected items by type, across masked, warned and blocked sends."
					unavailable={summary === null}
					loaded={loaded}
					rows={(summary?.byEntity ?? []).map((row) => ({
						key: row.entityType,
						label: entityLabel(row.entityType),
						value: row.items,
						detail: `${row.items.toLocaleString()} item(s)`,
					}))}
				/>
				<BreakdownCard
					title="By AI site"
					description="Scanned sends per AI product."
					unavailable={summary === null}
					loaded={loaded}
					rows={(summary?.bySite ?? []).map((row) => ({
						key: row.site,
						label: siteLabel(row.site),
						value: row.scans,
						detail: `${row.scans.toLocaleString()} send(s) · ${row.items.toLocaleString()} item(s) · ${row.blocked.toLocaleString()} blocked`,
					}))}
				/>
			</section>

			<SeriesCard summary={summary} loaded={loaded} windowDays={windowDays} />

			<section className="card" aria-labelledby="privacy-recent-heading">
				<div className="panel-head">
					<h2 id="privacy-recent-heading">Recent privacy events</h2>
					<Link className="view-all" to="/events">
						All events
					</Link>
				</div>
				<p className="muted small">The latest {RECENT_LIMIT} scans. Counts only.</p>
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>Time</th>
								<th>Browser install</th>
								<th>AI site</th>
								<th>Channel</th>
								<th>Action</th>
								<th>Detected items</th>
							</tr>
						</thead>
						<tbody>
							{(recent ?? []).map((event) => {
								const install = installs.get(event.agentId);
								return (
									<tr key={event.id}>
										<td className="mono">{new Date(event.createdAt).toLocaleString()}</td>
										<td className="mono">
											{install?.display_name ??
												install?.iid.slice(0, 12) ??
												event.agentId.slice(0, 12)}
										</td>
										<td>{siteLabel(event.site)}</td>
										<td>{event.channel}</td>
										<td>
											<span className={actionBadge(event.action)}>{event.action}</span>
										</td>
										<td>
											{event.entityCounts.length > 0
												? event.entityCounts
														.map(([type, amount]) => `${entityLabel(type)} ×${amount}`)
														.join(", ")
												: event.findingsCount !== null
													? `${event.findingsCount} item(s)`
													: "—"}
										</td>
									</tr>
								);
							})}
							{recent === null || recent.length === 0 ? (
								<tr>
									<td colSpan={6} className="muted">
										{recent === null
											? loaded
												? "Recent privacy events are unavailable right now."
												: "Loading privacy events…"
											: "No privacy events yet. Enroll browsers below to start reporting."}
									</td>
								</tr>
							) : null}
						</tbody>
					</table>
				</div>
			</section>

			<EnrollBrowsersPanel />
		</div>
	);
}

function BreakdownCard(props: {
	title: string;
	description: string;
	unavailable: boolean;
	loaded: boolean;
	rows: Array<{ key: string; label: string; value: number; detail: string }>;
}) {
	const max = Math.max(1, ...props.rows.map((row) => row.value));
	return (
		<section className="card" aria-label={props.title}>
			<h2>{props.title}</h2>
			<p className="muted small">{props.description}</p>
			{props.unavailable ? (
				<p className="muted">{props.loaded ? "Unavailable right now." : "Loading…"}</p>
			) : props.rows.length === 0 ? (
				<p className="muted">No detections in this window.</p>
			) : (
				<ul className="privacy-breakdown">
					{props.rows.map((row) => (
						<li key={row.key}>
							<div className="row space-between">
								<span>{row.label}</span>
								<span className="mono small">{row.detail}</span>
							</div>
							<div className="usage-bar" aria-hidden="true">
								<div className="usage-fill" style={{ width: `${(row.value / max) * 100}%` }} />
							</div>
						</li>
					))}
				</ul>
			)}
		</section>
	);
}

function SeriesCard({
	summary,
	loaded,
	windowDays,
}: {
	summary: PrivacySummary | null;
	loaded: boolean;
	windowDays: PrivacyWindow;
}) {
	const series = summary?.series ?? [];
	const max = Math.max(1, ...series.map((day) => day.scans));
	const totalScans = series.reduce((sum, day) => sum + day.scans, 0);
	return (
		<section className="card" aria-label="Daily privacy activity">
			<h2>Daily activity</h2>
			<p className="muted small">
				Scanned sends per UTC day over the last {windowDays} days, split by guard action.
			</p>
			{summary === null ? (
				<p className="muted">{loaded ? "Unavailable right now." : "Loading…"}</p>
			) : (
				<>
					<div
						className="privacy-series"
						role="img"
						aria-label={`${totalScans} scanned sends over ${windowDays} days`}
					>
						{series.map((day) => (
							<div
								key={day.day}
								className="privacy-series-day"
								title={`${day.day}: ${day.scans} scans, ${day.masked} masked, ${day.warned} warned, ${day.blocked} blocked`}
							>
								<div
									className="privacy-series-stack"
									style={{ height: `${(day.scans / max) * 100}%` }}
								>
									<span className="privacy-series-blocked" style={{ flexGrow: day.blocked }} />
									<span className="privacy-series-warned" style={{ flexGrow: day.warned }} />
									<span className="privacy-series-masked" style={{ flexGrow: day.masked }} />
									<span
										className="privacy-series-allowed"
										style={{
											flexGrow: Math.max(0, day.scans - day.blocked - day.warned - day.masked),
										}}
									/>
								</div>
							</div>
						))}
					</div>
					<div className="row small muted" style={{ marginTop: 8 }}>
						<span>
							<span className="privacy-key privacy-series-masked" /> masked
						</span>
						<span>
							<span className="privacy-key privacy-series-warned" /> warned
						</span>
						<span>
							<span className="privacy-key privacy-series-blocked" /> blocked
						</span>
						<span>
							<span className="privacy-key privacy-series-allowed" /> allowed
						</span>
					</div>
					<details style={{ marginTop: 10 }}>
						<summary className="small">Daily table</summary>
						<div className="table-wrap">
							<table className="table">
								<thead>
									<tr>
										<th>Day (UTC)</th>
										<th>Scans</th>
										<th>Masked</th>
										<th>Warned</th>
										<th>Blocked</th>
									</tr>
								</thead>
								<tbody>
									{series.map((day) => (
										<tr key={day.day}>
											<td className="mono">{day.day}</td>
											<td>{day.scans}</td>
											<td>{day.masked}</td>
											<td>{day.warned}</td>
											<td>{day.blocked}</td>
										</tr>
									))}
								</tbody>
							</table>
						</div>
					</details>
				</>
			)}
		</section>
	);
}

function EnrollBrowsersPanel() {
	const [mode, setMode] = useState<GuardModeValue>("auto");
	const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
	const snippet = useMemo(
		() => managedPolicySnippet({ controlPlaneUrl: supabaseProjectUrl, mode }),
		[mode],
	);
	const copy = useCallback(async () => {
		try {
			await navigator.clipboard.writeText(snippet);
			setCopyState("copied");
		} catch {
			setCopyState("failed");
		}
	}, [snippet]);

	return (
		<section className="card" aria-labelledby="enroll-browsers-heading">
			<h2 id="enroll-browsers-heading">Enroll browsers</h2>
			<p className="muted small">
				Each enrolled browser profile is a protected agent seat. Detection and masking run locally
				in the browser whether or not it is enrolled; enrollment only adds reporting to this page.
			</p>
			<ol className="stack" style={{ paddingLeft: 20 }}>
				<li>
					<b>Install the extension.</b> Deploy the Singularity AIDR Browser Guard package from your
					AIDR release to Chrome, Edge or Firefox, either per user or force-installed through your
					browser management policy.
				</li>
				<li>
					<b>Create a tenant API key.</b> Create a write-capable key on the{" "}
					<Link to="/api-keys">API Keys</Link> page. The key is shown once; paste it into the policy
					below or into the extension's options page.
				</li>
				<li>
					<b>Push the managed policy.</b> Managed values override the user's settings and lock those
					fields in the extension.
				</li>
			</ol>
			<div className="row" style={{ alignItems: "center", marginTop: 8 }}>
				<label className="label" htmlFor="privacy-guard-mode">
					Guard mode
				</label>
				<select
					id="privacy-guard-mode"
					className="input"
					style={{ maxWidth: 220 }}
					value={mode}
					onChange={(event) => {
						setMode(event.target.value as GuardModeValue);
						setCopyState("idle");
					}}
				>
					{GUARD_MODES.map((option) => (
						<option key={option.value} value={option.value}>
							{option.label}
						</option>
					))}
				</select>
				<span className="muted small">
					{GUARD_MODES.find((option) => option.value === mode)?.hint}
				</span>
			</div>
			<pre className="mono small" aria-label="Managed policy JSON" style={{ overflowX: "auto" }}>
				{snippet}
			</pre>
			<div className="row" style={{ alignItems: "center" }}>
				<button className="button button-secondary button-sm" type="button" onClick={copy}>
					Copy policy JSON
				</button>
				<span className="muted small" role="status">
					{copyState === "copied"
						? "Copied. Replace the apiKey placeholder before deploying."
						: copyState === "failed"
							? "Copy failed. Select the JSON and copy it manually."
							: ""}
				</span>
			</div>
		</section>
	);
}
