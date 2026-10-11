import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import { governanceAction, governanceErrorMessage, stepUpPath } from "../../lib/ai-governance";
import { readErrorMessage } from "../../lib/errors";
import { supabase, supabaseProjectUrl } from "../../lib/supabase";
import {
	acceptableUseNotice,
	actionBadge,
	entityLabel,
	GUARD_MODES,
	type GuardModeValue,
	managedPolicySnippet,
	PRIVACY_WINDOWS,
	type PrivacyEventRow,
	type PrivacySummary,
	type PrivacyWindow,
	parseBrowserGuardSettings,
	parsePrivacyEventRow,
	parsePrivacySummary,
	siteLabel,
} from "../privacy-guard";
import {
	categoryLabel,
	parseShadowAiDecisions,
	parseShadowAiSummary,
	SHADOW_AI_SERVICES,
	type ShadowAiDecision,
	type ShadowAiDecisionRow,
	type ShadowAiSummary,
	serviceName,
	shadowAiDecisionPayload,
	shadowAiPolicySnippet,
} from "../shadow-ai";

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
	const { currentTeam, currentRole, isLoading } = useTeam();
	if (isLoading) return <div role="status">Resolving the managed tenant…</div>;
	if (!currentTeam) return <div role="alert">Select a team to view Browser Privacy Guard.</div>;
	return (
		<TenantPrivacyGuardPage
			key={currentTeam.id}
			tenantId={currentTeam.id}
			canDecide={currentRole === "owner" || currentRole === "admin"}
		/>
	);
}

function numberText(value: number | undefined): string {
	return value === undefined ? "—" : value.toLocaleString();
}

function TenantPrivacyGuardPage({ tenantId, canDecide }: { tenantId: string; canDecide: boolean }) {
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

			<ShadowAiPanel
				tenantId={tenantId}
				windowDays={windowDays}
				refreshTick={refreshTick}
				canDecide={canDecide}
			/>

			<NativeNerPanel tenantId={tenantId} refreshTick={refreshTick} canDecide={canDecide} />

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
											{event.nativeNer === "unavailable" ? (
												<>
													{" "}
													<span className="badge badge-ask">not NER-checked</span>
												</>
											) : null}
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

const SHADOW_UNAVAILABLE = "Shadow AI summary is unavailable.";
const TOP_SERVICES = 12;

async function readShadowAi(
	tenantId: string,
	windowDays: PrivacyWindow,
): Promise<Read<ShadowAiSummary>> {
	try {
		const { data, error } = await supabase.rpc("shadow_ai_summary", {
			p_tenant_id: tenantId,
			p_days: windowDays,
		});
		if (error) throw new Error(readErrorMessage(error, SHADOW_UNAVAILABLE));
		return { ok: true, value: parseShadowAiSummary(data, windowDays) };
	} catch (cause) {
		return { ok: false, error: readErrorMessage(cause, SHADOW_UNAVAILABLE) };
	}
}

const DECISIONS_UNAVAILABLE = "Allow/block decisions are unavailable.";
const SHADOW_AI_SERVICE_IDS = Object.keys(SHADOW_AI_SERVICES);

/**
 * The tenant's `ai_site` register entries for catalogued services (RLS: members
 * read their tenant's rows). The read is filtered to the catalog ids rather
 * than taking the first N `ai_site` rows: the register can hold far more
 * hostnames than one API page (max_rows = 1000), and an unfiltered read could
 * silently leave out a catalogued service's decision.
 */
async function readShadowAiDecisions(
	tenantId: string,
): Promise<Read<Map<string, ShadowAiDecisionRow>>> {
	try {
		const { data, error } = await supabase
			.from("ai_assets")
			.select("id,identifier,status,version")
			.eq("tenant_id", tenantId)
			.eq("asset_type", "ai_site")
			.in("identifier", SHADOW_AI_SERVICE_IDS);
		if (error) throw new Error(DECISIONS_UNAVAILABLE);
		return { ok: true, value: parseShadowAiDecisions(data) };
	} catch {
		return { ok: false, error: DECISIONS_UNAVAILABLE };
	}
}

type DecisionNotice = { tone: "ok" | "error"; text: string; stepUp?: boolean };

function DecisionNoticeLine({ notice, tenantId }: { notice: DecisionNotice; tenantId: string }) {
	const ok = notice.tone === "ok";
	return (
		<p
			className={ok ? "notice notice-success" : "notice notice-danger"}
			role={ok ? "status" : "alert"}
		>
			{notice.text}
			{notice.stepUp ? (
				<>
					{" "}
					<Link to={stepUpPath(tenantId)}>Verify now</Link>
				</>
			) : null}
		</p>
	);
}

/** Register-backed allow/block decisions and the `upsert_asset` action that changes one. */
function useShadowAiDecisions(tenantId: string, refreshTick: number) {
	const [decisions, setDecisions] = useState<Read<Map<string, ShadowAiDecisionRow>> | null>(null);
	const [busy, setBusy] = useState<string | null>(null);
	const [notice, setNotice] = useState<DecisionNotice | null>(null);
	const [decisionTick, setDecisionTick] = useState(0);

	useEffect(() => {
		let cancelled = false;
		void readShadowAiDecisions(tenantId).then((next) => {
			if (!cancelled) setDecisions(next);
		});
		return () => {
			cancelled = true;
		};
		// refreshTick / decisionTick re-run the read on demand.
	}, [tenantId, refreshTick, decisionTick]);

	const decide = useCallback(
		async (serviceId: string, decision: ShadowAiDecision) => {
			if (!decisions?.ok) return;
			setBusy(serviceId);
			setNotice(null);
			const result = await governanceAction(
				tenantId,
				"upsert_asset",
				shadowAiDecisionPayload(serviceId, decision, decisions.value.get(serviceId)),
			);
			setBusy(null);
			setDecisionTick((tick) => tick + 1);
			setNotice(
				result.ok
					? {
							tone: "ok",
							text: `${serviceName(serviceId)} ${decision}. Enrolled browsers apply it at their next policy refresh (within about 15 minutes).`,
						}
					: {
							tone: "error",
							text: governanceErrorMessage(result.error),
							stepUp: result.error === "mfa_required",
						},
			);
		},
		[tenantId, decisions],
	);

	return { decisions, busy, notice, decide };
}

const NATIVE_NER_UNAVAILABLE = "The native NER setting is unavailable.";

async function readBrowserGuardSettings(
	tenantId: string,
): Promise<Read<{ requireNativeNer: boolean }>> {
	try {
		const { data, error } = await supabase
			.from("tenant_ai_governance_settings")
			.select("browser_guard_require_native_ner")
			.eq("tenant_id", tenantId)
			.maybeSingle();
		if (error) throw new Error(NATIVE_NER_UNAVAILABLE);
		return { ok: true, value: parseBrowserGuardSettings(data) };
	} catch {
		return { ok: false, error: NATIVE_NER_UNAVAILABLE };
	}
}

/**
 * "Require native NER" for every enrolled browser: an owner/admin setting delivered in the
 * signed Browser Guard policy (`require_native_ner`). Browser Guard merges it with the
 * managed `requireNativeNer` key, and true wins.
 */
function NativeNerPanel({
	tenantId,
	refreshTick,
	canDecide,
}: {
	tenantId: string;
	refreshTick: number;
	canDecide: boolean;
}) {
	const [read, setRead] = useState<Read<{ requireNativeNer: boolean }> | null>(null);
	const [busy, setBusy] = useState(false);
	const [notice, setNotice] = useState<DecisionNotice | null>(null);
	const [tick, setTick] = useState(0);

	useEffect(() => {
		let cancelled = false;
		void readBrowserGuardSettings(tenantId).then((next) => {
			if (!cancelled) setRead(next);
		});
		return () => {
			cancelled = true;
		};
		// refreshTick / tick re-run the read on demand.
	}, [tenantId, refreshTick, tick]);

	const current = read?.ok ? read.value.requireNativeNer : null;

	async function change(next: boolean) {
		setBusy(true);
		setNotice(null);
		const result = await governanceAction(tenantId, "update_browser_guard_settings", {
			require_native_ner: next,
		});
		setBusy(false);
		setTick((value) => value + 1);
		setNotice(
			result.ok
				? {
						tone: "ok",
						text: next
							? "Native NER is now required. Enrolled browsers apply it at their next policy refresh (within about 15 minutes)."
							: "Native NER is no longer required by the dashboard. Browsers whose management (MDM/GPO) policy sets requireNativeNer keep requiring it.",
					}
				: {
						tone: "error",
						text: governanceErrorMessage(result.error),
						stepUp: result.error === "mfa_required",
					},
		);
	}

	return (
		<section className="card" aria-labelledby="native-ner-heading">
			<div className="panel-head">
				<h2 id="native-ner-heading">Require native NER</h2>
				{current === null ? null : (
					<span className={current ? "badge badge-deny" : "badge badge-allow"}>
						{current ? "required" : "not required"}
					</span>
				)}
			</div>
			<p className="muted small">
				When required, a prompt, paste or file upload that the Browser Guard native host could not
				check for names, addresses and locations (host not installed, crashed or timed out,
				rules-only host, text over the host limit) is blocked instead of being sent after the
				built-in rules only; in monitor mode it is reported as not NER-checked. It needs the native
				messaging host on every browser, and large uploads wait for the host's answer. Your browser
				management (MDM/GPO) <code>requireNativeNer</code> policy still wins where it is stricter:
				the dashboard can switch the requirement on, never off for those browsers.
			</p>
			{read && !read.ok ? (
				<p className="muted" role="status">
					{read.error}
				</p>
			) : null}
			{notice ? <DecisionNoticeLine notice={notice} tenantId={tenantId} /> : null}
			{canDecide ? (
				<label className="row" style={{ alignItems: "center" }}>
					<input
						type="checkbox"
						checked={current === true}
						disabled={current === null || busy}
						onChange={(event) => void change(event.target.checked)}
					/>
					Require native NER for every enrolled browser
				</label>
			) : (
				<p className="muted small">Owners and administrators can change this setting.</p>
			)}
		</section>
	);
}

/**
 * Shadow AI: which catalogued AI services managed browsers opened, sanctioned vs not,
 * and navigations the policy blocked. Loads on its own so an older control plane
 * without `shadow_ai_summary` only greys out this panel. Owners and administrators can
 * allow or block a service here; enrolled browsers apply it from a signed policy.
 */
function ShadowAiPanel({
	tenantId,
	windowDays,
	refreshTick,
	canDecide,
}: {
	tenantId: string;
	windowDays: PrivacyWindow;
	refreshTick: number;
	canDecide: boolean;
}) {
	const [read, setRead] = useState<Read<ShadowAiSummary> | null>(null);
	const { decisions, busy, notice, decide } = useShadowAiDecisions(tenantId, refreshTick);
	const [policyMode, setPolicyMode] = useState<"monitor" | "block-unsanctioned">("monitor");

	useEffect(() => {
		let cancelled = false;
		const load = async () => {
			const next = await readShadowAi(tenantId, windowDays);
			if (!cancelled) setRead(next);
		};
		setRead(null);
		void load();
		const timer = setInterval(() => void load(), REFRESH_MS);
		return () => {
			cancelled = true;
			clearInterval(timer);
		};
		// refreshTick re-runs the read on demand.
	}, [tenantId, windowDays, refreshTick]);

	const summary = read?.ok ? read.value : null;
	const totals = summary?.totals;
	const sanctionedShare =
		totals && totals.visits > 0
			? Math.round((totals.sanctionedVisits / totals.visits) * 100)
			: null;
	const snippet = shadowAiPolicySnippet({
		mode: policyMode,
		sanctioned: (summary?.byService ?? [])
			.filter((row) => row.sanctioned)
			.map((row) => row.serviceId),
	});

	return (
		<section className="card" aria-labelledby="shadow-ai-heading">
			<div className="panel-head">
				<h2 id="shadow-ai-heading">Shadow AI</h2>
			</div>
			<p className="muted small">
				Generative-AI services your managed browsers opened, whether your policy sanctions them, and
				navigations the Shadow AI policy blocked. Browsers report a catalog service id and counts
				per day only: never page addresses, titles or content.
			</p>
			{read && !read.ok ? (
				<p className="muted" role="status">
					{read.error}
				</p>
			) : null}
			<div className="grid" role="group" aria-label="Shadow AI counters">
				<div className="card stat-card">
					<div className="stat-label">AI service visits</div>
					<div className="stat-value">{numberText(totals?.visits)}</div>
					<div className="stat-hint">
						{totals ? `${totals.services.toLocaleString()} service(s) · ${windowDays} days` : "—"}
					</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">Unsanctioned visits</div>
					<div className="stat-value">{numberText(totals?.unsanctionedVisits)}</div>
					<div className="stat-hint">
						{sanctionedShare === null
							? "no visits yet"
							: `${sanctionedShare}% of visits sanctioned`}
					</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">Blocked attempts</div>
					<div className="stat-value">{numberText(totals?.blockedAttempts)}</div>
					<div className="stat-hint">navigations refused by policy</div>
				</div>
			</div>

			<h3 style={{ marginTop: 16 }}>Top AI services</h3>
			<p className="muted small">
				{canDecide
					? "Allow or block a service for every enrolled browser. Decisions are recorded in the AI governance register (audited, multi-factor verification required) and delivered to Browser Guard as a signed policy. Your browser management (MDM/GPO) policy still wins where it is stricter: a dashboard allow never unblocks a service it blocks."
					: "Owners and administrators can allow or block a service here; enrolled browsers apply it from a signed policy."}
			</p>
			{decisions && !decisions.ok ? (
				<p className="muted" role="status">
					{decisions.error}
				</p>
			) : null}
			{notice ? <DecisionNoticeLine notice={notice} tenantId={tenantId} /> : null}
			{summary === null ? (
				<p className="muted">{read ? "Unavailable right now." : "Loading…"}</p>
			) : (
				<ShadowAiServicesTable
					summary={summary}
					decisions={decisions?.ok ? decisions.value : null}
					canDecide={canDecide && decisions?.ok === true}
					busy={busy}
					onDecide={(serviceId, decision) => void decide(serviceId, decision)}
				/>
			)}

			{summary ? <ShadowAiTrend summary={summary} /> : null}

			<details style={{ marginTop: 12 }}>
				<summary className="small">Configure Shadow AI and internal AI sites</summary>
				<p className="muted small">
					Alternative to dashboard decisions, or for browsers without a control plane: add these
					keys to the Browser Guard managed policy. To apply dashboard decisions, the managed policy
					also needs <code>telemetry</code> and <code>dashboardPolicy</code> (the control plane's
					policy signing public key). <code>sanctioned</code> lists the catalog ids you approve
					(prefilled from the services reported as sanctioned);
					<code> block-unsanctioned</code> blocks every other catalogued AI service. Each user
					grants the extension access to the AI service sites and internal hosts once, on its
					options page.
				</p>
				<div className="row" style={{ alignItems: "center" }}>
					<label className="label" htmlFor="shadow-ai-mode">
						Shadow AI mode
					</label>
					<select
						id="shadow-ai-mode"
						className="input"
						style={{ maxWidth: 220 }}
						value={policyMode}
						onChange={(event) =>
							setPolicyMode(
								event.target.value === "block-unsanctioned" ? "block-unsanctioned" : "monitor",
							)
						}
					>
						<option value="monitor">Monitor (count only)</option>
						<option value="block-unsanctioned">Block unsanctioned</option>
					</select>
				</div>
				<pre
					className="mono small"
					aria-label="Shadow AI policy JSON"
					style={{ overflowX: "auto" }}
				>
					{snippet}
				</pre>
			</details>
		</section>
	);
}

function decisionBadge(row: ShadowAiDecisionRow | undefined) {
	if (!row?.decision) return <span className="muted">—</span>;
	return (
		<span className={row.decision === "allowed" ? "badge badge-allow" : "badge badge-deny"}>
			{row.decision}
		</span>
	);
}

function ShadowAiServicesTable({
	summary,
	decisions,
	canDecide,
	busy,
	onDecide,
}: {
	summary: ShadowAiSummary;
	decisions: Map<string, ShadowAiDecisionRow> | null;
	canDecide: boolean;
	busy: string | null;
	onDecide: (serviceId: string, decision: ShadowAiDecision) => void;
}) {
	const services = summary.byService.slice(0, TOP_SERVICES);
	if (services.length === 0) {
		return (
			<p className="muted">
				No Shadow AI activity in this window. Set <code>shadowAi</code> in the Browser Guard managed
				policy (monitor or block-unsanctioned) to start reporting.
			</p>
		);
	}
	const max = Math.max(1, ...services.map((row) => row.visits + row.blocked));
	return (
		<div className="table-wrap">
			<table className="table" aria-label="Top AI services">
				<thead>
					<tr>
						<th>AI service</th>
						<th>Category</th>
						<th>Status</th>
						<th>Visits</th>
						<th>Blocked</th>
						<th aria-hidden="true" />
						<th>Dashboard decision</th>
						{canDecide ? <th>Change</th> : null}
					</tr>
				</thead>
				<tbody>
					{services.map((row) => {
						const name = serviceName(row.serviceId);
						const current = decisions?.get(row.serviceId);
						// Decisions are read for catalogued services only (see readShadowAiDecisions).
						const decidable = Object.hasOwn(SHADOW_AI_SERVICES, row.serviceId);
						return (
							<tr key={row.serviceId}>
								<td>{name}</td>
								<td>{categoryLabel(row.category)}</td>
								<td>
									<span className={row.sanctioned ? "badge badge-allow" : "badge badge-ask"}>
										{row.sanctioned ? "sanctioned" : "unsanctioned"}
									</span>
								</td>
								<td>{row.visits.toLocaleString()}</td>
								<td>{row.blocked.toLocaleString()}</td>
								<td style={{ minWidth: 120 }}>
									<div className="usage-bar" aria-hidden="true">
										<div
											className="usage-fill"
											style={{ width: `${((row.visits + row.blocked) / max) * 100}%` }}
										/>
									</div>
								</td>
								<td>{decisions && decidable ? decisionBadge(current) : "—"}</td>
								{canDecide ? (
									<td>
										{decidable ? (
											<div className="row" style={{ gap: 4, flexWrap: "nowrap" }}>
												<button
													type="button"
													className="btn btn-sm"
													aria-label={`Allow ${name}`}
													disabled={busy !== null || current?.decision === "allowed"}
													onClick={() => onDecide(row.serviceId, "allowed")}
												>
													Allow
												</button>
												<button
													type="button"
													className="btn btn-sm btn-danger"
													aria-label={`Block ${name}`}
													disabled={busy !== null || current?.decision === "blocked"}
													onClick={() => onDecide(row.serviceId, "blocked")}
												>
													Block
												</button>
											</div>
										) : null}
									</td>
								) : null}
							</tr>
						);
					})}
				</tbody>
			</table>
		</div>
	);
}

function ShadowAiTrend({ summary }: { summary: ShadowAiSummary }) {
	const { series, totals, windowDays } = summary;
	const max = Math.max(1, ...series.map((day) => day.visits + day.blocked));
	return (
		<>
			<h3 style={{ marginTop: 16 }}>Daily trend</h3>
			<div
				className="privacy-series"
				role="img"
				aria-label={`${totals.visits} AI service visits and ${totals.blockedAttempts} blocked attempts over ${windowDays} days`}
			>
				{series.map((day) => (
					<div
						key={day.day}
						className="privacy-series-day"
						title={`${day.day}: ${day.visits} visits (${day.unsanctionedVisits} unsanctioned), ${day.blocked} blocked`}
					>
						<div
							className="privacy-series-stack"
							style={{ height: `${((day.visits + day.blocked) / max) * 100}%` }}
						>
							<span className="privacy-series-blocked" style={{ flexGrow: day.blocked }} />
							<span
								className="privacy-series-warned"
								style={{ flexGrow: day.unsanctionedVisits }}
							/>
							<span
								className="privacy-series-masked"
								style={{ flexGrow: Math.max(0, day.visits - day.unsanctionedVisits) }}
							/>
						</div>
					</div>
				))}
			</div>
			<div className="row small muted" style={{ marginTop: 8 }}>
				<span>
					<span className="privacy-key privacy-series-masked" /> sanctioned visits
				</span>
				<span>
					<span className="privacy-key privacy-series-warned" /> unsanctioned visits
				</span>
				<span>
					<span className="privacy-key privacy-series-blocked" /> blocked
				</span>
			</div>
		</>
	);
}

function EnrollBrowsersPanel() {
	const [mode, setMode] = useState<GuardModeValue>("auto");
	const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
	const [noticeOn, setNoticeOn] = useState(false);
	const [notice, setNotice] = useState({
		id: "ai-acceptable-use",
		version: "1",
		title: "",
		text: "",
		url: "",
	});
	const noticeResult = useMemo(
		() => (noticeOn ? acceptableUseNotice(notice) : null),
		[noticeOn, notice],
	);
	const snippet = useMemo(
		() =>
			managedPolicySnippet({
				controlPlaneUrl: supabaseProjectUrl,
				mode,
				acceptableUse: noticeResult?.ok ? noticeResult.value : null,
			}),
		[mode, noticeResult],
	);
	const editNotice = (field: keyof typeof notice) => (value: string) => {
		setNotice((current) => ({ ...current, [field]: value }));
		setCopyState("idle");
	};
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
					<b>Create a Browser Guard ingest-only key.</b> On the{" "}
					<Link to="/api-keys?type=browser_guard">API Keys</Link> page, choose{" "}
					<i>Browser Guard ingest-only key</i> and set an installation limit that fits your fleet.
					Anyone using a managed browser can read its policy, so do not deploy a tenant key here: an
					ingest-only key can only report counts-only privacy scans, from at most that many
					browsers, and cannot read policy, packs or reputation data. The key is shown once; paste
					it into the policy below. Owners and admins can create it.
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
			<fieldset className="stack" style={{ border: 0, padding: 0, marginTop: 12 }}>
				<legend>
					<b>AI acceptable-use notice</b>{" "}
					<span className="muted small">(optional; AI literacy)</span>
				</legend>
				<label className="row" style={{ alignItems: "center", gap: 8 }}>
					<input
						type="checkbox"
						checked={noticeOn}
						onChange={(event) => {
							setNoticeOn(event.target.checked);
							setCopyState("idle");
						}}
					/>
					Show an acceptable-use notice on protected AI sites
				</label>
				<p className="muted small">
					Each browser shows the notice once per version, on the first visit to a protected AI site,
					with an "I understand" button. Only acknowledgement counts per version are reported (see
					Governance); the text stays in the browser. Raise the version to show a changed notice
					again.
				</p>
				{noticeOn ? (
					<>
						<div className="row" style={{ flexWrap: "wrap", gap: 12 }}>
							<label className="label">
								Notice ID
								<input
									className="input"
									value={notice.id}
									onChange={(e) => editNotice("id")(e.target.value)}
								/>
							</label>
							<label className="label">
								Version
								<input
									className="input"
									type="number"
									min={1}
									value={notice.version}
									onChange={(e) => editNotice("version")(e.target.value)}
								/>
							</label>
							<label className="label">
								Policy link (https, optional)
								<input
									className="input"
									value={notice.url}
									onChange={(e) => editNotice("url")(e.target.value)}
								/>
							</label>
						</div>
						<label className="label">
							Title
							<input
								className="input"
								maxLength={120}
								value={notice.title}
								onChange={(e) => editNotice("title")(e.target.value)}
							/>
						</label>
						<label className="label">
							Notice text (plain text; blank lines separate paragraphs)
							<textarea
								className="input"
								rows={5}
								maxLength={4000}
								value={notice.text}
								onChange={(e) => editNotice("text")(e.target.value)}
							/>
						</label>
						{noticeResult && !noticeResult.ok ? (
							<div className="notice" role="alert">
								{noticeResult.error} The notice is left out of the policy below until this is fixed.
							</div>
						) : null}
					</>
				) : null}
			</fieldset>
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
