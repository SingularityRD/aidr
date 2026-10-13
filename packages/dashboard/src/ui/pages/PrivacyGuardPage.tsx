import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import { type Translate, useRichT, useT } from "../../i18n/I18nProvider";
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

async function readSummary(
	tenantId: string,
	windowDays: PrivacyWindow,
	t: Translate,
): Promise<Read<PrivacySummary>> {
	const SUMMARY_UNAVAILABLE = t("pg.summaryUnavailable");
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

async function readRecent(tenantId: string, t: Translate): Promise<Read<PrivacyEventRow[]>> {
	const RECENT_UNAVAILABLE = t("pg.recentUnavailable");
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
	const t = useT();
	if (isLoading) return <div role="status">{t("layout.resolvingTenant")}</div>;
	if (!currentTeam) return <div role="alert">{t("pg.noTeam")}</div>;
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
	const t = useT();
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
					readSummary(tenantId, windowDays, t),
					readRecent(tenantId, t),
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
						<h1 lang="en">{t("nav.browserGuard")}</h1>
						<p className="muted">{t("pg.intro")}</p>
					</div>
					<div className="row" role="group" aria-label={t("pg.window")}>
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
								{t("pg.days", { days })}
							</button>
						))}
						<button
							type="button"
							className="button button-secondary button-sm"
							onClick={() => setRefreshTick((tick) => tick + 1)}
						>
							{t("common.refresh")}
						</button>
					</div>
				</div>
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}
			</section>

			<section className="grid" aria-label={t("pg.counters")}>
				<div className="card stat-card">
					<div className="stat-label">{t("pg.protected")}</div>
					<div className="stat-value">{numberText(totals?.promptsProtected)}</div>
					<div className="stat-hint">{t("pg.protectedHint", { days: windowDays })}</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">{t("pg.masked")}</div>
					<div className="stat-value">{numberText(totals?.itemsMasked)}</div>
					<div className="stat-hint">{t("pg.maskedHint")}</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">{t("pg.blocked")}</div>
					<div className="stat-value">{numberText(totals?.blockedSends)}</div>
					<div className="stat-hint">{t("pg.blockedHint")}</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">{t("pg.installs")}</div>
					<div className="stat-value">{numberText(summary?.installs.active)}</div>
					<div className="stat-hint">
						{summary
							? t("pg.installsOf", { count: summary.installs.enrolled.toLocaleString() })
							: t("pg.installsHint")}
					</div>
				</div>
			</section>

			<section className="cols">
				<BreakdownCard
					title={t("pg.byEntity")}
					description={t("pg.byEntityDesc")}
					unavailable={summary === null}
					loaded={loaded}
					rows={(summary?.byEntity ?? []).map((row) => ({
						key: row.entityType,
						label: entityLabel(row.entityType, t),
						value: row.items,
						detail: t("pg.items", { count: row.items.toLocaleString() }),
					}))}
				/>
				<BreakdownCard
					title={t("pg.bySite")}
					description={t("pg.bySiteDesc")}
					unavailable={summary === null}
					loaded={loaded}
					rows={(summary?.bySite ?? []).map((row) => ({
						key: row.site,
						label: siteLabel(row.site, t),
						value: row.scans,
						detail: t("pg.siteDetail", {
							scans: row.scans.toLocaleString(),
							items: row.items.toLocaleString(),
							blocked: row.blocked.toLocaleString(),
						}),
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
					<h2 id="privacy-recent-heading">{t("pg.recent")}</h2>
					<Link className="view-all" to="/events">
						{t("pg.allEvents")}
					</Link>
				</div>
				<p className="muted small">{t("pg.recentNote", { count: RECENT_LIMIT })}</p>
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>{t("activity.time")}</th>
								<th>{t("pg.col.install")}</th>
								<th>{t("pg.col.site")}</th>
								<th>{t("pg.col.channel")}</th>
								<th>{t("pg.col.action")}</th>
								<th>{t("pg.col.items")}</th>
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
										<td>{siteLabel(event.site, t)}</td>
										<td>{event.channel}</td>
										<td>
											<span className={actionBadge(event.action)}>{event.action}</span>
										</td>
										<td>
											{event.entityCounts.length > 0
												? event.entityCounts
														.map(([type, amount]) => `${entityLabel(type, t)} ×${amount}`)
														.join(", ")
												: event.findingsCount !== null
													? t("pg.items", { count: event.findingsCount })
													: "—"}
											{event.nativeNer === "unavailable" ? (
												<>
													{" "}
													<span className="badge badge-ask">{t("pg.notNer")}</span>
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
												? t("pg.recentUnavailableNow")
												: t("pg.loadingEvents")
											: t("pg.noEvents")}
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
	const t = useT();
	const max = Math.max(1, ...props.rows.map((row) => row.value));
	return (
		<section className="card" aria-label={props.title}>
			<h2>{props.title}</h2>
			<p className="muted small">{props.description}</p>
			{props.unavailable ? (
				<p className="muted">{props.loaded ? t("pg.unavailableNow") : t("common.loading")}</p>
			) : props.rows.length === 0 ? (
				<p className="muted">{t("pg.noDetections")}</p>
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
	const t = useT();
	const series = summary?.series ?? [];
	const max = Math.max(1, ...series.map((day) => day.scans));
	const totalScans = series.reduce((sum, day) => sum + day.scans, 0);
	return (
		<section className="card" aria-label={t("pg.daily")}>
			<h2>{t("pg.dailyTitle")}</h2>
			<p className="muted small">{t("pg.dailyDesc", { days: windowDays })}</p>
			{summary === null ? (
				<p className="muted">{loaded ? t("pg.unavailableNow") : t("common.loading")}</p>
			) : (
				<>
					<div
						className="privacy-series"
						role="img"
						aria-label={t("pg.seriesLabel", { count: totalScans, days: windowDays })}
					>
						{series.map((day) => (
							<div
								key={day.day}
								className="privacy-series-day"
								title={t("pg.dayTitle", {
									day: day.day,
									scans: day.scans,
									masked: day.masked,
									warned: day.warned,
									blocked: day.blocked,
								})}
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
							<span className="privacy-key privacy-series-masked" /> {t("pg.key.masked")}
						</span>
						<span>
							<span className="privacy-key privacy-series-warned" /> {t("pg.key.warned")}
						</span>
						<span>
							<span className="privacy-key privacy-series-blocked" /> {t("pg.key.blocked")}
						</span>
						<span>
							<span className="privacy-key privacy-series-allowed" /> {t("pg.key.allowed")}
						</span>
					</div>
					<details style={{ marginTop: 10 }}>
						<summary className="small">{t("pg.dailyTable")}</summary>
						<div className="table-wrap">
							<table className="table">
								<thead>
									<tr>
										<th>{t("pg.col.day")}</th>
										<th>{t("pg.col.scans")}</th>
										<th>{t("pg.col.masked")}</th>
										<th>{t("pg.col.warned")}</th>
										<th>{t("pg.col.blocked")}</th>
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

const TOP_SERVICES = 12;

async function readShadowAi(
	tenantId: string,
	windowDays: PrivacyWindow,
	t: Translate,
): Promise<Read<ShadowAiSummary>> {
	const SHADOW_UNAVAILABLE = t("pg.shadowUnavailable");
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
	t: Translate,
): Promise<Read<Map<string, ShadowAiDecisionRow>>> {
	const DECISIONS_UNAVAILABLE = t("pg.decisionsUnavailable");
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
	const t = useT();
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
					<Link to={stepUpPath(tenantId)}>{t("pg.verifyNow")}</Link>
				</>
			) : null}
		</p>
	);
}

/** Register-backed allow/block decisions and the `upsert_asset` action that changes one. */
function useShadowAiDecisions(tenantId: string, refreshTick: number) {
	const t = useT();
	const [decisions, setDecisions] = useState<Read<Map<string, ShadowAiDecisionRow>> | null>(null);
	const [busy, setBusy] = useState<string | null>(null);
	const [notice, setNotice] = useState<DecisionNotice | null>(null);
	const [decisionTick, setDecisionTick] = useState(0);

	useEffect(() => {
		let cancelled = false;
		void readShadowAiDecisions(tenantId, t).then((next) => {
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
							text: t(decision === "allowed" ? "pg.decided.allowed" : "pg.decided.blocked", {
								service: serviceName(serviceId),
							}),
						}
					: {
							tone: "error",
							text: governanceErrorMessage(result.error, t),
							stepUp: result.error === "mfa_required",
						},
			);
		},
		[tenantId, decisions, t],
	);

	return { decisions, busy, notice, decide };
}

async function readBrowserGuardSettings(
	tenantId: string,
	t: Translate,
): Promise<Read<{ requireNativeNer: boolean }>> {
	const NATIVE_NER_UNAVAILABLE = t("pg.nerUnavailable");
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
	const t = useT();
	const richT = useRichT();
	const [read, setRead] = useState<Read<{ requireNativeNer: boolean }> | null>(null);
	const [busy, setBusy] = useState(false);
	const [notice, setNotice] = useState<DecisionNotice | null>(null);
	const [tick, setTick] = useState(0);

	useEffect(() => {
		let cancelled = false;
		void readBrowserGuardSettings(tenantId, t).then((next) => {
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
						text: next ? t("pg.ner.required") : t("pg.ner.notRequired"),
					}
				: {
						tone: "error",
						text: governanceErrorMessage(result.error, t),
						stepUp: result.error === "mfa_required",
					},
		);
	}

	return (
		<section className="card" aria-labelledby="native-ner-heading">
			<div className="panel-head">
				<h2 id="native-ner-heading">{t("pg.ner.title")}</h2>
				{current === null ? null : (
					<span className={current ? "badge badge-deny" : "badge badge-allow"}>
						{current ? t("pg.ner.badgeRequired") : t("pg.ner.badgeNot")}
					</span>
				)}
			</div>
			<p className="muted small">{richT("pg.ner.body", { code: <code>requireNativeNer</code> })}</p>
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
					{t("pg.ner.checkbox")}
				</label>
			) : (
				<p className="muted small">{t("pg.ownersCanChange")}</p>
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
	const t = useT();
	const richT = useRichT();
	const [read, setRead] = useState<Read<ShadowAiSummary> | null>(null);
	const { decisions, busy, notice, decide } = useShadowAiDecisions(tenantId, refreshTick);
	const [policyMode, setPolicyMode] = useState<"monitor" | "block-unsanctioned">("monitor");

	useEffect(() => {
		let cancelled = false;
		const load = async () => {
			const next = await readShadowAi(tenantId, windowDays, t);
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
				<h2 id="shadow-ai-heading">{t("pg.shadow.title")}</h2>
			</div>
			<p className="muted small">{t("pg.shadow.intro")}</p>
			{read && !read.ok ? (
				<p className="muted" role="status">
					{read.error}
				</p>
			) : null}
			<div className="grid" role="group" aria-label={t("pg.shadow.counters")}>
				<div className="card stat-card">
					<div className="stat-label">{t("pg.shadow.visits")}</div>
					<div className="stat-value">{numberText(totals?.visits)}</div>
					<div className="stat-hint">
						{totals
							? t("pg.shadow.servicesHint", {
									count: totals.services.toLocaleString(),
									days: windowDays,
								})
							: "—"}
					</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">{t("pg.shadow.unsanctioned")}</div>
					<div className="stat-value">{numberText(totals?.unsanctionedVisits)}</div>
					<div className="stat-hint">
						{sanctionedShare === null
							? t("pg.shadow.noVisits")
							: t("pg.shadow.share", { percent: sanctionedShare })}
					</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">{t("pg.shadow.blocked")}</div>
					<div className="stat-value">{numberText(totals?.blockedAttempts)}</div>
					<div className="stat-hint">{t("pg.shadow.blockedHint")}</div>
				</div>
			</div>

			<h3 style={{ marginTop: 16 }}>{t("pg.shadow.top")}</h3>
			<p className="muted small">
				{canDecide ? t("pg.shadow.canDecide") : t("pg.shadow.cannotDecide")}
			</p>
			{decisions && !decisions.ok ? (
				<p className="muted" role="status">
					{decisions.error}
				</p>
			) : null}
			{notice ? <DecisionNoticeLine notice={notice} tenantId={tenantId} /> : null}
			{summary === null ? (
				<p className="muted">{read ? t("pg.unavailableNow") : t("common.loading")}</p>
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
				<summary className="small">{t("pg.shadow.configure")}</summary>
				<p className="muted small">
					{richT("pg.shadow.configureBody", {
						telemetry: <code>telemetry</code>,
						dashboardPolicy: <code>dashboardPolicy</code>,
						sanctioned: <code>sanctioned</code>,
						block: <code>block-unsanctioned</code>,
					})}
				</p>
				<div className="row" style={{ alignItems: "center" }}>
					<label className="label" htmlFor="shadow-ai-mode">
						{t("pg.shadow.mode")}
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
						<option value="monitor">{t("pg.shadow.monitor")}</option>
						<option value="block-unsanctioned">{t("pg.shadow.blockUnsanctioned")}</option>
					</select>
				</div>
				<pre className="mono small" aria-label={t("pg.shadow.json")} style={{ overflowX: "auto" }}>
					{snippet}
				</pre>
			</details>
		</section>
	);
}

function DecisionBadge({ row }: { row: ShadowAiDecisionRow | undefined }) {
	const t = useT();
	if (!row?.decision) return <span className="muted">—</span>;
	return (
		<span className={row.decision === "allowed" ? "badge badge-allow" : "badge badge-deny"}>
			{row.decision === "allowed" ? t("pg.decision.allowed") : t("pg.decision.blocked")}
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
	const t = useT();
	const richT = useRichT();
	const services = summary.byService.slice(0, TOP_SERVICES);
	if (services.length === 0) {
		return <p className="muted">{richT("pg.shadow.none", { key: <code>shadowAi</code> })}</p>;
	}
	const max = Math.max(1, ...services.map((row) => row.visits + row.blocked));
	return (
		<div className="table-wrap">
			<table className="table" aria-label={t("pg.shadow.top")}>
				<thead>
					<tr>
						<th>{t("pg.col.service")}</th>
						<th>{t("pg.col.category")}</th>
						<th>{t("common.status")}</th>
						<th>{t("pg.col.visits")}</th>
						<th>{t("pg.col.blocked")}</th>
						<th aria-hidden="true" />
						<th>{t("pg.col.decision")}</th>
						{canDecide ? <th>{t("pg.col.change")}</th> : null}
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
								<td>{categoryLabel(row.category, t)}</td>
								<td>
									<span className={row.sanctioned ? "badge badge-allow" : "badge badge-ask"}>
										{row.sanctioned ? t("pg.sanctioned") : t("pg.unsanctioned")}
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
								<td>{decisions && decidable ? <DecisionBadge row={current} /> : "—"}</td>
								{canDecide ? (
									<td>
										{decidable ? (
											<div className="row" style={{ gap: 4, flexWrap: "nowrap" }}>
												<button
													type="button"
													className="btn btn-sm"
													aria-label={t("pg.allowLabel", { name })}
													disabled={busy !== null || current?.decision === "allowed"}
													onClick={() => onDecide(row.serviceId, "allowed")}
												>
													{t("pg.allow")}
												</button>
												<button
													type="button"
													className="btn btn-sm btn-danger"
													aria-label={t("pg.blockLabel", { name })}
													disabled={busy !== null || current?.decision === "blocked"}
													onClick={() => onDecide(row.serviceId, "blocked")}
												>
													{t("pg.block")}
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
	const t = useT();
	const { series, totals, windowDays } = summary;
	const max = Math.max(1, ...series.map((day) => day.visits + day.blocked));
	return (
		<>
			<h3 style={{ marginTop: 16 }}>{t("pg.trend")}</h3>
			<div
				className="privacy-series"
				role="img"
				aria-label={t("pg.trendLabel", {
					visits: totals.visits,
					blocked: totals.blockedAttempts,
					days: windowDays,
				})}
			>
				{series.map((day) => (
					<div
						key={day.day}
						className="privacy-series-day"
						title={t("pg.trendDay", {
							day: day.day,
							visits: day.visits,
							unsanctioned: day.unsanctionedVisits,
							blocked: day.blocked,
						})}
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
					<span className="privacy-key privacy-series-masked" /> {t("pg.key.sanctionedVisits")}
				</span>
				<span>
					<span className="privacy-key privacy-series-warned" /> {t("pg.key.unsanctionedVisits")}
				</span>
				<span>
					<span className="privacy-key privacy-series-blocked" /> {t("pg.key.blocked")}
				</span>
			</div>
		</>
	);
}

function EnrollBrowsersPanel() {
	const t = useT();
	const richT = useRichT();
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
		() => (noticeOn ? acceptableUseNotice(notice, t) : null),
		[noticeOn, notice, t],
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
			<h2 id="enroll-browsers-heading">{t("pg.enroll.title")}</h2>
			<p className="muted small">{t("pg.enroll.intro")}</p>
			<ol className="stack" style={{ paddingLeft: 20 }}>
				<li>
					<b>{t("pg.enroll.step1Title")}</b> {t("pg.enroll.step1")}
				</li>
				<li>
					<b>{t("pg.enroll.step2Title")}</b>{" "}
					{richT("pg.enroll.step2", {
						link: <Link to="/api-keys?type=browser_guard">{t("nav.apiKeys")}</Link>,
						option: <i>{t("keys.option.bg")}</i>,
					})}
				</li>
				<li>
					<b>{t("pg.enroll.step3Title")}</b> {t("pg.enroll.step3")}
				</li>
			</ol>
			<div className="row" style={{ alignItems: "center", marginTop: 8 }}>
				<label className="label" htmlFor="privacy-guard-mode">
					{t("pg.enroll.mode")}
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
							{t(option.label)}
						</option>
					))}
				</select>
				<span className="muted small">
					{t(GUARD_MODES.find((option) => option.value === mode)?.hint ?? "pg.mode.autoHint")}
				</span>
			</div>
			<fieldset className="stack" style={{ border: 0, padding: 0, marginTop: 12 }}>
				<legend>
					<b>{t("pg.aup.legend")}</b> <span className="muted small">{t("pg.aup.optional")}</span>
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
					{t("pg.aup.checkbox")}
				</label>
				<p className="muted small">{t("pg.aup.body")}</p>
				{noticeOn ? (
					<>
						<div className="row" style={{ flexWrap: "wrap", gap: 12 }}>
							<label className="label">
								{t("pg.aup.id")}
								<input
									className="input"
									value={notice.id}
									onChange={(e) => editNotice("id")(e.target.value)}
								/>
							</label>
							<label className="label">
								{t("pg.aup.version")}
								<input
									className="input"
									type="number"
									min={1}
									value={notice.version}
									onChange={(e) => editNotice("version")(e.target.value)}
								/>
							</label>
							<label className="label">
								{t("pg.aup.url")}
								<input
									className="input"
									value={notice.url}
									onChange={(e) => editNotice("url")(e.target.value)}
								/>
							</label>
						</div>
						<label className="label">
							{t("pg.aup.title")}
							<input
								className="input"
								maxLength={120}
								value={notice.title}
								onChange={(e) => editNotice("title")(e.target.value)}
							/>
						</label>
						<label className="label">
							{t("pg.aup.text")}
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
								{noticeResult.error} {t("pg.aup.leftOut")}
							</div>
						) : null}
					</>
				) : null}
			</fieldset>
			<pre className="mono small" aria-label={t("pg.policyJson")} style={{ overflowX: "auto" }}>
				{snippet}
			</pre>
			<div className="row" style={{ alignItems: "center" }}>
				<button className="button button-secondary button-sm" type="button" onClick={copy}>
					{t("pg.copyJson")}
				</button>
				<span className="muted small" role="status">
					{copyState === "copied"
						? t("pg.copied")
						: copyState === "failed"
							? t("pg.copyFailed")
							: ""}
				</span>
			</div>
		</section>
	);
}
