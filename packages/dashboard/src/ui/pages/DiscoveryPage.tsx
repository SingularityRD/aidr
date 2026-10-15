import { useCallback, useEffect, useRef, useState } from "react";
import { useTeam } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import { type Translate, useRichT, useT } from "../../i18n/I18nProvider";
import { readErrorMessage } from "../../lib/errors";
import { supabase } from "../../lib/supabase";

type CoverageState = "current" | "attention" | "unknown";
type CollectorState = "current" | "partial" | "stale";
type Freshness = "fresh" | "stale" | "never_seen";
type AlertState =
	| "healthy"
	| "unreachable"
	| "stale"
	| "never_seen"
	| "not_reported"
	| "collection_partial";

type DiscoverySummary = {
	collector_count: number;
	partial_collector_count: number;
	stale_collector_count: number;
	observation_count: number;
	unreachable_count: number;
	never_seen_count: number;
	stale_observation_count: number;
	not_reported_count: number;
	coverage_scope: "reported_collectors_only";
	reported_scope_state: CoverageState;
};

type Collector = {
	collector_id: string;
	sequence: number;
	stale_after_ms: number;
	complete: boolean;
	expected_targets: number;
	observed_targets: number;
	reported_at: string;
	state: CollectorState;
	provider_evidence?: {
		provider: string;
		scope_hash: string;
		coverage: string;
		complete: boolean;
		observed_at: string;
	} | null;
};

type ProviderResource = {
	provider: string;
	scope_hash: string;
	resource_id: string;
	resource_type: string;
	scope_id: string;
	region: string | null;
	observed_at: string;
	freshness: Freshness;
	alert_state: AlertState;
};
type ResourcePage = {
	resources: ProviderResource[];
	truncated: boolean;
	next_resource: string | null;
};

type DiscoveryItem = {
	target: string;
	last_reported_at: string;
	last_reachable_at: string | null;
	reachable: boolean;
	attempts: number;
	error_code: string | null;
	freshness: Freshness;
	alert_state: AlertState;
};

type CollectorPage = { collectors: Collector[]; truncated: boolean; next_collector: string | null };
type ItemPage = { items: DiscoveryItem[]; truncated: boolean; next_target: string | null };

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isCount(value: unknown): value is number {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isCollectorId(value: unknown): value is string {
	return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value);
}

function isTimestamp(value: unknown): value is string {
	return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function isProviderEvidence(value: unknown): boolean {
	const coverage: Record<string, string> = {
		aws: "tagged_resources",
		azure: "resource_groups",
		gcp: "project_asset_types",
		intune: "managed_devices",
	};
	return (
		isRecord(value) &&
		Object.hasOwn(coverage, String(value.provider)) &&
		value.coverage === coverage[String(value.provider)] &&
		typeof value.scope_hash === "string" &&
		/^[a-f0-9]{64}$/.test(value.scope_hash) &&
		typeof value.complete === "boolean" &&
		isTimestamp(value.observed_at)
	);
}

function isDiscoverySummary(value: unknown): value is DiscoverySummary {
	return (
		isRecord(value) &&
		isCount(value.collector_count) &&
		isCount(value.partial_collector_count) &&
		isCount(value.stale_collector_count) &&
		isCount(value.observation_count) &&
		isCount(value.unreachable_count) &&
		isCount(value.never_seen_count) &&
		isCount(value.stale_observation_count) &&
		isCount(value.not_reported_count) &&
		value.coverage_scope === "reported_collectors_only" &&
		(value.reported_scope_state === "current" ||
			value.reported_scope_state === "attention" ||
			value.reported_scope_state === "unknown")
	);
}

function isCollector(value: unknown): value is Collector {
	return (
		isRecord(value) &&
		isCollectorId(value.collector_id) &&
		isCount(value.sequence) &&
		value.sequence > 0 &&
		Number.isSafeInteger(value.stale_after_ms) &&
		(value.stale_after_ms as number) >= 60_000 &&
		(value.stale_after_ms as number) <= 2_592_000_000 &&
		typeof value.complete === "boolean" &&
		isCount(value.expected_targets) &&
		(value.expected_targets as number) >= (value.provider_evidence ? 0 : 1) &&
		(value.expected_targets as number) <= 100 &&
		isCount(value.observed_targets) &&
		(value.observed_targets as number) <= (value.expected_targets as number) &&
		isTimestamp(value.reported_at) &&
		(value.provider_evidence === undefined ||
			value.provider_evidence === null ||
			isProviderEvidence(value.provider_evidence)) &&
		(value.state === "current" || value.state === "partial" || value.state === "stale")
	);
}

function isOrigin(value: unknown): value is string {
	if (typeof value !== "string") return false;
	try {
		const url = new URL(value);
		return (
			(url.protocol === "http:" || url.protocol === "https:") &&
			!url.username &&
			!url.password &&
			!url.search &&
			!url.hash &&
			url.pathname === "/" &&
			`${url.origin}/` === value
		);
	} catch {
		return false;
	}
}

/**
 * Collectors report each target as a keyed, tenant-scoped pseudonym; the HMAC
 * key and the address stay on the collector.
 */
function isTargetId(value: unknown): value is string {
	return typeof value === "string" && /^tid1_[a-f0-9]{64}$/.test(value);
}

/** Pseudonyms, plus origin rows stored before pseudonymisation (read-only legacy). */
function isReportedTarget(value: unknown): value is string {
	return isTargetId(value) || isOrigin(value);
}

function isDiscoveryItem(value: unknown): value is DiscoveryItem {
	const errorCodes = [
		"timeout",
		"unreachable",
		"target_not_allowed",
		"invalid_target_url",
		"collector_exception",
		"other",
	];
	return (
		isRecord(value) &&
		isReportedTarget(value.target) &&
		isTimestamp(value.last_reported_at) &&
		(value.last_reachable_at === null || isTimestamp(value.last_reachable_at)) &&
		typeof value.reachable === "boolean" &&
		isCount(value.attempts) &&
		(value.attempts as number) >= 1 &&
		(value.attempts as number) <= 5 &&
		(value.reachable
			? value.error_code === null
			: typeof value.error_code === "string" && errorCodes.includes(value.error_code)) &&
		(value.freshness === "fresh" ||
			value.freshness === "stale" ||
			value.freshness === "never_seen") &&
		(value.alert_state === "healthy" ||
			value.alert_state === "unreachable" ||
			value.alert_state === "stale" ||
			value.alert_state === "never_seen" ||
			value.alert_state === "not_reported" ||
			value.alert_state === "collection_partial")
	);
}

async function invokeDiscovery(
	tenantId: string,
	body: Record<string, unknown>,
): Promise<Record<string, unknown>> {
	const { data, error } = await supabase.functions.invoke("discovery", {
		body: { ...body, tenant_id: tenantId },
	});
	if (error) throw new Error(readErrorMessage(error, "Discovery data is unavailable."));
	if (!isRecord(data) || data.ok !== true) throw new Error("Malformed discovery response.");
	return data;
}

async function loadSummary(tenantId: string): Promise<DiscoverySummary> {
	const data = await invokeDiscovery(tenantId, { action: "summary" });
	if (!isDiscoverySummary(data.summary)) throw new Error("Malformed discovery summary.");
	return data.summary;
}

async function loadCollectors(tenantId: string, afterCollector?: string): Promise<CollectorPage> {
	const data = await invokeDiscovery(tenantId, {
		action: "list",
		limit: 50,
		...(afterCollector ? { after_collector: afterCollector } : {}),
	});
	if (
		data.coverage_scope !== "reported_collectors_only" ||
		!Array.isArray(data.collectors) ||
		!data.collectors.every(isCollector) ||
		typeof data.truncated !== "boolean" ||
		(data.next_collector !== null && !isCollectorId(data.next_collector))
	) {
		throw new Error("Malformed discovery collector list.");
	}
	return {
		collectors: data.collectors,
		truncated: data.truncated,
		next_collector: data.next_collector,
	};
}

async function loadItems(
	tenantId: string,
	collectorId: string,
	afterTarget?: string,
): Promise<ItemPage> {
	const data = await invokeDiscovery(tenantId, {
		action: "read",
		collector_id: collectorId,
		limit: 100,
		...(afterTarget ? { after_target: afterTarget } : {}),
	});
	if (
		data.collector === null ||
		!isRecord(data.collector) ||
		data.collector.collector_id !== collectorId ||
		!Array.isArray(data.items) ||
		!data.items.every(isDiscoveryItem) ||
		typeof data.truncated !== "boolean" ||
		(data.next_target !== null && !isReportedTarget(data.next_target))
	) {
		throw new Error("Malformed discovery target list.");
	}
	return { items: data.items, truncated: data.truncated, next_target: data.next_target };
}

function isResourceId(value: unknown): value is string {
	return (
		typeof value === "string" &&
		value.length > 0 &&
		value.length <= 1024 &&
		!/[\u0000-\u001f\u007f]/.test(value)
	);
}
async function loadResources(
	tenantId: string,
	collectorId: string,
	sequence: number,
	afterResource?: string,
): Promise<ResourcePage> {
	const data = await invokeDiscovery(tenantId, {
		action: "resources",
		collector_id: collectorId,
		expected_sequence: sequence,
		limit: 100,
		...(afterResource ? { after_resource: afterResource } : {}),
	});
	if (
		!isRecord(data.collector) ||
		data.collector.collector_id !== collectorId ||
		!Array.isArray(data.provider_resources) ||
		!data.provider_resources.every(
			(r) =>
				isRecord(r) &&
				["aws", "azure", "gcp", "intune"].includes(String(r.provider)) &&
				typeof r.scope_hash === "string" &&
				/^[a-f0-9]{64}$/.test(r.scope_hash) &&
				isResourceId(r.resource_id) &&
				typeof r.resource_type === "string" &&
				r.resource_type.length > 0 &&
				r.resource_type.length <= 256 &&
				typeof r.scope_id === "string" &&
				r.scope_id.length > 0 &&
				r.scope_id.length <= 256 &&
				(r.region === null || (typeof r.region === "string" && r.region.length <= 64)) &&
				isTimestamp(r.observed_at) &&
				["fresh", "stale", "never_seen"].includes(String(r.freshness)) &&
				["healthy", "stale", "not_reported", "collection_partial"].includes(String(r.alert_state)),
		) ||
		typeof data.truncated !== "boolean" ||
		(data.next_resource !== null && !isResourceId(data.next_resource))
	)
		throw new Error("Malformed provider resource list.");
	return {
		resources: data.provider_resources as ProviderResource[],
		truncated: data.truncated,
		next_resource: data.next_resource as string | null,
	};
}

function badgeClass(state: string): string {
	if (state === "current" || state === "healthy" || state === "fresh") return "badge badge-success";
	return state === "unknown" ? "badge badge-neutral" : "badge badge-warning";
}

const STATE_LABELS: Record<string, DashboardMessageKey> = {
	current: "disc.state.current",
	attention: "disc.state.attention",
	unknown: "disc.state.unknown",
	partial: "disc.state.partial",
	stale: "disc.state.stale",
	fresh: "disc.state.fresh",
	never_seen: "disc.state.neverSeen",
	healthy: "disc.state.healthy",
	unreachable: "disc.state.unreachable",
	not_reported: "disc.state.notReported",
	collection_partial: "disc.state.collectionPartial",
};

/** A state word in the current language; unknown values are shown as sent. */
function stateLabel(state: string, t: Translate): string {
	const key = STATE_LABELS[state];
	return key ? t(key) : state;
}

function timestamp(value: string | null, t: Translate): string {
	return value ? new Date(value).toLocaleString() : t("disc.never");
}

export function DiscoveryPage() {
	const { currentTeam } = useTeam();
	const t = useT();
	const richT = useRichT();
	const tenantId = currentTeam?.id ?? null;
	const [summary, setSummary] = useState<DiscoverySummary | null>(null);
	const [collectors, setCollectors] = useState<Collector[]>([]);
	const [collectorCursor, setCollectorCursor] = useState<string | null>(null);
	const [collectorsTruncated, setCollectorsTruncated] = useState(false);
	const [selectedCollector, setSelectedCollector] = useState<string | null>(null);
	const [items, setItems] = useState<DiscoveryItem[] | null>(null);
	const [itemCursor, setItemCursor] = useState<string | null>(null);
	const [itemsTruncated, setItemsTruncated] = useState(false);
	const [overviewError, setOverviewError] = useState<string | null>(null);
	const [itemsError, setItemsError] = useState<string | null>(null);
	const [loadingMoreCollectors, setLoadingMoreCollectors] = useState(false);
	const [loadingMoreItems, setLoadingMoreItems] = useState(false);
	const [refreshVersion, setRefreshVersion] = useState(0);
	const [itemsCheckedAt, setItemsCheckedAt] = useState<string | null>(null);
	const [resources, setResources] = useState<ProviderResource[]>([]);
	const [resourceCursor, setResourceCursor] = useState<string | null>(null);
	const [resourceError, setResourceError] = useState<string | null>(null);
	const [resourcesLoading, setResourcesLoading] = useState(false);
	const [loadingMoreResources, setLoadingMoreResources] = useState(false);
	const selectedCollectorRow = collectors.find(
		(collector) => collector.collector_id === selectedCollector,
	);
	const selectedProvider = selectedCollectorRow?.provider_evidence;
	const selectedSequence = selectedCollectorRow?.sequence;
	const resourceScope = useRef("");
	resourceScope.current = `${tenantId}:${selectedCollector}:${selectedSequence}:${selectedProvider?.scope_hash ?? ""}`;

	useEffect(() => {
		let cancelled = false;
		setResources([]);
		setResourceCursor(null);
		setResourceError(null);
		setLoadingMoreResources(false);
		setResourcesLoading(
			Boolean(tenantId && selectedCollector && selectedProvider && selectedSequence),
		);
		if (tenantId && selectedCollector && selectedProvider && selectedSequence)
			void loadResources(tenantId, selectedCollector, selectedSequence)
				.then((page) => {
					if (!cancelled) {
						setResources(page.resources);
						setResourceCursor(page.next_resource);
					}
				})
				.catch((error: unknown) => {
					if (!cancelled) setResourceError(readErrorMessage(error, t("disc.resourcesUnavailable")));
				})
				.finally(() => {
					if (!cancelled) setResourcesLoading(false);
				});
		return () => {
			cancelled = true;
		};
	}, [tenantId, selectedCollector, selectedProvider, selectedSequence, refreshVersion]);
	const loadMoreResources = async () => {
		if (
			!tenantId ||
			!selectedCollector ||
			!selectedSequence ||
			!resourceCursor ||
			loadingMoreResources
		)
			return;
		const scope = resourceScope.current;
		setLoadingMoreResources(true);
		try {
			const page = await loadResources(
				tenantId,
				selectedCollector,
				selectedSequence,
				resourceCursor,
			);
			if (scope === resourceScope.current) {
				setResources((rows) => [...rows, ...page.resources]);
				setResourceCursor(page.next_resource);
			}
		} catch (error) {
			if (scope === resourceScope.current)
				setResourceError(readErrorMessage(error, t("disc.resourcesUnavailable")));
		} finally {
			if (scope === resourceScope.current) setLoadingMoreResources(false);
		}
	};

	useEffect(() => {
		let cancelled = false;
		setSummary(null);
		setCollectors([]);
		setCollectorCursor(null);
		setCollectorsTruncated(false);
		setSelectedCollector(null);
		setItems(null);
		setItemCursor(null);
		setItemsTruncated(false);
		setOverviewError(null);
		setItemsError(null);
		setItemsCheckedAt(null);
		if (!tenantId)
			return () => {
				cancelled = true;
			};

		async function load() {
			try {
				const [nextSummary, nextCollectors] = await Promise.all([
					loadSummary(tenantId as string),
					loadCollectors(tenantId as string),
				]);
				if (cancelled) return;
				setSummary(nextSummary);
				setCollectors(nextCollectors.collectors);
				setCollectorCursor(nextCollectors.next_collector);
				setCollectorsTruncated(nextCollectors.truncated);
				setOverviewError(null);
				setSelectedCollector((current) =>
					current &&
					nextCollectors.collectors.some((collector) => collector.collector_id === current)
						? current
						: (nextCollectors.collectors[0]?.collector_id ?? null),
				);
			} catch (cause) {
				if (!cancelled) {
					setSummary(null);
					setCollectors([]);
					setOverviewError(readErrorMessage(cause, t("disc.unavailable")));
				}
			}
		}
		void load();
		return () => {
			cancelled = true;
		};
	}, [tenantId, refreshVersion]);

	useEffect(() => {
		let cancelled = false;
		setItems(null);
		setItemCursor(null);
		setItemsTruncated(false);
		setItemsError(null);
		setItemsCheckedAt(null);
		if (!tenantId || !selectedCollector)
			return () => {
				cancelled = true;
			};
		void loadItems(tenantId, selectedCollector)
			.then((page) => {
				if (cancelled) return;
				setItems(page.items);
				setItemCursor(page.next_target);
				setItemsTruncated(page.truncated);
				setItemsCheckedAt(new Date().toISOString());
			})
			.catch((cause: unknown) => {
				if (!cancelled) {
					setItems(null);
					setItemsError(readErrorMessage(cause, t("disc.targetsUnavailable")));
				}
			});
		return () => {
			cancelled = true;
		};
	}, [tenantId, selectedCollector, refreshVersion]);

	const loadMoreCollectors = useCallback(async () => {
		if (!tenantId || !collectorCursor || loadingMoreCollectors) return;
		setLoadingMoreCollectors(true);
		try {
			const page = await loadCollectors(tenantId, collectorCursor);
			setCollectors((current) => [...current, ...page.collectors]);
			setCollectorCursor(page.next_collector);
			setCollectorsTruncated(page.truncated);
		} catch (cause) {
			setOverviewError(readErrorMessage(cause, t("disc.moreCollectors")));
		} finally {
			setLoadingMoreCollectors(false);
		}
	}, [tenantId, collectorCursor, loadingMoreCollectors]);

	const loadMoreItems = useCallback(async () => {
		if (!tenantId || !selectedCollector || !itemCursor || loadingMoreItems) return;
		setLoadingMoreItems(true);
		try {
			const page = await loadItems(tenantId, selectedCollector, itemCursor);
			setItems((current) => (current ? [...current, ...page.items] : page.items));
			setItemCursor(page.next_target);
			setItemsTruncated(page.truncated);
			setItemsCheckedAt(new Date().toISOString());
		} catch (cause) {
			setItemsError(readErrorMessage(cause, t("disc.moreTargets")));
		} finally {
			setLoadingMoreItems(false);
		}
	}, [tenantId, selectedCollector, itemCursor, loadingMoreItems]);

	return (
		<div className="stack">
			<section className="card">
				<div className="row space-between" style={{ alignItems: "flex-start", gap: 16 }}>
					<div>
						<p className="eyebrow">{t("disc.eyebrow")}</p>
						<h1>{t("nav.discovery")}</h1>
						<p className="muted">{currentTeam?.name ?? t("disc.noTeam")}</p>
					</div>
					<button
						className="button button-secondary button-sm"
						type="button"
						onClick={() => setRefreshVersion((value) => value + 1)}
					>
						{t("common.refresh")}
					</button>
				</div>
				<div className="notice notice-warning" role="note" style={{ marginTop: 12 }}>
					{t("disc.scopeNote")}
				</div>
				{overviewError ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{overviewError}
					</div>
				) : null}
				{summary ? (
					<>
						<div className="row" style={{ marginTop: 12 }}>
							<span className={badgeClass(summary.reported_scope_state)}>
								{stateLabel(summary.reported_scope_state, t)}
							</span>
							<span className="badge badge-neutral">
								{t("disc.scope", { scope: summary.coverage_scope })}
							</span>
						</div>
						<section className="grid" aria-label={t("disc.summary")} style={{ marginTop: 12 }}>
							<div className="card stat-card">
								<div className="stat-label">{t("disc.collectors")}</div>
								<div className="stat-value">{summary.collector_count}</div>
							</div>
							<div className="card stat-card">
								<div className="stat-label">{t("disc.targets")}</div>
								<div className="stat-value">{summary.observation_count}</div>
							</div>
							<div className="card stat-card">
								<div className="stat-label">{t("disc.stale")}</div>
								<div className="stat-value">
									{summary.stale_collector_count} / {summary.stale_observation_count}
								</div>
							</div>
							<div className="card stat-card">
								<div className="stat-label">{t("disc.unreachable")}</div>
								<div className="stat-value">
									{summary.unreachable_count} / {summary.never_seen_count}
								</div>
							</div>
							<div className="card stat-card">
								<div className="stat-label">{t("disc.partial")}</div>
								<div className="stat-value">
									{summary.partial_collector_count} / {summary.not_reported_count}
								</div>
							</div>
						</section>
					</>
				) : (
					<p className="muted" role="status">
						{overviewError ? t("disc.summaryUnavailable") : t("disc.summaryLoading")}
					</p>
				)}
			</section>

			<section className="card">
				<div className="panel-head">
					<h2>{t("disc.collectors")}</h2>
				</div>
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>{t("disc.col.collector")}</th>
								<th>{t("disc.col.state")}</th>
								<th>{t("disc.col.reported")}</th>
								<th>{t("disc.col.targets")}</th>
							</tr>
						</thead>
						<tbody>
							{collectors.map((collector) => (
								<tr key={collector.collector_id}>
									<td>
										<button
											className="button button-secondary button-sm mono"
											type="button"
											onClick={() => setSelectedCollector(collector.collector_id)}
											aria-pressed={selectedCollector === collector.collector_id}
										>
											{collector.collector_id}
										</button>
									</td>
									<td>
										<span className={badgeClass(collector.state)}>
											{stateLabel(collector.state, t)}
										</span>
									</td>
									<td className="mono">{timestamp(collector.reported_at, t)}</td>
									<td>
										{collector.observed_targets} / {collector.expected_targets}
										{collector.complete ? "" : t("disc.partialSuffix")}
									</td>
								</tr>
							))}
							{collectors.length === 0 ? (
								<tr>
									<td colSpan={4} className="muted">
										{summary ? t("disc.noCollectors") : t("disc.collectorsUnavailable")}
									</td>
								</tr>
							) : null}
						</tbody>
					</table>
				</div>
				{collectorsTruncated && collectorCursor ? (
					<button
						className="button button-secondary button-sm"
						type="button"
						onClick={() => void loadMoreCollectors()}
						disabled={loadingMoreCollectors}
					>
						{loadingMoreCollectors ? t("common.loading") : t("disc.loadMoreCollectors")}
					</button>
				) : null}
			</section>

			<section className="card">
				<div className="panel-head">
					<h2>{t("disc.freshness")}</h2>
					{selectedCollector ? <span className="muted small">{selectedCollector}</span> : null}
				</div>
				<p className="muted small">
					{richT("disc.pseudonyms", {
						field: <code>panel_id</code>,
						command: <code>aidr collect</code>,
					})}
				</p>
				{itemsCheckedAt ? (
					<p className="muted small">{t("disc.checked", { time: timestamp(itemsCheckedAt, t) })}</p>
				) : null}
				{itemsError ? (
					<div className="notice notice-danger" role="alert">
						{itemsError}
					</div>
				) : null}
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>{t("disc.col.target")}</th>
								<th>{t("disc.col.reachability")}</th>
								<th>{t("disc.col.freshness")}</th>
								<th>{t("disc.col.alert")}</th>
								<th>{t("disc.col.lastReachable")}</th>
							</tr>
						</thead>
						<tbody>
							{(items ?? []).map((item) => (
								<tr key={item.target}>
									<td className="mono">
										{isTargetId(item.target) ? (
											<span title={t("disc.pseudonymTitle")}>{item.target}</span>
										) : (
											<>
												{item.target}{" "}
												<span className={badgeClass("stale")}>{t("disc.legacy")}</span>
											</>
										)}
									</td>
									<td>
										<span className={badgeClass(item.reachable ? "healthy" : "unreachable")}>
											{item.reachable
												? t("disc.reachable")
												: (item.error_code ?? t("disc.state.unreachable"))}
										</span>
									</td>
									<td>
										<span className={badgeClass(item.freshness)}>
											{stateLabel(item.freshness, t)}
										</span>
									</td>
									<td>
										<span className={badgeClass(item.alert_state)}>
											{stateLabel(item.alert_state, t)}
										</span>
									</td>
									<td className="mono">{timestamp(item.last_reachable_at, t)}</td>
								</tr>
							))}
							{items === null || items.length === 0 ? (
								<tr>
									<td colSpan={5} className="muted">
										{itemsError
											? t("disc.targetUnavailable")
											: selectedCollector
												? t("disc.targetLoading")
												: t("disc.selectCollector")}
									</td>
								</tr>
							) : null}
						</tbody>
					</table>
				</div>
				{itemsTruncated && itemCursor ? (
					<button
						className="button button-secondary button-sm"
						type="button"
						onClick={() => void loadMoreItems()}
						disabled={loadingMoreItems}
					>
						{loadingMoreItems ? t("common.loading") : t("disc.loadMoreTargets")}
					</button>
				) : null}
			</section>
			{selectedProvider ? (
				<section className="card">
					<h2>{t("disc.provider")}</h2>
					<p className="muted">
						{t("disc.providerLine", {
							provider: selectedProvider.provider,
							coverage: selectedProvider.coverage,
							time: timestamp(selectedProvider.observed_at, t),
						})}
					</p>
					{resourceError ? (
						<div className="notice notice-danger" role="alert">
							{resourceError}
						</div>
					) : null}
					<div className="table-wrap">
						<table className="table">
							<thead>
								<tr>
									<th>{t("disc.col.resource")}</th>
									<th>{t("disc.col.type")}</th>
									<th>{t("disc.col.region")}</th>
									<th>{t("disc.col.freshness")}</th>
									<th>{t("disc.col.alert")}</th>
								</tr>
							</thead>
							<tbody>
								{resources.map((resource) => (
									<tr key={resource.resource_id}>
										<td className="mono">{resource.resource_id}</td>
										<td>
											{resource.resource_type}
											<br />
											{resource.scope_id}
										</td>
										<td>{resource.region ?? "—"}</td>
										<td>
											<span className={badgeClass(resource.freshness)}>
												{stateLabel(resource.freshness, t)}
											</span>
										</td>
										<td>
											<span className={badgeClass(resource.alert_state)}>
												{stateLabel(resource.alert_state, t)}
											</span>
										</td>
									</tr>
								))}
								{!resources.length ? (
									<tr>
										<td colSpan={5}>
											{resourcesLoading
												? t("disc.resourcesLoading")
												: resourceError
													? t("disc.resourceEvidenceUnavailable")
													: selectedProvider.complete
														? t("disc.noResources")
														: t("disc.partialProvider")}
										</td>
									</tr>
								) : null}
							</tbody>
						</table>
					</div>
					{resourceCursor ? (
						<button
							className="button button-secondary button-sm"
							type="button"
							disabled={loadingMoreResources}
							onClick={() => void loadMoreResources()}
						>
							{loadingMoreResources ? t("common.loading") : t("disc.loadMoreResources")}
						</button>
					) : null}
				</section>
			) : null}
		</div>
	);
}
