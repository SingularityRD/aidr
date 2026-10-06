type DiscoveryItem = {
	target: string;
	reachable: boolean;
	attempts: number;
	error_code: string | null;
};

type ProviderScope = { provider: "aws" | "azure" | "gcp" | "intune"; scope_hash: string };
type ProviderResources = ProviderScope & {
	coverage: "tagged_resources" | "resource_groups" | "project_asset_types" | "managed_devices";
	complete: boolean;
	observed_at: string;
	items: { resource_id: string; resource_type: string; scope_id: string; region: string | null; observed_at: string }[];
};

export type DiscoveryIngest = {
	action: "ingest";
	tenant_id: string;
	collector_id: string;
	cycle_id: string;
	sequence: number;
	stale_after_ms: number;
	complete: boolean;
	expected_targets: number;
	items: DiscoveryItem[];
	provider_resources?: ProviderResources;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const COLLECTOR = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ERROR_CODE = /^(timeout|unreachable|target_not_allowed|invalid_target_url|collector_exception|other)$/;

function record(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
	return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

const PROVIDER_COVERAGE = { aws: "tagged_resources", azure: "resource_groups", gcp: "project_asset_types", intune: "managed_devices" } as const;
function metadata(value: unknown, max: number): value is string {
	return typeof value === "string" && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
}
function observationTime(value: unknown): value is string {
	return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value) && Number.isFinite(Date.parse(value)) && Date.parse(value) <= Date.now() + 300_000;
}
export function parseProviderScope(value: unknown): ProviderScope | null {
	if (!record(value) || !exactKeys(value, ["provider", "scope_hash"]) || !Object.hasOwn(PROVIDER_COVERAGE, String(value.provider))
		|| typeof value.scope_hash !== "string" || !/^[a-f0-9]{64}$/.test(value.scope_hash)) return null;
	return { provider: value.provider as ProviderScope["provider"], scope_hash: value.scope_hash };
}
function parseProviderResources(value: unknown): ProviderResources | null {
	if (!record(value) || !exactKeys(value, ["provider", "scope_hash", "coverage", "complete", "observed_at", "items"])) return null;
	const scope = parseProviderScope({ provider: value.provider, scope_hash: value.scope_hash });
	if (!scope || value.coverage !== PROVIDER_COVERAGE[scope.provider] || typeof value.complete !== "boolean" || !observationTime(value.observed_at)
		|| !Array.isArray(value.items) || value.items.length > 1000) return null;
	const seen = new Set<string>();
	for (const item of value.items) {
		if (!record(item) || !exactKeys(item, ["resource_id", "resource_type", "scope_id", "region", "observed_at"])
			|| !metadata(item.resource_id, 1024) || !metadata(item.resource_type, 256) || !metadata(item.scope_id, 256)
			|| (item.region !== null && !metadata(item.region, 64)) || !observationTime(item.observed_at)
			|| Date.parse(item.observed_at) > Date.parse(value.observed_at) || seen.has(item.resource_id)) return null;
		seen.add(item.resource_id);
	}
	return { ...scope, coverage: value.coverage as ProviderResources["coverage"], complete: value.complete,
		observed_at: value.observed_at, items: value.items as ProviderResources["items"] };
}

export function validUuid(value: unknown): value is string {
	return typeof value === "string" && UUID.test(value);
}

export function validCollectorId(value: unknown): value is string {
	return typeof value === "string" && COLLECTOR.test(value);
}

/** Central inventory records origins only; paths can carry tenant secrets. */
export function canonicalDiscoveryOrigin(value: unknown): string | null {
	if (typeof value !== "string" || value.length < 8 || value.length > 512 || /[\u0000-\u001f\u007f]/.test(value)) return null;
	try {
		const url = new URL(value);
		if (url.protocol !== "http:" && url.protocol !== "https:") return null;
		if (url.username || url.password || url.search || url.hash || url.pathname !== "/") return null;
		return `${url.origin}/`;
	} catch {
		return null;
	}
}

export function parseDiscoveryIngest(value: unknown): DiscoveryIngest | null {
	if (!record(value)) return null;
	const keys = ["action", "tenant_id", "collector_id", "cycle_id", "sequence", "stale_after_ms", "complete", "expected_targets", "items"];
	if (!exactKeys(value, Object.hasOwn(value, "provider_resources") ? [...keys, "provider_resources"] : keys)) return null;
	const provider = Object.hasOwn(value, "provider_resources") ? parseProviderResources(value.provider_resources) : undefined;
	if (provider === null) return null;
	if (value.action !== "ingest" || !validUuid(value.tenant_id) || !validCollectorId(value.collector_id) || !validUuid(value.cycle_id)) return null;
	if (typeof value.sequence !== "number" || !Number.isSafeInteger(value.sequence) || value.sequence < 1) return null;
	if (typeof value.stale_after_ms !== "number" || !Number.isSafeInteger(value.stale_after_ms) || value.stale_after_ms < 60_000 || value.stale_after_ms > 2_592_000_000) return null;
	if (typeof value.complete !== "boolean" || typeof value.expected_targets !== "number" || !Number.isSafeInteger(value.expected_targets) || value.expected_targets < (provider ? 0 : 1) || value.expected_targets > 100) return null;
	if (!Array.isArray(value.items) || value.items.length > value.expected_targets || (value.complete && value.items.length !== value.expected_targets)) return null;
	const seen = new Set<string>();
	const items: DiscoveryItem[] = [];
	for (const item of value.items) {
		if (!record(item) || !exactKeys(item, ["target", "reachable", "attempts", "error_code"])) return null;
		const target = canonicalDiscoveryOrigin(item.target);
		if (!target || seen.has(target) || typeof item.reachable !== "boolean" || typeof item.attempts !== "number" || !Number.isSafeInteger(item.attempts) || item.attempts < 1 || item.attempts > 5) return null;
		if (item.reachable ? item.error_code !== null : typeof item.error_code !== "string" || !ERROR_CODE.test(item.error_code)) return null;
		seen.add(target);
		items.push({ target, reachable: item.reachable, attempts: item.attempts, error_code: item.error_code as string | null });
	}
	return {
		action: "ingest",
		tenant_id: value.tenant_id,
		collector_id: value.collector_id,
		cycle_id: value.cycle_id,
		sequence: value.sequence,
		stale_after_ms: value.stale_after_ms,
		complete: value.complete && (!provider || provider.complete),
		expected_targets: value.expected_targets,
		items,
		...(provider ? { provider_resources: provider } : {}),
	};
}

export type DiscoveryFreshness = "fresh" | "stale" | "never_seen";

export function discoveryFreshness(lastReachableAt: string | null, staleAfterMs: number, now = Date.now()): DiscoveryFreshness {
	if (!lastReachableAt) return "never_seen";
	const last = Date.parse(lastReachableAt);
	if (!Number.isFinite(last)) return "never_seen";
	return last <= now && now - last <= staleAfterMs ? "fresh" : "stale";
}

export function discoveryCollectorState(
	reportedAt: string,
	complete: boolean,
	staleAfterMs: number,
	now = Date.now(),
): "current" | "partial" | "stale" {
	if (!complete) return "partial";
	return discoveryFreshness(reportedAt, staleAfterMs, now) === "fresh" ? "current" : "stale";
}

export function discoveryAlertState(input: { lastReachableAt: string | null; lastCycleId: string; cycleId: string; reachable: boolean; complete: boolean; staleAfterMs: number }, now = Date.now()): "healthy" | "unreachable" | "stale" | "never_seen" | "not_reported" | "collection_partial" {
	if (!input.complete) return "collection_partial";
	if (input.lastCycleId !== input.cycleId) return "not_reported";
	if (!input.reachable) return "unreachable";
	const freshness = discoveryFreshness(input.lastReachableAt, input.staleAfterMs, now);
	return freshness === "fresh" ? "healthy" : freshness;
}
