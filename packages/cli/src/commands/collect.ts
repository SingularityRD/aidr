import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import {
	createDiscoveryProvider,
	defaultFleetInventoryPath,
	type DiscoveryProviderResult,
	type FleetInventory,
	getInstallationId,
	loadFleetInventory,
	normalizeFleetTargets,
	resolvePath,
	saveFleetInventory,
} from "@singularityrd/aidr-core";

export interface CollectOptions {
	tenant: string;
	/** Provider selection is explicit; local is the only implemented provider. */
	provider?: string;
	target?: string[];
	file?: string;
	inventory?: string;
	interval?: string;
	staleAfter?: string;
	retryAttempts?: string;
	retryBaseMs?: string;
	timeout?: string;
	concurrency?: string;
	allowPublic?: boolean;
	json?: boolean;
}

export interface DiscoveryUploadConfig {
	url: string;
	accessToken: string;
	anonKey: string;
	mode: "operator" | "collector";
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const COLLECTOR_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HEADER_TOKEN = /^[A-Za-z0-9._-]+$/;
const DISCOVERY_ERROR = /^[a-z][a-z0-9_]{0,63}$/;
const MAX_DISCOVERY_UPLOAD_TARGETS = 100;

/** Upload is opt-in; an incomplete configuration cannot silently fall back to local-only mode. */
export function discoveryUploadConfig(env: NodeJS.ProcessEnv = process.env): DiscoveryUploadConfig | null {
	const url = env.AIDR_DISCOVERY_URL?.trim();
	const accessToken = env.AIDR_DISCOVERY_ACCESS_TOKEN?.trim();
	const collectorCredential = env.AIDR_DISCOVERY_COLLECTOR_CREDENTIAL?.trim();
	const anonKey = env.AIDR_DISCOVERY_ANON_KEY?.trim();
	if (!url && !accessToken && !collectorCredential && !anonKey) return null;
	if (!url || !anonKey || (!accessToken && !collectorCredential)) throw new Error("discovery_upload_config_incomplete");
	if (accessToken && collectorCredential) throw new Error("discovery_upload_auth_ambiguous");
	const token = collectorCredential ?? accessToken;
	if (!token) throw new Error("discovery_upload_config_incomplete");
	let endpoint: URL;
	try {
		endpoint = new URL(url);
	} catch {
		throw new Error("discovery_upload_url_invalid");
	}
	const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(endpoint.hostname);
	if (
		(endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" && loopback)) ||
		endpoint.username || endpoint.password || endpoint.search || endpoint.hash ||
		!endpoint.pathname.endsWith("/functions/v1/discovery") ||
		!HEADER_TOKEN.test(token) || !HEADER_TOKEN.test(anonKey) ||
		(collectorCredential !== undefined && !/^aidr_dc_[A-Za-z0-9_-]{43}$/.test(collectorCredential))
	) throw new Error("discovery_upload_config_invalid");
	return { url: endpoint.toString(), accessToken: token, anonKey, mode: collectorCredential ? "collector" : "operator" };
}

export interface DiscoveryIngestPayload {
	action: "ingest";
	tenant_id: string;
	collector_id: string;
	cycle_id: string;
	sequence: number;
	stale_after_ms: number;
	complete: true;
	expected_targets: number;
	items: Array<{ target: string; reachable: boolean; attempts: number; error_code: string | null }>;
}

/** Only origin-level reachability crosses the tenant boundary. Paths and scan findings stay local. */
export function discoveryIngestPayload(inventory: FleetInventory, sequence: number): DiscoveryIngestPayload {
	if (!UUID.test(inventory.tenantId) || !COLLECTOR_ID.test(inventory.collectorId)) {
		throw new Error("discovery_upload_identity_invalid");
	}
	if (!Number.isSafeInteger(sequence) || sequence < 1) throw new Error("discovery_upload_sequence_invalid");
	if (!Number.isSafeInteger(inventory.staleAfterMs) || inventory.staleAfterMs < 60_000 || inventory.staleAfterMs > 2_592_000_000) {
		throw new Error("discovery_upload_freshness_invalid");
	}
	if (inventory.items.length < 1 || inventory.items.length > MAX_DISCOVERY_UPLOAD_TARGETS) throw new Error("discovery_upload_target_count_invalid");
	const origins = new Set<string>();
	const items = inventory.items.map((item) => {
		let parsed: URL;
		try {
			parsed = new URL(item.target);
		} catch {
			throw new Error("discovery_upload_observation_invalid");
		}
		if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.username || parsed.password || parsed.search || parsed.hash) {
			throw new Error("discovery_upload_observation_invalid");
		}
		const target = parsed.origin + "/";
		if (target.length < 8 || target.length > 512) throw new Error("discovery_upload_observation_invalid");
		if (origins.has(target)) throw new Error("discovery_upload_duplicate_origin");
		origins.add(target);
		if (item.reachability === "not_checked" || !Number.isInteger(item.attempts) || item.attempts < 1 || item.attempts > 5) {
			throw new Error("discovery_upload_observation_invalid");
		}
		// A partial scan is not healthy coverage even if one HTTP probe responded.
		const reachable = item.reachability === "reachable" && item.scan.reachable && item.scan.error === null;
		const rawError = item.scan.error?.split(":", 1)[0];
		const error_code = reachable ? null
			: rawError === "timeout" || rawError === "unreachable" || rawError === "target_not_allowed" || rawError === "invalid_target_url" || rawError === "collector_exception"
				? rawError : "other";
		return { target, reachable, attempts: item.attempts, error_code };
	});
	const payload: DiscoveryIngestPayload = {
		action: "ingest", tenant_id: inventory.tenantId, collector_id: inventory.collectorId,
		cycle_id: randomUUID(), sequence, stale_after_ms: inventory.staleAfterMs,
		complete: true, expected_targets: items.length, items,
	};
	if (Buffer.byteLength(JSON.stringify(payload), "utf8") > 65_536) throw new Error("discovery_upload_payload_too_large");
	return payload;
}

async function discoveryRequest(
	config: DiscoveryUploadConfig,
	body: object,
	fetchImpl: typeof fetch,
): Promise<{ status: number; data: Record<string, unknown> | null }> {
	let response: Response;
	try {
		response = await fetchImpl(config.url, {
			method: "POST",
			headers: {
				apikey: config.anonKey,
				Authorization: `Bearer ${config.accessToken}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify(body),
			signal: AbortSignal.timeout(30_000),
			redirect: "error",
		});
	} catch {
		throw new Error("discovery_upload_network_error");
	}
	const parsed: unknown = await response.json().catch(() => null);
	const data = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
	return { status: response.status, data };
}

/** Read the server cursor first so process restarts and clock changes cannot replay a cycle. */
export async function publishDiscoveryInventory(
	inventory: FleetInventory,
	config: DiscoveryUploadConfig,
	fetchImpl: typeof fetch = fetch,
): Promise<void> {
	// Validate before any authenticated request, including the read call.
	discoveryIngestPayload(inventory, 1);
	const current = await discoveryRequest(config, {
		...(config.mode === "collector" ? { action: "cursor" } : { action: "read", limit: 1 }),
		tenant_id: inventory.tenantId, collector_id: inventory.collectorId,
	}, fetchImpl);
	let sequence = 1;
	if (current.status === 200 && config.mode === "collector") {
		const next = current.data?.next_sequence;
		if (current.data?.ok !== true || current.data?.collector_id !== inventory.collectorId ||
			typeof next !== "number" || !Number.isSafeInteger(next) || next < 1) {
			throw new Error("discovery_upload_cursor_invalid");
		}
		sequence = next;
	} else if (current.status === 200) {
		const collector = current.data?.collector;
		if (current.data?.ok !== true || !collector || typeof collector !== "object" || Array.isArray(collector) ||
			(collector as Record<string, unknown>).collector_id !== inventory.collectorId) {
			throw new Error("discovery_upload_cursor_invalid");
		}
		const previous = (collector as Record<string, unknown>).sequence;
		if (typeof previous !== "number" || !Number.isSafeInteger(previous) || previous < 1 || previous >= Number.MAX_SAFE_INTEGER) {
			throw new Error("discovery_upload_cursor_invalid");
		}
		sequence = previous + 1;
	} else if (!(config.mode === "operator" && current.status === 404 && current.data?.error === "collector_not_found")) {
		const code = current.data?.error;
		throw new Error(typeof code === "string" && DISCOVERY_ERROR.test(code) ? `discovery_upload_${code}` : `discovery_upload_http_${current.status}`);
	}
	const payload = discoveryIngestPayload(inventory, sequence);
	const uploaded = await discoveryRequest(config, payload, fetchImpl);
	if (uploaded.status !== 201) {
		const code = uploaded.data?.error;
		throw new Error(typeof code === "string" && DISCOVERY_ERROR.test(code) ? `discovery_upload_${code}` : `discovery_upload_http_${uploaded.status}`);
	}
	const cycle = uploaded.data?.cycle;
	if (uploaded.data?.ok !== true || !cycle || typeof cycle !== "object" || Array.isArray(cycle) ||
		(cycle as Record<string, unknown>).sequence !== sequence ||
		(cycle as Record<string, unknown>).collector_id !== inventory.collectorId ||
		(cycle as Record<string, unknown>).cycle_id !== payload.cycle_id) {
		throw new Error("discovery_upload_receipt_invalid");
	}
}

/** A failed interval upload leaves the server's previous report to age into stale. */
export async function publishDiscoveryCycle(
	inventory: FleetInventory,
	config: DiscoveryUploadConfig,
	continuous: boolean,
	publish: typeof publishDiscoveryInventory = publishDiscoveryInventory,
): Promise<boolean> {
	try {
		await publish(inventory, config);
		return true;
	} catch (error) {
		if (!continuous) throw error;
		console.error(
			`AIDR discovery upload failed: ${error instanceof Error ? error.message : String(error)}`,
		);
		return false;
	}
}

function parseBoundedInteger(
	label: string,
	value: string | undefined,
	fallback: number,
	min: number,
	max: number,
): number {
	if (value === undefined) return fallback;
	if (!/^\d+$/.test(value.trim())) throw new Error(`${label}_invalid`);
	const parsed = Number.parseInt(value, 10);
	if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
		throw new Error(`${label}_out_of_range`);
	}
	return parsed;
}

export function collectTargetInputs(options: Pick<CollectOptions, "target" | "file">): string[] {
	const inputs = [...(options.target ?? [])];
	if (options.file) {
		const contents = readFileSync(resolvePath(options.file), "utf8");
		for (const line of contents.split(/\r?\n/)) {
			const trimmed = line.trim();
			if (trimmed && !trimmed.startsWith("#")) inputs.push(trimmed);
		}
	}
	return normalizeFleetTargets(inputs);
}

export function fleetCollectionExitCode(inventory: FleetInventory): number {
	if (
		inventory.items.some((item) =>
			item.scan.cves.some((cve) => cve.severity === "critical" || cve.severity === "high"),
		)
	) {
		return 2;
	}
	if (
		inventory.items.length === 0 ||
		inventory.items.some((item) =>
			item.reachability !== "reachable" || item.freshness !== "fresh" || item.scan.error !== null,
		)
	) {
		return 1;
	}
	return 0;
}

function printInventory(
	inventory: FleetInventory,
	path: string,
	json: boolean,
	streaming: boolean,
	result: DiscoveryProviderResult,
): void {
	const discovery = {
		provider: result.provider,
		status: result.status,
		freshness: result.freshness,
		reason: result.reason,
	};
	if (json) {
		// Keep existing inventory fields while exposing attempt status separately.
		const output = { ...inventory, discovery };
		console.log(streaming ? JSON.stringify(output) : JSON.stringify(output, null, 2));
		return;
	}
	const fresh = inventory.items.filter((item) => item.freshness === "fresh").length;
	const stale = inventory.items.filter((item) => item.freshness === "stale").length;
	const neverSeen = inventory.items.filter((item) => item.freshness === "never_seen").length;
	const unreachable = inventory.items.filter((item) => item.reachability === "unreachable").length;
	const scanErrors = inventory.items.filter((item) => item.scan.error !== null).length;
	console.log("\nAIDR tenant infrastructure collection\n");
	console.log(`Provider: ${result.provider}   Status: ${result.status}   Freshness: ${result.freshness}`);
	console.log(`Tenant: ${inventory.tenantId}   Collector: ${inventory.collectorId}`);
	console.log(`Inventory: ${path}`);
	console.log(
		`Targets: ${inventory.items.length}   Fresh: ${fresh}   Stale: ${stale}   Never seen: ${neverSeen}   Unreachable now: ${unreachable}   Scan errors: ${scanErrors}`,
	);
	for (const item of inventory.items) {
		console.log(
			`  ${item.target}  ${item.freshness}/${item.reachability}  attempts=${item.attempts}  last_seen=${item.lastSeenAt ?? "never"}`,
		);
	}
	if (stale > 0 || neverSeen > 0 || unreachable > 0 || scanErrors > 0) {
		console.error(
			"Discovery coverage alert: at least one target lacks current evidence or has an incomplete scan.",
		);
	}
}

async function waitForNextCycle(delayMs: number): Promise<boolean> {
	return new Promise<boolean>((resolve) => {
		let settled = false;
		const finish = (continueRunning: boolean) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			process.off("SIGINT", stop);
			process.off("SIGTERM", stop);
			resolve(continueRunning);
		};
		const stop = () => finish(false);
		const timer = setTimeout(() => finish(true), delayMs);
		process.once("SIGINT", stop);
		process.once("SIGTERM", stop);
	});
}

/**
 * `aidr collect` performs one durable collection by default, which makes it
 * suitable for cron/Task Scheduler. `--interval` keeps one non-overlapping
 * collector alive for environments that do not provide an external scheduler.
 */
export default async function collectCommand(options: CollectOptions): Promise<void> {
	try {
		const provider = createDiscoveryProvider(options.provider);
		if (!provider.configured) throw new Error(`discovery_provider_not_configured:${provider.id}`);
		const targets = collectTargetInputs(options);
		if (targets.length === 0) throw new Error("collector_targets_required");
		const upload = discoveryUploadConfig();
		if (upload && targets.length > MAX_DISCOVERY_UPLOAD_TARGETS) {
			throw new Error("managed_discovery_upload_supports_at_most_100_targets");
		}
		if (upload && !UUID.test(options.tenant)) throw new Error("discovery_upload_tenant_uuid_required");

		const intervalSeconds =
			options.interval === undefined
				? null
				: parseBoundedInteger("interval", options.interval, 0, 10, 86_400);
		const staleAfterMs =
			parseBoundedInteger("stale_after", options.staleAfter, 15, 1, 43_200) * 60_000;
		const maxAttempts = parseBoundedInteger("retry_attempts", options.retryAttempts, 3, 1, 5);
		const baseRetryDelayMs = parseBoundedInteger(
			"retry_base_ms",
			options.retryBaseMs,
			250,
			0,
			60_000,
		);
		const timeoutMs = parseBoundedInteger("timeout", options.timeout, 3_000, 1, 60_000);
		const concurrency = parseBoundedInteger("concurrency", options.concurrency, 4, 1, 32);
		const collectorId = await getInstallationId();
		if (!collectorId) throw new Error("collector_identity_unavailable");
		const inventoryPath = resolvePath(
			options.inventory ?? defaultFleetInventoryPath(options.tenant),
		);

		let previous = await loadFleetInventory(inventoryPath);
		while (true) {
			const result = await provider.collect({
				tenantId: options.tenant,
				collectorId,
				targets,
				previous,
				options: {
					staleAfterMs,
					maxAttempts,
					baseRetryDelayMs,
					concurrency,
					scanOptions: {
						timeoutMs,
						allowPublicTargets: Boolean(options.allowPublic),
					},
				},
			});
			if (result.failClosed || result.status === "unconfigured" || result.status === "unavailable" || !result.inventory) {
				throw new Error(result.reason ?? `discovery_provider_${result.status}`);
			}
			const inventory = result.inventory;
			await saveFleetInventory(inventoryPath, inventory);
			const uploaded = upload
				? await publishDiscoveryCycle(inventory, upload, intervalSeconds !== null)
				: true;
			printInventory(
				inventory,
				inventoryPath,
				Boolean(options.json),
				intervalSeconds !== null,
				result,
			);
			process.exitCode = Math.max(uploaded ? 0 : 1, fleetCollectionExitCode(inventory));
			previous = inventory;
			if (intervalSeconds === null || !(await waitForNextCycle(intervalSeconds * 1_000))) break;
		}
	} catch (error) {
		console.error(
			`AIDR collection failed: ${error instanceof Error ? error.message : String(error)}`,
		);
		process.exitCode = 1;
	}
}
