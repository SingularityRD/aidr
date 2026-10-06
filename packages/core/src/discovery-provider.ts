/**
 * Provider boundary for tenant-scoped infrastructure discovery.
 *
 * External providers require explicit credentials and tenant-bound resource scopes.
 * Unknown or unprovisioned selections never fall back to local collection.
 */

import {
	type CloudDiscoveryDependencies,
	CloudDiscoveryProvider,
} from "./discovery-cloud-provider.js";
import {
	collectFleetInventory,
	type FleetCollectionOptions,
	type FleetFreshness,
	type FleetInventory,
} from "./fleet-inventory.js";

/** Availability of this attempt, independent of the age of retained evidence. */
export type DiscoveryProviderStatus = "ready" | "degraded" | "unconfigured" | "unavailable";

/** No freshness claim is made when a provider did not run. */
export type DiscoveryProviderFreshness = FleetFreshness | "unknown";

export interface DiscoveryProviderRequest {
	tenantId: string;
	collectorId: string;
	targets: readonly string[];
	previous?: FleetInventory | null;
	options?: FleetCollectionOptions;
}

export interface DiscoveryProviderResult {
	/** Stable provider selection label, never a claim that the provider exists. */
	provider: string;
	/** Overall status for this collection attempt. */
	status: DiscoveryProviderStatus;
	/** Freshness is separated from provider availability for honest UI/telemetry. */
	freshness: DiscoveryProviderFreshness;
	/** Missing on unconfigured/unavailable paths; no synthetic inventory is made. */
	inventory: FleetInventory | null;
	/** True when no inventory may be used. Degraded evidence is usable, not healthy. */
	failClosed: boolean;
	/** Safe machine-readable reason, or null for a completed, reachable collection. */
	reason: string | null;
}

/**
 * Minimal fleet-collection contract shared by local and future provider
 * adapters. MCP configuration discovery has a separate report shape and remains
 * on `discoverMcpServers`; this boundary intentionally does not conflate them.
 */
export interface DiscoveryProvider {
	readonly id: string;
	/** Adapter availability; collect still validates the request's target source. */
	readonly configured: boolean;
	collect(request: DiscoveryProviderRequest): Promise<DiscoveryProviderResult>;
}

/**
 * Aggregate item freshness without turning an empty/unseen inventory into a
 * clean result. Reachability remains a separate field on each fleet item; this
 * function answers only the age of the last positive evidence.
 */
export function discoveryFreshnessForInventory(
	inventory: Pick<FleetInventory, "items">,
): FleetFreshness {
	if (
		inventory.items.length === 0 ||
		inventory.items.some((item) => item.freshness === "never_seen")
	) {
		return "never_seen";
	}
	return inventory.items.some((item) => item.freshness === "stale") ? "stale" : "fresh";
}

const PROVIDER_ID = /^[a-z][a-z0-9._:-]{0,63}$/;

const SAFE_FAILURE_REASONS = new Set([
	"tenant_id_invalid",
	"collector_id_invalid",
	"fleet_target_invalid",
	"fleet_target_protocol_invalid",
	"fleet_target_contains_private_components",
	"fleet_inventory_scope_mismatch",
	"fleet_retry_invariant_failed",
]);

function safeReason(error: unknown): string {
	const message = error instanceof Error ? error.message : "";
	return SAFE_FAILURE_REASONS.has(message) ? message : "collection_failed";
}

function normalizedProviderId(selected: string): string {
	const id = selected.trim().toLowerCase();
	return PROVIDER_ID.test(id) ? id : "unknown";
}

function localResult(inventory: FleetInventory): DiscoveryProviderResult {
	const unreachable = inventory.items.some((item) => item.reachability !== "reachable");
	const incomplete = inventory.items.some((item) => item.scan.error !== null);
	return {
		provider: "local",
		status: unreachable || incomplete ? "degraded" : "ready",
		freshness: discoveryFreshnessForInventory(inventory),
		inventory,
		failClosed: false,
		reason: unreachable ? "targets_unreachable" : incomplete ? "target_scan_incomplete" : null,
	};
}

/**
 * Native HTTP/configured-target collection backed by the existing fleet scanner.
 * Ready means the configured endpoints responded, not that a product was found
 * or that the endpoints are vulnerability-free. Failed probes remain inventory
 * observations; only a failed collection itself produces no inventory.
 */
export class LocalDiscoveryProvider implements DiscoveryProvider {
	readonly id = "local" as const;
	readonly configured = true as const;

	async collect(request: DiscoveryProviderRequest): Promise<DiscoveryProviderResult> {
		// An absent target source is not a successful scan of an empty estate.
		if (request.targets.length === 0) {
			return {
				provider: this.id,
				status: "unconfigured",
				freshness: "unknown",
				inventory: null,
				failClosed: true,
				reason: "collector_targets_required",
			};
		}
		try {
			return localResult(
				await collectFleetInventory(
					request.tenantId,
					request.collectorId,
					[...request.targets],
					request.previous,
					request.options,
				),
			);
		} catch (error) {
			return {
				provider: this.id,
				status: "unavailable",
				freshness: "unknown",
				inventory: null,
				failClosed: true,
				reason: safeReason(error),
			};
		}
	}
}

/**
 * Explicit placeholder for an adapter that has not been provisioned.
 * Returning no inventory is deliberate: callers must not mistake an absent
 * cloud/MDM adapter for a successful empty local discovery.
 */
export class UnconfiguredDiscoveryProvider implements DiscoveryProvider {
	readonly configured = false as const;
	readonly id: string;

	constructor(id = "unconfigured") {
		this.id = normalizedProviderId(id);
	}

	collect(_request: DiscoveryProviderRequest): Promise<DiscoveryProviderResult> {
		return Promise.resolve({
			provider: this.id,
			status: "unconfigured",
			freshness: "unknown",
			inventory: null,
			failClosed: true,
			reason: "provider_not_configured",
		});
	}
}

/**
 * Select local by default; external adapters require explicit validated configuration.
 */
export function createDiscoveryProvider(
	selected?: string,
	config?: unknown,
	dependencies?: CloudDiscoveryDependencies,
): DiscoveryProvider {
	if (selected === undefined) {
		if (config !== undefined) throw new Error("discovery_provider_selection_required");
		return new LocalDiscoveryProvider();
	}
	const id = normalizedProviderId(selected);
	if (id === "local") {
		if (config !== undefined) throw new Error("discovery_provider_config_mismatch");
		return new LocalDiscoveryProvider();
	}
	if (["aws", "azure", "gcp", "intune", "cloud", "mdm"].includes(id) && config !== undefined) {
		const provider = new CloudDiscoveryProvider(config, dependencies);
		if (
			provider.id !== id &&
			!(id === "cloud" && provider.id !== "intune") &&
			!(id === "mdm" && provider.id === "intune")
		)
			throw new Error("discovery_provider_config_mismatch");
		return provider;
	}
	return new UnconfiguredDiscoveryProvider(id);
}

/** Names reserved for future customer-owned integrations. */
export type ExternalDiscoveryProvider = "aws" | "azure" | "gcp" | "intune" | "cloud" | "mdm";
