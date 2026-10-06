import { createHash } from "node:crypto";
import { discoverAwsResources } from "./discovery-aws.js";
import {
	type CloudDiscoveryConfig,
	type DiscoverySecretResolver,
	parseCloudDiscoveryConfig,
	resolveDiscoverySecret,
} from "./discovery-cloud-config.js";
import {
	CloudDiscoveryEvidenceSchema,
	DiscoveryHttpClient,
	type DiscoveryHttpOptions,
	type DiscoveryResource,
} from "./discovery-cloud-http.js";
import { discoverGcpResources } from "./discovery-gcp.js";
import { discoverMicrosoftResources } from "./discovery-microsoft.js";
import type {
	DiscoveryProvider,
	DiscoveryProviderRequest,
	DiscoveryProviderResult,
} from "./discovery-provider.js";
import { collectFleetInventory, refreshFleetInventoryFreshness } from "./fleet-inventory.js";

type CloudDiscoveryCoverage =
	| "tagged_resources"
	| "resource_groups"
	| "project_asset_types"
	| "managed_devices";
export interface CloudDiscoveryEvidence {
	provider: CloudDiscoveryConfig["provider"];
	scopeHash: string;
	coverage: CloudDiscoveryCoverage;
	complete: boolean;
	observedAt: string;
	/** Last fully successful API snapshot; never advanced on partial/failure. */
	lastSuccessfulAt: string | null;
	resources: DiscoveryResource[];
}

export interface CloudDiscoveryDependencies extends DiscoveryHttpOptions {
	secret?: DiscoverySecretResolver;
}

export function parseCloudDiscoveryEvidence(value: unknown): CloudDiscoveryEvidence {
	const parsed = CloudDiscoveryEvidenceSchema.safeParse(value);
	if (!parsed.success) throw new Error("discovery_provider_evidence_invalid");
	return parsed.data;
}

/** Stable grant binding excludes credential values and references, retaining every scope filter. */
export function cloudDiscoveryScopeHash(config: CloudDiscoveryConfig): string {
	const { credentials: _credentials, ...scope } = config;
	const normalized = Object.fromEntries(
		Object.entries(scope)
			.sort(([a], [b]) => a.localeCompare(b))
			.map(([key, value]) => [
				key,
				Array.isArray(value)
					? [
							...new Set(
								value.map((item) =>
									config.provider === "azure" || config.provider === "intune"
										? item.toLowerCase()
										: item,
								),
							),
						].sort()
					: typeof value === "string" && ["directoryTenantId"].includes(key)
						? value.toLowerCase()
						: value,
			]),
	);
	return createHash("sha256").update(JSON.stringify(normalized)).digest("hex");
}

function providerHosts(config: CloudDiscoveryConfig): string[] {
	if (config.provider === "aws")
		return config.regions.flatMap((region) => [
			`sts.${region}.amazonaws.com`,
			`tagging.${region}.amazonaws.com`,
		]);
	if (config.provider === "gcp") return ["oauth2.googleapis.com", "cloudasset.googleapis.com"];
	return [
		"login.microsoftonline.com",
		config.provider === "azure" ? "management.azure.com" : "graph.microsoft.com",
	];
}

function coverage(provider: CloudDiscoveryConfig["provider"]): CloudDiscoveryCoverage {
	return {
		aws: "tagged_resources",
		azure: "resource_groups",
		gcp: "project_asset_types",
		intune: "managed_devices",
	}[provider] as CloudDiscoveryCoverage;
}

const SAFE_REASONS = new Set([
	"discovery_credentials_unavailable",
	"discovery_credentials_rejected",
	"discovery_endpoint_not_allowed",
	"discovery_cancelled",
	"discovery_request_failed",
	"discovery_rate_limited",
	"discovery_provider_http_failed",
	"discovery_response_invalid",
	"discovery_response_limit_exceeded",
	"discovery_request_limit_exceeded",
	"discovery_page_limit_exceeded",
	"discovery_pagination_invalid",
	"discovery_resource_replayed",
	"discovery_resource_limit_exceeded",
	"discovery_resource_scope_mismatch",
	"discovery_response_incomplete",
	"discovery_account_scope_mismatch",
	"discovery_scope_mismatch",
	"discovery_scope_unsupported",
	"discovery_cycle_timeout",
	"discovery_clock_invalid",
	"discovery_insecure_tls_not_allowed",
]);

/** Resource visibility and HTTP probes remain distinct pieces of evidence. */
export class CloudDiscoveryProvider implements DiscoveryProvider {
	readonly configured = true;
	readonly id: CloudDiscoveryConfig["provider"];
	private readonly config: CloudDiscoveryConfig;
	constructor(
		config: unknown,
		private readonly dependencies: CloudDiscoveryDependencies = {},
	) {
		this.config = parseCloudDiscoveryConfig(config);
		this.id = this.config.provider;
	}

	async collect(request: DiscoveryProviderRequest): Promise<DiscoveryProviderResult> {
		if (
			request.tenantId !== this.config.tenantId ||
			(request.previous && request.previous.tenantId !== request.tenantId)
		)
			return {
				provider: this.id,
				status: "unavailable",
				freshness: "unknown",
				inventory: null,
				failClosed: true,
				reason: "discovery_tenant_scope_mismatch",
			};
		let inventory;
		try {
			inventory = await collectFleetInventory(
				request.tenantId,
				request.collectorId,
				[...request.targets],
				request.previous,
				request.options,
			);
		} catch {
			return {
				provider: this.id,
				status: "unavailable",
				freshness: "unknown",
				inventory: null,
				failClosed: true,
				reason: "discovery_collection_invalid",
			};
		}
		const now = request.options?.now ?? Date.now;
		const scopeHash = cloudDiscoveryScopeHash(this.config);
		const prior = request.previous?.providerEvidence;
		const previous = prior?.provider === this.id && prior.scopeHash === scopeHash ? prior : null;
		const http = new DiscoveryHttpClient(providerHosts(this.config), {
			...this.dependencies,
			timeoutMs: request.options?.scanOptions?.timeoutMs ?? this.dependencies.timeoutMs,
			signal: request.options?.signal ?? this.dependencies.signal,
		});
		const context = {
			config: this.config,
			http,
			secret: this.dependencies.secret ?? resolveDiscoverySecret,
			now,
		};
		let resources: DiscoveryResource[] = [];
		let reason: string | null = null;
		try {
			resources = await (this.id === "aws"
				? discoverAwsResources(context)
				: this.id === "gcp"
					? discoverGcpResources(context)
					: discoverMicrosoftResources(context));
		} catch (error) {
			const message = error instanceof Error ? error.message : "";
			reason = SAFE_REASONS.has(message) ? message : "discovery_collection_failed";
		}
		const observedAt = new Date(now()).toISOString();
		inventory = refreshFleetInventoryFreshness(inventory, Date.parse(observedAt));
		inventory.providerEvidence = {
			provider: this.id,
			scopeHash,
			coverage: coverage(this.id),
			complete: reason === null,
			observedAt,
			lastSuccessfulAt: reason === null ? observedAt : (previous?.lastSuccessfulAt ?? null),
			resources: reason === null ? resources : (previous?.resources ?? []),
		};
		const probesIncomplete = inventory.items.some(
			(item) => item.reachability !== "reachable" || item.scan.error !== null,
		);
		const lastSuccess = inventory.providerEvidence.lastSuccessfulAt;
		const epoch = lastSuccess ? Date.parse(lastSuccess) : Number.NaN;
		const resourceFreshness = !Number.isFinite(epoch)
			? "never_seen"
			: epoch > Date.parse(observedAt) || Date.parse(observedAt) - epoch > inventory.staleAfterMs
				? "stale"
				: "fresh";
		const freshness =
			resourceFreshness === "never_seen" ||
			inventory.items.some((item) => item.freshness === "never_seen")
				? "never_seen"
				: resourceFreshness === "stale" ||
						inventory.items.some((item) => item.freshness === "stale")
					? "stale"
					: "fresh";
		return {
			provider: this.id,
			status: reason || probesIncomplete ? "degraded" : "ready",
			freshness,
			inventory,
			failClosed: false,
			reason: reason ?? (probesIncomplete ? "target_scan_incomplete" : null),
		};
	}
}
