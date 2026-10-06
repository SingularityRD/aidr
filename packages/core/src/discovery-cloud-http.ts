import { performance } from "node:perf_hooks";
import { setTimeout as sleep } from "node:timers/promises";
import { z } from "zod";
import type { CloudDiscoveryConfig, DiscoverySecretResolver } from "./discovery-cloud-config.js";

const MAX_DISCOVERY_RESOURCES = 1000;
const MAX_DISCOVERY_PAGES = 100;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_CYCLE_BYTES = 8 * 1024 * 1024;

export interface DiscoveryResource {
	id: string;
	type: string;
	scope: string;
	region?: string;
	/** API visibility is management evidence, never endpoint reachability. */
	observedAt: string;
}

const evidenceString = (max: number) =>
	z
		.string()
		.min(1)
		.max(max)
		.regex(/^[^\x00-\x1f]*$/);
export const CloudDiscoveryEvidenceSchema = z
	.object({
		provider: z.enum(["aws", "azure", "gcp", "intune"]),
		scopeHash: z.string().regex(/^[a-f0-9]{64}$/),
		coverage: z.enum([
			"tagged_resources",
			"resource_groups",
			"project_asset_types",
			"managed_devices",
		]),
		complete: z.boolean(),
		observedAt: z.string().datetime(),
		lastSuccessfulAt: z.string().datetime().nullable(),
		resources: z
			.array(
				z
					.object({
						id: evidenceString(1024),
						type: evidenceString(256),
						scope: evidenceString(256),
						region: evidenceString(64).optional(),
						observedAt: z.string().datetime(),
					})
					.strict(),
			)
			.max(MAX_DISCOVERY_RESOURCES),
	})
	.strict()
	.superRefine((evidence, context) => {
		const kinds = {
			aws: "tagged_resources",
			azure: "resource_groups",
			gcp: "project_asset_types",
			intune: "managed_devices",
		};
		if (
			kinds[evidence.provider] !== evidence.coverage ||
			(evidence.complete && evidence.lastSuccessfulAt !== evidence.observedAt)
		)
			context.addIssue({ code: z.ZodIssueCode.custom, message: "invalid provider evidence" });
		const ids = new Set<string>();
		for (const resource of evidence.resources) {
			if (!resource.scope.startsWith(`${evidence.provider}:`) || ids.has(resource.id))
				context.addIssue({ code: z.ZodIssueCode.custom, message: "invalid provider resource" });
			ids.add(resource.id);
		}
	});

export interface CloudDiscoveryContext {
	config: CloudDiscoveryConfig;
	http: DiscoveryHttpClient;
	secret: DiscoverySecretResolver;
	now: () => number;
}

/** Dependency injection is programmatic only; JSON configuration cannot override hosts. */
export interface DiscoveryHttpOptions {
	fetch?: typeof fetch;
	timeoutMs?: number;
	signal?: AbortSignal;
	sleep?: (ms: number) => Promise<void>;
}

export class DiscoveryHttpClient {
	private bytes = 0;
	private requests = 0;
	private readonly deadline = performance.now() + 120_000;
	constructor(
		private readonly allowedHosts: readonly string[],
		private readonly options: DiscoveryHttpOptions = {},
	) {}

	async request(url: string, init: RequestInit = {}): Promise<string> {
		if (!this.options.fetch && process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0")
			throw new Error("discovery_insecure_tls_not_allowed");
		const target = new URL(url);
		if (
			target.protocol !== "https:" ||
			!this.allowedHosts.includes(target.hostname) ||
			target.port ||
			target.username ||
			target.password ||
			target.hash
		) {
			throw new Error("discovery_endpoint_not_allowed");
		}
		for (let attempt = 0; attempt < 3; attempt++) {
			if (++this.requests > 300) throw new Error("discovery_request_limit_exceeded");
			if (performance.now() >= this.deadline) throw new Error("discovery_cycle_timeout");
			this.options.signal?.throwIfAborted();
			const timeout = AbortSignal.timeout(
				Math.max(
					1,
					Math.min(
						60_000,
						this.options.timeoutMs ?? 10_000,
						Math.floor(this.deadline - performance.now()),
					),
				),
			);
			const signal = this.options.signal
				? AbortSignal.any([this.options.signal, timeout])
				: timeout;
			let response: Response;
			try {
				response = await (this.options.fetch ?? fetch)(target, {
					...init,
					signal,
					redirect: "error",
				});
			} catch {
				throw new Error(
					this.options.signal?.aborted ? "discovery_cancelled" : "discovery_request_failed",
				);
			}
			const throttled =
				response.status === 429 ||
				response.status === 503 ||
				(response.status === 400 &&
					response.headers.get("x-amzn-errortype")?.split(":", 1)[0] === "ThrottledException");
			if (throttled && attempt < 2) {
				await response.body?.cancel();
				const retryAfter = Number(response.headers.get("retry-after"));
				const delay = Math.max(
					250 * 2 ** attempt,
					Number.isFinite(retryAfter) ? retryAfter * 1000 : 0,
				);
				if (delay > 5000) throw new Error("discovery_rate_limited");
				if (performance.now() + delay >= this.deadline) throw new Error("discovery_cycle_timeout");
				await (
					this.options.sleep ?? ((ms) => sleep(ms, undefined, { signal: this.options.signal }))
				)(delay);
				continue;
			}
			if (!response.ok) {
				await response.body?.cancel();
				throw new Error(
					response.status === 401 || response.status === 403
						? "discovery_credentials_rejected"
						: throttled
							? "discovery_rate_limited"
							: "discovery_provider_http_failed",
				);
			}
			const reader = response.body?.getReader();
			if (!reader) throw new Error("discovery_response_invalid");
			const chunks: Uint8Array[] = [];
			let size = 0;
			try {
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					size += value.byteLength;
					this.bytes += value.byteLength;
					if (size > MAX_RESPONSE_BYTES || this.bytes > MAX_CYCLE_BYTES)
						throw new Error("discovery_response_limit_exceeded");
					chunks.push(value);
				}
			} catch {
				await reader.cancel().catch(() => {});
				throw new Error(
					signal.aborted ? "discovery_request_failed" : "discovery_response_limit_exceeded",
				);
			}
			return Buffer.concat(chunks).toString("utf8");
		}
		throw new Error("discovery_rate_limited");
	}

	async json(url: string, init: RequestInit = {}): Promise<Record<string, unknown>> {
		try {
			const value: unknown = JSON.parse(await this.request(url, init));
			if (!value || typeof value !== "object" || Array.isArray(value))
				throw new Error("discovery_response_invalid");
			return value as Record<string, unknown>;
		} catch (error) {
			if (error instanceof Error && /^discovery_/.test(error.message)) throw error;
			throw new Error("discovery_response_invalid");
		}
	}
}

export function discoveryPageToken(value: unknown, seen: Set<string>): string | undefined {
	if (value === undefined || value === null || value === "") return undefined;
	if (
		typeof value !== "string" ||
		value.length > 8192 ||
		/[\x00-\x1f]/.test(value) ||
		seen.has(value)
	)
		throw new Error("discovery_pagination_invalid");
	seen.add(value);
	if (seen.size >= MAX_DISCOVERY_PAGES) throw new Error("discovery_page_limit_exceeded");
	return value;
}

export function appendDiscoveryResource(
	resources: DiscoveryResource[],
	resource: DiscoveryResource,
): void {
	if (
		!resource.id ||
		resource.id.length > 1024 ||
		!resource.type ||
		resource.type.length > 256 ||
		!resource.scope ||
		resource.scope.length > 256 ||
		/[\x00-\x1f]/.test(resource.id + resource.type + resource.scope)
	)
		throw new Error("discovery_response_invalid");
	if (resources.some((item) => item.id === resource.id))
		throw new Error("discovery_resource_replayed");
	if (resources.length >= MAX_DISCOVERY_RESOURCES)
		throw new Error("discovery_resource_limit_exceeded");
	resources.push(resource);
}
