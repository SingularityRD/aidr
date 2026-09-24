/**
 * Package supply-chain checker.
 * Orchestrates registry lookup + file reputation check + age analysis.
 */

import { FileCheckClient } from "./clients/file-check.js";
import { type PackageMetadata, RegistryClient } from "./clients/package-registry.js";
import {
	loadReputationFeed,
	type ReputationFeedLoadOptions,
	type ReputationFeedLoadResult,
	type ReputationFeedRecord,
} from "./reputation-feed.js";
import type { Logger, PackageCheckResult } from "./types.js";
import { nullLogger } from "./types.js";

const SUSPICIOUS_AGE_DAYS = 7;
const MAX_CONCURRENT = 10;

export interface PackageCheckInput {
	name: string;
	registry: "npm" | "pypi";
	version?: string;
}

export interface PackageCheckerConfig {
	registryTimeoutSeconds?: number;
	fileCheckEndpoint?: string;
	fileCheckTimeoutSeconds?: number;
	fileCheckEnabled?: boolean;
	fileCheckAllowInsecureLoopback?: boolean;
	apiKey?: string;
	/**
	 * Optional offline intel packs (owned reputation substrate).
	 * If provided, these are checked before any network calls.
	 */
	intelPackageNameDeny?: Set<string>;
	intelPackageHashDeny?: Set<string>;
	/** Verified, freshness-bound signed feed. Missing or untrusted configured feed is unavailable, never clean. */
	reputationFeed?: ReputationFeedLoadOptions;
}

export class PackageChecker {
	private readonly registryClient: RegistryClient;
	private readonly fileCheckClient: FileCheckClient | null;
	private readonly logger: Logger;
	private readonly intelPackageNameDeny: Set<string> | null;
	private readonly intelPackageHashDeny: Set<string> | null;
	private readonly reputationFeed?: ReputationFeedLoadOptions;

	constructor(config: PackageCheckerConfig = {}, logger: Logger = nullLogger) {
		this.logger = logger;
		this.registryClient = new RegistryClient(
			{ timeout_seconds: config.registryTimeoutSeconds },
			logger,
		);
		this.fileCheckClient =
			config.fileCheckEnabled !== false
				? new FileCheckClient(
						{
							endpoint: config.fileCheckEndpoint,
							timeout_seconds: config.fileCheckTimeoutSeconds,
							allow_insecure_loopback: config.fileCheckAllowInsecureLoopback,
						},
						logger,
						config.apiKey,
					)
				: null;

		this.intelPackageNameDeny = config.intelPackageNameDeny ?? null;
		this.intelPackageHashDeny = config.intelPackageHashDeny ?? null;
		this.reputationFeed = config.reputationFeed;
	}

	private loadSignedFeed(): Promise<ReputationFeedLoadResult | null> {
		return this.reputationFeed ? loadReputationFeed(this.reputationFeed) : Promise.resolve(null);
	}

	private signedNameMatch(
		feed: ReputationFeedLoadResult | null,
		pkg: PackageCheckInput,
	): ReputationFeedRecord | undefined {
		if (feed?.availability !== "available") return undefined;
		const normalize = (name: string) =>
			pkg.registry === "pypi" ? name.toLowerCase().replace(/[-_.]+/g, "-") : name.toLowerCase();
		const packageName = normalize(pkg.name);
		return feed.records.find(
			(record) =>
				record.kind === "package_name" &&
				record.verdict === "deny" &&
				normalize(record.indicator.replace(/^(npm|pypi):/i, "")) === packageName &&
				(!record.indicator.includes(":") ||
					record.indicator.toLowerCase().startsWith(`${pkg.registry}:`)),
		);
	}

	private signedHashMatch(
		feed: ReputationFeedLoadResult | null,
		metadata: PackageMetadata,
	): ReputationFeedRecord | undefined {
		if (feed?.availability !== "available" || metadata.hashAlgorithm !== "sha256") return undefined;
		return feed.records.find(
			(record) =>
				(record.kind === "package_sha256" || record.kind === "file_sha256") &&
				record.verdict === "deny" &&
				record.indicator.toLowerCase() === metadata.latestHash.toLowerCase(),
		);
	}

	private signedMalicious(
		pkg: PackageCheckInput,
		feedId: string,
		record: ReputationFeedRecord,
	): PackageCheckResult {
		return {
			packageName: pkg.name,
			registry: pkg.registry,
			verdict: "malicious",
			confidence: record.confidence ?? 0.9,
			details: `Package '${pkg.name}' denied by verified signed feed ${feedId}, record ${record.id}${record.reason ? `: ${record.reason}` : ""}`,
		};
	}

	async checkPackages(packages: PackageCheckInput[]): Promise<PackageCheckResult[]> {
		const feed = await this.loadSignedFeed();
		// Signed and legacy offline denylists take precedence over registry checks.
		const toCheck: PackageCheckInput[] = [];
		const results: PackageCheckResult[] = [];

		for (const pkg of packages) {
			const signedMatch = this.signedNameMatch(feed, pkg);
			if (signedMatch && feed?.availability === "available") {
				results.push(this.signedMalicious(pkg, feed.feedId, signedMatch));
				continue;
			}
			// Offline intel: denylist by name (works for scoped packages too).
			if (this.intelPackageNameDeny?.has(pkg.name)) {
				results.push({
					packageName: pkg.name,
					registry: pkg.registry,
					verdict: "malicious",
					confidence: 1.0,
					details: `Package '${pkg.name}' is denied by offline intel packs`,
				});
				continue;
			}

			// Scoped packages (@scope/name) are checked like any other package.
			//
			// They used to be skipped and reported "clean" at confidence 1.0, which
			// is a positive false-clean: a large share of the npm ecosystem is
			// scoped, and an attacker can register a scope as easily as a plain
			// name, so `npm install @evil/pkg` was reported as verified clean
			// without any registry lookup, hash reputation or age analysis.
			toCheck.push(pkg);
		}

		// Run checks with concurrency limit
		const checkResults = await this.runWithConcurrencyLimit(
			toCheck,
			(pkg) => this.checkSinglePackageWithFeed(pkg, feed),
			MAX_CONCURRENT,
		);
		results.push(...checkResults);

		return results;
	}

	async checkSinglePackage(pkg: PackageCheckInput): Promise<PackageCheckResult> {
		return this.checkSinglePackageWithFeed(pkg, await this.loadSignedFeed());
	}

	private async checkSinglePackageWithFeed(
		pkg: PackageCheckInput,
		feed: ReputationFeedLoadResult | null,
	): Promise<PackageCheckResult> {
		const signedName = this.signedNameMatch(feed, pkg);
		if (signedName && feed?.availability === "available") {
			return this.signedMalicious(pkg, feed.feedId, signedName);
		}
		if (feed && feed.availability !== "available") {
			return {
				packageName: pkg.name,
				registry: pkg.registry,
				verdict: "unknown",
				confidence: 0,
				details: `Signed feed ${feed.feedId} is ${feed.availability}: ${feed.detail}`,
			};
		}
		// Step 1: Query registry
		let metadata: PackageMetadata | null;
		try {
			metadata = await this.registryClient.getPackageMetadata(pkg.name, pkg.registry, pkg.version);
		} catch (error) {
			const reason =
				error instanceof Error && /^Malformed (npm|PyPI) registry response$/.test(error.message)
					? "registry response was malformed"
					: "registry lookup failed";
			return {
				packageName: pkg.name,
				registry: pkg.registry,
				verdict: "unknown",
				confidence: 0.6,
				details: `Package check for '${pkg.name}' is unavailable: ${reason} (verify manually)`,
			};
		}

		if (metadata === null) {
			return {
				packageName: pkg.name,
				registry: pkg.registry,
				verdict: "not_found",
				confidence: 0.95,
				details: `Package '${pkg.name}' not found on ${pkg.registry} (non-existent or misspelled)`,
			};
		}

		// Step 2a: Check if requested version exists
		if (!metadata.requestedVersionFound && pkg.version) {
			return {
				packageName: pkg.name,
				registry: pkg.registry,
				verdict: "not_found",
				confidence: 0.9,
				details: `Package '${pkg.name}@${pkg.version}' version not found on ${pkg.registry} (hallucinated or unpublished)`,
			};
		}

		// Step 2b: File reputation check (sha256 only — file-check API requires sha256)
		if (metadata.latestHash && this.intelPackageHashDeny?.has(metadata.latestHash.toLowerCase())) {
			return {
				packageName: pkg.name,
				registry: pkg.registry,
				verdict: "malicious",
				confidence: 1.0,
				details: `Package '${pkg.name}' matches offline malicious hash intel`,
				fileCheckSeverity: "SEVERITY_MALWARE",
			};
		}
		const signedHash = this.signedHashMatch(feed, metadata);
		if (signedHash && feed?.availability === "available") {
			return this.signedMalicious(pkg, feed.feedId, signedHash);
		}

		// The file-check endpoint accepts SHA-256 only. Supplying a SHA-512 digest
		// in its sha256 field would produce a meaningless negative verdict.
		let fileReputationUnclassified = false;
		let fileReputationUnavailable = false;
		if (metadata.latestHash && this.fileCheckClient && metadata.hashAlgorithm === "sha256") {
			try {
				const fileResult = await this.fileCheckClient.checkHash(metadata.latestHash);
				if (fileResult) {
					const sev = fileResult.severity.toUpperCase();
					if (sev === "SEVERITY_MALWARE") {
						const detections =
							fileResult.detectionNames.length > 0 ? fileResult.detectionNames.join(", ") : sev;
						return {
							packageName: pkg.name,
							registry: pkg.registry,
							verdict: "malicious",
							confidence: 1.0,
							details: `Malicious package '${pkg.name}' (${detections})`,
							fileCheckSeverity: sev,
						};
					}
					// SEVERITY_UNKNOWN means no malicious match, not a verified benign file.
					fileReputationUnclassified = true;
				} else {
					// The client returns null for HTTP, timeout and malformed-response
					// failures. None of those is a clean reputation verdict.
					fileReputationUnavailable = true;
				}
			} catch {
				fileReputationUnavailable = true;
				this.logger.warn("File-check failed for package", { name: pkg.name });
			}
		}

		// Step 3: Age check
		const ageDays = metadata.firstReleaseDate
			? (Date.now() - metadata.firstReleaseDate.getTime()) / (1000 * 60 * 60 * 24)
			: undefined;

		if (ageDays !== undefined && ageDays < SUSPICIOUS_AGE_DAYS) {
			return {
				packageName: pkg.name,
				registry: pkg.registry,
				verdict: "suspicious_age",
				confidence: 0.75,
				details: `Package '${pkg.name}' first published ${Math.floor(ageDays)} days ago (suspicious age)${fileReputationUnavailable ? "; file reputation check unavailable" : fileReputationUnclassified ? "; file reputation unclassified" : ""}`,
				ageDays,
			};
		}
		if (fileReputationUnavailable) {
			return {
				packageName: pkg.name,
				registry: pkg.registry,
				verdict: "unknown",
				confidence: 0,
				details: `Package '${pkg.name}' exists, but its file reputation check is unavailable; it was not verified clean`,
				ageDays,
			};
		}
		return {
			packageName: pkg.name,
			registry: pkg.registry,
			verdict: "unknown",
			confidence: 0,
			details: fileReputationUnclassified
				? `Package '${pkg.name}' has SEVERITY_UNKNOWN file reputation, which is NOT verified clean`
				: `Package '${pkg.name}' was not verified clean: file reputation was unavailable or not applicable${feed ? "; signed feed had no matching deny indicator" : ""}`,
			ageDays,
		};
	}

	private async runWithConcurrencyLimit<T, R>(
		items: T[],
		fn: (item: T) => Promise<R>,
		limit: number,
	): Promise<R[]> {
		const results: R[] = new Array(items.length);
		let next = 0;
		await Promise.all(
			Array.from({ length: Math.min(limit, items.length) }, async () => {
				while (next < items.length) {
					const index = next++;
					results[index] = await fn(items[index] as T);
				}
			}),
		);
		return results;
	}
}
