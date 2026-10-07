/**
 * Registry client for npm and PyPI.
 * Fetches package metadata (existence, hashes, release dates) — no tarball downloads.
 * Returns null only for a genuine 404 (or a locally rejected package name).
 * Transport and malformed-success failures reject so callers can mark the
 * package check unavailable instead of claiming the package does not exist.
 */

import type { Logger } from "../types.js";
import { clampLegTimeoutSeconds, DEFAULT_LEG_TIMEOUT_SECONDS, nullLogger } from "../types.js";

const NPM_REGISTRY = "https://registry.npmjs.org";
const NPM_DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-week";
const PYPI_REGISTRY = "https://pypi.org/pypi";
const DEFAULT_TIMEOUT = DEFAULT_LEG_TIMEOUT_SECONDS;
export const MAX_REGISTRY_RESPONSE_BYTES = 20 * 1024 * 1024;

/** Package name validation — prevents SSRF via crafted names. */
const NPM_NAME_RE = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const PYPI_NAME_RE = /^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/;

function isRecord(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function malformedRegistryResponse(registry: "npm" | "PyPI"): Error {
	return new Error(`Malformed ${registry} registry response`);
}

async function readRegistryJson(response: Response): Promise<unknown> {
	const contentLength = response.headers?.get("content-length");
	if (contentLength && Number(contentLength) > MAX_REGISTRY_RESPONSE_BYTES) {
		void response.body?.cancel().catch(() => undefined);
		throw new Error("Registry response exceeds the size limit");
	}

	// Native fetch responses expose a stream; the fallback keeps lightweight fetch
	// mocks usable while production response bodies are always bounded before JSON parsing.
	if (!response.body) return response.json();

	const reader = response.body.getReader();
	const chunks: Uint8Array[] = [];
	let size = 0;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			size += value.byteLength;
			if (size > MAX_REGISTRY_RESPONSE_BYTES) {
				await reader.cancel().catch(() => undefined);
				throw new Error("Registry response exceeds the size limit");
			}
			chunks.push(value);
		}
	} finally {
		reader.releaseLock();
	}

	const bytes = new Uint8Array(size);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
}

/**
 * Choose the strongest digest a registry advertised for a release.
 *
 * npm publishes `dist.integrity` as `sha512-<base64>` and only keeps the legacy
 * `sha1` in `dist.shasum`. The previous implementation recognised a `sha256-`
 * prefix only, so for essentially every npm package the algorithm stayed `sha1`
 * and every downstream SHA-256 hash check silently did nothing - and the package
 * was then reported "clean" at confidence 1.0 without any hash check having run.
 *
 * Exported for testing: this decision is pure and directly assertable, unlike the
 * registry fetch around it.
 */
export function resolveDistDigest(
	shasum: string,
	integrity: string,
): { hash: string; hashAlgorithm: "sha1" | "sha256" | "sha384" | "sha512" } {
	const match = String(integrity ?? "").match(/^(sha256|sha384|sha512)-(.+)$/);
	if (match?.[1] && match[2]) {
		const hex = Buffer.from(match[2], "base64").toString("hex");
		const expectedHexLength = Number.parseInt(match[1].slice(3), 10) / 4;
		// Require a well-formed digest rather than trusting a decoding accident.
		if (hex.length === expectedHexLength && /^[0-9a-f]+$/.test(hex)) {
			return { hash: hex, hashAlgorithm: match[1] as "sha256" | "sha384" | "sha512" };
		}
	}
	// Only the legacy digest was available. Callers must not treat this as verified.
	return { hash: String(shasum ?? ""), hashAlgorithm: "sha1" };
}

export interface PackageMetadata {
	name: string;
	resolvedVersion: string;
	latestHash: string;
	/**
	 * Digest algorithm of `latestHash`.
	 *
	 * npm publishes `sha512-` in `dist.integrity`, so `sha512` is the common case;
	 * `sha1` means only the legacy `shasum` was available, which is too weak to
	 * use for a reputation lookup and must not be treated as a verified hash.
	 * `sha256` is kept for registries (and the PyPI path) that publish it.
	 */
	hashAlgorithm: "sha1" | "sha256" | "sha384" | "sha512";
	firstReleaseDate: Date | null;
	/** False when a specific version was requested but not found in the registry. */
	requestedVersionFound: boolean;
	/** Published versions (npm) or releases with files (PyPI); an adoption proxy. */
	versionCount?: number;
}

export class RegistryClient {
	private readonly timeoutMs: number;
	private readonly logger: Logger;

	constructor(config?: { timeout_seconds?: number }, logger: Logger = nullLogger) {
		this.timeoutMs = clampLegTimeoutSeconds(config?.timeout_seconds, DEFAULT_TIMEOUT) * 1000;
		this.logger = logger;
	}

	async getPackageMetadata(
		name: string,
		registry: "npm" | "pypi",
		version?: string,
	): Promise<PackageMetadata | null> {
		if (registry === "npm") return this.getNpmMetadata(name, version);
		return this.getPypiMetadata(name, version);
	}

	/**
	 * Last-week npm download count, or null when it is unavailable (non-npm
	 * registry, invalid name, HTTP/timeout failure or malformed answer). Null is
	 * "adoption unknown", never "low adoption".
	 */
	async getWeeklyDownloads(name: string, registry: "npm" | "pypi"): Promise<number | null> {
		if (registry !== "npm" || !NPM_NAME_RE.test(name)) return null;
		try {
			const response = await fetch(`${NPM_DOWNLOADS_API}/${name}`, {
				signal: AbortSignal.timeout(this.timeoutMs),
			});
			if (!response.ok) return null;
			const data = await readRegistryJson(response);
			const downloads = isRecord(data) ? data.downloads : undefined;
			return typeof downloads === "number" && Number.isSafeInteger(downloads) && downloads >= 0
				? downloads
				: null;
		} catch (e) {
			this.logger.warn("npm downloads lookup failed", { name, error: String(e) });
			return null;
		}
	}

	private async getNpmMetadata(name: string, version?: string): Promise<PackageMetadata | null> {
		if (!NPM_NAME_RE.test(name)) {
			this.logger.warn("Invalid npm package name rejected", { name });
			return null;
		}

		// Scoped packages: @scope/pkg → @scope%2fpkg in URL
		const encodedName = name.includes("/") ? `${name.split("/")[0]}%2f${name.split("/")[1]}` : name;
		const url = `${NPM_REGISTRY}/${encodedName}`;

		try {
			const response = await fetch(url, {
				signal: AbortSignal.timeout(this.timeoutMs),
			});

			if (response.status === 404) return null;
			if (!response.ok) {
				this.logger.warn(`npm registry HTTP error: ${response.status}`, { name });
				throw new Error(`npm registry HTTP ${response.status}`);
			}

			const data = (await readRegistryJson(response)) as Record<string, unknown>;
			return this.parseNpmResponse(name, data, version);
		} catch (e) {
			this.logger.warn("npm registry request failed", { name, error: String(e) });
			throw e;
		}
	}

	private parseNpmResponse(
		name: string,
		data: Record<string, unknown>,
		requestedVersion?: string,
	): PackageMetadata {
		try {
			if (!isRecord(data) || !isRecord(data["dist-tags"]) || !isRecord(data.versions)) {
				throw malformedRegistryResponse("npm");
			}
			const distTags = (data["dist-tags"] ?? {}) as Record<string, string>;
			const latestTag = distTags.latest;
			if (typeof latestTag !== "string" || !latestTag.trim()) {
				throw malformedRegistryResponse("npm");
			}

			const versions = (data.versions ?? {}) as Record<string, Record<string, unknown>>;
			// Resolve dist-tags (e.g. "latest", "next", "canary") to actual version strings
			const effectiveVersion =
				requestedVersion && distTags[requestedVersion]
					? distTags[requestedVersion]
					: requestedVersion;
			// Use requested version if specified and exists, otherwise fall back to latest
			const requestedVersionFound = !effectiveVersion || Boolean(versions[effectiveVersion]);
			const resolvedVersion =
				effectiveVersion && versions[effectiveVersion] ? effectiveVersion : latestTag;
			const resolvedVersionData = versions[resolvedVersion];
			if (!isRecord(resolvedVersionData) || !isRecord(resolvedVersionData.dist)) {
				throw malformedRegistryResponse("npm");
			}

			const dist = (resolvedVersionData.dist ?? {}) as Record<string, unknown>;
			if (
				(dist.shasum !== undefined && typeof dist.shasum !== "string") ||
				(dist.integrity !== undefined && typeof dist.integrity !== "string") ||
				(!dist.shasum && !dist.integrity)
			) {
				throw malformedRegistryResponse("npm");
			}
			const shasum = (dist.shasum ?? "") as string;
			const integrity = (dist.integrity ?? "") as string;
			const { hash: latestHash, hashAlgorithm } = resolveDistDigest(shasum, integrity);
			if (!latestHash) throw malformedRegistryResponse("npm");

			// Find first release date from `time` field
			const time = (data.time ?? {}) as Record<string, string>;
			let firstReleaseDate: Date | null = null;
			const created = time.created;
			if (created) {
				firstReleaseDate = new Date(created);
				if (Number.isNaN(firstReleaseDate.getTime())) {
					throw malformedRegistryResponse("npm");
				}
			}

			return {
				name,
				resolvedVersion: resolvedVersion,
				latestHash,
				hashAlgorithm,
				firstReleaseDate,
				requestedVersionFound,
				versionCount: Object.keys(versions).length,
			};
		} catch (e) {
			this.logger.warn("Failed to parse npm response", { name, error: String(e) });
			throw e;
		}
	}

	private async getPypiMetadata(name: string, version?: string): Promise<PackageMetadata | null> {
		if (!PYPI_NAME_RE.test(name)) {
			this.logger.warn("Invalid PyPI package name rejected", { name });
			return null;
		}

		const url = `${PYPI_REGISTRY}/${name}/json`;

		try {
			const response = await fetch(url, {
				signal: AbortSignal.timeout(this.timeoutMs),
			});

			if (response.status === 404) return null;
			if (!response.ok) {
				this.logger.warn(`PyPI registry HTTP error: ${response.status}`, { name });
				throw new Error(`PyPI registry HTTP ${response.status}`);
			}

			const data = (await readRegistryJson(response)) as Record<string, unknown>;
			return this.parsePypiResponse(name, data, version);
		} catch (e) {
			this.logger.warn("PyPI registry request failed", { name, error: String(e) });
			throw e;
		}
	}

	private parsePypiResponse(
		name: string,
		data: Record<string, unknown>,
		requestedVersion?: string,
	): PackageMetadata {
		try {
			if (!isRecord(data) || !isRecord(data.info) || !isRecord(data.releases)) {
				throw malformedRegistryResponse("PyPI");
			}
			const info = (data.info ?? {}) as Record<string, unknown>;
			const latestTag = (info.version ?? "") as string;
			if (typeof latestTag !== "string" || !latestTag.trim()) {
				throw malformedRegistryResponse("PyPI");
			}

			const releases = (data.releases ?? {}) as Record<string, Record<string, unknown>[]>;
			const requestedVersionFound =
				!requestedVersion || Boolean(releases[requestedVersion]?.length);
			const resolvedVersion =
				requestedVersion && releases[requestedVersion]?.length ? requestedVersion : latestTag;
			if (!Array.isArray(releases[resolvedVersion]) || releases[resolvedVersion].length === 0) {
				throw malformedRegistryResponse("PyPI");
			}

			// Get hash from resolved version's first file
			let latestHash = "";
			const latestFiles = releases[resolvedVersion] ?? [];
			for (const file of latestFiles) {
				if (!isRecord(file) || !isRecord(file.digests)) {
					throw malformedRegistryResponse("PyPI");
				}
				const digests = (file.digests ?? {}) as Record<string, string>;
				if (digests.sha256 !== undefined && typeof digests.sha256 !== "string") {
					throw malformedRegistryResponse("PyPI");
				}
				if (digests.sha256) {
					if (!/^[a-f0-9]{64}$/i.test(digests.sha256)) {
						throw malformedRegistryResponse("PyPI");
					}
					latestHash = digests.sha256.toLowerCase();
					break;
				}
			}
			if (!latestHash) throw malformedRegistryResponse("PyPI");

			// Find first release date (earliest version upload)
			let firstReleaseDate: Date | null = null;
			for (const [, files] of Object.entries(releases)) {
				if (!Array.isArray(files)) throw malformedRegistryResponse("PyPI");
				for (const file of files) {
					if (!isRecord(file)) throw malformedRegistryResponse("PyPI");
					const uploadTime = file.upload_time_iso_8601 as string | undefined;
					if (uploadTime) {
						const date = new Date(uploadTime);
						if (Number.isNaN(date.getTime())) throw malformedRegistryResponse("PyPI");
						if (!firstReleaseDate || date < firstReleaseDate) {
							firstReleaseDate = date;
						}
					}
				}
			}

			return {
				name,
				resolvedVersion: resolvedVersion,
				latestHash,
				hashAlgorithm: "sha256",
				firstReleaseDate,
				requestedVersionFound,
				versionCount: Object.values(releases).filter(
					(files) => Array.isArray(files) && files.length > 0,
				).length,
			};
		} catch (e) {
			this.logger.warn("Failed to parse PyPI response", { name, error: String(e) });
			throw e;
		}
	}
}
