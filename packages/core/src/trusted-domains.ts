/**
 * Trusted installer domains — suppresses pipe-to-shell false positives.
 */

import { readdir } from "node:fs/promises";
import { join } from "node:path";
import {
	loadResourceManifestCoverage,
	readShippedResourceText,
} from "./integrity/resource-manifest.js";
import type { Logger, TrustedDomain } from "./types.js";
import { nullLogger } from "./types.js";
import { parseShippedYaml } from "./yaml-parse-cache.js";

export async function loadTrustedDomains(
	allowlistsDir: string,
	logger: Logger = nullLogger,
): Promise<TrustedDomain[]> {
	let files: string[];
	try {
		files = (await readdir(allowlistsDir)).filter((f) => f.endsWith(".yaml")).sort();
	} catch {
		logger.debug("Allowlists directory does not exist", { path: allowlistsDir });
		return [];
	}

	const domains: TrustedDomain[] = [];
	// Shipped allowlists are a closed set: when a manifest covers this
	// directory, an unlisted or modified file is ignored rather than trusted.
	const coverage = await loadResourceManifestCoverage(allowlistsDir);

	for (const filename of files) {
		const filePath = join(allowlistsDir, filename);
		let content: string;
		try {
			const shipped = await readShippedResourceText(coverage, filename, filePath, logger);
			if (shipped === null) continue;
			content = shipped;
		} catch (e) {
			logger.warn(`Failed to read ${filename}`, { error: String(e) });
			continue;
		}

		let data: unknown;
		try {
			data = parseShippedYaml(content);
		} catch (e) {
			logger.warn(`Failed to parse ${filename}`, { error: String(e) });
			continue;
		}

		if (!Array.isArray(data)) {
			logger.warn(`Expected list in ${filename}, got ${typeof data}`);
			continue;
		}

		for (const entry of data) {
			if (typeof entry !== "object" || entry === null) {
				logger.warn(`Skipping non-object entry in ${filename}`);
				continue;
			}

			const record = entry as Record<string, unknown>;
			const domain = record.domain;
			const reason = record.reason;

			if (!domain || typeof domain !== "string") {
				logger.warn(`Skipping entry without valid 'domain' in ${filename}`);
				continue;
			}

			if (!reason || typeof reason !== "string") {
				logger.warn(`Skipping entry without valid 'reason' in ${filename}`);
				continue;
			}

			const paths = record.paths;
			if (paths === undefined) {
				domains.push({ domain: domain.toLowerCase(), reason });
				continue;
			}
			if (
				!Array.isArray(paths) ||
				paths.length === 0 ||
				!paths.every((p) => typeof p === "string" && p.startsWith("/"))
			) {
				// A malformed path scope must not widen into a whole-domain trust.
				logger.warn(
					`Skipping '${domain}' in ${filename}: 'paths' must be a non-empty list of absolute paths`,
				);
				continue;
			}
			domains.push({ domain: domain.toLowerCase(), reason, paths: [...paths] });
		}
	}

	logger.debug(`Loaded ${domains.length} trusted domains from ${allowlistsDir}`);
	return domains;
}

export function extractDomain(url: string): string | null {
	try {
		const parsed = new URL(url);
		return parsed.hostname.toLowerCase() || null;
	} catch {
		return null;
	}
}

/** Whole-domain trust only: path-scoped entries never trust a bare domain. */
export function isTrustedDomain(domain: string, trusted: TrustedDomain[]): boolean {
	const domainLower = domain.toLowerCase();
	for (const td of trusted) {
		if (td.paths) continue;
		if (domainLower === td.domain) return true;
		if (domainLower.endsWith(`.${td.domain}`)) return true;
	}
	return false;
}

/**
 * Trust for a full URL: whole-domain entries match the host by dot-bounded suffix; path-scoped
 * entries need the exact host and one of the listed paths (no query or fragment).
 */
export function isTrustedUrl(url: string, trusted: TrustedDomain[]): boolean {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return false;
	}
	const host = parsed.hostname.toLowerCase();
	if (!host || parsed.username || parsed.password) return false;
	for (const td of trusted) {
		if (td.paths) {
			if (
				host === td.domain &&
				!parsed.search &&
				!parsed.hash &&
				td.paths.includes(parsed.pathname)
			)
				return true;
			continue;
		}
		if (host === td.domain || host.endsWith(`.${td.domain}`)) return true;
	}
	return false;
}
