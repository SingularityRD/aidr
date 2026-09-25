/**
 * Load and validate YAML-based threat definitions.
 */

import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { getFileContent } from "./file-utils.js";
import { loadFrameworkMappings, resolveRuleFrameworks } from "./framework-mappings.js";
import type { Logger, Threat } from "./types.js";
import { nullLogger } from "./types.js";

const REQUIRED_FIELDS = new Set([
	"id",
	"category",
	"severity",
	"confidence",
	"action",
	"pattern",
	"match_on",
	"title",
]);

function parseExpiresAt(value: string | null | undefined): Date | null {
	if (value == null) return null;
	try {
		const date = new Date(String(value));
		return Number.isNaN(date.getTime()) ? null : date;
	} catch {
		return null;
	}
}

function isExpired(entry: Record<string, unknown>): boolean {
	const expiresAt = parseExpiresAt(entry.expires_at as string | null | undefined);
	if (expiresAt === null) return false;
	return Date.now() > expiresAt.getTime();
}

export async function loadThreats(
	threatDir: string,
	logger: Logger = nullLogger,
): Promise<Threat[]> {
	const threats: Threat[] = [];
	const errors: string[] = [];

	let files: string[];
	try {
		files = (await readdir(threatDir)).filter((f) => f.endsWith(".yaml")).sort();
	} catch (error) {
		const errorMsg = `Threat directory does not exist or is unreadable: ${threatDir}`;
		logger.error(errorMsg, { path: threatDir, error: String(error) });
		throw new Error(errorMsg);
	}

	// Enrichment only: a missing or invalid mapping file leaves `frameworks` off
	// the loaded rules and is logged; it never stops a rule from loading.
	const frameworkMappings = await loadFrameworkMappings(threatDir, logger);

	for (const filename of files) {
		const filePath = join(threatDir, filename);
		let content: string;
		try {
			content = await getFileContent(filePath);
		} catch (e) {
			const errorMsg = `Failed to read ${filename}: ${String(e)}`;
			errors.push(errorMsg);
			logger.error(errorMsg, { file: filename, error: String(e) });
			continue;
		}

		let data: unknown;
		try {
			data = parseYaml(content);
		} catch {
			// Retry: escape backslashes before regex-special chars that
			// are not valid YAML double-quoted string escape sequences
			try {
				const fixed = content.replace(/\\(?=[.*+?^$()\[\]{}|\\])/g, "\\\\");
				data = parseYaml(fixed);
			} catch (e2) {
				const errorMsg = `Failed to parse ${filename}: ${String(e2)}`;
				errors.push(errorMsg);
				logger.error(errorMsg, { file: filename, error: String(e2) });
				continue;
			}
		}

		if (!Array.isArray(data)) {
			const errorMsg = `Expected list in ${filename}, got ${typeof data}`;
			errors.push(errorMsg);
			logger.error(errorMsg, { file: filename });
			continue;
		}

		for (const entry of data) {
			if (typeof entry !== "object" || entry === null) {
				logger.warn(`Skipping non-object entry in ${filename}`);
				continue;
			}

			const record = entry as Record<string, unknown>;
			const keys = new Set(Object.keys(record));
			const missing = [...REQUIRED_FIELDS].filter((f) => !keys.has(f));
			if (missing.length > 0) {
				const errorMsg = `Skipping threat in ${filename}: missing fields ${missing.join(", ")}`;
				errors.push(errorMsg);
				logger.error(errorMsg, { file: filename, threatId: record.id });
				continue;
			}

			if (record.revoked === true) continue;
			if (isExpired(record)) continue;

			// Validate confidence is within valid range (0-1)
			const confidenceValue = Number(record.confidence);
			if (Number.isNaN(confidenceValue) || confidenceValue < 0 || confidenceValue > 1) {
				const errorMsg = `Skipping threat ${record.id} in ${filename}: confidence must be between 0 and 1, got ${record.confidence}`;
				errors.push(errorMsg);
				logger.error(errorMsg, { file: filename, threatId: record.id });
				continue;
			}

			let compiledPattern: RegExp;
			try {
				const flags = record.case_insensitive === true ? "i" : "";
				compiledPattern = new RegExp(record.pattern as string, flags);
			} catch (e) {
				const errorMsg = `Skipping threat ${record.id}: invalid regex pattern - ${String(e)}`;
				errors.push(errorMsg);
				logger.error(errorMsg, { file: filename, threatId: record.id, error: String(e) });
				continue;
			}

			// Normalize match_on to Set
			const rawMatchOn = record.match_on;
			const matchOn: Set<string> = new Set(
				Array.isArray(rawMatchOn) ? rawMatchOn : [rawMatchOn as string],
			);

			const frameworks = frameworkMappings
				? resolveRuleFrameworks(frameworkMappings, {
						id: record.id as string,
						category: record.category as string,
						sourceFile: filename,
					})
				: null;

			threats.push({
				id: record.id as string,
				category: record.category as string,
				severity: record.severity as Threat["severity"],
				confidence: confidenceValue,
				action: record.action as Threat["action"],
				pattern: record.pattern as string,
				compiledPattern,
				matchOn,
				title: record.title as string,
				expiresAt: parseExpiresAt(record.expires_at as string | null | undefined),
				revoked: false,
				sourceFile: filename,
				...(frameworks ? { frameworks } : {}),
			});
		}
	}

	if (errors.length > 0) {
		logger.warn(`Loaded ${threats.length} threats from ${threatDir} with ${errors.length} errors`, {
			path: threatDir,
			errors,
		});
	} else {
		logger.debug(`Loaded ${threats.length} threats from ${threatDir}`);
	}

	return threats;
}

/**
 * Load threats from multiple directories and merge them by threat ID.
 * Later directories win on ID collisions (override semantics).
 */
export async function loadThreatsFromDirs(
	threatDirs: string[],
	logger: Logger = nullLogger,
): Promise<Threat[]> {
	const merged = new Map<string, Threat>();
	for (const dir of threatDirs) {
		if (!dir) continue;
		try {
			const threats = await loadThreats(dir, logger);
			for (const threat of threats) {
				merged.set(threat.id, threat);
			}
		} catch (error) {
			// Skip directories that don't exist (e.g., optional user threats dir)
			// Only the first (primary) directory should be mandatory
			logger.debug(`Skipping threat directory: ${dir}`, { error: String(error) });
		}
	}
	return [...merged.values()];
}
