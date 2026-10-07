/**
 * Load and validate YAML-based threat definitions.
 */

import { createHash } from "node:crypto";
import { readdir, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { getFileContent } from "./file-utils.js";
import { loadFrameworkMappings, resolveRuleFrameworks } from "./framework-mappings.js";
import { BUNDLED_THREAT_FILES, THREAT_PARSE_CACHE } from "./generated/threat-parse-cache.js";
import { unlistedResourceReason } from "./integrity/resource-gate.js";
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

const DIFF_MODES: ReadonlySet<string> = new Set(["added", "removed", "value_decreased"]);

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

/** SHA-256 of a threat file's content with line endings normalised (CRLF checkouts). */
export function threatContentHash(content: string): string {
	return createHash("sha256").update(content.replace(/\r\n/g, "\n"), "utf8").digest("hex");
}

/**
 * Parse one threat YAML file. A hook is a fresh process per tool call, so the
 * YAML parser would run cold over every rule file; files whose exact content was
 * pre-parsed at build time (scripts/compile-threat-cache.mjs) skip it. The YAML
 * on disk stays authoritative: any other content is parsed normally.
 */
export function parseThreatYaml(content: string): unknown {
	const cached = THREAT_PARSE_CACHE[threatContentHash(content)];
	if (cached) return cached;
	try {
		return parseYaml(content);
	} catch {
		// Retry: escape backslashes before regex-special chars that
		// are not valid YAML double-quoted string escape sequences
		return parseYaml(content.replace(/\\(?=[.*+?^$()\[\]{}|\\])/g, "\\\\"));
	}
}

/** Options for loading a subset of the rule files. */
export interface LoadThreatsOptions {
	/**
	 * Parse only the files whose raw text satisfies this predicate. Detectors that
	 * consume a few dedicated `match_on` values use it to avoid parsing every rule
	 * file on each call; the default parses all files.
	 */
	includeFile?: (content: string) => boolean;
}

/** The outcome of loading one rules directory, including what did NOT load. */
export interface ThreatDirectoryLoad {
	threats: Threat[];
	/**
	 * Every file or rule that failed to load, plus bundled rule files that are
	 * missing. Non-empty means the directory's rule set is incomplete.
	 */
	errors: string[];
}

export async function loadThreats(
	threatDir: string,
	logger: Logger = nullLogger,
	options: LoadThreatsOptions = {},
): Promise<Threat[]> {
	return (await loadThreatDirectory(threatDir, logger, options)).threats;
}

/**
 * Load one rules directory and report every failure instead of only logging
 * it: a corrupt, empty, unreadable or unlisted rule file must be visible to the
 * caller, so a partially loaded rule set is never presented as a complete one.
 *
 * `bundled` marks the shipped rules directory. Only that directory is held to
 * the integrity manifest (see integrity/resource-gate.ts) and to the expected
 * set of shipped rule files; a user rules directory is held to neither.
 */
export async function loadThreatDirectory(
	threatDir: string,
	logger: Logger = nullLogger,
	options: LoadThreatsOptions & { bundled?: boolean } = {},
): Promise<ThreatDirectoryLoad> {
	const threats: Threat[] = [];
	const errors: string[] = [];
	const bundled = options.bundled ?? false;
	let shipsBundledContent = false;

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
		const unlisted = bundled ? unlistedResourceReason(filePath) : null;
		if (unlisted) {
			const errorMsg = `Refusing rule file ${filename}: ${unlisted}`;
			errors.push(errorMsg);
			logger.error(errorMsg, { file: filename });
			continue;
		}
		let content: string;
		try {
			content = await getFileContent(filePath);
		} catch (e) {
			const errorMsg = `Failed to read ${filename}: ${String(e)}`;
			errors.push(errorMsg);
			logger.error(errorMsg, { file: filename, error: String(e) });
			continue;
		}
		if (bundled && THREAT_PARSE_CACHE[threatContentHash(content)]) shipsBundledContent = true;
		if (options.includeFile && !options.includeFile(content)) continue;

		let data: unknown;
		try {
			data = parseThreatYaml(content);
		} catch (e2) {
			const errorMsg = `Failed to parse ${filename}: ${String(e2)}`;
			errors.push(errorMsg);
			logger.error(errorMsg, { file: filename, error: String(e2) });
			continue;
		}

		if (!Array.isArray(data)) {
			const errorMsg = `Expected list in ${filename}, got ${typeof data}`;
			errors.push(errorMsg);
			logger.error(errorMsg, { file: filename });
			continue;
		}
		if (data.length === 0) {
			// A rule file that holds no rules at all is a truncated or emptied
			// file, not a deliberate statement that nothing should be detected.
			const errorMsg = `Rule file ${filename} contains no rules`;
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

			// File-edit view rules (agent-safety/edit-views.ts) may declare how the
			// added and removed lines of an edit are compared. A malformed value is
			// a rule error, never a silently widened rule.
			const diff = record.diff;
			if (diff !== undefined && !DIFF_MODES.has(diff as string)) {
				const errorMsg = `Skipping threat ${record.id} in ${filename}: diff must be one of ${[...DIFF_MODES].join(", ")}`;
				errors.push(errorMsg);
				logger.error(errorMsg, { file: filename, threatId: record.id });
				continue;
			}
			const minMatches = record.min_matches;
			if (
				minMatches !== undefined &&
				(!Number.isInteger(minMatches) ||
					(minMatches as number) < 1 ||
					(minMatches as number) > 1000)
			) {
				const errorMsg = `Skipping threat ${record.id} in ${filename}: min_matches must be an integer between 1 and 1000`;
				errors.push(errorMsg);
				logger.error(errorMsg, { file: filename, threatId: record.id });
				continue;
			}
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
				...(diff === undefined ? {} : { diff: diff as NonNullable<Threat["diff"]> }),
				...(minMatches === undefined ? {} : { minMatches: minMatches as number }),
				sourceFile: filename,
				...(frameworks ? { frameworks } : {}),
			});
		}
	}

	// A directory that ships verbatim bundled rule files is a bundled rules
	// directory, and it must ship all of them: a deleted file would otherwise
	// silently remove its rules. A directory of custom rules matches no shipped
	// content and is not held to the shipped file set.
	if (bundled && shipsBundledContent) {
		const present = new Set(files);
		for (const expected of BUNDLED_THREAT_FILES) {
			if (present.has(expected)) continue;
			const errorMsg = `Bundled rule file ${expected} is missing from ${threatDir}`;
			errors.push(errorMsg);
			logger.error(errorMsg, { file: expected });
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

	return { threats, errors };
}

/** The merged rule set of several directories, and what did not load. */
export interface ThreatSetLoad {
	threats: Threat[];
	/**
	 * Load failures of the primary (bundled) directory. Non-empty means some
	 * bundled rules are NOT in `threats`, so a match-free result is not clean.
	 */
	bundledErrors: string[];
	/** User rule IDs ignored because they clash with a bundled rule ID. */
	ignoredOverrides: string[];
}

/**
 * Load threats from multiple directories and merge them by threat ID.
 * See {@link loadThreatSet} for the merge rules.
 */
export async function loadThreatsFromDirs(
	threatDirs: string[],
	logger: Logger = nullLogger,
	options: LoadThreatsOptions = {},
): Promise<Threat[]> {
	return (await loadThreatSet(threatDirs, logger, options)).threats;
}

/**
 * Load and merge rule directories. The first directory is the bundled rule set;
 * later directories (the user's `~/.singularity-aidr/threats`) may ADD rules
 * with new IDs but never replace a bundled rule. A clashing user rule is logged
 * and ignored, so a writable state directory cannot weaken or silence a shipped
 * detection.
 */
export async function loadThreatSet(
	threatDirs: string[],
	logger: Logger = nullLogger,
	options: LoadThreatsOptions = {},
): Promise<ThreatSetLoad> {
	const merged = new Map<string, Threat>();
	const bundledIds = new Set<string>();
	const bundledErrors: string[] = [];
	const ignoredOverrides: string[] = [];
	for (const [index, dir] of threatDirs.entries()) {
		const primary = index === 0;
		if (!dir) {
			if (primary) bundledErrors.push("No bundled threat directory was supplied");
			continue;
		}
		// Only the first (primary) directory is mandatory. An absent optional
		// directory (e.g. ~/.singularity-aidr/threats on a fresh install) is the
		// normal case, so it must not be reported as an error on every call.
		// A connector whose bundled assets are missing may fall back to the user
		// directory as its primary one; loading it twice would only report every
		// rule as clashing with itself.
		if (!primary && threatDirs[0] && resolve(dir) === resolve(threatDirs[0])) continue;
		if (!primary && !(await isDirectory(dir))) {
			logger.debug(`Skipping absent optional threat directory: ${dir}`);
			continue;
		}
		let loaded: ThreatDirectoryLoad;
		try {
			loaded = await loadThreatDirectory(dir, logger, { ...options, bundled: primary });
		} catch (error) {
			if (primary) bundledErrors.push(error instanceof Error ? error.message : String(error));
			logger.debug(`Skipping threat directory: ${dir}`, { error: String(error) });
			continue;
		}
		if (primary) bundledErrors.push(...loaded.errors);
		for (const threat of loaded.threats) {
			if (primary) {
				bundledIds.add(threat.id);
				merged.set(threat.id, threat);
				continue;
			}
			if (bundledIds.has(threat.id)) {
				ignoredOverrides.push(threat.id);
				logger.warn(
					`Ignoring user rule ${threat.id}: it clashes with a bundled rule ID, and user rules may only add new IDs`,
					{ threatId: threat.id, path: dir, sourceFile: threat.sourceFile },
				);
				continue;
			}
			merged.set(threat.id, threat);
		}
	}
	return { threats: [...merged.values()], bundledErrors, ignoredOverrides };
}

async function isDirectory(path: string): Promise<boolean> {
	try {
		return (await stat(path)).isDirectory();
	} catch {
		return false;
	}
}
