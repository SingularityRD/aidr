/**
 * Load and validate YAML-based threat definitions.
 */

import { createHash } from "node:crypto";
import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { getFileContentRaw } from "./file-utils.js";
import { loadFrameworkMappings, resolveRuleFrameworks } from "./framework-mappings.js";
import { THREAT_PARSE_CACHE } from "./generated/threat-parse-cache.js";
import {
	checkCoveredFile,
	loadResourceManifestCoverage,
	type ResourceManifestCoverage,
} from "./integrity/resource-manifest.js";
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
	/**
	 * Check each rule file against the artifact manifest that ships with the
	 * rule directory, when one is present (see `integrity/resource-manifest.ts`):
	 * a listed file must match its digest and an unlisted file is ignored. When
	 * `publicKeysPem` is non-empty the manifest signature is required too.
	 * {@link loadThreatsFromDirsWithReport} applies it to the bundled directory only.
	 */
	manifest?: { publicKeysPem?: readonly string[] };
}

/** A rule file (or a rule inside one) that did not load as shipped. */
export interface ThreatLoadError {
	file: string;
	kind:
		| "read"
		| "parse"
		| "not_a_list"
		| "empty"
		| "invalid_rule"
		| "integrity"
		| "unlisted"
		| "missing";
	message: string;
	threatId?: string;
}

export interface ThreatLoadReport {
	threats: Threat[];
	errors: ThreatLoadError[];
}

export async function loadThreats(
	threatDir: string,
	logger: Logger = nullLogger,
	options: LoadThreatsOptions = {},
): Promise<Threat[]> {
	return (await loadThreatsWithReport(threatDir, logger, options)).threats;
}

/**
 * Load one rule directory and report every file or rule that did not load.
 * A caller that enforces must treat errors in the bundled rules as degraded
 * detection: the affected rules are simply absent from `threats`, so a corrupt
 * or emptied file would otherwise look exactly like "nothing matched".
 */
export async function loadThreatsWithReport(
	threatDir: string,
	logger: Logger = nullLogger,
	options: LoadThreatsOptions = {},
): Promise<ThreatLoadReport> {
	const threats: Threat[] = [];
	const errors: ThreatLoadError[] = [];
	const fail = (error: ThreatLoadError, context: Record<string, unknown> = {}): void => {
		errors.push(error);
		logger.error(error.message, { file: error.file, ...context });
	};
	const ruleError = (filename: string, record: Record<string, unknown>, message: string) =>
		fail(
			{
				file: filename,
				kind: "invalid_rule",
				message,
				...(typeof record.id === "string" ? { threatId: record.id } : {}),
			},
			{ threatId: record.id },
		);

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

	const coverage: ResourceManifestCoverage = options.manifest
		? await loadResourceManifestCoverage(threatDir, options.manifest)
		: { status: "none" };
	if (coverage.status === "invalid") {
		fail({
			file: coverage.manifestPath,
			kind: "integrity",
			message: `Rule files cannot be verified: ${coverage.reason}`,
		});
	} else if (coverage.status === "covered") {
		// A shipped rule file that is gone takes its rules with it.
		const present = new Set(files);
		for (const listed of coverage.files.keys()) {
			if (listed.endsWith(".yaml") && !listed.includes("/") && !present.has(listed)) {
				fail({
					file: listed,
					kind: "missing",
					message: `Rule file ${listed} is listed in the artifact manifest but missing`,
				});
			}
		}
	}

	for (const filename of files) {
		const filePath = join(threatDir, filename);
		let content: string;
		try {
			const bytes = await getFileContentRaw(filePath);
			const verified = checkCoveredFile(coverage, filename, bytes);
			if (verified && !verified.ok) {
				const unlisted = verified.reason === "unlisted";
				fail({
					file: filename,
					kind: unlisted ? "unlisted" : "integrity",
					message: unlisted
						? `Ignoring ${filename}: not listed in the artifact manifest`
						: `Ignoring ${filename}: does not verify against the artifact manifest (${verified.reason})`,
				});
				continue;
			}
			content = bytes.toString("utf8");
		} catch (e) {
			fail({ file: filename, kind: "read", message: `Failed to read ${filename}: ${String(e)}` });
			continue;
		}
		if (options.includeFile && !options.includeFile(content)) continue;

		let data: unknown;
		try {
			data = parseThreatYaml(content);
		} catch (e2) {
			fail({
				file: filename,
				kind: "parse",
				message: `Failed to parse ${filename}: ${String(e2)}`,
			});
			continue;
		}

		if (!Array.isArray(data)) {
			fail({
				file: filename,
				kind: data == null ? "empty" : "not_a_list",
				message: `Expected list in ${filename}, got ${data == null ? "an empty document" : typeof data}`,
			});
			continue;
		}
		if (data.length === 0) {
			fail({ file: filename, kind: "empty", message: `Rule file ${filename} contains no rules` });
			continue;
		}

		for (const entry of data) {
			if (typeof entry !== "object" || entry === null) {
				fail({
					file: filename,
					kind: "invalid_rule",
					message: `Skipping non-object entry in ${filename}`,
				});
				continue;
			}

			const record = entry as Record<string, unknown>;
			const keys = new Set(Object.keys(record));
			const missing = [...REQUIRED_FIELDS].filter((f) => !keys.has(f));
			if (missing.length > 0) {
				ruleError(
					filename,
					record,
					`Skipping threat in ${filename}: missing fields ${missing.join(", ")}`,
				);
				continue;
			}

			if (record.revoked === true) continue;
			if (isExpired(record)) continue;

			// Validate confidence is within valid range (0-1)
			const confidenceValue = Number(record.confidence);
			if (Number.isNaN(confidenceValue) || confidenceValue < 0 || confidenceValue > 1) {
				ruleError(
					filename,
					record,
					`Skipping threat ${record.id} in ${filename}: confidence must be between 0 and 1, got ${record.confidence}`,
				);
				continue;
			}

			let compiledPattern: RegExp;
			try {
				const flags = record.case_insensitive === true ? "i" : "";
				compiledPattern = new RegExp(record.pattern as string, flags);
			} catch (e) {
				ruleError(
					filename,
					record,
					`Skipping threat ${record.id}: invalid regex pattern - ${String(e)}`,
				);
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
				ruleError(
					filename,
					record,
					`Skipping threat ${record.id} in ${filename}: diff must be one of ${[...DIFF_MODES].join(", ")}`,
				);
				continue;
			}
			const minMatches = record.min_matches;
			if (
				minMatches !== undefined &&
				(!Number.isInteger(minMatches) ||
					(minMatches as number) < 1 ||
					(minMatches as number) > 1000)
			) {
				ruleError(
					filename,
					record,
					`Skipping threat ${record.id} in ${filename}: min_matches must be an integer between 1 and 1000`,
				);
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

	if (errors.length > 0) {
		logger.warn(`Loaded ${threats.length} threats from ${threatDir} with ${errors.length} errors`, {
			path: threatDir,
			errors: errors.map((error) => error.message),
		});
	} else {
		logger.debug(`Loaded ${threats.length} threats from ${threatDir}`);
	}

	return { threats, errors };
}

/** The merged rule set plus what the bundled (first) directory failed to load. */
export interface MergedThreatLoadReport {
	threats: Threat[];
	/** Rules loaded from the bundled (first) directory. */
	bundledCount: number;
	/** Files or rules in the bundled directory that did not load or verify. */
	bundledErrors: ThreatLoadError[];
	/** Set when the bundled directory itself could not be read. */
	bundledUnavailable?: string;
	/** User rule ids that clashed with an already loaded id and were ignored. */
	ignoredOverrides: string[];
}

/**
 * Load threats from multiple directories. The first directory holds the
 * bundled rules; later directories (user rules in ~/.singularity-aidr/threats)
 * are additive only. A later rule whose id is already loaded is ignored and
 * logged: a writable user directory must not be able to replace a shipped rule
 * (for example with a never-matching pattern) and so switch it off. Disabling
 * a shipped rule is what `disabled_threats` is for.
 */
export async function loadThreatsFromDirsWithReport(
	threatDirs: string[],
	logger: Logger = nullLogger,
	options: LoadThreatsOptions = {},
): Promise<MergedThreatLoadReport> {
	const merged = new Map<string, Threat>();
	const report: MergedThreatLoadReport = {
		threats: [],
		bundledCount: 0,
		bundledErrors: [],
		ignoredOverrides: [],
	};
	for (const [index, dir] of threatDirs.entries()) {
		if (!dir) continue;
		// Only the first (primary) directory is mandatory. An absent optional
		// directory (e.g. ~/.singularity-aidr/threats on a fresh install) is the
		// normal case, so it must not be reported as an error on every call.
		if (index > 0 && !(await isDirectory(dir))) {
			logger.debug(`Skipping absent optional threat directory: ${dir}`);
			continue;
		}
		try {
			const loaded = await loadThreatsWithReport(
				dir,
				logger,
				index === 0 ? options : { ...options, manifest: undefined },
			);
			if (index === 0) {
				report.bundledCount = loaded.threats.length;
				report.bundledErrors = loaded.errors;
			}
			for (const threat of loaded.threats) {
				if (merged.has(threat.id)) {
					report.ignoredOverrides.push(threat.id);
					logger.warn(
						`Ignoring rule ${threat.id} from ${dir}: a rule with this id is already loaded (user rules are additive only)`,
						{ threatId: threat.id, path: dir },
					);
					continue;
				}
				merged.set(threat.id, threat);
			}
		} catch (error) {
			if (index === 0) report.bundledUnavailable = String(error);
			// Skip directories that don't exist (e.g., optional user threats dir)
			// Only the first (primary) directory should be mandatory
			logger.debug(`Skipping threat directory: ${dir}`, { error: String(error) });
		}
	}
	report.threats = [...merged.values()];
	return report;
}

/** {@link loadThreatsFromDirsWithReport}, returning only the merged rules. */
export async function loadThreatsFromDirs(
	threatDirs: string[],
	logger: Logger = nullLogger,
	options: LoadThreatsOptions = {},
): Promise<Threat[]> {
	return (await loadThreatsFromDirsWithReport(threatDirs, logger, options)).threats;
}

async function isDirectory(path: string): Promise<boolean> {
	try {
		return (await stat(path)).isDirectory();
	} catch {
		return false;
	}
}
