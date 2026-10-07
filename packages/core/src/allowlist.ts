/**
 * User-managed allowlist for overriding false positives.
 * JSON file at ~/.singularity-aidr/allowlist.json containing URLs, command hashes,
 * and file paths that the user has explicitly approved.
 */

import { resolve } from "node:path";
import { resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import type { Allowlist, AllowlistConfig, AllowlistEntry, Artifact, Logger } from "./types.js";
import { nullLogger } from "./types.js";
import { hashCommand, normalizeFilePath, normalizeUrl } from "./url-utils.js";

export function emptyAllowlist(): Allowlist {
	return { urls: {}, commands: {}, filePaths: {} };
}

function addEntry(
	record: Record<string, AllowlistEntry>,
	key: string,
	reason: string,
	originalVerdict: string,
): void {
	record[key] = { addedAt: new Date().toISOString(), reason, originalVerdict };
}

function removeEntry(record: Record<string, AllowlistEntry>, key: string): boolean {
	if (key in record) {
		delete record[key];
		return true;
	}
	return false;
}

function parseEntries(raw: Record<string, unknown>): Record<string, AllowlistEntry> {
	const entries: Record<string, AllowlistEntry> = {};
	for (const [key, entryData] of Object.entries(raw)) {
		if (typeof entryData !== "object" || entryData === null) continue;
		const data = entryData as Record<string, unknown>;
		if (
			typeof data.added_at === "string" &&
			typeof data.reason === "string" &&
			typeof data.original_verdict === "string"
		) {
			entries[key] = {
				addedAt: data.added_at,
				reason: data.reason,
				originalVerdict: data.original_verdict,
			};
		}
	}
	return entries;
}

export async function loadAllowlist(
	config: AllowlistConfig,
	logger: Logger = nullLogger,
): Promise<Allowlist> {
	const path = resolvePath(config.path);

	let raw: string;
	try {
		raw = await getFileContent(path);
	} catch {
		return emptyAllowlist();
	}

	let data: unknown;
	try {
		data = JSON.parse(raw);
	} catch (e) {
		logger.warn(`Failed to load allowlist from ${path}`, { error: String(e) });
		return emptyAllowlist();
	}

	if (typeof data !== "object" || data === null || Array.isArray(data)) {
		logger.warn(`Allowlist file ${path} does not contain a JSON object`);
		return emptyAllowlist();
	}

	const record = data as Record<string, unknown>;
	const rawUrls = parseEntries((record.urls ?? {}) as Record<string, unknown>);
	// Normalize URL keys on load for backward compatibility with pre-normalization data
	const urls: Record<string, AllowlistEntry> = {};
	for (const [key, entry] of Object.entries(rawUrls)) {
		urls[normalizeUrl(key)] = entry;
	}
	// Normalize file path keys on load
	const rawFilePaths = parseEntries((record.file_paths ?? {}) as Record<string, unknown>);
	const filePaths: Record<string, AllowlistEntry> = {};
	for (const [key, entry] of Object.entries(rawFilePaths)) {
		filePaths[normalizeFilePath(key)] = entry;
	}
	return {
		urls,
		commands: parseEntries((record.commands ?? {}) as Record<string, unknown>),
		filePaths,
	};
}

export async function saveAllowlist(
	allowlist: Allowlist,
	config: AllowlistConfig,
	logger: Logger = nullLogger,
): Promise<boolean> {
	const path = resolvePath(config.path);

	const serializeEntries = (entries: Record<string, AllowlistEntry>) =>
		Object.fromEntries(
			Object.entries(entries).map(([key, entry]) => [
				key,
				{
					added_at: entry.addedAt,
					reason: entry.reason,
					original_verdict: entry.originalVerdict,
				},
			]),
		);

	const data = {
		urls: serializeEntries(allowlist.urls),
		commands: serializeEntries(allowlist.commands),
		file_paths: serializeEntries(allowlist.filePaths),
	};

	try {
		await atomicWriteJson(path, data);
		return true;
	} catch (e) {
		logger.warn(`Failed to save allowlist to ${path}`, { error: String(e) });
		return false;
	}
}

/**
 * A file path as the allowlist compares it: `~` expanded, normalized, and
 * resolved against the working directory. A relative entry or artifact
 * therefore names one file under that directory, never "any file with this
 * relative name anywhere".
 */
function allowlistPathKey(raw: string, workingDirectory: string): string {
	const resolved = resolve(workingDirectory, normalizeFilePath(raw));
	return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

/**
 * The artifacts an allowlist entry covers. An entry suppresses only the
 * signals of what it names:
 *
 * - a command (by hash) covers its own command artifacts and the URL/path
 *   artifacts extracted from that command text;
 * - a file path covers that file path artifact only (content written to it is
 *   still inspected);
 * - a URL covers that URL artifact only.
 *
 * Everything else stays subject to detection.
 */
export function allowlistedArtifacts(
	allowlist: Allowlist,
	artifacts: readonly Artifact[],
	workingDirectory: string = process.cwd(),
): Set<Artifact> {
	const covered = new Set<Artifact>();
	const allowlistedCommands: string[] = [];
	for (const artifact of artifacts) {
		if (artifact.type === "command" && hashCommand(artifact.value) in allowlist.commands) {
			covered.add(artifact);
			allowlistedCommands.push(artifact.value);
		}
	}
	const filePathKeys = new Set(
		Object.keys(allowlist.filePaths).map((key) => allowlistPathKey(key, workingDirectory)),
	);
	for (const artifact of artifacts) {
		if (covered.has(artifact)) continue;
		if (
			(artifact.type === "url" || artifact.type === "file_path") &&
			allowlistedCommands.some((command) => command.includes(artifact.value))
		) {
			covered.add(artifact);
		} else if (
			artifact.type === "file_path" &&
			filePathKeys.has(allowlistPathKey(artifact.value, workingDirectory))
		) {
			covered.add(artifact);
		} else if (artifact.type === "url" && normalizeUrl(artifact.value) in allowlist.urls) {
			covered.add(artifact);
		}
	}
	return covered;
}

/**
 * True only when every artifact of the call is covered by an allowlist entry.
 * One allowlisted artifact never clears the rest of the call.
 */
export function isAllowlisted(
	allowlist: Allowlist,
	artifacts: readonly Artifact[],
	workingDirectory?: string,
): boolean {
	if (artifacts.length === 0) return false;
	const covered = allowlistedArtifacts(allowlist, artifacts, workingDirectory);
	return artifacts.every((artifact) => covered.has(artifact));
}

export function addUrl(
	allowlist: Allowlist,
	url: string,
	reason: string,
	originalVerdict: string,
): void {
	addEntry(allowlist.urls, normalizeUrl(url), reason, originalVerdict);
}

export function addCommand(
	allowlist: Allowlist,
	command: string,
	reason: string,
	originalVerdict: string,
): void {
	addEntry(allowlist.commands, hashCommand(command), reason, originalVerdict);
}

/**
 * A relative path is stored resolved against the current working directory,
 * so the entry names one file rather than every file with that relative name.
 */
function storedFilePathKey(filePath: string): string {
	return normalizeFilePath(resolve(normalizeFilePath(filePath)));
}

export function addFilePath(
	allowlist: Allowlist,
	filePath: string,
	reason: string,
	originalVerdict: string,
): void {
	addEntry(allowlist.filePaths, storedFilePathKey(filePath), reason, originalVerdict);
}

export function removeFilePath(allowlist: Allowlist, filePath: string): boolean {
	// Also removes a legacy entry stored before relative paths were resolved.
	const legacy = removeEntry(allowlist.filePaths, normalizeFilePath(filePath));
	return removeEntry(allowlist.filePaths, storedFilePathKey(filePath)) || legacy;
}

export function removeUrl(allowlist: Allowlist, url: string): boolean {
	return removeEntry(allowlist.urls, normalizeUrl(url));
}

export function removeCommand(allowlist: Allowlist, commandHash: string): boolean {
	return removeEntry(allowlist.commands, commandHash);
}
