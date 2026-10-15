/**
 * User-managed allowlist for overriding false positives.
 * JSON file at ~/.singularity-aidr/allowlist.json containing URLs, command hashes,
 * and file paths that the user has explicitly approved.
 */

import { BlockList, isIP } from "node:net";
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
	const configured = {
		internalNetworks: [...(config.internal_networks ?? [])],
		internalDomainSuffixes: [...(config.internal_domain_suffixes ?? [])],
	};
	const empty = (): Allowlist => ({ ...emptyAllowlist(), configured });

	let raw: string;
	try {
		raw = await getFileContent(path);
	} catch {
		return empty();
	}

	let data: unknown;
	try {
		data = JSON.parse(raw);
	} catch (e) {
		logger.warn(`Failed to load allowlist from ${path}`, { error: String(e) });
		return empty();
	}

	if (typeof data !== "object" || data === null || Array.isArray(data)) {
		logger.warn(`Allowlist file ${path} does not contain a JSON object`);
		return empty();
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
		...internalScopeFromFile(record, path, logger),
		configured,
	};
}

/** Every string of an optional list field; anything else is reported and dropped. */
function stringList(value: unknown, field: string, source: string, logger: Logger): string[] {
	if (value === undefined) return [];
	if (!Array.isArray(value)) {
		logger.warn(`Ignoring '${field}' in ${source}: expected a list of strings`);
		return [];
	}
	return value.filter((item): item is string => typeof item === "string");
}

function internalScopeFromFile(
	record: Record<string, unknown>,
	path: string,
	logger: Logger,
): Pick<Allowlist, "internalNetworks" | "internalDomainSuffixes"> {
	const networks = stringList(record.internal_networks, "internal_networks", path, logger);
	const suffixes = stringList(
		record.internal_domain_suffixes,
		"internal_domain_suffixes",
		path,
		logger,
	);
	return {
		...(networks.length > 0 ? { internalNetworks: networks } : {}),
		...(suffixes.length > 0 ? { internalDomainSuffixes: suffixes } : {}),
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

	// Configuration-provided internal scope is not written back: it belongs to
	// the configuration, and the file keeps only what was already in it.
	const data = {
		urls: serializeEntries(allowlist.urls),
		commands: serializeEntries(allowlist.commands),
		file_paths: serializeEntries(allowlist.filePaths),
		...(allowlist.internalNetworks?.length
			? { internal_networks: [...allowlist.internalNetworks] }
			: {}),
		...(allowlist.internalDomainSuffixes?.length
			? { internal_domain_suffixes: [...allowlist.internalDomainSuffixes] }
			: {}),
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

// ── Internal networks and domain suffixes (administrator-declared) ──────

/** Narrowest prefix an internal network may declare: anything broader is refused. */
const MIN_IPV4_PREFIX = 8;
const MIN_IPV6_PREFIX = 16;

/**
 * Suffixes that name a registry or a shared hosting platform rather than one
 * organisation. Trusting one would trust everyone who can register under it,
 * so such an entry is ignored. Not a complete public-suffix list: it catches
 * the common mistakes, and the administrator remains responsible for naming a
 * domain the organisation controls.
 */
const PUBLIC_SUFFIXES = new Set([
	"com.tr",
	"net.tr",
	"org.tr",
	"gov.tr",
	"edu.tr",
	"k12.tr",
	"bel.tr",
	"mil.tr",
	"pol.tr",
	"tsk.tr",
	"gen.tr",
	"web.tr",
	"biz.tr",
	"info.tr",
	"av.tr",
	"dr.tr",
	"co.uk",
	"org.uk",
	"com.au",
	"co.jp",
	"com.br",
	"github.io",
	"gitlab.io",
	"pages.dev",
	"workers.dev",
	"vercel.app",
	"netlify.app",
	"herokuapp.com",
	"azurewebsites.net",
	"cloudfront.net",
	"amazonaws.com",
	"appspot.com",
	"web.app",
	"firebaseapp.com",
	"ngrok.io",
	"ngrok-free.app",
	"trycloudflare.com",
	"blob.core.windows.net",
]);

/** Single-label suffixes reserved for private use (RFC 6762, RFC 8375, common practice). */
const PRIVATE_SINGLE_LABELS = new Set([
	"local",
	"lan",
	"internal",
	"intranet",
	"corp",
	"home",
	"localdomain",
]);

const DOMAIN_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

/**
 * Normalise one administrator-supplied domain suffix, or null when it is not
 * acceptable (malformed, a bare public label, or a shared public suffix).
 */
function normalizeInternalDomainSuffix(raw: string): string | null {
	const suffix = raw
		.trim()
		.toLowerCase()
		.replace(/^\*?\./, "")
		.replace(/\.$/, "");
	if (!suffix || suffix.length > 253) return null;
	const labels = suffix.split(".");
	if (!labels.every((label) => DOMAIN_LABEL.test(label))) return null;
	if (labels.length === 1 && !PRIVATE_SINGLE_LABELS.has(suffix)) return null;
	if (PUBLIC_SUFFIXES.has(suffix)) return null;
	return suffix;
}

/** Parse one CIDR (or bare address) into a family/network/prefix, or null when invalid or too broad. */
function parseInternalNetwork(
	raw: string,
): { family: "ipv4" | "ipv6"; network: string; prefix: number } | null {
	const [address = "", prefixText, extra] = raw.trim().split("/");
	if (extra !== undefined) return null;
	const version = isIP(address);
	if (version === 0) return null;
	const family = version === 4 ? "ipv4" : "ipv6";
	const max = version === 4 ? 32 : 128;
	const prefix = prefixText === undefined ? max : Number(prefixText);
	if (!/^\d{1,3}$/.test(prefixText ?? String(max)) || !Number.isInteger(prefix)) return null;
	if (prefix > max || prefix < (version === 4 ? MIN_IPV4_PREFIX : MIN_IPV6_PREFIX)) return null;
	return { family, network: address, prefix };
}

interface InternalScope {
	networks: BlockList;
	hasNetworks: boolean;
	suffixes: string[];
}

function internalScopeOf(allowlist: Allowlist): InternalScope {
	const networks = new BlockList();
	let hasNetworks = false;
	for (const raw of [
		...(allowlist.internalNetworks ?? []),
		...(allowlist.configured?.internalNetworks ?? []),
	]) {
		const parsed = parseInternalNetwork(raw);
		if (!parsed) continue;
		networks.addSubnet(parsed.network, parsed.prefix, parsed.family);
		hasNetworks = true;
	}
	const suffixes = [
		...(allowlist.internalDomainSuffixes ?? []),
		...(allowlist.configured?.internalDomainSuffixes ?? []),
	]
		.map(normalizeInternalDomainSuffix)
		.filter((suffix): suffix is string => suffix !== null);
	return { networks, hasNetworks, suffixes };
}

/**
 * Whether a URL points at an administrator-declared internal host: a literal
 * IP inside an internal network, or a hostname under an internal domain
 * suffix. URLs carrying credentials (`user@host`) never qualify, since the
 * visible prefix of such a URL is not where it goes.
 */
function isInternalUrl(url: string, scope: InternalScope): boolean {
	if (!scope.hasNetworks && scope.suffixes.length === 0) return false;
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return false;
	}
	if (parsed.username || parsed.password) return false;
	const host = parsed.hostname.toLowerCase().replace(/^\[(.*)\]$/, "$1");
	if (!host) return false;
	const version = isIP(host);
	if (version !== 0) {
		return scope.hasNetworks && scope.networks.check(host, version === 4 ? "ipv4" : "ipv6");
	}
	const bare = host.replace(/\.$/, "");
	return scope.suffixes.some((suffix) => bare === suffix || bare.endsWith(`.${suffix}`));
}

/**
 * The artifacts an allowlist entry covers. An entry suppresses only the
 * signals of what it names:
 *
 * - a command (by hash) covers its own command artifacts and the URL/path
 *   artifacts extracted from that command text;
 * - a file path covers that file path artifact only (content written to it is
 *   still inspected);
 * - a URL covers that URL artifact only;
 * - an internal network / domain suffix covers the URL artifacts whose host
 *   it names (the command those URLs appear in is still inspected).
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
	const internal = internalScopeOf(allowlist);
	const coveredByEntry = (artifact: Artifact): boolean => {
		if (artifact.type === "file_path") {
			return filePathKeys.has(allowlistPathKey(artifact.value, workingDirectory));
		}
		return (
			artifact.type === "url" &&
			(normalizeUrl(artifact.value) in allowlist.urls || isInternalUrl(artifact.value, internal))
		);
	};
	for (const artifact of artifacts) {
		if (covered.has(artifact)) continue;
		const inAllowlistedCommand =
			(artifact.type === "url" || artifact.type === "file_path") &&
			allowlistedCommands.some((command) => command.includes(artifact.value));
		if (inAllowlistedCommand || coveredByEntry(artifact)) covered.add(artifact);
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
