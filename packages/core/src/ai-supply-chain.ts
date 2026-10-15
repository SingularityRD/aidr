/**
 * AI model supply chain: trusted model sources.
 *
 * The rules themselves are data (`threats/ai-supply-chain.yaml`). This module
 * owns the one decision a regular expression cannot make: whether the
 * publisher or host a model-source rule matched is on the trusted list.
 *
 * Trusted sources are data too: `allowlists/model-sources/*.yaml` (shipped)
 * plus `ai_supply_chain.trusted_model_orgs` / `trusted_model_hosts` in the
 * local configuration. They live in a subdirectory of `allowlists/` because
 * every `*.yaml` directly under it is read as a trusted *installer* domain
 * list (see `trusted-domains.ts`), and a model hub must never suppress a
 * pipe-to-shell rule.
 *
 * Failure policy: a missing or unreadable list trusts nothing, so the source
 * rules keep asking. That is the conservative direction for a suppression list.
 */

import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { extractUrls } from "./extractors.js";
import {
	loadResourceManifestCoverage,
	readShippedResourceText,
} from "./integrity/resource-manifest.js";
import type { AiSupplyChainConfig, Logger } from "./types.js";
import { nullLogger } from "./types.js";
import { parseShippedYaml } from "./yaml-parse-cache.js";

/** Subdirectory of the allowlists directory holding trusted model sources. */
export const MODEL_SOURCES_SUBDIR = "model-sources";

export interface TrustedModelSources {
	/** Lower-cased Hugging Face organisation / user names. */
	orgs: ReadonlySet<string>;
	/** Lower-cased hosts, matched by suffix on a dot boundary. */
	hosts: readonly string[];
}

export const NO_TRUSTED_MODEL_SOURCES: TrustedModelSources = Object.freeze({
	orgs: new Set<string>(),
	hosts: [],
});

/** Rules that report an unvetted *publisher*: suppressed when every named repository's org is trusted. */
const ORG_SUPPRESSIBLE: ReadonlySet<string> = new Set(["AISC-007", "AISC-008", "AISC-012"]);
/** Rules that report an unvetted *host*: suppressed when every URL is HTTPS on a trusted host. */
const HOST_SUPPRESSIBLE: ReadonlySet<string> = new Set(["AISC-013"]);

const ORG_NAME = /^[A-Za-z0-9][\w.-]{0,95}$/;
const HOST_NAME =
	/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+$/;

function normalizeOrg(value: unknown): string | null {
	if (typeof value !== "string") return null;
	const trimmed = value.trim();
	return ORG_NAME.test(trimmed) ? trimmed.toLowerCase() : null;
}

function normalizeHost(value: unknown): string | null {
	if (typeof value !== "string") return null;
	const trimmed = value
		.trim()
		.toLowerCase()
		.replace(/^\*?\./, "");
	return HOST_NAME.test(trimmed) ? trimmed : null;
}

function readEntries(
	data: Record<string, unknown>,
	listKey: "orgs" | "hosts",
	field: "org" | "host",
	file: string,
	logger: Logger,
): unknown[] {
	const list = data[listKey];
	if (list === undefined) return [];
	if (!Array.isArray(list)) {
		logger.warn(`Ignoring '${listKey}' in ${file}: expected a list`);
		return [];
	}
	const values: unknown[] = [];
	for (const entry of list) {
		if (
			entry &&
			typeof entry === "object" &&
			typeof (entry as Record<string, unknown>).reason === "string"
		) {
			values.push((entry as Record<string, unknown>)[field]);
		} else {
			logger.warn(`Skipping ${field} entry without a '${field}' and a 'reason' in ${file}`);
		}
	}
	return values;
}

/**
 * Load the trusted model sources: shipped lists under
 * `<allowlistsDir>/model-sources/*.yaml` plus the configured additions.
 */
export async function loadTrustedModelSources(
	allowlistsDir: string,
	config?: Partial<AiSupplyChainConfig>,
	logger: Logger = nullLogger,
): Promise<TrustedModelSources> {
	const orgs = new Set<string>();
	const hosts = new Set<string>();
	const addOrg = (value: unknown, origin: string): void => {
		const org = normalizeOrg(value);
		if (org) orgs.add(org);
		else logger.warn(`Ignoring invalid trusted model organisation from ${origin}`);
	};
	const addHost = (value: unknown, origin: string): void => {
		const host = normalizeHost(value);
		if (host) hosts.add(host);
		else logger.warn(`Ignoring invalid trusted model host from ${origin}`);
	};

	// JavaScript callers may omit the directory; that trusts nothing from disk.
	const dir = typeof allowlistsDir === "string" ? join(allowlistsDir, MODEL_SOURCES_SUBDIR) : "";
	let files: string[] = [];
	try {
		files = dir ? (await readdir(dir)).filter((name) => name.endsWith(".yaml")).sort() : [];
	} catch {
		logger.debug("Trusted model-source directory is absent; no model source is trusted", {
			path: dir,
		});
	}
	// Shipped model-source lists are a closed set: when a manifest covers the
	// allowlists directory, an unlisted or modified list is ignored, not trusted.
	const coverage =
		files.length > 0
			? await loadResourceManifestCoverage(allowlistsDir)
			: ({ status: "none" } as const);
	for (const file of files) {
		let data: unknown;
		try {
			const shipped = await readShippedResourceText(
				coverage,
				`${MODEL_SOURCES_SUBDIR}/${file}`,
				join(dir, file),
				logger,
			);
			if (shipped === null) continue;
			data = parseShippedYaml(shipped);
		} catch (error) {
			logger.warn(`Failed to read trusted model sources from ${file}`, { error: String(error) });
			continue;
		}
		if (!data || typeof data !== "object" || Array.isArray(data)) {
			logger.warn(`Expected a mapping with 'orgs'/'hosts' in ${file}`);
			continue;
		}
		const record = data as Record<string, unknown>;
		for (const org of readEntries(record, "orgs", "org", file, logger)) addOrg(org, file);
		for (const host of readEntries(record, "hosts", "host", file, logger)) addHost(host, file);
	}

	for (const org of config?.trusted_model_orgs ?? [])
		addOrg(org, "ai_supply_chain.trusted_model_orgs");
	for (const host of config?.trusted_model_hosts ?? []) {
		addHost(host, "ai_supply_chain.trusted_model_hosts");
	}
	return { orgs, hosts: [...hosts] };
}

function isTrustedHost(hostname: string, sources: TrustedModelSources): boolean {
	const host = hostname.toLowerCase();
	return sources.hosts.some((trusted) => host === trusted || host.endsWith(`.${trusted}`));
}

const HUGGING_FACE_HOSTS: ReadonlySet<string> = new Set([
	"huggingface.co",
	"www.huggingface.co",
	"hf.co",
	"www.hf.co",
]);

/** Any host of the Hugging Face family, including its LFS/CDN download hosts. */
function isHuggingFaceFamilyHost(hostname: string): boolean {
	const host = hostname.toLowerCase();
	return ["huggingface.co", "hf.co"].some((base) => host === base || host.endsWith(`.${base}`));
}

/**
 * A hub endpoint override (`HF_ENDPOINT=…`, `endpoint="…"`, `--endpoint …`): the
 * repository id then names nothing on the real hub, the bytes come from wherever
 * the endpoint points, so a trusted organisation in the id proves nothing.
 */
const HUB_ENDPOINT_OVERRIDE =
	/\bHF_(?:HUB_)?ENDPOINT\b|(?:^|[\s,(])--?endpoint\b|\bendpoint\s{0,4}=/i;
const HUGGING_FACE_REPO_KINDS: ReadonlySet<string> = new Set(["datasets", "spaces", "models"]);

/**
 * The repository organisation a Hugging Face Hub URL downloads from, or null
 * when the URL does not name one (a CDN object, the site root).
 */
function huggingFaceOrgFromUrl(url: URL): string | null {
	if (!HUGGING_FACE_HOSTS.has(url.hostname.toLowerCase())) return null;
	const segments = url.pathname.split("/").filter((segment) => segment !== "");
	const offset = HUGGING_FACE_REPO_KINDS.has(segments[0] ?? "") ? 1 : 0;
	const org = segments[offset];
	return segments.length > offset + 1 && org ? org.toLowerCase() : null;
}

/**
 * Repository ids (`org/name`) in the syntactic slots the model-source rules
 * capture: a download/serve argument, the first argument of `from_pretrained` /
 * `hf_hub_download` / `snapshot_download`, and `repo_id=` / `model=` /
 * `pretrained=` / `--model` values. Other paths in the matched text (a
 * `cache_dir`, a `--local-dir`) are deliberately not read as publishers.
 */
const REPO_SLOT = new RegExp(
	String.raw`(?:\b(?:download|serve)\s{1,4}(?:--[\w-]{1,30}(?:=[^\s]{1,100}|\s{1,4}(?!-)[^\s]{1,100})?\s{1,4}){0,4}|\b(?:from_pretrained|hf_hub_download|snapshot_download)\s{0,4}\(\s{0,20}(?:\w{1,40}\s{0,4}=\s{0,4})?|\b(?:repo_id|model|model_id|pretrained)\s{0,4}[=:]\s{0,4}|--model(?:[-_]id)?[= ]\s{0,4})["']?([A-Za-z0-9][\w.-]{0,95})/[\w.-]{1,96}`,
	"g",
);

/** Organisations of the repositories a model-source match names. */
export function modelRepoOrgs(matchValue: string): string[] {
	const orgs: string[] = [];
	for (const match of matchValue.matchAll(REPO_SLOT)) {
		if (match[1]) orgs.push(match[1].toLowerCase());
	}
	return orgs;
}

/**
 * True when a model-source rule matched only trusted sources, so the match is
 * not a finding. Rules that report unsafe *loading* are never suppressed.
 */
export function isTrustedModelSourceMatch(
	threatId: string,
	matchValue: string,
	sources: TrustedModelSources,
	/** The whole code block or command the match came from, for context the match omits. */
	context = matchValue,
): boolean {
	if (ORG_SUPPRESSIBLE.has(threatId)) {
		if (sources.orgs.size === 0) return false;
		if (HUB_ENDPOINT_OVERRIDE.test(context) || HUB_ENDPOINT_OVERRIDE.test(matchValue)) return false;
		const orgs = modelRepoOrgs(matchValue);
		return orgs.length > 0 && orgs.every((org) => sources.orgs.has(org));
	}
	if (HOST_SUPPRESSIBLE.has(threatId)) {
		if (sources.hosts.length === 0) return false;
		const urls = extractUrls(matchValue);
		if (urls.length === 0) return false;
		return urls.every((raw) => {
			let url: URL;
			try {
				url = new URL(raw);
			} catch {
				return false;
			}
			if (url.protocol !== "https:" || !isTrustedHost(url.hostname, sources)) return false;
			// A hub host is only as trustworthy as the repository on it. Anyone can
			// upload to the hub, so a Hugging Face URL that names no repository (an
			// LFS/CDN object URL) is not trusted either.
			const org = huggingFaceOrgFromUrl(url);
			if (org === null) return !isHuggingFaceFamilyHost(url.hostname);
			return sources.orgs.has(org);
		});
	}
	return false;
}
