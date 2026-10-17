#!/usr/bin/env node
/**
 * Release pipeline for license-bound intel update packs (docs/operations/intel-pack-releases.md).
 *
 *   build   threats/*.yaml + an optional curated intel directory -> an unsigned pack
 *           directory in the format packages/core/src/intel loads (manifest.json with
 *           issued_at, optional expires_at, optional audience.customer_ids, per-file
 *           SHA-256, `lists/<kind>` files). Encrypt it afterwards, if wanted, with
 *           scripts/intel-pack-keys.mjs encrypt-pack, then sign it with
 *           scripts/sign-intel-pack-manifest.mjs (--audience checks the signed audience).
 *   verify  the signed pack with the endpoint's own code: the offline importer's
 *           verifier (signature against the published trusted key, digests, expiry),
 *           then the core loader (`loadMergedIntelFromDisk`) in a disposable HOME,
 *           whose loaded entry counts must equal the counts the signed manifest
 *           declares, and a tampered copy must be refused. Then core `acceptPack`
 *           against sample licenses signed with a throwaway key: in-term accepted,
 *           out-of-term refused, audience mismatch refused, a revoked license
 *           refused. A real `aidr-license-revocations-v1` list, when given, is
 *           verified against the license public-key registry.
 *   export  the verified pack as release assets and an offline (air-gapped) folder:
 *           the single-file `aidr-intel-pack-bundle-v1`, the public trusted key, the
 *           revocation list, SHA256SUMS and import instructions (EN/TR).
 *
 * What the threats directory contributes: the endpoint's intel kinds are lists
 * (hosts, package names, hashes, domain risk), not regex rules, so only rules that
 * are an exact host literal with `action: block` on `match_on: url` become
 * url_denylist entries; every other rule ships with the connector release. The
 * manifest records the SHA-256 of the rule set it was built against
 * (`source.threats_sha256`) so a pack can be traced to its rules.
 *
 * Signing keys are never read here. Nothing contacts the network.
 */
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { createBundle, loadTrustedKeys, readPackSource, verifyOfflinePack } from "./import-offline-pack.mjs";
import { parseSharedPackKeys } from "./intel-pack-keys.mjs";

export class PackReleaseError extends Error {
	constructor(message) {
		super(message);
		this.name = "PackReleaseError";
	}
}

const DAY_MS = 24 * 60 * 60 * 1000;
const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const CUSTOMER_ID = /^[a-z0-9][a-z0-9-]{1,31}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const PACKAGE_NAME = /^[@A-Za-z0-9][@A-Za-z0-9._/:-]{0,213}$/;
const ISO_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/** Curated intel files: the closed set of names an intel directory may hold, by kind. */
export const INTEL_FILES = Object.freeze({
	url_denylist: "url_denylist.txt",
	url_allowlist: "url_allowlist.txt",
	domain_risk: "domain_risk.json",
	package_name_denylist: "package_name_denylist.txt",
	package_hash_denylist: "package_hash_denylist.txt",
	plugin_signature_denylist: "plugin_signature_denylist.txt",
});
const KINDS = Object.keys(INTEL_FILES);

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
export const isoSeconds = (ms) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z");

async function loadCore() {
	try {
		const [loader, acceptance, revocations, license, licenseVerify, threats] = await Promise.all([
			import("../packages/core/dist/intel/loader.js"),
			import("../packages/core/dist/intel/acceptance.js"),
			import("../packages/core/dist/intel/license-revocations.js"),
			import("../packages/core/dist/customer-license/index.js"),
			import("../packages/core/dist/customer-license/verify.js"),
			import("../packages/core/dist/threat-loader.js"),
		]);
		return {
			loadMergedIntelFromDisk: loader.loadMergedIntelFromDisk,
			acceptPack: acceptance.acceptPack,
			verifyLicenseRevocations: revocations.verifyLicenseRevocations,
			LICENSE_REVOCATIONS_FORMAT: revocations.LICENSE_REVOCATIONS_FORMAT,
			verifyLicense: license.verifyLicense,
			parseLicensePublicKeyRegistry: license.parseLicensePublicKeyRegistry,
			readSignedDocumentFile: license.readSignedDocumentFile,
			licenseCanonicalJson: licenseVerify.licenseCanonicalJson,
			parseThreatYaml: threats.parseThreatYaml,
		};
	} catch (error) {
		throw new PackReleaseError(`the core build is unavailable (${error?.code ?? error?.message}); run "pnpm -C packages/core build" first`);
	}
}

function regularFile(path, label) {
	const stats = lstatSync(path, { throwIfNoEntry: false });
	if (!stats || stats.isSymbolicLink() || !stats.isFile()) throw new PackReleaseError(`${label} must be an existing regular, non-symlink file`);
	return readFileSync(path);
}

function lines(text) {
	return text
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter((line) => line && !line.startsWith("#"));
}

/** A host from a host or URL line; anything else is refused (never silently dropped). */
export function normalizeHost(value, where) {
	let host = value.toLowerCase();
	if (/^[a-z][a-z0-9+.-]*:\/\//.test(host)) {
		try {
			host = new URL(host).hostname;
		} catch {
			throw new PackReleaseError(`${where}: ${JSON.stringify(value)} is not a URL`);
		}
	}
	host = host.replace(/^\.+|\.+$/g, "");
	if (!HOST.test(host)) throw new PackReleaseError(`${where}: ${JSON.stringify(value)} is not a host name`);
	return host;
}

/** Parse and validate one curated intel file into sorted, unique entries. */
export function parseIntelFile(kind, text, where) {
	if (kind === "domain_risk") {
		let data;
		try {
			data = JSON.parse(text);
		} catch {
			throw new PackReleaseError(`${where} is not JSON`);
		}
		if (!Array.isArray(data)) throw new PackReleaseError(`${where} must be a JSON array`);
		const byDomain = new Map();
		for (const [index, item] of data.entries()) {
			const at = `${where}[${index}]`;
			if (!item || typeof item !== "object" || Array.isArray(item)) throw new PackReleaseError(`${at} must be an object`);
			const unknown = Object.keys(item).filter((key) => !["domain", "action", "severity", "confidence", "reason"].includes(key));
			if (unknown.length) throw new PackReleaseError(`${at} has unknown field(s): ${unknown.join(", ")}`);
			const domain = normalizeHost(String(item.domain ?? ""), at);
			if (!["allow", "ask", "deny"].includes(item.action)) throw new PackReleaseError(`${at}.action must be allow, ask or deny`);
			if (!["critical", "high", "medium", "low"].includes(item.severity)) throw new PackReleaseError(`${at}.severity must be critical, high, medium or low`);
			if (item.confidence !== undefined && !(typeof item.confidence === "number" && item.confidence >= 0 && item.confidence <= 1)) {
				throw new PackReleaseError(`${at}.confidence must be a number between 0 and 1`);
			}
			if (item.reason !== undefined && (typeof item.reason !== "string" || item.reason.length > 500)) throw new PackReleaseError(`${at}.reason must be a string of at most 500 characters`);
			if (byDomain.has(domain)) throw new PackReleaseError(`${at}: ${domain} is listed twice`);
			byDomain.set(domain, { domain, action: item.action, severity: item.severity, ...(item.confidence === undefined ? {} : { confidence: item.confidence }), ...(item.reason === undefined ? {} : { reason: item.reason }) });
		}
		return [...byDomain.values()].sort((a, b) => a.domain.localeCompare(b.domain));
	}
	const entries = lines(text).map((line, index) => {
		const at = `${where} line ${index + 1}`;
		if (kind === "url_denylist" || kind === "url_allowlist") return normalizeHost(line, at);
		if (kind === "package_name_denylist") {
			if (!PACKAGE_NAME.test(line)) throw new PackReleaseError(`${at}: ${JSON.stringify(line)} is not a package name`);
			return line;
		}
		const hash = line.toLowerCase();
		if (!SHA256_HEX.test(hash)) throw new PackReleaseError(`${at}: expected a SHA-256 hex digest`);
		return hash;
	});
	return [...new Set(entries)].sort();
}

/** Read a curated intel directory (closed set of file names; README.md is ignored). */
export function readIntelDir(dir) {
	const root = resolve(dir);
	const stats = lstatSync(root, { throwIfNoEntry: false });
	if (!stats || stats.isSymbolicLink() || !stats.isDirectory()) throw new PackReleaseError(`intel directory ${root} must be an existing, non-symlink directory`);
	const byName = new Map(Object.entries(INTEL_FILES).map(([kind, name]) => [name, kind]));
	const out = {};
	const digest = createHash("sha256");
	for (const name of readdirSync(root).sort()) {
		if (name === "README.md") continue;
		const kind = byName.get(name);
		if (!kind) throw new PackReleaseError(`intel directory holds an unknown file ${name}; allowed: ${Object.values(INTEL_FILES).join(", ")}`);
		const bytes = regularFile(join(root, name), `intel file ${name}`);
		digest.update(`${name}\0${sha256(bytes)}\n`);
		out[kind] = parseIntelFile(kind, bytes.toString("utf8"), name);
	}
	return { entries: out, sha256: digest.digest("hex") };
}

/**
 * The host of a rule pattern that is nothing but an escaped host literal, with
 * optional `^`, `https?://` and a trailing `$`, `/` or `(?:/|$)`; else null.
 */
export function exactHostOfPattern(pattern) {
	if (typeof pattern !== "string") return null;
	const match = /^\^?(?:https\?:\/\/|https:\/\/|http:\/\/)?((?:[a-z0-9-]+\\\.)+[a-z0-9-]+)(?:\$|\/|\(\?:\/\|\$\))?$/i.exec(pattern);
	if (!match) return null;
	const host = match[1].replaceAll("\\.", ".").toLowerCase();
	return HOST.test(host) ? host : null;
}

/** Rules from threats/*.yaml: the rule-set digest and the url_denylist entries derived from them. */
export function readThreats(dir, parseThreatYaml, nowMs) {
	const root = resolve(dir);
	const files = readdirSync(root).filter((name) => name.endsWith(".yaml")).sort();
	if (files.length === 0) throw new PackReleaseError(`no threat rule files (*.yaml) in ${root}`);
	const digest = createHash("sha256");
	const hosts = new Set();
	const derivedRuleIds = [];
	let rules = 0;
	for (const name of files) {
		const text = regularFile(join(root, name), `threat file ${name}`).toString("utf8");
		digest.update(`${name}\0${sha256(Buffer.from(text, "utf8"))}\n`);
		const parsed = parseThreatYaml(text);
		if (!Array.isArray(parsed)) throw new PackReleaseError(`threat file ${name} is not a rule list`);
		for (const rule of parsed) {
			rules += 1;
			if (!rule || typeof rule !== "object" || rule.revoked === true || rule.action !== "block") continue;
			const matchOn = Array.isArray(rule.match_on) ? rule.match_on : [rule.match_on];
			if (!matchOn.includes("url")) continue;
			if (rule.expires_at !== null && rule.expires_at !== undefined && !(Date.parse(rule.expires_at) > nowMs)) continue;
			const host = exactHostOfPattern(rule.pattern);
			if (!host) continue;
			hosts.add(host);
			derivedRuleIds.push(String(rule.id));
		}
	}
	return { sha256: digest.digest("hex"), rules, files: files.length, hosts: [...hosts].sort(), derivedRuleIds: derivedRuleIds.sort() };
}

/** Build an unsigned pack directory. Returns { outcome, manifest } ("empty" writes nothing). */
export async function buildPack(options, core) {
	const lib = core ?? (await loadCore());
	const { out, packId, version, keyId, threatsDir = "threats", intelDir, audience = [], ifEmpty = "fail", sourceRef } = options;
	if (!SEGMENT.test(String(packId ?? ""))) throw new PackReleaseError("--pack-id must be 1..128 characters of [A-Za-z0-9._-]");
	if (!SEGMENT.test(String(version ?? ""))) throw new PackReleaseError("--version must be a single path-safe segment such as 2026.1014.7");
	if (!SEGMENT.test(String(keyId ?? ""))) throw new PackReleaseError("--key-id must name the publisher key in the trusted-keys file");
	const nowMs = options.now ?? Date.now();
	const issuedAt = options.issuedAt ?? isoSeconds(nowMs);
	if (!ISO_SECONDS.test(issuedAt) || !Number.isFinite(Date.parse(issuedAt))) throw new PackReleaseError("--issued-at must be YYYY-MM-DDTHH:MM:SSZ");
	let expiresAt = options.expiresAt;
	if (expiresAt === undefined && options.expiresInDays !== undefined) {
		const days = Number(options.expiresInDays);
		if (!Number.isInteger(days) || days < 1 || days > 366) throw new PackReleaseError("--expires-in-days must be an integer between 1 and 366");
		expiresAt = isoSeconds(Date.parse(issuedAt) + days * DAY_MS);
	}
	if (expiresAt !== undefined && (!ISO_SECONDS.test(expiresAt) || !(Date.parse(expiresAt) > Date.parse(issuedAt)))) {
		throw new PackReleaseError("--expires-at must be YYYY-MM-DDTHH:MM:SSZ after issued_at");
	}
	const customers = [...new Set(audience)].sort();
	if (customers.length > 256 || customers.some((id) => !CUSTOMER_ID.test(id))) throw new PackReleaseError("--audience takes up to 256 customer ids of 2..32 [a-z0-9-]");
	if (!["fail", "skip"].includes(ifEmpty)) throw new PackReleaseError("--if-empty must be fail or skip");

	const threats = readThreats(threatsDir, lib.parseThreatYaml, Date.parse(issuedAt));
	const intel = intelDir ? readIntelDir(intelDir) : { entries: {}, sha256: null };
	const entries = { ...intel.entries };
	if (threats.hosts.length) entries.url_denylist = [...new Set([...(entries.url_denylist ?? []), ...threats.hosts])].sort();
	const allowed = new Set(entries.url_allowlist ?? []);
	const conflict = (entries.url_denylist ?? []).find((host) => allowed.has(host));
	if (conflict) throw new PackReleaseError(`${conflict} is on both the URL denylist and the URL allowlist; the allowlist would win on endpoints`);
	const total = KINDS.reduce((sum, kind) => sum + (entries[kind]?.length ?? 0), 0);
	if (total === 0) {
		if (ifEmpty === "skip") return { outcome: "empty", threats };
		throw new PackReleaseError("the pack would carry no intel entries; add curated data with --intel-dir (see docs/operations/intel-pack-releases.md)");
	}

	const target = resolve(out);
	if (existsSync(target)) throw new PackReleaseError(`${target} already exists; a pack version is built once`);
	mkdirSync(join(target, "lists"), { recursive: true });
	const files = [];
	const counts = {};
	for (const kind of KINDS) {
		const list = entries[kind];
		if (!list?.length) continue;
		const name = INTEL_FILES[kind];
		const body = kind === "domain_risk" ? `${JSON.stringify(list, null, 2)}\n` : `${list.join("\n")}\n`;
		writeFileSync(join(target, "lists", name), body, { flag: "wx", mode: 0o644 });
		files.push({ kind, path: `lists/${name}`, sha256: sha256(Buffer.from(body, "utf8")) });
		counts[kind] = list.length;
	}
	const manifest = {
		pack_id: packId,
		version,
		issued_at: issuedAt,
		...(expiresAt === undefined ? {} : { expires_at: expiresAt }),
		key_id: keyId,
		...(customers.length ? { audience: { customer_ids: customers } } : {}),
		files,
		// Informational, covered by the signature; the loader ignores it.
		source: {
			threats_sha256: threats.sha256,
			threat_rules: threats.rules,
			derived_rule_ids: threats.derivedRuleIds,
			intel_sha256: intel.sha256,
			entries: counts,
			...(sourceRef ? { ref: String(sourceRef) } : {}),
		},
	};
	writeFileSync(join(target, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx", mode: 0o644 });
	return { outcome: "built", path: target, manifest };
}

function loadedCounts(merged) {
	return {
		url_denylist: merged.urlDenyHosts.size,
		url_allowlist: merged.urlAllowHosts.size,
		domain_risk: merged.domainRisk.size,
		package_name_denylist: merged.packageNameDeny.size,
		package_hash_denylist: merged.packageHashDeny.size,
		plugin_signature_denylist: merged.pluginSignatureDeny.size,
	};
}

/** Load the pack through the core loader in a disposable HOME; returns the merged intel. */
async function loadWithCoreLoader(pack, manifest, { trustedKeys, sharedKeys, tamper = false }, lib) {
	const root = mkdtempSync(join(tmpdir(), "aidr-intel-release-"));
	const previousHome = process.env.HOME;
	try {
		const home = join(root, "home");
		const packsDir = join(home, ".singularity-aidr", "intel", "packs");
		const versionDir = join(packsDir, manifest.pack_id, manifest.version);
		mkdirSync(versionDir, { recursive: true });
		const manifestBytes = tamper ? Buffer.concat([pack.manifestBytes, Buffer.from(" ")]) : pack.manifestBytes;
		writeFileSync(join(versionDir, "manifest.json"), manifestBytes);
		writeFileSync(join(versionDir, "manifest.sig"), `${pack.signatureBase64}\n`);
		for (const [path, bytes] of pack.files) {
			mkdirSync(dirname(join(versionDir, ...path.split("/"))), { recursive: true });
			writeFileSync(join(versionDir, ...path.split("/")), bytes);
		}
		const trustedKeysPath = join(root, "trusted-keys.json");
		writeFileSync(trustedKeysPath, JSON.stringify(Object.fromEntries(trustedKeys)));
		if (sharedKeys.length) {
			mkdirSync(join(home, ".singularity-aidr", "intel"), { recursive: true });
			writeFileSync(join(home, ".singularity-aidr", "intel", "keys.json"), JSON.stringify({ keys: Object.fromEntries(sharedKeys.map((key) => [key.key_id, key.key_b64])) }), { mode: 0o600 });
		}
		// The loader resolves its keyring under ~; point ~ at the disposable HOME.
		process.env.HOME = home;
		const warnings = [];
		const logger = { debug() {}, info() {}, warn: (message) => warnings.push(message), error: (message) => warnings.push(message) };
		const merged = await lib.loadMergedIntelFromDisk({ packsDir, trustedKeysPath, retainedKeysPath: join(root, "retained", "pack-keys.json") }, logger);
		return { merged, warnings };
	} finally {
		if (previousHome === undefined) delete process.env.HOME;
		else process.env.HOME = previousHome;
		rmSync(root, { recursive: true, force: true });
	}
}

/** Sample licenses around the pack's signed issued_at, signed with a throwaway key. */
function sampleLicenses(manifest, lib) {
	const signer = generateKeyPairSync("ed25519");
	const keyId = "aidr-intel-release-selftest";
	const issued = Date.parse(manifest.issued_at);
	const registry = lib.parseLicensePublicKeyRegistry({
		format: "aidr-license-public-keys-v1",
		schema_version: 1,
		keys: [{ key_id: keyId, algorithm: "ed25519", public_key_pem: signer.publicKey.export({ type: "spki", format: "pem" }).toString(), not_before: isoSeconds(issued - 1000 * DAY_MS), not_after: null, status: "active" }],
	});
	const signDocument = (format, payload) => ({ format, key_id: keyId, payload, sig: sign(null, Buffer.from(`${format}\n${lib.licenseCanonicalJson(payload)}`, "utf8"), signer.privateKey).toString("base64") });
	const audience = manifest.audience?.customer_ids ?? [];
	const outsider = ["sample-outsider", "sample-outsider-2"].find((id) => !audience.includes(id));
	const license = (licenseId, customerId, from, to) =>
		lib.verifyLicense(
			signDocument("aidr-license-v1", {
				license_id: licenseId,
				customer: "Self-test customer",
				customer_id: customerId,
				plan_id: "enterprise",
				seats: 10,
				features: ["premium_intel"],
				deployment: "onprem",
				issued_at: isoSeconds(from),
				not_before: isoSeconds(from),
				expires_at: isoSeconds(to),
				grace_days: 14,
			}),
			{ registry, now: issued },
		);
	const inTerm = license("SELFTEST-IN-TERM", audience[0] ?? "sample-customer", issued - 180 * DAY_MS, issued + 185 * DAY_MS);
	const revocations = lib.verifyLicenseRevocations(signDocument(lib.LICENSE_REVOCATIONS_FORMAT, { issued_at: isoSeconds(issued), sequence: 1, license_ids: ["SELFTEST-IN-TERM"] }), { registry, now: issued });
	return {
		inTerm,
		outOfTerm: license("SELFTEST-OUT-OF-TERM", audience[0] ?? "sample-customer", issued - 400 * DAY_MS, issued - 30 * DAY_MS),
		otherCustomer: license("SELFTEST-OTHER-CUSTOMER", outsider, issued - 180 * DAY_MS, issued + 185 * DAY_MS),
		revocations,
	};
}

/** Verify a real revocation list against the license registry it is signed for (fail closed). */
function verifyRevocationsFile(revocationsPath, licensePublicKeysPath, now, lib) {
	if (!licensePublicKeysPath) throw new PackReleaseError("--license-revocations needs --license-public-keys (the registry the list is signed for)");
	try {
		const registry = lib.parseLicensePublicKeyRegistry(lib.readSignedDocumentFile(resolve(licensePublicKeysPath), "license public-key registry"));
		return lib.verifyLicenseRevocations(lib.readSignedDocumentFile(resolve(revocationsPath), "license revocation list"), { registry, now });
	} catch (error) {
		throw new PackReleaseError(`license revocation list does not verify: ${error.message}`);
	}
}

/** Every check a release must pass before it is published. Throws on the first failure. */
export async function verifyRelease({ packDir, trustedKeysPath, sharedKeyFile, licensePublicKeysPath, revocationsPath, now = Date.now() }, core) {
	const lib = core ?? (await loadCore());
	const trustedKeys = loadTrustedKeys(trustedKeysPath);
	const pack = readPackSource(packDir);
	let verified;
	try {
		verified = await verifyOfflinePack(pack, { trustedKeys, now });
	} catch (error) {
		throw new PackReleaseError(`offline verifier refused the pack: ${error.message}`);
	}
	const { manifest } = verified;
	const declared = JSON.parse(pack.manifestBytes.toString("utf8")).source?.entries;
	if (!declared || typeof declared !== "object") throw new PackReleaseError("manifest.source.entries is missing; build packs with this script");
	const sharedKeys = sharedKeyFile ? parseSharedPackKeys(regularFile(resolve(sharedKeyFile), "shared key file").toString("utf8").trim()) : [];
	const encrypted = manifest.files.filter((file) => file.encrypted).map((file) => file.key_id);
	const missing = [...new Set(encrypted)].filter((keyId) => !sharedKeys.some((key) => key.key_id === keyId));
	if (missing.length) throw new PackReleaseError(`encrypted files use key(s) ${missing.join(", ")}; pass --shared-key-file so the loader check can decrypt them`);

	const loaded = await loadWithCoreLoader(pack, manifest, { trustedKeys, sharedKeys }, lib);
	if (loaded.merged.availability !== "available") {
		throw new PackReleaseError(`the core loader did not load the pack (${loaded.merged.detail}): ${loaded.warnings.join("; ")}`);
	}
	const counts = loadedCounts(loaded.merged);
	for (const kind of KINDS) {
		if ((declared[kind] ?? 0) !== counts[kind]) throw new PackReleaseError(`the core loader loaded ${counts[kind]} ${kind} entries, the signed manifest declares ${declared[kind] ?? 0}`);
	}
	const tampered = await loadWithCoreLoader(pack, manifest, { trustedKeys, sharedKeys, tamper: true }, lib);
	if (tampered.merged.availability !== "unavailable") throw new PackReleaseError("the core loader accepted a tampered manifest; refusing to publish");

	const samples = sampleLicenses(manifest, lib);
	const decisions = {
		in_term: lib.acceptPack(manifest, samples.inTerm),
		out_of_term: lib.acceptPack(manifest, samples.outOfTerm),
		other_customer: lib.acceptPack(manifest, samples.otherCustomer),
		revoked_license: lib.acceptPack(manifest, samples.inTerm, { revocations: samples.revocations }),
	};
	const expected = {
		in_term: true,
		out_of_term: "license_term_ended",
		other_customer: manifest.audience ? "pack_audience_mismatch" : true,
		revoked_license: "license_revoked",
	};
	for (const [name, want] of Object.entries(expected)) {
		const got = decisions[name].accepted ? true : decisions[name].code;
		if (got !== want) throw new PackReleaseError(`acceptPack self-test ${name}: expected ${want}, got ${got}`);
	}

	let revocations = null;
	if (revocationsPath) {
		const list = verifyRevocationsFile(revocationsPath, licensePublicKeysPath, now, lib);
		revocations = { sequence: list.sequence, issued_at: list.issuedAt, revoked_licenses: list.licenseIds.size };
	}
	return {
		outcome: "verified",
		pack_id: manifest.pack_id,
		version: manifest.version,
		key_id: manifest.key_id,
		issued_at: manifest.issued_at,
		expires_at: manifest.expires_at ?? null,
		audience: manifest.audience?.customer_ids ?? null,
		manifest_sha256: verified.manifestSha256,
		encrypted_files: encrypted.length,
		loader: { availability: loaded.merged.availability, entries: counts, tampered_copy: "refused" },
		acceptance: Object.fromEntries(Object.entries(decisions).map(([name, decision]) => [name, decision.accepted ? "accepted" : decision.code])),
		license_revocations: revocations,
	};
}

const IMPORT_TEXT = (bundle, hasRevocations) => `Singularity AIDR intel update pack
==================================

EN  Verify the files first:   sha256sum --check SHA256SUMS
    Install on an endpoint:   node scripts/import-offline-pack.mjs --pack ${bundle} \\
                                --trusted-keys intel-trusted-keys.json --target local --license <your license.json>${hasRevocations ? " \\\n                                --license-revocations license-revocations.json" : ""}
    Serve from your server:   ... --target storage --deployment /srv/aidr --license <your license.json>
    The pack is refused when its signature, digests or expiry do not verify, when
    it was issued after your license's update term (expires_at + grace days), when
    it is issued for other customers, or when your license is revoked. Installed
    packs keep enforcing in every case.

TR  Önce dosyaları doğrulayın: sha256sum --check SHA256SUMS
    Uç noktaya kurun:          node scripts/import-offline-pack.mjs --pack ${bundle} \\
                                --trusted-keys intel-trusted-keys.json --target local --license <lisans.json>${hasRevocations ? " \\\n                                --license-revocations license-revocations.json" : ""}
    Sunucunuzdan dağıtın:      ... --target storage --deployment /srv/aidr --license <lisans.json>
    İmza, özet ya da süre doğrulanmazsa, paket lisansınızın güncelleme süresinden
    (bitiş + ek süre) sonra yayımlandıysa, başka müşteriler için yayımlandıysa ya da
    lisansınız iptal edildiyse paket kurulmaz. Kurulu paketler her durumda
    korumaya devam eder.
`;

/** Write release assets / the offline folder for a verified pack. */
export async function exportRelease({ packDir, trustedKeysPath, out, revocationsPath, licensePublicKeysPath, now = Date.now() }, core) {
	if (revocationsPath) verifyRevocationsFile(revocationsPath, licensePublicKeysPath, now, core ?? (await loadCore()));
	const trustedKeys = loadTrustedKeys(trustedKeysPath);
	const pack = readPackSource(packDir);
	let verified;
	try {
		verified = await verifyOfflinePack(pack, { trustedKeys, now });
	} catch (error) {
		throw new PackReleaseError(`offline verifier refused the pack: ${error.message}`);
	}
	const { manifest } = verified;
	const target = resolve(out);
	if (existsSync(target)) throw new PackReleaseError(`${target} already exists`);
	mkdirSync(target, { recursive: true });
	const bundleName = `${manifest.pack_id}-${manifest.version}.aidrpack.json`;
	const written = [bundleName, "intel-trusted-keys.json", "IMPORT.txt"];
	writeFileSync(join(target, bundleName), createBundle(pack, manifest), { flag: "wx", mode: 0o644 });
	writeFileSync(join(target, "intel-trusted-keys.json"), `${JSON.stringify({ [manifest.key_id]: trustedKeys.get(manifest.key_id) }, null, 2)}\n`, { flag: "wx", mode: 0o644 });
	if (revocationsPath) {
		copyFileSync(resolve(revocationsPath), join(target, "license-revocations.json"));
		written.push("license-revocations.json");
	}
	writeFileSync(join(target, "IMPORT.txt"), IMPORT_TEXT(bundleName, Boolean(revocationsPath)), { flag: "wx", mode: 0o644 });
	const sums = written.sort().map((name) => `${sha256(readFileSync(join(target, name)))}  ${name}`);
	writeFileSync(join(target, "SHA256SUMS"), `${sums.join("\n")}\n`, { flag: "wx", mode: 0o644 });
	return { outcome: "exported", path: target, bundle: bundleName, files: [...written, "SHA256SUMS"].sort(), manifest_sha256: verified.manifestSha256 };
}

const USAGE = `Usage:
  node scripts/intel-pack-release.mjs build --out <new dir> --pack-id <id> --version <v> --key-id <publisher key id>
    [--threats-dir threats] [--intel-dir <dir>] [--issued-at <ISO>] [--expires-in-days <n> | --expires-at <ISO>]
    [--audience <customer id>]... [--source-ref <git sha>] [--if-empty fail|skip]
  node scripts/intel-pack-release.mjs verify --pack <signed dir> --trusted-keys <trusted-keys.json>
    [--shared-key-file <key_id=base64 file>] [--license-public-keys <registry.json> --license-revocations <list.json>] [--report <file>]
  node scripts/intel-pack-release.mjs export --pack <signed dir> --trusted-keys <trusted-keys.json> --out <new dir>
    [--license-public-keys <registry.json> --license-revocations <list.json>]`;

const invoked = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invoked) {
	try {
		const { positionals, values } = parseArgs({
			allowPositionals: true,
			strict: true,
			options: {
				help: { type: "boolean", short: "h" },
				out: { type: "string" },
				"pack-id": { type: "string" },
				version: { type: "string" },
				"key-id": { type: "string" },
				"threats-dir": { type: "string" },
				"intel-dir": { type: "string" },
				"issued-at": { type: "string" },
				"expires-in-days": { type: "string" },
				"expires-at": { type: "string" },
				audience: { type: "string", multiple: true },
				"source-ref": { type: "string" },
				"if-empty": { type: "string" },
				pack: { type: "string" },
				"trusted-keys": { type: "string" },
				"shared-key-file": { type: "string" },
				"license-public-keys": { type: "string" },
				"license-revocations": { type: "string" },
				report: { type: "string" },
			},
		});
		const [command] = positionals;
		if (values.help || !command) {
			console.log(USAGE);
			process.exit(values.help ? 0 : 1);
		}
		let result;
		if (command === "build") {
			if (!values.out) throw new PackReleaseError(USAGE);
			result = await buildPack({
				out: values.out,
				packId: values["pack-id"],
				version: values.version,
				keyId: values["key-id"],
				threatsDir: values["threats-dir"],
				intelDir: values["intel-dir"],
				issuedAt: values["issued-at"],
				expiresAt: values["expires-at"],
				expiresInDays: values["expires-in-days"],
				audience: (values.audience ?? []).flatMap((value) => value.split(",")).map((id) => id.trim()).filter(Boolean),
				sourceRef: values["source-ref"],
				ifEmpty: values["if-empty"],
			});
			result = result.outcome === "empty" ? { outcome: "empty", threat_rules: result.threats.rules } : { outcome: "built", path: result.path, pack_id: result.manifest.pack_id, version: result.manifest.version, entries: result.manifest.source.entries };
		} else if (command === "verify") {
			if (!values.pack || !values["trusted-keys"]) throw new PackReleaseError(USAGE);
			result = await verifyRelease({ packDir: values.pack, trustedKeysPath: values["trusted-keys"], sharedKeyFile: values["shared-key-file"], licensePublicKeysPath: values["license-public-keys"], revocationsPath: values["license-revocations"] });
			if (values.report) writeFileSync(resolve(values.report), `${JSON.stringify(result, null, 2)}\n`, { flag: "wx", mode: 0o644 });
		} else if (command === "export") {
			if (!values.pack || !values["trusted-keys"] || !values.out) throw new PackReleaseError(USAGE);
			result = await exportRelease({ packDir: values.pack, trustedKeysPath: values["trusted-keys"], out: values.out, revocationsPath: values["license-revocations"], licensePublicKeysPath: values["license-public-keys"] });
		} else {
			throw new PackReleaseError(USAGE);
		}
		console.log(JSON.stringify(result));
	} catch (error) {
		console.error(`ERROR: ${error instanceof Error ? error.message : "intel pack release failed"}`);
		process.exitCode = 1;
	}
}
