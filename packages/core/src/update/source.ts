/**
 * Where an update comes from, and getting its bytes:
 *
 * - `portal`: the tenant's control plane (SaaS or on-prem), `installer-update`
 *   Edge Function, authenticated with the endpoint's managed API key. It hands
 *   over the exact signed catalog bytes and, for the installer, a short-lived
 *   signed URL.
 * - `mirror`: a copy of the portal bucket tree (latest.json, <version>/...) in
 *   a directory or on an internal HTTPS server - what
 *   `publish-installers.mjs --dry-run --out <dir>` stages.
 * - `file`: one installer an administrator provides (`--from`), with the signed
 *   manifest.json it was published with.
 *
 * Every source is verified the same way: the catalog signature with the pinned
 * installer-catalog key, then the installer bytes against the catalog's size
 * and SHA-256 while they are written. Nothing a server says about a file is
 * trusted. Only https is fetched (plain http only to a loopback address when
 * explicitly allowed for development).
 */
import { createHash, type KeyObject } from "node:crypto";
import { createReadStream, createWriteStream, lstatSync, readFileSync, rmSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { controlPlaneUrl } from "../clients/control-plane-url.js";
import {
	type CatalogVerification,
	type InstallerCatalog,
	type InstallerCatalogFile,
	MAX_CATALOG_BYTES,
	MAX_POINTER_BYTES,
	MAX_SIGNATURE_BYTES,
	readVerifiedPointer,
	type SignedDocument,
	verifyCatalogDocument,
	verifyPublishedCatalog,
} from "./catalog.js";

export type UpdateSource =
	| {
			kind: "portal";
			/** control_plane.endpoint */
			endpoint: string;
			apiKey: string;
			allowInsecureLoopback?: boolean;
	  }
	| { kind: "mirror"; location: string; allowInsecureLoopback?: boolean }
	| { kind: "file"; installer: string; catalog?: string; allowInsecureLoopback?: boolean };

export type SourceErrorCode =
	| "source_unreachable"
	| "source_insecure"
	| "unauthorized"
	| "entitlement_required"
	| "not_published"
	| "rate_limited"
	| "server_error"
	| "invalid_response"
	| "catalog_not_found"
	| "installer_not_in_catalog"
	| "download_failed"
	| "size_mismatch"
	| "digest_mismatch";

export type SourceFailure = { ok: false; error: SourceErrorCode; status?: number; detail?: string };

export type LoadedCatalog =
	| {
			ok: true;
			catalog: InstallerCatalog;
			/** Set for a `file` source: the catalog entry the provided installer must be. */
			providedFile?: string;
	  }
	| SourceFailure
	| Extract<CatalogVerification, { ok: false }>;

export interface SourceDeps {
	fetch?: typeof fetch;
	timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 15_000;
const PORTAL_RESPONSE_BYTES = 2 * (MAX_POINTER_BYTES + MAX_CATALOG_BYTES + 2 * MAX_SIGNATURE_BYTES);

function isUrl(location: string): boolean {
	return /^[a-z][a-z0-9+.-]*:\/\//iu.test(location) && !/^file:/iu.test(location);
}

function localPath(location: string): string {
	return /^file:/iu.test(location) ? fileURLToPath(location) : resolve(location);
}

/** https, or http to a loopback host when the caller explicitly allows it. */
function secureUrl(location: string, allowInsecureLoopback = false): URL | null {
	try {
		const url = new URL(location);
		if (url.username || url.password) return null;
		if (url.protocol === "https:") return url;
		const loopback =
			url.hostname === "localhost" ||
			url.hostname === "[::1]" ||
			/^127(?:\.\d{1,3}){3}$/u.test(url.hostname);
		return url.protocol === "http:" && loopback && allowInsecureLoopback ? url : null;
	} catch {
		return null;
	}
}

async function readCapped(response: Response, maxBytes: number): Promise<Uint8Array | "too_large"> {
	const declared = Number(response.headers.get("content-length") ?? Number.NaN);
	if (Number.isFinite(declared) && declared > maxBytes) return "too_large";
	const bytes = new Uint8Array(await response.arrayBuffer());
	return bytes.length > maxBytes ? "too_large" : bytes;
}

async function fetchDocument(
	location: string,
	maxBytes: number,
	deps: SourceDeps,
	allowInsecureLoopback: boolean,
): Promise<Uint8Array | SourceFailure> {
	const url = secureUrl(location, allowInsecureLoopback);
	if (!url) return { ok: false, error: "source_insecure", detail: location };
	try {
		const response = await (deps.fetch ?? fetch)(url, {
			redirect: "error",
			signal: AbortSignal.timeout(deps.timeoutMs ?? DEFAULT_TIMEOUT_MS),
		});
		if (response.status === 404) return { ok: false, error: "catalog_not_found", detail: location };
		if (!response.ok) return { ok: false, error: "source_unreachable", status: response.status };
		const bytes = await readCapped(response, maxBytes);
		return bytes === "too_large"
			? { ok: false, error: "invalid_response", detail: location }
			: bytes;
	} catch (error) {
		return { ok: false, error: "source_unreachable", detail: String(error) };
	}
}

function readLocalDocument(location: string, maxBytes: number): Uint8Array | SourceFailure {
	const path = localPath(location);
	try {
		const info = lstatSync(path);
		if (!info.isFile()) return { ok: false, error: "catalog_not_found", detail: path };
		if (info.size > maxBytes) return { ok: false, error: "invalid_response", detail: path };
		return new Uint8Array(readFileSync(path));
	} catch {
		return { ok: false, error: "catalog_not_found", detail: path };
	}
}

/** Read a small document (pointer, catalog, signature) from a path or an https URL. */
function readDocument(
	location: string,
	maxBytes: number,
	deps: SourceDeps,
	allowInsecureLoopback = false,
): Promise<Uint8Array | SourceFailure> | Uint8Array | SourceFailure {
	return isUrl(location)
		? fetchDocument(location, maxBytes, deps, allowInsecureLoopback)
		: readLocalDocument(location, maxBytes);
}

/** `relative` resolved against a mirror base (directory or URL), never escaping it. */
function mirrorLocation(base: string, relative: string): string {
	if (isUrl(base)) return new URL(relative, base.endsWith("/") ? base : `${base}/`).toString();
	return join(localPath(base), ...relative.split("/"));
}

function failure(value: unknown): value is SourceFailure {
	return !!value && typeof value === "object" && (value as { ok?: unknown }).ok === false;
}

function portalError(status: number, code: unknown): SourceFailure {
	const error = typeof code === "string" ? code : "";
	if (status === 401 || error === "invalid_api_key" || error === "missing_api_key")
		return { ok: false, error: "unauthorized", status };
	if (error === "entitlement_required" || error === "tenant_access_denied" || status === 403)
		return { ok: false, error: "entitlement_required", status };
	if (status === 404) return { ok: false, error: "not_published", status };
	if (status === 429) return { ok: false, error: "rate_limited", status };
	return { ok: false, error: "server_error", status, detail: error || undefined };
}

function parseObject(bytes: Uint8Array | "too_large"): Record<string, unknown> | null {
	if (bytes === "too_large") return null;
	try {
		const parsed = JSON.parse(new TextDecoder().decode(bytes));
		return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
	} catch {
		return null;
	}
}

function portalUrl(source: Extract<UpdateSource, { kind: "portal" }>): string | null {
	try {
		const url = controlPlaneUrl(source.endpoint, "installer-update");
		return secureUrl(url, source.allowInsecureLoopback) ? url : null;
	} catch {
		return null;
	}
}

async function portalRequest(
	source: Extract<UpdateSource, { kind: "portal" }>,
	body: string | undefined,
	deps: SourceDeps,
): Promise<Record<string, unknown> | SourceFailure> {
	const url = portalUrl(source);
	if (!url) return { ok: false, error: "source_insecure", detail: source.endpoint };
	const headers: Record<string, string> = {
		Accept: "application/json",
		Authorization: `Bearer ${source.apiKey}`,
		"User-Agent": "aidr",
	};
	if (body) headers["Content-Type"] = "application/json";
	try {
		const response = await (deps.fetch ?? fetch)(url, {
			method: body ? "POST" : "GET",
			redirect: "error",
			signal: AbortSignal.timeout(deps.timeoutMs ?? DEFAULT_TIMEOUT_MS),
			headers,
			...(body ? { body } : {}),
		});
		const parsed = parseObject(await readCapped(response, PORTAL_RESPONSE_BYTES));
		if (!response.ok) return portalError(response.status, parsed?.error);
		return parsed ?? { ok: false, error: "invalid_response" };
	} catch (error) {
		return { ok: false, error: "source_unreachable", detail: String(error) };
	}
}

const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/u;

function decodeDocument(value: unknown): SignedDocument | null {
	const entry = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
	const { document_b64: document, signature_b64: signature } = entry;
	if (typeof document !== "string" || typeof signature !== "string") return null;
	if (!BASE64.test(document) || !BASE64.test(signature)) return null;
	return {
		document: new Uint8Array(Buffer.from(document, "base64")),
		signature: new Uint8Array(Buffer.from(signature, "base64")),
	};
}

async function loadPortalCatalog(
	source: Extract<UpdateSource, { kind: "portal" }>,
	keys: readonly KeyObject[],
	deps: SourceDeps,
): Promise<LoadedCatalog> {
	const body = await portalRequest(source, undefined, deps);
	if (failure(body)) return body;
	const pointer = decodeDocument(body.pointer);
	const catalog = decodeDocument(body.catalog);
	if (!pointer || !catalog) return { ok: false, error: "invalid_response" };
	return verifyPublishedCatalog({ pointer, catalog }, keys);
}

async function readSignedPair(
	location: string,
	maxBytes: number,
	deps: SourceDeps,
	allowInsecureLoopback: boolean | undefined,
): Promise<SignedDocument | SourceFailure> {
	const document = await readDocument(location, maxBytes, deps, allowInsecureLoopback);
	if (failure(document)) return document;
	const signature = await readDocument(
		`${location}.sig`,
		MAX_SIGNATURE_BYTES,
		deps,
		allowInsecureLoopback,
	);
	if (failure(signature)) return signature;
	return { document, signature };
}

async function loadMirrorCatalog(
	source: Extract<UpdateSource, { kind: "mirror" }>,
	keys: readonly KeyObject[],
	deps: SourceDeps,
): Promise<LoadedCatalog> {
	const at = (relative: string) => mirrorLocation(source.location, relative);
	const pointer = await readSignedPair(
		at("latest.json"),
		MAX_POINTER_BYTES,
		deps,
		source.allowInsecureLoopback,
	);
	if (failure(pointer)) return pointer;
	const located = readVerifiedPointer(pointer, keys);
	if (!located) return { ok: false, error: "signature_invalid" };
	const catalog = await readSignedPair(
		at(located.manifestPath),
		MAX_CATALOG_BYTES,
		deps,
		source.allowInsecureLoopback,
	);
	if (failure(catalog)) return catalog;
	return verifyPublishedCatalog({ pointer, catalog }, keys);
}

/** Where the portal tree puts an installer's catalog: <version>/manifest.json next to <version>/<platform>/<file>. */
function catalogCandidates(installer: string): string[] {
	if (isUrl(installer)) {
		return [
			new URL("manifest.json", installer).toString(),
			new URL("../manifest.json", installer).toString(),
		];
	}
	const folder = dirname(localPath(installer));
	return [join(folder, "manifest.json"), join(dirname(folder), "manifest.json")];
}

async function loadProvidedCatalog(
	source: Extract<UpdateSource, { kind: "file" }>,
	keys: readonly KeyObject[],
	deps: SourceDeps,
): Promise<LoadedCatalog> {
	const installerName = basename(
		isUrl(source.installer) ? new URL(source.installer).pathname : localPath(source.installer),
	);
	let lastFailure: SourceFailure = { ok: false, error: "catalog_not_found" };
	for (const candidate of source.catalog ? [source.catalog] : catalogCandidates(source.installer)) {
		const document = await readDocument(
			candidate,
			MAX_CATALOG_BYTES,
			deps,
			source.allowInsecureLoopback,
		);
		if (failure(document)) {
			lastFailure = document;
			continue;
		}
		const signature = await readDocument(
			`${candidate}.sig`,
			MAX_SIGNATURE_BYTES,
			deps,
			source.allowInsecureLoopback,
		);
		if (failure(signature)) return { ok: false, error: "signature_invalid" };
		const verified = verifyCatalogDocument({ document, signature }, keys);
		return verified.ok ? { ...verified, providedFile: installerName } : verified;
	}
	return lastFailure;
}

/** Fetch and verify the signed catalog of a source. */
export function loadCatalog(
	source: UpdateSource,
	keys: readonly KeyObject[],
	deps: SourceDeps = {},
): Promise<LoadedCatalog> {
	if (keys.length === 0) return Promise.resolve({ ok: false, error: "no_trusted_key" });
	if (source.kind === "portal") return loadPortalCatalog(source, keys, deps);
	if (source.kind === "mirror") return loadMirrorCatalog(source, keys, deps);
	return loadProvidedCatalog(source, keys, deps);
}

/** Where to read the installer bytes from (a signed portal URL, a mirror path or the provided file). */
export async function installerLocation(
	source: UpdateSource,
	catalog: InstallerCatalog,
	file: InstallerCatalogFile,
	deps: SourceDeps = {},
): Promise<{ ok: true; location: string } | SourceFailure> {
	if (source.kind === "file") return { ok: true, location: source.installer };
	if (source.kind === "mirror")
		return { ok: true, location: mirrorLocation(source.location, file.path) };
	const body = await portalRequest(
		source,
		JSON.stringify({ version: catalog.version, platform: file.platform }),
		deps,
	);
	if (failure(body)) return body;
	if (typeof body.url !== "string" || !secureUrl(body.url, source.allowInsecureLoopback)) {
		return { ok: false, error: "invalid_response" };
	}
	return { ok: true, location: body.url };
}

/** The installer's bytes as a stream, from an https URL or a local file. */
async function openInstaller(
	location: string,
	deps: SourceDeps & { allowInsecureLoopback?: boolean },
): Promise<AsyncIterable<Uint8Array> | SourceFailure> {
	if (!isUrl(location)) {
		const path = localPath(location);
		return lstatSync(path).isFile()
			? createReadStream(path)
			: { ok: false, error: "download_failed", detail: path };
	}
	const url = secureUrl(location, deps.allowInsecureLoopback);
	if (!url) return { ok: false, error: "source_insecure", detail: location };
	const response = await (deps.fetch ?? fetch)(url, {
		redirect: "error",
		signal: AbortSignal.timeout(Math.max(deps.timeoutMs ?? 0, 15 * 60_000)),
	});
	if (!response.ok || !response.body)
		return { ok: false, error: "download_failed", status: response.status };
	return response.body as unknown as AsyncIterable<Uint8Array>;
}

/**
 * Copy the installer to `destination`, hashing while writing and stopping at
 * the catalog size. The file is removed unless both size and SHA-256 match.
 */
export async function downloadVerified(
	location: string,
	expected: { size: number; sha256: string },
	destination: string,
	deps: SourceDeps & { allowInsecureLoopback?: boolean } = {},
): Promise<{ ok: true; path: string } | SourceFailure> {
	const hash = createHash("sha256");
	let written = 0;
	const out = createWriteStream(destination, { flags: "wx", mode: 0o600 });
	const write = (chunk: Uint8Array) =>
		new Promise<void>((done, fail) => out.write(chunk, (error) => (error ? fail(error) : done())));
	const close = () => new Promise<void>((done) => out.end(done));
	const discard = async (result: SourceFailure) => {
		await close();
		rmSync(destination, { force: true });
		return result;
	};
	try {
		const chunks = await openInstaller(location, deps);
		if (failure(chunks)) return discard(chunks);
		for await (const chunk of chunks) {
			written += chunk.length;
			if (written > expected.size) return discard({ ok: false, error: "size_mismatch" });
			hash.update(chunk);
			await write(chunk);
		}
	} catch (error) {
		return discard({ ok: false, error: "download_failed", detail: String(error) });
	}
	if (written !== expected.size) return discard({ ok: false, error: "size_mismatch" });
	if (hash.digest("hex") !== expected.sha256)
		return discard({ ok: false, error: "digest_mismatch" });
	await close();
	return { ok: true, path: destination };
}
