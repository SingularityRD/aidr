/**
 * Native AI-infrastructure scanner.
 *
 * Reimplements AIG's *Infra Scan* capability directly in TypeScript, using the
 * data compiled from the pinned AI-Infra-Guard source (`aig-fingerprints.json`,
 * `aig-cve-index.json`). No Go server, no Python worker, no Docker stack, no LLM:
 * the entire capability is an HTTP probe plus a version comparison, so it runs
 * in-process with the same runtime the rest of AIDR uses.
 *
 * What it does, per target:
 *   1. runs the fingerprint's declared HTTP probe (`path`, method),
 *   2. evaluates the matcher expressions against the response,
 *   3. extracts the service version via the fingerprint's own regex,
 *   4. matches the detected product+version against the CVE index,
 *   5. returns findings that the policy layer can act on.
 *
 * Safety posture (this makes outbound requests, so it is deliberately narrow):
 *   - Only loopback and private/link-local targets are scanned by default. A
 *     public host requires an explicit `allowPublicTargets` opt-in, so a
 *     misconfiguration cannot turn the agent into a public port scanner.
 *   - Bounded concurrency, a per-request timeout, and a total deadline.
 *   - Response bodies are truncated before matching, so a hostile server cannot
 *     make us buffer unbounded data.
 *   - The scanner never sends credentials and follows no redirects to another
 *     host.
 */

import { existsSync, readFileSync } from "node:fs";
import { isIP } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { validateAigDataBundle } from "./aig-sync.js";

/**
 * Directory this module was loaded from.
 *
 * This module is also bundled into the connectors as CommonJS, where
 * `import.meta` is empty (esbuild emits `empty-import-meta`) and `__dirname` is
 * the bundle's directory. `__dirname` is therefore checked FIRST: preferring it
 * is what lets a bundled copy resolve its data. The `import.meta` branch is the
 * ESM fallback for the unbundled core package.
 */
function moduleDirectory(): string {
	if (typeof __dirname !== "undefined" && __dirname) return __dirname;
	try {
		return dirname(fileURLToPath(import.meta.url));
	} catch {
		return process.cwd();
	}
}

/**
 * The compiled AIG data lives beside the runtime bundle and may be swapped by a
 * signed bundle promotion, so it is read lazily rather than bundled as a static
 * import.
 *
 * When this module is bundled into a connector, the data sits at the CONNECTOR
 * package root rather than next to the bundle, so the candidate list walks up as
 * well. Missing data yields an empty index instead of throwing, which keeps a
 * bad dataset from breaking a hook; the scan then reports that it identified
 * nothing rather than inventing a clean result.
 */
function resolveGeneratedFile(name: string): string {
	const configured = process.env.AIG_GENERATED_DIR?.trim();
	if (configured) return join(configured, name);
	const dir = moduleDirectory();
	const candidates = [
		join(dir, "generated", name),
		join(dir, "..", "generated", name),
		// Bundled into a connector: <root>/dist/<bundle> -> <root>/dist/generated
		join(dir, "..", "dist", "generated", name),
		// Unbundled core running from dist/ with the data still in src/generated.
		join(dir, "..", "src", "generated", name),
		join(resolve(dir, "..", ".."), "core", "dist", "generated", name),
	];
	for (const candidate of candidates) {
		if (existsSync(candidate)) return candidate;
	}
	return candidates[candidates.length - 1] ?? name;
}

function loadJson<T>(name: string, directory?: string): T | null {
	try {
		const path = directory ? join(directory, name) : resolveGeneratedFile(name);
		return JSON.parse(readFileSync(path, "utf8")) as T;
	} catch {
		return null;
	}
}

export interface AigInfraScanTarget {
	/** Base URL, e.g. http://127.0.0.1:8080 */
	url: string;
}

export interface AigFingerprintMatch {
	product: string;
	vendor: string;
	name: string;
	severity: string;
	description: string;
	version: string | null;
	probePath: string;
}

export interface AigCveFinding {
	cveId: string;
	product: string;
	severity: string;
	cvss: number | null;
	/** Version constraint source text from AIG, e.g. `version < "0.5.2"` */
	rule: string;
	ruleStatus: string;
	/** false when AIG's rule could not be reduced to a semver comparison */
	evaluated: boolean;
}

export interface AigInfraTargetResult {
	url: string;
	reachable: boolean;
	matched: AigFingerprintMatch[];
	cves: AigCveFinding[];
	/** Set when the scan itself could not complete, so callers never read "clean" */
	error: string | null;
	requestsMade: number;
}

export interface AigInfraScanOptions {
	/** Per-request timeout in ms. Default 3000. */
	timeoutMs?: number;
	/** Maximum concurrent requests. Default 4. */
	concurrency?: number;
	/** Overall deadline in ms. Default 15000. */
	deadlineMs?: number;
	/** Allow scanning non-private hosts. Default false. */
	allowPublicTargets?: boolean;
	/** Injectable fetch, for tests. */
	fetchImpl?: typeof fetch;
	/** Cancel an active scan, including its in-flight request. */
	signal?: AbortSignal;
}

interface CompiledMatcher {
	key: string;
	negate?: boolean;
	contains?: string;
	regex?: string;
}

interface CompiledProbe {
	method: string;
	path: string;
	matchers: Array<CompiledMatcher | { unsupported: string }>;
	supported: boolean;
}

interface CompiledVersionExtractor {
	method: string;
	path: string;
	part: string;
	group: number;
	regex: string;
}

interface CompiledFingerprint {
	n: string;
	a: string;
	sev: string;
	desc: string;
	p: string;
	v: string;
	http?: CompiledProbe[];
	ver?: CompiledVersionExtractor[];
}

interface CompiledCve {
	id: string;
	p: string;
	a: string[];
	s: string;
	r: string | null;
	u: string;
	o: string;
	f: string;
	c?: number;
}

let _fingerprints: CompiledFingerprint[] | null = null;
let _cves: CompiledCve[] | null = null;
let _dataDirectory: string | null = null;
let _bundleValid: Promise<boolean> | null = null;

function prepareDataDirectory(): string {
	const directory = dirname(resolveGeneratedFile("aig-cve-index.json"));
	if (_dataDirectory !== directory) {
		_fingerprints = null;
		_cves = null;
		_cveByAlias = null;
		_bundleValid = null;
		_dataDirectory = directory;
	}
	return directory;
}

function fingerprints(): CompiledFingerprint[] {
	const directory = prepareDataDirectory();
	if (_fingerprints === null) {
		const data = loadJson<{ fingerprints?: CompiledFingerprint[] }>(
			"aig-fingerprints.json",
			directory,
		);
		_fingerprints = Array.isArray(data?.fingerprints) ? data.fingerprints : [];
	}
	return _fingerprints;
}

function cves(): CompiledCve[] {
	const directory = prepareDataDirectory();
	if (_cves === null) {
		const data = loadJson<{ cves?: CompiledCve[] }>("aig-cve-index.json", directory);
		_cves = Array.isArray(data?.cves) ? data.cves : [];
	}
	return _cves;
}

async function dataAvailable(): Promise<boolean> {
	const directory = prepareDataDirectory();
	_bundleValid ??= validateAigDataBundle(directory).then((result) => result.valid, () => false);
	if (!(await _bundleValid)) return false;
	return fingerprints().length > 0 && cves().length > 0;
}

/** Reset memoised indexes (tests and signed bundle promotion). */
export function resetAigScanCache(): void {
	_fingerprints = null;
	_cves = null;
	_cveByAlias = null;
	_dataDirectory = null;
	_bundleValid = null;
}

/** Cap on how much of a response body we will buffer and match. */
const MAX_BODY_BYTES = 256 * 1024;

// ── Target validation ───────────────────────────────────────────────

export function isScannableHost(hostname: string): boolean {
	const host = hostname.replace(/^\[|\]$/g, "");
	if (host.toLowerCase() === "localhost") return true;
	const version = isIP(host);
	if (version === 4) {
		const octets = host.split(".").map(Number);
		const [first, second] = octets;
		return first === 10 || first === 127 ||
			(first === 192 && second === 168) ||
			(first === 172 && second !== undefined && second >= 16 && second <= 31) ||
			(first === 169 && second === 254);
	}
	if (version === 6) {
		const normalized = host.toLowerCase();
		if (normalized === "::1") return true;
		const firstHextet = Number.parseInt(normalized.split(":", 1)[0] ?? "", 16);
		return (firstHextet >= 0xfc00 && firstHextet <= 0xfdff) || // unique-local fc00::/7
			(firstHextet >= 0xfe80 && firstHextet <= 0xfebf); // link-local fe80::/10
	}
	// DNS names are not resolved and reclassified here, so only literal IP
	// addresses from the private ranges above are allowed by default.
	return false;
}

export function isTargetAllowed(target: string, allowPublicTargets: boolean): boolean {
	let parsed: URL;
	try {
		parsed = new URL(target);
	} catch {
		return false;
	}
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
	if (allowPublicTargets) return true;
	return isScannableHost(parsed.hostname);
}

// ── Version comparison ──────────────────────────────────────────────

/**
 * Compare two version strings. Returns -1, 0 or 1, or null when either side is
 * not a plain dotted numeric version (those cannot be ordered reliably, and a
 * wrong comparison would produce a wrong vulnerability verdict).
 */
export function compareVersions(a: string, b: string): number | null {
	const parse = (value: string): number[] | null => {
		const core = value.trim().replace(/^v(?=\d)/i, "").split(/[-+]/)[0] ?? "";
		if (!/^\d+(\.\d+)*$/.test(core)) return null;
		const parts = core.split(".").map((part) => Number.parseInt(part, 10));
		// A four-digit leading component is a date (e.g. `2026.01.01`), a build
		// stamp or a sentinel such as `9999.12.31`, not a comparable release
		// version. Ordering it numerically would produce a wrong vulnerability
		// verdict, so refuse to compare instead.
		const first = parts[0];
		if (first === undefined || first > 9999 || (first > 999 && core.length >= 4 && /^\d{4}/.test(core))) {
			return null;
		}
		return parts;
	};
	const left = parse(a);
	const right = parse(b);
	if (!left || !right) return null;
	const len = Math.max(left.length, right.length);
	for (let i = 0; i < len; i++) {
		const l = left[i] ?? 0;
		const r = right[i] ?? 0;
		if (l < r) return -1;
		if (l > r) return 1;
	}
	return 0;
}

/**
 * Evaluate AIG's rule expression against a concrete version.
 *
 * AIG reduces to forms like `version < "0.5.2"`, `version >= "1.2" && version <
 * "2.0"`, or `||`-joined branches. Anything that is not a pure version
 * comparison returns `false` for `evaluated`, so callers can distinguish "not
 * vulnerable" from "we could not tell".
 */
export function evaluateVersionRule(
	rule: string | null,
	version: string,
): { matched: boolean; evaluated: boolean } {
	if (!rule) return { matched: false, evaluated: false };
	const branches = rule.split(/\s*\|\|\s*/);
	// Track whether ANY branch was fully understood. A branch we could not parse
	// or compare must never be silently treated as "not vulnerable"; the caller
	// needs to know the rule was opaque.
	let anyEvaluated = false;
	for (const rawBranch of branches) {
		const branch = rawBranch.replace(/^\s*\(|\)\s*$/g, "").trim();
		if (!branch) continue;
		const comparisons = branch.split(/\s*&&\s*/);
		let branchMatched = true;
		let branchEvaluated = true;
		for (const comparison of comparisons) {
			const m = comparison
				.trim()
				.match(/^version\s*(<=|>=|<|>|==|=)\s*["']?([^"']+?)["']?$/i);
			if (!m) {
				branchEvaluated = false;
				break;
			}
			const operator = m[1];
			const bound = m[2];
			if (!operator || !bound) {
				branchEvaluated = false;
				break;
			}
			const cmp = compareVersions(version, bound);
			if (cmp === null) {
				branchEvaluated = false;
				break;
			}
			const op = operator === "==" ? "=" : operator;
			const ok =
				op === "<"
					? cmp < 0
					: op === "<="
						? cmp <= 0
						: op === ">"
							? cmp > 0
							: op === ">="
								? cmp >= 0
								: cmp === 0;
			if (!ok) {
				branchMatched = false;
				break;
			}
		}
		if (branchMatched && branchEvaluated) return { matched: true, evaluated: true };
		if (branchEvaluated) anyEvaluated = true;
	}
	// No branch matched. Only claim a definitive "not vulnerable" if at least one
	// branch was fully understood; otherwise the rule was opaque and the caller
	// must not read this as a clean result.
	return { matched: false, evaluated: anyEvaluated };
}

/** Alias index: canonical product + aliases (lower-cased) -> CVEs. */
let _cveByAlias: Map<string, CompiledCve[]> | null = null;

function cveByAlias(): Map<string, CompiledCve[]> {
	if (_cveByAlias === null) {
		const map = new Map<string, CompiledCve[]>();
		for (const cve of cves()) {
			const keys = new Set<string>([
				cve.p.toLowerCase(),
				...(cve.a ?? []).map((a) => a.toLowerCase()),
			]);
			for (const key of keys) {
				const list = map.get(key);
				if (list) list.push(cve);
				else map.set(key, [cve]);
			}
		}
		_cveByAlias = map;
	}
	return _cveByAlias;
}

export function lookupCvesForProduct(product: string, version: string | null): AigCveFinding[] {
	const candidates = cveByAlias().get(product.toLowerCase()) ?? [];
	const findings: AigCveFinding[] = [];
	for (const cve of candidates) {
		// Without a version we cannot decide applicability; report it as an
		// unevaluated finding rather than claiming the target is affected.
		if (!version) {
			findings.push({
				cveId: cve.id,
				product: cve.p,
				severity: cve.s,
				cvss: cve.c ?? null,
				rule: cve.o,
				ruleStatus: cve.u,
				evaluated: false,
			});
			continue;
		}
		const { matched, evaluated } = evaluateVersionRule(cve.r, version);
		if (matched || !evaluated) {
			findings.push({
				cveId: cve.id,
				product: cve.p,
				severity: cve.s,
				cvss: cve.c ?? null,
				rule: cve.o,
				ruleStatus: cve.u,
				evaluated,
			});
		}
	}
	return findings;
}

// ── Response matching ───────────────────────────────────────────────

function matcherTarget(key: string, body: string, headers: Headers, status: number): string | null {
	switch (key) {
		case "body":
			return body;
		case "header":
			return [...headers.entries()].map(([k, v]) => `${k}: ${v}`).join("\n");
		case "status":
			return String(status);
		case "title": {
			const m = body.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
			return m?.[1] ?? null;
		}
		default:
			return null;
	}
}

/** A probe matches only if EVERY matcher holds (all matchers are AND-ed). */
export function probeMatches(
	probe: CompiledProbe,
	body: string,
	headers: Headers,
	status: number,
): boolean {
	if (!probe.supported) return false;
	for (const matcher of probe.matchers) {
		if ("unsupported" in matcher) return false;
		const target = matcherTarget(matcher.key, body, headers, status);
		if (target === null) return false;
		let hit: boolean;
		if (matcher.regex !== undefined) {
			try {
				hit = new RegExp(matcher.regex, "i").test(target);
			} catch {
				hit = false;
			}
		} else {
			hit = target.includes(matcher.contains ?? "");
		}
		if (matcher.negate ? hit : !hit) return false;
	}
	return true;
}

export function extractVersion(
	extractor: CompiledVersionExtractor,
	body: string,
	headers: Headers,
): string | null {
	const target =
		extractor.part === "header"
			? [...headers.entries()].map(([k, v]) => `${k}: ${v}`).join("\n")
			: body;
	try {
		const re = new RegExp(extractor.regex, "i");
		const m = re.exec(target);
		if (!m) return null;
		const group = extractor.group > 0 ? m[extractor.group] : m[1];
		return group ? group.trim() : null;
	} catch {
		return null;
	}
}

// ── Scanner ─────────────────────────────────────────────────────────

async function fetchBounded(
	url: string,
	method: string,
	timeoutMs: number,
	fetchImpl: typeof fetch,
	parentSignal?: AbortSignal,
): Promise<{ status: number; body: string; headers: Headers } | { error: string }> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	const abort = () => controller.abort(parentSignal?.reason);
	if (parentSignal?.aborted) abort();
	else parentSignal?.addEventListener("abort", abort, { once: true });
	try {
		const response = await fetchImpl(url, {
			method,
			redirect: "manual",
			signal: controller.signal,
			headers: { accept: "*/*", "user-agent": "SingularityAIDR/infra-scan" },
		});
		if (parentSignal?.aborted) {
			await response.body?.cancel();
			return { error: "scan_aborted" };
		}
		if (response.status >= 300 && response.status < 400) { await response.body?.cancel(); return { error: "redirect_not_followed" }; }
		const chunks: Uint8Array[] = [];
		let size = 0;
		const reader = response.body?.getReader();
		try {
			if (reader) {
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					size += value.byteLength;
					if (size > MAX_BODY_BYTES) { await reader.cancel(); return { error: "response_too_large" }; }
					chunks.push(value);
				}
			}
		} finally { reader?.releaseLock(); }
		const body = Buffer.concat(chunks).toString("utf8");
		return { status: response.status, body, headers: response.headers };
	} catch (error) {
		if (parentSignal?.aborted) return { error: "scan_aborted" };
		return { error: error instanceof Error ? error.message : String(error) };
	} finally {
		clearTimeout(timer);
		parentSignal?.removeEventListener("abort", abort);
	}
}

/**
 * Scan one target. Never throws: an unreachable target or a failed probe is
 * reported via `error`/`reachable` so that a caller can never mistake "we could
 * not check" for "clean".
 */
export async function scanTarget(
	target: AigInfraScanTarget,
	options: AigInfraScanOptions = {},
): Promise<AigInfraTargetResult> {
	const {
		timeoutMs = 3000,
		deadlineMs = 15000,
		allowPublicTargets = false,
		fetchImpl = globalThis.fetch,
		signal,
	} = options;

	const result: AigInfraTargetResult = {
		url: target.url,
		reachable: false,
		matched: [],
		cves: [],
		error: null,
		requestsMade: 0,
	};

	if (!isTargetAllowed(target.url, allowPublicTargets)) {
		result.error = "target_not_allowed";
		return result;
	}

	let base: URL;
	try {
		base = new URL(target.url);
	} catch {
		result.error = "invalid_target_url";
		return result;
	}
	if (!(await dataAvailable())) {
		result.error = "dataset_unavailable";
		return result;
	}

	const deadline = Date.now() + deadlineMs;
	let lastError: string | null = null;

	fingerprintLoop: for (const fingerprint of fingerprints()) {
		if (signal?.aborted) {
			lastError = "scan_aborted";
			break;
		}
		if (Date.now() > deadline) {
			lastError = lastError ?? "deadline_exceeded";
			break;
		}
		for (const probe of fingerprint.http ?? []) {
			if (!probe.supported) continue;
			if (Date.now() >= deadline) { lastError = lastError ?? "deadline_exceeded"; break; }
			const probeUrl = new URL(probe.path, base).toString();
			if (new URL(probeUrl).origin !== base.origin) { lastError = "cross_origin_probe_refused"; continue; }
			const response = await fetchBounded(
				probeUrl,
				probe.method,
				Math.max(1, Math.min(timeoutMs, deadline - Date.now())),
				fetchImpl,
				signal,
			);
			result.requestsMade++;
			if ("error" in response) {
				lastError = response.error;
				if (response.error === "scan_aborted") break fingerprintLoop;
				continue;
			}
			result.reachable = true;
			if (!probeMatches(probe, response.body, response.headers, response.status)) continue;

			// Detected. Extract a version if the fingerprint declares one.
			let version: string | null = null;
			for (const extractor of fingerprint.ver ?? []) {
				if (extractor.path !== probe.path) continue;
				version = extractVersion(extractor, response.body, response.headers);
				if (version) break;
			}

			result.matched.push({
				product: fingerprint.p || fingerprint.n,
				vendor: fingerprint.v,
				name: fingerprint.n,
				severity: fingerprint.sev,
				description: fingerprint.desc,
				version,
				probePath: probe.path,
			});
			result.cves.push(...lookupCvesForProduct(fingerprint.p || fingerprint.n, version));
			break; // one probe per fingerprint is enough to identify it
		}
	}

	if (lastError) result.error = lastError;
	if (result.matched.length === 0 && !result.error) result.error = "no_fingerprint_matched";
	return result;
}

export interface AigInfraScanSummary {
	targets: AigInfraTargetResult[];
	critical: number;
	high: number;
	cvesFound: number;
	scannedAt: string;
}

/** Scan several targets with bounded concurrency. */
export async function scanTargets(
	targets: string[],
	options: AigInfraScanOptions = {},
): Promise<AigInfraScanSummary> {
	const { concurrency = 4 } = options;
	const results: AigInfraTargetResult[] = [];
	let index = 0;
	const workers = Array.from({ length: Math.max(1, Math.min(concurrency, targets.length)) }, async () => {
		while (index < targets.length) {
			options.signal?.throwIfAborted();
			const current = index++;
			const target = targets[current];
			if (!target) continue;
			results.push(await scanTarget({ url: target }, options));
		}
	});
	await Promise.all(workers);

	let critical = 0;
	let high = 0;
	let cvesFound = 0;
	for (const r of results) {
		for (const cve of r.cves) {
			cvesFound++;
			if (cve.severity === "critical") critical++;
			else if (cve.severity === "high") high++;
		}
	}
	return {
		targets: results,
		critical,
		high,
		cvesFound,
		scannedAt: new Date().toISOString(),
	};
}

/** Fingerprints known to the compiled dataset (for diagnostics/UI). */
export function fingerprintCount(): number {
	return fingerprints().length;
}

/** CVEs known to the compiled dataset (for diagnostics/UI). */
export function cveCount(): number {
	return cves().length;
}
