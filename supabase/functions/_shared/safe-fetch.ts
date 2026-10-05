// SSRF-safe JSON fetch for operator-supplied URLs (OIDC discovery, JWKS, token
// endpoint). Policy, in the order it is enforced:
//
//   1. https only, no URL credentials, no fragment, port allow-list (443 by default);
//   2. host is a DNS name (IP literals and single-label / internal suffixes are refused);
//   3. every A/AAAA answer must be a public address (egress-guard.ts, a port of the
//      core MCP SSRF guard), so a mixed answer cannot slip an internal address in;
//   4. redirects are never followed (a 3xx is an error, not a hop);
//   5. bounded time and bounded response bytes, JSON content type required.
//
// Residual risk (documented in docs/production-readiness/oidc-sso-admin.md): the
// Edge runtime's `fetch` resolves the name again, so DNS answers can change
// between the check and the connection. The check removes static and
// mixed-answer SSRF; it cannot pin the connection the way the core transport
// does. The Supabase Edge network has no route to the project's private
// services, which is the compensating control.

import { isBlockedHostname, isPublicIpAddress, ipVersion } from "./egress-guard.ts";

type SafeFetchError =
	| "invalid_url"
	| "insecure_scheme"
	| "url_credentials_forbidden"
	| "port_not_allowed"
	| "blocked_host"
	| "dns_lookup_failed"
	| "private_address"
	| "redirect_blocked"
	| "response_too_large"
	| "unexpected_content_type"
	| "invalid_json"
	| "timeout"
	| "network_error"
	| "http_status";

export type SafeFetchResult =
	| { ok: true; status: number; json: unknown; headers: Headers }
	| { ok: false; error: SafeFetchError; status?: number };

type DnsResolver = (hostname: string, type: "A" | "AAAA") => Promise<string[]>;

export interface SafeFetchOptions {
	fetch?: typeof fetch;
	resolveDns?: DnsResolver;
	timeoutMs?: number;
	maxBytes?: number;
	allowedPorts?: readonly number[];
}

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_BYTES = 256 * 1024;

type DenoLike = { resolveDns?: (name: string, type: string) => Promise<string[]> };

const defaultResolver: DnsResolver = async (hostname, type) => {
	const deno = (globalThis as { Deno?: DenoLike }).Deno;
	if (!deno?.resolveDns) throw new Error("dns_resolver_unavailable");
	return await deno.resolveDns(hostname, type);
};

export type SafeUrlResult =
	| { ok: true; url: URL; addresses: string[] }
	| { ok: false; error: SafeFetchError };

/** Validate a URL against the egress policy and return its public addresses. */
export async function assertSafeUrl(
	value: string,
	options: SafeFetchOptions = {},
): Promise<SafeUrlResult> {
	let url: URL;
	try {
		url = new URL(value);
	} catch {
		return { ok: false, error: "invalid_url" };
	}
	if (url.protocol !== "https:") return { ok: false, error: "insecure_scheme" };
	if (url.username || url.password || url.hash)
		return { ok: false, error: "url_credentials_forbidden" };
	const port = url.port === "" ? 443 : Number(url.port);
	if (!(options.allowedPorts ?? [443]).includes(port)) return { ok: false, error: "port_not_allowed" };
	const host = url.hostname.replace(/^\[|\]$/g, "").replace(/\.+$/, "").toLowerCase();
	if (!host || ipVersion(host) !== 0 || isBlockedHostname(host))
		return { ok: false, error: "blocked_host" };

	const resolve = options.resolveDns ?? defaultResolver;
	const answers: string[] = [];
	let anyLookupSucceeded = false;
	for (const type of ["A", "AAAA"] as const) {
		try {
			answers.push(...(await resolve(host, type)));
			anyLookupSucceeded = true;
		} catch {
			// NODATA for one family is normal; both failing is handled below.
		}
	}
	const addresses = [...new Set(answers.map((address) => address.trim().toLowerCase()))];
	if (!anyLookupSucceeded || addresses.length === 0) return { ok: false, error: "dns_lookup_failed" };
	if (!addresses.every(isPublicIpAddress)) return { ok: false, error: "private_address" };
	return { ok: true, url, addresses };
}

async function readCapped(response: Response, maxBytes: number): Promise<Uint8Array | null> {
	const declared = Number(response.headers.get("content-length") ?? "0");
	if (Number.isFinite(declared) && declared > maxBytes) return null;
	if (!response.body) return new Uint8Array();
	const reader = response.body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	try {
		for (;;) {
			const part = await reader.read();
			if (part.done) break;
			total += part.value.byteLength;
			if (total > maxBytes) return null;
			chunks.push(part.value);
		}
	} finally {
		await reader.cancel().catch(() => undefined);
	}
	const output = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		output.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return output;
}

/** Fetch a JSON document (or POST a form and read the JSON reply) under the egress policy. */
export async function safeFetchJson(
	value: string,
	init: RequestInit = {},
	options: SafeFetchOptions = {},
): Promise<SafeFetchResult> {
	const checked = await assertSafeUrl(value, options);
	if (!checked.ok) return checked;
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
	try {
		const response = await (options.fetch ?? fetch)(checked.url.toString(), {
			...init,
			redirect: "manual",
			credentials: "omit",
			signal: controller.signal,
		});
		if (response.status >= 300 && response.status < 400) {
			await response.body?.cancel().catch(() => undefined);
			return { ok: false, error: "redirect_blocked", status: response.status };
		}
		if (response.status < 200 || response.status >= 300) {
			await response.body?.cancel().catch(() => undefined);
			return { ok: false, error: "http_status", status: response.status };
		}
		if (!/json/i.test(response.headers.get("content-type") ?? "")) {
			await response.body?.cancel().catch(() => undefined);
			return { ok: false, error: "unexpected_content_type", status: response.status };
		}
		const bytes = await readCapped(response, options.maxBytes ?? DEFAULT_MAX_BYTES);
		if (!bytes) return { ok: false, error: "response_too_large", status: response.status };
		try {
			const json: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
			return { ok: true, status: response.status, json, headers: response.headers };
		} catch {
			return { ok: false, error: "invalid_json", status: response.status };
		}
	} catch (error) {
		return {
			ok: false,
			error: controller.signal.aborted || (error as Error)?.name === "AbortError" ? "timeout" : "network_error",
		};
	} finally {
		clearTimeout(timer);
	}
}
