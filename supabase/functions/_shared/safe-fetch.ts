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
//
// On-prem identity providers (Keycloak, ADFS) usually live on an internal
// network. The operator - never a tenant owner - may exempt exact host names
// from rules 1-3 with AIDR_OIDC_INTERNAL_IDP_HOSTS (parseInternalHosts below):
// a listed host may use a listed port and resolve to RFC 1918 / CGNAT / IPv6
// ULA addresses. https, the no-redirect rule, the size/time bounds and the
// refusal of loopback, link-local, metadata and other reserved addresses still
// apply to it, and every host that is not listed keeps the public-only policy.

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

/** Operator-listed internal hosts: exact lower-case DNS name -> extra allowed ports. */
export type InternalHosts = ReadonlyMap<string, readonly number[]>;

export interface SafeFetchOptions {
	fetch?: typeof fetch;
	resolveDns?: DnsResolver;
	timeoutMs?: number;
	maxBytes?: number;
	allowedPorts?: readonly number[];
	internalHosts?: InternalHosts;
}

export const INTERNAL_HOSTS_ENV = "AIDR_OIDC_INTERNAL_IDP_HOSTS";
const MAX_INTERNAL_HOSTS = 16;
const DNS_NAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
// Names that stay refused even when listed: loopback aliases and cloud metadata.
const NEVER_INTERNAL = /(^|\.)localhost$|^localhost\.localdomain$|^ip6-(localhost|loopback)$|^metadata\.google\.(internal|com)$|^instance-data\.ec2\.internal$/;

/**
 * Parse AIDR_OIDC_INTERNAL_IDP_HOSTS: comma- or space-separated `host[:port]`
 * entries, fully qualified DNS names only (no IP literals, no wildcards). An
 * empty value means no exemption; any malformed entry rejects the whole value,
 * so a typo never silently widens or narrows the policy.
 */
export function parseInternalHosts(raw: string | undefined | null):
	| { ok: true; hosts: InternalHosts }
	| { ok: false; error: "invalid_internal_hosts" } {
	const hosts = new Map<string, number[]>();
	const entries = (raw ?? "").split(/[\s,]+/).filter(Boolean);
	if (entries.length > MAX_INTERNAL_HOSTS) return { ok: false, error: "invalid_internal_hosts" };
	for (const entry of entries) {
		const match = /^([^:]+)(?::(\d{1,5}))?$/.exec(entry.toLowerCase());
		const host = match?.[1]?.replace(/\.$/, "") ?? "";
		const port = match?.[2] === undefined ? 443 : Number(match[2]);
		if (!match || !DNS_NAME.test(host) || ipVersion(host) !== 0 || NEVER_INTERNAL.test(host) || port < 1 || port > 65_535)
			return { ok: false, error: "invalid_internal_hosts" };
		const ports = hosts.get(host) ?? [];
		if (!ports.includes(port)) ports.push(port);
		hosts.set(host, ports);
	}
	return { ok: true, hosts };
}

/**
 * Private ranges an operator may reach through a listed internal host:
 * 10/8, 172.16/12, 192.168/16, 100.64/10 (CGNAT) and fc00::/7 (ULA). Loopback,
 * link-local, unspecified, multicast, documentation and every other reserved
 * range stay refused.
 */
export function isOperatorPrivateAddress(value: string): boolean {
	const address = value.trim().toLowerCase().replace(/^\[|\]$/g, "");
	const version = ipVersion(address);
	if (version === 4) {
		const [a, b] = address.split(".").map(Number) as [number, number];
		return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
	}
	return version === 6 && /^f[cd][0-9a-f]{0,2}:/.test(address);
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
	const host = url.hostname.replace(/^\[|\]$/g, "").replace(/\.+$/, "").toLowerCase();
	const internalPorts = options.internalHosts?.get(host);
	if (!(options.allowedPorts ?? [443]).includes(port) && !internalPorts?.includes(port))
		return { ok: false, error: "port_not_allowed" };
	if (!host || ipVersion(host) !== 0 || (!internalPorts && isBlockedHostname(host)))
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
	const permitted = internalPorts
		? (address: string) => isPublicIpAddress(address) || isOperatorPrivateAddress(address)
		: isPublicIpAddress;
	if (!addresses.every(permitted)) return { ok: false, error: "private_address" };
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
