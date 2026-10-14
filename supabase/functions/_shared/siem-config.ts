// SIEM forwarding destinations: validation, encryption at rest and the
// network policy for collector addresses. Contract: docs/contracts/siem-forwarding.md.
//
// A destination's connection settings (collector address, HEC token, Elastic
// API key, Sentinel client secret, webhook signing secret, internal CA) are a
// credential. They are validated here, sealed with the notification keyring
// (AIDR_NOTIFICATION_ENCRYPTION_KEYS) under associated data that binds the
// tenant, destination and provider, and never returned by any API: the
// dashboard sees `targetHint` (provider and host:port) only.
//
// Network policy. SaaS tenants must never reach the control plane's own
// network, so by default every resolved collector address must be public
// unicast (the same classification as alert webhooks). On-prem collectors
// usually live on RFC 1918 networks: a deployment operator may allow private
// collector addresses with AIDR_SIEM_ALLOW_PRIVATE_NETWORKS=true, and then a
// destination must still opt in (`allow_private_network`). Loopback,
// link-local (including cloud metadata), multicast and reserved addresses are
// refused in every configuration. Hosts are re-resolved and re-checked before
// every delivery, and the forwarder dials the exact address it checked.

import {
	type DnsResolver,
	isBlockedAddress,
	type NotificationKeyring,
	openJson,
	parseIpv4,
	parseIpv6,
	sealJson,
} from "./notification-targets.ts";
import { pemCertificates } from "./socket-transport.ts";

export const SIEM_PROVIDERS = ["syslog", "splunk_hec", "elastic", "sentinel", "webhook"] as const;
export type SiemProvider = (typeof SIEM_PROVIDERS)[number];
export const SIEM_FORMATS = ["json", "cef", "leef"] as const;
export type SiemFormat = (typeof SIEM_FORMATS)[number];

interface NetworkOptions {
	/** PEM CA bundle that replaces the system roots (internal CA). */
	ca_pem?: string;
	/** Allow RFC 1918 / ULA / CGNAT collectors (needs AIDR_SIEM_ALLOW_PRIVATE_NETWORKS). */
	allow_private_network?: boolean;
}

export interface SyslogDestinationConfig extends NetworkOptions {
	provider: "syslog";
	transport: "tls" | "tcp" | "udp";
	host: string;
	port: number;
	/** Plain TCP/UDP sends events unencrypted; requires this explicit opt-in. */
	allow_plaintext?: boolean;
	facility?: number;
	app_name?: string;
	hostname?: string;
}

interface SplunkHecDestinationConfig extends NetworkOptions {
	provider: "splunk_hec";
	url: string;
	token: string;
	index?: string;
	source?: string;
	sourcetype?: string;
}

interface ElasticDestinationConfig extends NetworkOptions {
	provider: "elastic";
	url: string;
	index: string;
	api_key?: string;
	username?: string;
	password?: string;
}

interface SentinelDestinationConfig {
	provider: "sentinel";
	/** Data collection endpoint, https://<name>.<region>.ingest.monitor.azure.com */
	endpoint: string;
	dcr_immutable_id: string;
	stream_name: string;
	azure_tenant_id: string;
	client_id: string;
	client_secret: string;
}

interface WebhookDestinationConfig extends NetworkOptions {
	provider: "webhook";
	url: string;
	secret: string;
}

export type SiemDestinationConfig =
	| SyslogDestinationConfig
	| SplunkHecDestinationConfig
	| ElasticDestinationConfig
	| SentinelDestinationConfig
	| WebhookDestinationConfig;

export type SiemConfigError =
	| "invalid_config"
	| "invalid_host"
	| "invalid_port"
	| "invalid_url"
	| "url_not_https"
	| "url_credentials_forbidden"
	| "plaintext_not_confirmed"
	| "invalid_ca"
	| "invalid_secret"
	| "invalid_index"
	| "invalid_sentinel"
	| "invalid_format";

const HOST_NAME = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const PRINTABLE_SECRET = /^[\x21-\x7e]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LABEL = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const SENTINEL_HOST_SUFFIXES = [".ingest.monitor.azure.com", ".ingest.monitor.azure.us", ".ingest.monitor.azure.cn"];
const MAX_CA_BYTES = 65_536;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function onlyKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[]): boolean {
	return required.every((key) => Object.hasOwn(value, key)) &&
		Object.keys(value).every((key) => required.includes(key) || optional.includes(key));
}

/** A DNS name or an IP literal (brackets stripped); null when neither. */
function normalizeHost(value: unknown): string | null {
	if (typeof value !== "string" || value.length === 0 || value.length > 255 || /\s/.test(value)) return null;
	const host = value.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
	if (parseIpv4(host) || parseIpv6(host)) return host;
	return HOST_NAME.test(host) ? host : null;
}

function validPort(value: unknown): value is number {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= 1 && value <= 65_535;
}

function validSecret(value: unknown, min: number, max: number): value is string {
	return typeof value === "string" && value.length >= min && value.length <= max && PRINTABLE_SECRET.test(value);
}

function checkCa(value: unknown): boolean {
	if (value === undefined) return true;
	return typeof value === "string" && value.length <= MAX_CA_BYTES && pemCertificates(value).length > 0;
}

function checkHttpsUrl(value: unknown, allowPath: boolean): { ok: true; url: URL } | { ok: false; error: SiemConfigError } {
	if (typeof value !== "string" || value.length === 0 || value.length > 2048 || /\s/.test(value)) {
		return { ok: false, error: "invalid_url" };
	}
	let url: URL;
	try {
		url = new URL(value);
	} catch {
		return { ok: false, error: "invalid_url" };
	}
	if (url.protocol !== "https:") return { ok: false, error: "url_not_https" };
	if (url.username || url.password) return { ok: false, error: "url_credentials_forbidden" };
	if (url.search || url.hash || (!allowPath && url.pathname !== "/" && url.pathname !== "")) {
		return { ok: false, error: "invalid_url" };
	}
	if (!normalizeHost(url.hostname)) return { ok: false, error: "invalid_host" };
	return { ok: true, url };
}

function network(value: Record<string, unknown>): NetworkOptions | null {
	if (!checkCa(value.ca_pem)) return null;
	if (value.allow_private_network !== undefined && typeof value.allow_private_network !== "boolean") return null;
	return {
		...(typeof value.ca_pem === "string" ? { ca_pem: value.ca_pem } : {}),
		...(value.allow_private_network === true ? { allow_private_network: true } : {}),
	};
}

/** Validate the write-only configuration a client submitted for a provider. */
export function parseSiemConfig(provider: SiemProvider, value: unknown):
	| { ok: true; config: SiemDestinationConfig }
	| { ok: false; error: SiemConfigError } {
	if (!isRecord(value)) return { ok: false, error: "invalid_config" };
	const net = provider === "sentinel" ? {} : network(value);
	if (net === null) return { ok: false, error: "invalid_ca" };
	const common = ["ca_pem", "allow_private_network"];
	if (provider === "syslog") {
		if (!onlyKeys(value, ["transport", "host", "port"], [...common, "allow_plaintext", "facility", "app_name", "hostname"])) {
			return { ok: false, error: "invalid_config" };
		}
		if (!["tls", "tcp", "udp"].includes(value.transport as string)) return { ok: false, error: "invalid_config" };
		const host = normalizeHost(value.host);
		if (!host) return { ok: false, error: "invalid_host" };
		if (!validPort(value.port)) return { ok: false, error: "invalid_port" };
		const transport = value.transport as SyslogDestinationConfig["transport"];
		if (transport !== "tls" && value.allow_plaintext !== true) return { ok: false, error: "plaintext_not_confirmed" };
		if (transport !== "tls" && net.ca_pem) return { ok: false, error: "invalid_ca" };
		if (value.facility !== undefined && !(Number.isSafeInteger(value.facility) && (value.facility as number) >= 0 && (value.facility as number) <= 23)) {
			return { ok: false, error: "invalid_config" };
		}
		for (const key of ["app_name", "hostname"] as const) {
			if (value[key] !== undefined && !(typeof value[key] === "string" && /^[\x21-\x7e]{1,48}$/.test(value[key] as string))) {
				return { ok: false, error: "invalid_config" };
			}
		}
		return {
			ok: true,
			config: {
				provider,
				transport,
				host,
				port: value.port,
				...net,
				...(transport !== "tls" ? { allow_plaintext: true } : {}),
				...(value.facility !== undefined ? { facility: value.facility as number } : {}),
				...(value.app_name !== undefined ? { app_name: value.app_name as string } : {}),
				...(value.hostname !== undefined ? { hostname: value.hostname as string } : {}),
			},
		};
	}
	if (provider === "splunk_hec") {
		if (!onlyKeys(value, ["url", "token"], [...common, "index", "source", "sourcetype"])) return { ok: false, error: "invalid_config" };
		const checked = checkHttpsUrl(value.url, false);
		if (!checked.ok) return checked;
		if (!validSecret(value.token, 8, 256)) return { ok: false, error: "invalid_secret" };
		for (const key of ["index", "source", "sourcetype"] as const) {
			if (value[key] !== undefined && !(typeof value[key] === "string" && LABEL.test(value[key] as string))) {
				return { ok: false, error: "invalid_index" };
			}
		}
		return {
			ok: true,
			config: {
				provider,
				url: checked.url.origin,
				token: value.token,
				...net,
				...(value.index !== undefined ? { index: value.index as string } : {}),
				...(value.source !== undefined ? { source: value.source as string } : {}),
				...(value.sourcetype !== undefined ? { sourcetype: value.sourcetype as string } : {}),
			},
		};
	}
	if (provider === "elastic") {
		if (!onlyKeys(value, ["url", "index"], [...common, "api_key", "username", "password"])) return { ok: false, error: "invalid_config" };
		const checked = checkHttpsUrl(value.url, false);
		if (!checked.ok) return checked;
		if (typeof value.index !== "string" || !/^[a-z0-9][a-z0-9._-]{0,254}$/.test(value.index)) return { ok: false, error: "invalid_index" };
		const hasKey = value.api_key !== undefined;
		const hasBasic = value.username !== undefined || value.password !== undefined;
		if (hasKey === hasBasic) return { ok: false, error: "invalid_secret" };
		if (hasKey && !validSecret(value.api_key, 8, 1024)) return { ok: false, error: "invalid_secret" };
		if (hasBasic && !(typeof value.username === "string" && /^[^:\p{Cc}]{1,128}$/u.test(value.username) && validSecret(value.password, 1, 256))) {
			return { ok: false, error: "invalid_secret" };
		}
		return {
			ok: true,
			config: {
				provider,
				url: checked.url.origin,
				index: value.index,
				...net,
				...(hasKey ? { api_key: value.api_key as string } : { username: value.username as string, password: value.password as string }),
			},
		};
	}
	if (provider === "sentinel") {
		if (!onlyKeys(value, ["endpoint", "dcr_immutable_id", "stream_name", "azure_tenant_id", "client_id", "client_secret"], [])) {
			return { ok: false, error: "invalid_config" };
		}
		const checked = checkHttpsUrl(value.endpoint, false);
		if (!checked.ok) return checked;
		const host = checked.url.hostname.toLowerCase();
		if (!SENTINEL_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix) && host.length > suffix.length) || checked.url.port !== "") {
			return { ok: false, error: "invalid_sentinel" };
		}
		if (
			typeof value.dcr_immutable_id !== "string" || !/^dcr-[0-9a-f]{32}$/.test(value.dcr_immutable_id) ||
			typeof value.stream_name !== "string" || !/^(Custom|Microsoft)-[A-Za-z0-9_]{1,100}$/.test(value.stream_name) ||
			typeof value.azure_tenant_id !== "string" || !UUID.test(value.azure_tenant_id) ||
			typeof value.client_id !== "string" || !UUID.test(value.client_id)
		) {
			return { ok: false, error: "invalid_sentinel" };
		}
		if (!validSecret(value.client_secret, 8, 256)) return { ok: false, error: "invalid_secret" };
		return {
			ok: true,
			config: {
				provider,
				endpoint: checked.url.origin,
				dcr_immutable_id: value.dcr_immutable_id,
				stream_name: value.stream_name,
				azure_tenant_id: value.azure_tenant_id.toLowerCase(),
				client_id: value.client_id.toLowerCase(),
				client_secret: value.client_secret,
			},
		};
	}
	if (!onlyKeys(value, ["url", "secret"], common)) return { ok: false, error: "invalid_config" };
	const checked = checkHttpsUrl(value.url, true);
	if (!checked.ok) return checked;
	if (!validSecret(value.secret, 32, 256)) return { ok: false, error: "invalid_secret" };
	return { ok: true, config: { provider, url: checked.url.href, secret: value.secret, ...net } };
}

/** CEF/LEEF are syslog payload formats; every HTTP provider carries JSON. */
export function formatAllowed(provider: SiemProvider, format: SiemFormat): boolean {
	return format === "json" || provider === "syslog";
}

/** Non-secret dashboard label: provider route and host:port, never a token or path. */
export function siemTargetHint(config: SiemDestinationConfig): string {
	const hostPort = (url: string) => {
		const parsed = new URL(url);
		return `${parsed.hostname}${parsed.port ? `:${parsed.port}` : ""}`;
	};
	switch (config.provider) {
		case "syslog": {
			const host = config.host.includes(":") ? `[${config.host}]` : config.host;
			return `${config.transport}://${host}:${config.port}`.slice(0, 160);
		}
		case "sentinel":
			return `${hostPort(config.endpoint)} · ${config.stream_name}`.slice(0, 160);
		case "elastic":
			return `${hostPort(config.url)} · ${config.index}`.slice(0, 160);
		default:
			return hostPort(config.url).slice(0, 160);
	}
}

export interface DestinationBinding {
	tenantId: string;
	destinationId: string;
	provider: SiemProvider;
}

function bindingContext(binding: DestinationBinding): string {
	return `aidr-siem-destination:v1:${binding.tenantId.toLowerCase()}:${binding.destinationId.toLowerCase()}:${binding.provider}`;
}

export async function encryptSiemConfig(
	keyring: NotificationKeyring,
	binding: DestinationBinding,
	config: SiemDestinationConfig,
): Promise<{ ciphertext: string; keyId: string }> {
	if (config.provider !== binding.provider) throw new TypeError("config provider does not match its binding");
	return await sealJson(keyring, bindingContext(binding), config);
}

/** Decrypt and re-validate a stored configuration; null on any failure. */
export async function decryptSiemConfig(
	keyring: NotificationKeyring,
	binding: DestinationBinding,
	ciphertext: string,
): Promise<SiemDestinationConfig | null> {
	const parsed = await openJson(keyring, bindingContext(binding), ciphertext);
	if (!isRecord(parsed) || parsed.provider !== binding.provider) return null;
	const { provider: _provider, ...rest } = parsed;
	const checked = parseSiemConfig(binding.provider, rest);
	return checked.ok ? checked.config : null;
}

// ── Address policy ────────────────────────────────────────────────────────

export type SiemAddressClass = "public" | "private" | "blocked";

/** public unicast, private (RFC 1918 / CGNAT / ULA), or never contactable. */
export function classifySiemAddress(address: string): SiemAddressClass {
	const bare = address.replace(/^\[|\]$/g, "");
	if (!isBlockedAddress(bare)) return "public";
	let v4 = parseIpv4(bare);
	const v6 = v4 ? null : parseIpv6(bare);
	if (v6) {
		const mapped = v6.slice(0, 10).every((byte) => byte === 0) && v6[10] === 0xff && v6[11] === 0xff;
		if (mapped) v4 = v6.slice(12);
		else {
			// fd00:ec2::254 is the AWS IMDS endpoint inside the ULA range.
			const imds = v6[0] === 0xfd && v6[1] === 0x00 && v6[2] === 0x0e && v6[3] === 0xc2 &&
				v6.slice(4, 14).every((byte) => byte === 0) && v6[14] === 0x02 && v6[15] === 0x54;
			return (v6[0] & 0xfe) === 0xfc && !imds ? "private" : "blocked";
		}
	}
	if (!v4) return "blocked";
	const [a, b] = v4;
	if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)) {
		return "private";
	}
	return "blocked";
}

export type ResolveResult =
	| { ok: true; addresses: string[] }
	| { ok: false; error: "dns_unavailable" | "dns_unresolved" | "destination_policy_rejected" };

/**
 * Resolve `host` and require EVERY answer to be allowed: public, or private
 * when both the deployment and the destination allow private collectors.
 */
export async function resolveCollector(
	host: string,
	resolve: DnsResolver,
	allowPrivate: boolean,
): Promise<ResolveResult> {
	let addresses: string[];
	if (parseIpv4(host) || parseIpv6(host)) addresses = [host];
	else {
		try {
			addresses = await resolve(host);
		} catch (error) {
			return { ok: false, error: error instanceof Error && error.message === "dns_unavailable" ? "dns_unavailable" : "dns_unresolved" };
		}
	}
	if (!Array.isArray(addresses) || addresses.length === 0) return { ok: false, error: "dns_unresolved" };
	for (const address of addresses) {
		const kind = typeof address === "string" ? classifySiemAddress(address) : "blocked";
		if (kind === "blocked" || (kind === "private" && !allowPrivate)) {
			return { ok: false, error: "destination_policy_rejected" };
		}
	}
	return { ok: true, addresses: [...new Set(addresses)] };
}
