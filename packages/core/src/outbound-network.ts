/**
 * Outbound network for every first-party client (control plane, reputation,
 * version and update checks, rule sync): an internal CA bundle, the operating
 * system's trust store and an HTTPS proxy, for company networks with their own
 * CA or a TLS-inspecting proxy.
 *
 * Every client uses the global `fetch`; this module installs one dispatcher
 * for it (Node's own undici `Agent`, reached through the documented
 * `Symbol.for("undici.globalDispatcher.1")` slot, so no extra dependency).
 *
 * - CA: `network.ca_file` (PEM) and, with `network.use_os_trust_store`, the OS
 *   store are trusted IN ADDITION to Node's bundled roots. Certificate
 *   verification is never turned off.
 * - Proxy: `network.https_proxy`, else `HTTPS_PROXY` / `https_proxy`. Hosts in
 *   `network.no_proxy` (else `NO_PROXY` / `no_proxy`) and loopback addresses go
 *   direct. HTTPS goes through an HTTP CONNECT tunnel; TLS to the destination is
 *   end-to-end and verified as usual.
 *
 * Nothing is installed when none of this is configured, so a default install
 * behaves exactly as before.
 */
import { readFileSync } from "node:fs";
import { type ClientRequest, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { Socket } from "node:net";
import { isIP } from "node:net";
import * as tls from "node:tls";
import type { Config, Logger } from "./types.js";
import { nullLogger } from "./types.js";

const GLOBAL_DISPATCHER = Symbol.for("undici.globalDispatcher.1");
const CONNECT_TIMEOUT_MS = 15_000;

export interface OutboundNetworkSettings {
	caFile?: string;
	useOsTrustStore: boolean;
	proxy?: URL;
	noProxy: string[];
}

type NetworkConfig = Partial<NonNullable<Config["network"]>>;

/** The effective settings: configuration first, then the standard environment variables. */
export function resolveOutboundNetwork(
	network: NetworkConfig | undefined,
	env: NodeJS.ProcessEnv = process.env,
): OutboundNetworkSettings {
	const proxyText = (network?.https_proxy ?? env.HTTPS_PROXY ?? env.https_proxy ?? "").trim();
	let proxy: URL | undefined;
	if (proxyText) {
		try {
			const parsed = new URL(proxyText.includes("://") ? proxyText : `http://${proxyText}`);
			if ((parsed.protocol === "http:" || parsed.protocol === "https:") && parsed.hostname) {
				proxy = parsed;
			}
		} catch {
			proxy = undefined;
		}
	}
	const noProxy = (network?.no_proxy ?? env.NO_PROXY ?? env.no_proxy ?? "")
		.split(/[\s,]+/u)
		.map((entry) => entry.trim().toLowerCase())
		.filter(Boolean);
	return {
		...(network?.ca_file ? { caFile: network.ca_file } : {}),
		useOsTrustStore: network?.use_os_trust_store === true,
		...(proxy ? { proxy } : {}),
		noProxy,
	};
}

function isLoopbackHost(hostname: string): boolean {
	const host = hostname.replace(/^\[|\]$/gu, "").toLowerCase();
	if (host === "localhost" || host.endsWith(".localhost")) return true;
	if (isIP(host) === 4) return host.startsWith("127.");
	return host === "::1";
}

/** Whether a request to `hostname:port` bypasses the proxy (curl's NO_PROXY rules, plus loopback). */
export function bypassesProxy(hostname: string, port: string, noProxy: readonly string[]): boolean {
	const host = hostname.replace(/^\[|\]$/gu, "").toLowerCase();
	if (isLoopbackHost(host)) return true;
	for (const raw of noProxy) {
		if (raw === "*") return true;
		const [entryHost = "", entryPort] = raw.startsWith("[")
			? [raw.slice(1, raw.indexOf("]")), raw.slice(raw.indexOf("]") + 2) || undefined]
			: raw.split(":");
		if (entryPort && entryPort !== port) continue;
		const suffix = entryHost.replace(/^\*?\./u, "");
		if (!suffix) continue;
		if (host === suffix || host.endsWith(`.${suffix}`)) return true;
	}
	return false;
}

function systemCertificates(logger: Logger): string[] {
	const get = (tls as { getCACertificates?: (type: string) => string[] }).getCACertificates;
	if (typeof get !== "function") {
		logger.warn(
			"network.use_os_trust_store needs Node.js 22.15 or newer; start Node with --use-system-ca instead",
		);
		return [];
	}
	try {
		return get("system");
	} catch (error) {
		logger.warn("The operating system's certificate store could not be read", {
			error: String(error),
		});
		return [];
	}
}

/** Bundled roots + OS store (opt-in) + the CA file; null when nothing is added. */
export function trustedCertificates(
	settings: Pick<OutboundNetworkSettings, "caFile" | "useOsTrustStore">,
	logger: Logger = nullLogger,
	readFile: (path: string) => string = (path) => readFileSync(path, "utf8"),
): string[] | null {
	if (!settings.caFile && !settings.useOsTrustStore) return null;
	const extra: string[] = [];
	if (settings.useOsTrustStore) extra.push(...systemCertificates(logger));
	if (settings.caFile) {
		let text = "";
		try {
			text = readFile(settings.caFile);
		} catch (error) {
			logger.warn("network.ca_file cannot be read; it is not trusted", {
				path: settings.caFile,
				error: String(error),
			});
		}
		const pems = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gu) ?? [];
		if (text && pems.length === 0) {
			logger.warn("network.ca_file holds no PEM certificate; it is not trusted", {
				path: settings.caFile,
			});
		}
		extra.push(...pems);
	}
	return [...new Set([...tls.rootCertificates, ...extra])];
}

type ConnectCallback = (error: Error | null, socket?: Socket | tls.TLSSocket) => void;
interface ConnectOptions {
	hostname: string;
	host?: string;
	protocol: string;
	port: string;
	servername?: string;
}

const unbracket = (host: string) => host.replace(/^\[|\]$/gu, "");

/** The `host:port` of a CONNECT request (IPv6 in brackets). */
function connectTarget(options: ConnectOptions): string {
	const port = options.port || (options.protocol === "https:" ? "443" : "80");
	const host =
		options.hostname.includes(":") && !options.hostname.startsWith("[")
			? `[${options.hostname}]`
			: options.hostname;
	return `${host}:${port}`;
}

/** Send `CONNECT target` to the proxy (Basic credentials from the proxy URL). */
function sendConnect(proxy: URL, target: string, ca: string[] | null): ClientRequest {
	const headers: Record<string, string> = { host: target };
	if (proxy.username || proxy.password) {
		const credentials = `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`;
		headers["proxy-authorization"] = `Basic ${Buffer.from(credentials).toString("base64")}`;
	}
	const secureProxy = proxy.protocol === "https:";
	return (secureProxy ? httpsRequest : httpRequest)({
		host: unbracket(proxy.hostname),
		port: proxy.port || (secureProxy ? 443 : 80),
		method: "CONNECT",
		path: target,
		headers,
		timeout: CONNECT_TIMEOUT_MS,
		...(secureProxy && ca ? { ca } : {}),
	});
}

/** An undici `connect` function that tunnels through an HTTP(S) proxy with CONNECT. */
function proxyConnector(
	proxy: URL,
	ca: string[] | null,
): (options: ConnectOptions, callback: ConnectCallback) => void {
	return (options, callback) => {
		let settled = false;
		const done = (error: Error | null, socket?: Socket | tls.TLSSocket) => {
			if (settled) {
				if (socket && error === null) socket.destroy();
				return;
			}
			settled = true;
			callback(error, socket);
		};
		const target = connectTarget(options);
		let req: ClientRequest;
		try {
			req = sendConnect(proxy, target, ca);
		} catch (error) {
			done(error as Error);
			return;
		}
		req.once("timeout", () => req.destroy(new Error("proxy CONNECT timed out")));
		req.once("error", (error) => done(error));
		req.once("connect", (response, socket) => {
			if (response.statusCode !== 200) {
				socket.destroy();
				done(new Error(`proxy refused CONNECT to ${target} (HTTP ${response.statusCode})`));
				return;
			}
			if (options.protocol !== "https:") {
				done(null, socket);
				return;
			}
			// TLS to the destination runs inside the tunnel and is verified as usual.
			const secure = tls.connect({
				socket,
				servername: options.servername || unbracket(options.hostname),
				ALPNProtocols: ["http/1.1"],
				...(ca ? { ca } : {}),
			});
			secure.once("secureConnect", () => done(null, secure));
			secure.once("error", (error) => done(error));
		});
		req.end();
	};
}

interface Dispatcher {
	dispatch(options: { origin?: string | URL }, handler: unknown): boolean;
	close(): Promise<void>;
	destroy(): Promise<void>;
}
type AgentConstructor = new (options: Record<string, unknown>) => Dispatcher;

// Captured at load, before a test (or anything else) replaces the global.
const nativeFetch: typeof fetch | undefined = globalThis.fetch;
let installed: { key: string; result: OutboundNetworkResult } | null = null;
let original: unknown;

const globalSlot = globalThis as unknown as Record<symbol, unknown>;

async function agentConstructor(): Promise<AgentConstructor | null> {
	if (!globalSlot[GLOBAL_DISPATCHER]) {
		try {
			// Node creates its default dispatcher on the first fetch; a data: URL
			// needs no network.
			await nativeFetch?.("data:,");
		} catch {
			return null;
		}
	}
	const current = installed ? original : globalSlot[GLOBAL_DISPATCHER];
	return current && typeof current === "object"
		? ((current as object).constructor as AgentConstructor)
		: null;
}

export interface OutboundNetworkResult {
	proxy: boolean;
	extraCa: boolean;
}

const NOTHING: OutboundNetworkResult = { proxy: false, extraCa: false };

/**
 * Install the dispatcher for these settings (idempotent per process: the CA
 * file and OS store are read once per distinct setting). Failures are logged
 * and leave the default dispatcher in place: connectivity settings never
 * change what is enforced.
 */
export async function configureOutboundNetwork(
	network: NetworkConfig | undefined,
	logger: Logger = nullLogger,
	env: NodeJS.ProcessEnv = process.env,
): Promise<OutboundNetworkResult> {
	const settings = resolveOutboundNetwork(network, env);
	if (!settings.proxy && !settings.caFile && !settings.useOsTrustStore) {
		if (installed) {
			globalSlot[GLOBAL_DISPATCHER] = original;
			installed = null;
		}
		return NOTHING;
	}
	const key = JSON.stringify({
		proxy: settings.proxy?.href ?? null,
		noProxy: settings.noProxy,
		caFile: settings.caFile ?? null,
		os: settings.useOsTrustStore,
	});
	if (installed?.key === key) return installed.result;
	const Agent = await agentConstructor();
	if (!Agent) {
		logger.warn("Outbound proxy / CA settings could not be applied: fetch is not Node's own");
		return NOTHING;
	}
	const ca = trustedCertificates(settings, logger);
	try {
		const direct = new Agent(ca ? { connect: { ca } } : {});
		const viaProxy = settings.proxy
			? new Agent({ connect: proxyConnector(settings.proxy, ca) })
			: null;
		const noProxy = settings.noProxy;
		const routing: Dispatcher = {
			dispatch(options, handler) {
				let target: URL | null = null;
				try {
					target = options.origin ? new URL(String(options.origin)) : null;
				} catch {
					target = null;
				}
				const port = target?.port || (target?.protocol === "http:" ? "80" : "443");
				const useProxy = viaProxy && target && !bypassesProxy(target.hostname, port, noProxy);
				return (useProxy ? viaProxy : direct).dispatch(options, handler);
			},
			async close() {
				await Promise.all([direct.close(), viaProxy?.close()]);
			},
			async destroy() {
				await Promise.all([direct.destroy(), viaProxy?.destroy()]);
			},
		};
		if (!installed) original = globalSlot[GLOBAL_DISPATCHER];
		globalSlot[GLOBAL_DISPATCHER] = routing;
		const result = { proxy: !!settings.proxy, extraCa: !!ca };
		installed = { key, result };
		return result;
	} catch (error) {
		logger.warn("Outbound proxy / CA settings could not be applied", { error: String(error) });
		return NOTHING;
	}
}
