/**
 * Network syslog sender for SIEM delivery: RFC 6587 octet-counted TCP, TLS with
 * certificate verification (optional CA / public-key pin) and UDP. Messages use
 * the RFC 5424 formatter in `siem-export.ts`.
 *
 * Syslog has no application-level acknowledgement. A TCP/TLS delivery is
 * recorded only after every byte was flushed and the peer closed cleanly; a UDP
 * delivery means "handed to the network" and carries the explicit receipt code
 * `syslog_udp_sent_unacknowledged`. Neither proves downstream indexing.
 */
import { createHash, X509Certificate } from "node:crypto";
import { createSocket } from "node:dgram";
import { lookup as dnsLookup } from "node:dns/promises";
import { connect as netConnect, isIP, type Socket } from "node:net";
import {
	connect as tlsConnect,
	type DetailedPeerCertificate,
	type PeerCertificate,
} from "node:tls";

import type { SiemDeliveryAttempt, SiemEventEnvelope } from "./siem-delivery.js";
import { formatSyslogMessage, SyslogMessageTooLargeError } from "./siem-export.js";
import { isPrivateIpAddress } from "./mcp-transport.js";
import type { IncidentSeverity } from "./incidents/types.js";

export type SyslogTransport = "tcp" | "tls" | "udp";

export interface SyslogSiemConfig {
	provider: "syslog";
	/** `tcp://host:port`, `tls://host:port` or `udp://host:port`. No credentials, path or query. */
	endpoint: string;
	/** Loopback destinations are accepted only when this is set (integration tests, local collectors). */
	allowInsecureLoopback?: boolean;
	/** RFC 1918 / ULA / CGNAT destinations (typical on-prem collectors) require this explicit opt-in. */
	allowPrivateNetwork?: boolean;
	/** Plain `tcp`/`udp` to a non-loopback host sends incident data unencrypted; require explicit opt-in. */
	allowPlaintextTransport?: boolean;
	facility?: number;
	hostname?: string;
	appName?: string;
	structuredDataId?: string;
	maxMessageBytes?: number;
	/** TLS only. A PEM CA certificate (or bundle) that replaces the system trust store. */
	tlsCaCertificatePem?: string;
	/** TLS only. SHA-256 public-key pins (hex or base64) of any certificate in the verified chain. */
	tlsPinnedSha256?: string[];
}

export const SIEM_SYSLOG_CONFIG_JSON_SCHEMA = {
	$schema: "https://json-schema.org/draft/2020-12/schema",
	title: "Singularity AIDR syslog SIEM adapter",
	type: "object",
	additionalProperties: false,
	required: ["provider", "endpoint"],
	properties: {
		provider: { const: "syslog" },
		endpoint: { type: "string", pattern: "^(tcp|tls|udp)://[^/?#@\\s]+:[0-9]{1,5}$" },
		allowInsecureLoopback: { type: "boolean" },
		allowPrivateNetwork: { type: "boolean" },
		allowPlaintextTransport: { type: "boolean" },
		facility: { type: "integer", minimum: 0, maximum: 23 },
		hostname: { type: "string", maxLength: 255 },
		appName: { type: "string", maxLength: 48 },
		structuredDataId: { type: "string", pattern: "^[A-Za-z0-9_.-]{1,32}@[0-9]{1,10}$" },
		maxMessageBytes: { type: "integer", minimum: 480, maximum: 1048576 },
		tlsCaCertificatePem: { type: "string", maxLength: 65536 },
		tlsPinnedSha256: {
			type: "array",
			maxItems: 8,
			items: { type: "string", pattern: "^([A-Fa-f0-9]{64}|[A-Za-z0-9+/_-]{43}={0,1})$" },
		},
	},
} as const;

interface SyslogDestination {
	transport: SyslogTransport;
	/** Lower-case host without brackets. */
	host: string;
	port: number;
	/** Origin-style identifier safe to store in receipts. */
	origin: string;
}

export type SyslogAddressClass = "public" | "loopback" | "private" | "blocked";

export type SyslogLookup = (hostname: string) => Promise<readonly string[]>;

interface SyslogSendContext {
	timeoutMs: number;
	lookup?: SyslogLookup;
}

const UDP_MAX_DATAGRAM_BYTES = 8_192;
const BLOCKED_HOSTNAMES = new Set([
	"localhost",
	"localhost.localdomain",
	"ip6-localhost",
	"ip6-loopback",
	"metadata.google.internal",
	"metadata.google.com",
	"instance-data.ec2.internal",
]);
const TLS_VERIFICATION_ERROR_CODES = new Set([
	"DEPTH_ZERO_SELF_SIGNED_CERT",
	"SELF_SIGNED_CERT_IN_CHAIN",
	"UNABLE_TO_GET_ISSUER_CERT",
	"UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
	"UNABLE_TO_VERIFY_LEAF_SIGNATURE",
	"CERT_HAS_EXPIRED",
	"CERT_NOT_YET_VALID",
	"CERT_UNTRUSTED",
	"CERT_REVOKED",
	"ERR_TLS_CERT_ALTNAME_INVALID",
	"HOSTNAME_MISMATCH",
]);

class SyslogPolicyError extends Error {
	constructor(readonly code: string) {
		super(code);
		this.name = "SyslogPolicyError";
	}
}

function stripBrackets(value: string): string {
	return value.replace(/^\[|\]$/g, "").toLowerCase();
}

function ipv4Parts(value: string): number[] | null {
	const parts = value.split(".");
	if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return null;
	const numbers = parts.map(Number);
	return numbers.every((part) => part <= 255) ? numbers : null;
}

/**
 * Classify a literal IP address for the egress policy.
 *
 * - `blocked`: never a SIEM collector (unspecified, link-local incl. cloud
 *   metadata, multicast, broadcast, reserved).
 * - `loopback`: this host only; accepted solely with `allowInsecureLoopback`.
 * - `private`: RFC 1918 / ULA / CGNAT / documentation ranges; needs `allowPrivateNetwork`.
 */
export function classifySyslogAddress(address: string): SyslogAddressClass {
	const value = stripBrackets(address.trim());
	const version = isIP(value);
	if (version === 4) return classifyIpv4(value);
	if (version === 6) return classifyIpv6(value);
	return "blocked";
}

function classifyIpv4(value: string): SyslogAddressClass {
	const parts = ipv4Parts(value);
	if (!parts) return "blocked";
	const [a = 0, b = 0] = parts;
	if (a === 127) return "loopback";
	if (a === 0 || (a === 169 && b === 254) || a >= 224) return "blocked";
	return isPrivateIpAddress(value) ? "private" : "public";
}

function classifyIpv6(value: string): SyslogAddressClass {
	// Normalise (compress, lower-case, expand embedded IPv4) through the URL parser.
	let normalised: string;
	try {
		normalised = new URL(`http://[${value}]/`).hostname.slice(1, -1);
	} catch {
		return "blocked";
	}
	if (normalised === "::1") return "loopback";
	if (normalised === "::") return "blocked";
	const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(normalised);
	if (mapped) {
		const high = Number.parseInt(mapped[1] as string, 16);
		const low = Number.parseInt(mapped[2] as string, 16);
		return classifyIpv4(`${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`);
	}
	if (/^fe[89ab][0-9a-f]:/.test(normalised) || normalised.startsWith("ff")) return "blocked";
	return isPrivateIpAddress(normalised) ? "private" : "public";
}

function assertAddressAllowed(address: string, config: SyslogSiemConfig): void {
	const addressClass = classifySyslogAddress(address);
	if (addressClass === "public") return;
	if (addressClass === "loopback" && config.allowInsecureLoopback === true) return;
	if (addressClass === "private" && config.allowPrivateNetwork === true) return;
	throw new SyslogPolicyError("destination_policy_rejected");
}

/** Synchronous destination checks. Hostnames are re-validated after DNS on every send. */
function parseSyslogDestination(config: SyslogSiemConfig): SyslogDestination {
	let url: URL;
	try {
		url = new URL(config.endpoint);
	} catch {
		throw new TypeError("Syslog endpoint must be an absolute tcp://, tls:// or udp:// URL");
	}
	const transport = url.protocol.slice(0, -1);
	if (transport !== "tcp" && transport !== "tls" && transport !== "udp")
		throw new TypeError("Syslog endpoint must use tcp://, tls:// or udp://");
	if (
		url.username ||
		url.password ||
		url.search ||
		url.hash ||
		(url.pathname && url.pathname !== "/")
	)
		throw new TypeError(
			"Syslog endpoint cannot contain credentials, a path, query parameters or a fragment",
		);
	const port = Number(url.port);
	if (!url.port || !Number.isInteger(port) || port < 1 || port > 65_535)
		throw new TypeError("Syslog endpoint requires an explicit port from 1 to 65535");
	const host = stripBrackets(url.hostname).replace(/\.+$/, "");
	if (!host) throw new TypeError("Syslog endpoint requires a host");
	if (BLOCKED_HOSTNAMES.has(host) && !(config.allowInsecureLoopback && host.includes("localhost")))
		throw new TypeError("Syslog destination is not permitted by the egress policy");
	if (isIP(host) !== 0) {
		try {
			assertAddressAllowed(host, config);
		} catch {
			throw new TypeError("Syslog destination is not permitted by the egress policy");
		}
	}
	const loopbackHost = host === "localhost" || classifySyslogAddress(host) === "loopback";
	if (
		transport !== "tls" &&
		!config.allowPlaintextTransport &&
		!(loopbackHost && config.allowInsecureLoopback)
	)
		throw new TypeError(
			"Plain tcp:// and udp:// syslog send incident data unencrypted; use tls:// or set allowPlaintextTransport",
		);
	if (transport !== "tls" && (config.tlsCaCertificatePem || config.tlsPinnedSha256?.length))
		throw new TypeError("TLS CA and pin settings apply only to tls:// endpoints");
	const displayHost = isIP(host) === 6 ? `[${host}]` : host;
	return { transport, host, port, origin: `${transport}://${displayHost}:${port}` };
}

function normalizeSyslogPin(value: string): string {
	if (/^[A-Fa-f0-9]{64}$/.test(value)) return Buffer.from(value, "hex").toString("base64");
	if (/^[A-Za-z0-9+/_-]{43}={0,1}$/.test(value)) {
		const bytes = Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
		if (bytes.length === 32) return bytes.toString("base64");
	}
	throw new TypeError("Syslog TLS pins must be SHA-256 values in hex or base64");
}

/** Validate TLS trust settings once at construction; returns normalised pins. */
function validateSyslogTls(config: SyslogSiemConfig): { ca?: string; pins: string[] } {
	if (config.tlsCaCertificatePem !== undefined) {
		const pem = config.tlsCaCertificatePem;
		const certificates = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
		if (!certificates?.length || pem.length > 65_536)
			throw new TypeError("Syslog TLS CA must be PEM-encoded certificates");
		for (const certificate of certificates) {
			try {
				new X509Certificate(certificate);
			} catch {
				throw new TypeError("Syslog TLS CA certificate is not valid");
			}
		}
	}
	const pins = (config.tlsPinnedSha256 ?? []).map(normalizeSyslogPin);
	if (pins.length > 8) throw new TypeError("At most 8 syslog TLS pins are allowed");
	return { ca: config.tlsCaCertificatePem, pins };
}

async function resolveAddresses(
	destination: SyslogDestination,
	config: SyslogSiemConfig,
	lookup: SyslogLookup | undefined,
): Promise<string[]> {
	if (isIP(destination.host) !== 0) {
		assertAddressAllowed(destination.host, config);
		return [destination.host];
	}
	const resolver: SyslogLookup =
		lookup ??
		(async (host) =>
			(await dnsLookup(host, { all: true, verbatim: true })).map((item) => item.address));
	let resolved: readonly string[];
	try {
		resolved = await resolver(destination.host);
	} catch {
		throw new SyslogPolicyError("dns_lookup_failed");
	}
	const addresses = [...new Set(resolved.map((address) => stripBrackets(address)))];
	if (addresses.length === 0 || addresses.some((address) => isIP(address) === 0))
		throw new SyslogPolicyError("dns_lookup_failed");
	// Every address must pass, so a mixed public/internal answer cannot be used to steer the sender.
	for (const address of addresses) assertAddressAllowed(address, config);
	return addresses;
}

function octetCountedFrame(message: string): Buffer {
	const body = Buffer.from(message, "utf8");
	return Buffer.concat([Buffer.from(`${body.length} `, "ascii"), body]);
}

function spkiPin(certificate: PeerCertificate): string | undefined {
	if (!certificate.raw) return undefined;
	try {
		const key = new X509Certificate(certificate.raw).publicKey.export({
			type: "spki",
			format: "der",
		});
		return createHash("sha256").update(key).digest("base64");
	} catch {
		return undefined;
	}
}

function chainPins(leaf: DetailedPeerCertificate): string[] {
	const pins: string[] = [];
	const seen = new Set<unknown>();
	let current: DetailedPeerCertificate | undefined = leaf;
	while (current && !seen.has(current)) {
		seen.add(current);
		const pin = spkiPin(current);
		if (pin) pins.push(pin);
		current = current.issuerCertificate;
	}
	return pins;
}

function connectionErrorCode(error: unknown): string {
	if (error instanceof SyslogPolicyError) return error.code;
	const code = (error as { code?: unknown } | null)?.code;
	if (code === "syslog_tls_pin_mismatch") return "tls_pin_mismatch";
	if (typeof code === "string" && TLS_VERIFICATION_ERROR_CODES.has(code))
		return "tls_verification_failed";
	if (code === "ETIMEDOUT" || code === "syslog_timeout") return "delivery_timeout";
	return "network_error";
}

function attemptFromError(error: unknown): SiemDeliveryAttempt {
	if (error instanceof SyslogMessageTooLargeError)
		return { outcome: "permanent", code: "syslog_message_too_large", statusCode: 0 };
	if (error instanceof SyslogPolicyError) {
		// A DNS outage may heal; a policy rejection never will without operator action.
		return error.code === "dns_lookup_failed"
			? { outcome: "retry", code: error.code, statusCode: 0 }
			: { outcome: "permanent", code: error.code, statusCode: 0 };
	}
	return { outcome: "retry", code: connectionErrorCode(error), statusCode: 0 };
}

function streamSend(
	address: string,
	destination: SyslogDestination,
	tls: { ca?: string; pins: string[] },
	frame: Buffer,
	timeoutMs: number,
): Promise<void> {
	return new Promise<void>((resolve, reject) => {
		let settled = false;
		let socket: Socket;
		const finish = (error?: unknown): void => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			socket?.destroy();
			if (error) reject(error);
			else resolve();
		};
		const timer = setTimeout(
			() => finish(Object.assign(new Error("syslog timeout"), { code: "syslog_timeout" })),
			timeoutMs,
		);
		timer.unref?.();
		const writeFrame = (): void => {
			socket.on("close", (hadError) => {
				if (hadError)
					finish(Object.assign(new Error("syslog connection error"), { code: "ECONNRESET" }));
				else finish();
			});
			// `end` flushes the frame and half-closes; success is declared only on a clean close.
			socket.end(frame);
		};
		try {
			if (destination.transport === "tls") {
				socket = tlsConnect({
					host: address,
					port: destination.port,
					servername: isIP(destination.host) === 0 ? destination.host : undefined,
					ca: tls.ca,
					rejectUnauthorized: true,
					minVersion: "TLSv1.2",
				});
				socket.once("secureConnect", () => {
					const secure = socket as ReturnType<typeof tlsConnect>;
					if (!secure.authorized)
						return finish(
							Object.assign(new Error("syslog tls unauthorized"), { code: "CERT_UNTRUSTED" }),
						);
					if (tls.pins.length > 0) {
						const presented = chainPins(secure.getPeerCertificate(true));
						if (!presented.some((pin) => tls.pins.includes(pin)))
							return finish(
								Object.assign(new Error("syslog tls pin mismatch"), {
									code: "syslog_tls_pin_mismatch",
								}),
							);
					}
					writeFrame();
				});
			} else {
				socket = netConnect({ host: address, port: destination.port });
				socket.once("connect", writeFrame);
			}
			socket.once("error", finish);
		} catch (error) {
			finish(error);
		}
	});
}

function udpSend(
	address: string,
	port: number,
	datagram: Buffer,
	timeoutMs: number,
): Promise<void> {
	return new Promise<void>((resolve, reject) => {
		const socket = createSocket(isIP(address) === 6 ? "udp6" : "udp4");
		let settled = false;
		const finish = (error?: unknown): void => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			try {
				socket.close();
			} catch {
				// Already closed.
			}
			if (error) reject(error);
			else resolve();
		};
		const timer = setTimeout(
			() => finish(Object.assign(new Error("syslog timeout"), { code: "syslog_timeout" })),
			timeoutMs,
		);
		timer.unref?.();
		socket.once("error", finish);
		socket.send(datagram, port, address, (error) => finish(error ?? undefined));
	});
}

async function deliverToAddress(
	address: string,
	destination: SyslogDestination,
	tls: { ca?: string; pins: string[] },
	message: string,
	timeoutMs: number,
): Promise<SiemDeliveryAttempt> {
	if (destination.transport === "udp") {
		const datagram = Buffer.from(message, "utf8");
		if (datagram.length > UDP_MAX_DATAGRAM_BYTES)
			return { outcome: "permanent", code: "syslog_message_too_large_for_udp", statusCode: 0 };
		await udpSend(address, destination.port, datagram, timeoutMs);
		return { outcome: "delivered", code: "syslog_udp_sent_unacknowledged", statusCode: 0 };
	}
	await streamSend(address, destination, tls, octetCountedFrame(message), timeoutMs);
	return {
		outcome: "delivered",
		code: destination.transport === "tls" ? "syslog_tls_written" : "syslog_tcp_written",
		statusCode: 0,
	};
}

export interface SyslogSender {
	readonly origin: string;
	readonly transport: SyslogTransport;
	/** Stable, credential-free description of the delivery route for state binding. */
	fingerprintInput(): Record<string, unknown>;
	send(envelope: SiemEventEnvelope, context: SyslogSendContext): Promise<SiemDeliveryAttempt>;
}

function envelopeSeverity(envelope: SiemEventEnvelope): IncidentSeverity {
	const severity = envelope.incident.severity;
	return severity === "critical" || severity === "high" || severity === "warning"
		? severity
		: "info";
}

function textField(value: unknown): string | undefined {
	return typeof value === "string" ? value : undefined;
}

export function createSyslogSender(config: SyslogSiemConfig): SyslogSender {
	const destination = parseSyslogDestination(config);
	const tls = validateSyslogTls(config);
	// Validate the format options eagerly so a bad config fails at startup, not on first delivery.
	const format = {
		facility: config.facility,
		hostname: config.hostname,
		appName: config.appName,
		structuredDataId: config.structuredDataId,
		maxBytes: config.maxMessageBytes,
	};
	formatSyslogMessage(
		{
			timestampMs: 0,
			severity: "info",
			eventId: "aidr_validate",
			incidentId: "validate",
			payload: {},
		},
		format,
	);
	return {
		origin: destination.origin,
		transport: destination.transport,
		fingerprintInput: () => ({
			transport: destination.transport,
			origin: destination.origin,
			facility: config.facility ?? 16,
			hostname: config.hostname ?? null,
			appName: config.appName ?? "aidr",
			structuredDataId: config.structuredDataId ?? "aidr@32473",
			allowPrivateNetwork: config.allowPrivateNetwork === true,
			tlsCaSha256: tls.ca ? createHash("sha256").update(tls.ca).digest("hex") : null,
			tlsPins: [...tls.pins].sort(),
		}),
		async send(envelope, context) {
			try {
				const incident = envelope.incident;
				const message = formatSyslogMessage(
					{
						timestampMs: envelope.observed_at_ms,
						severity: envelopeSeverity(envelope),
						eventId: envelope.event_id,
						incidentId: textField(incident.incident_id) ?? envelope.event_id,
						status: textField(incident.status),
						connector: textField(incident.connector),
						agentIid: textField(incident.agent_iid),
						payload: envelope as unknown as Record<string, unknown>,
					},
					format,
				);
				const addresses = await resolveAddresses(destination, config, context.lookup);
				let lastError: unknown;
				for (const address of addresses) {
					try {
						return await deliverToAddress(address, destination, tls, message, context.timeoutMs);
					} catch (error) {
						lastError = error;
						// A verification or pin failure on one address is not cured by another.
						if (connectionErrorCode(error) !== "network_error") break;
					}
				}
				return attemptFromError(lastError);
			} catch (error) {
				return attemptFromError(error);
			}
		},
	};
}
