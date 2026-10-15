// Central SIEM forwarding: event envelope, payload formats (JSON, CEF, LEEF),
// transports (syslog TCP/TLS/UDP, Splunk HEC, Elastic _bulk, Microsoft
// Sentinel Logs Ingestion, signed webhook) and the forwarder loop shared by
// `siem-forwarder` (scheduled) and `siem-destinations` (dashboard test send).
//
// Contract: docs/contracts/siem-forwarding.md. Delivery is at-least-once:
// every event carries a stable `event_id`, which Elastic uses as the document
// _id (a re-delivery is a 409 and counts as delivered), HEC and webhooks get
// as an idempotency key, and syslog/CEF/LEEF carry for de-duplication.
//
// The outbox row already holds an allow-listed projection of sanitised
// telemetry (migration 20261014000130); `buildForwardedEvent` re-validates
// every field against a fixed allow-list again, so an unexpected key in the
// database can never reach a collector.
//
// Network: the forwarder resolves and vets the collector (siem-config.ts),
// then connects to the exact address it vetted. HTTPS is spoken over the
// injectable socket transport so an internal CA can be pinned per destination
// and redirects are never followed.

import { backoffSeconds, signatureHeader } from "./notification-delivery.ts";
import type { DnsResolver, NotificationKeyring } from "./notification-targets.ts";
import {
	decryptSiemConfig,
	resolveCollector,
	SIEM_PROVIDERS,
	type SiemDestinationConfig,
	type SiemFormat,
	type SiemProvider,
	type SyslogDestinationConfig,
} from "./siem-config.ts";
import {
	pemCertificates,
	type SocketTransport,
	type StreamConnection,
	StreamReader,
	TransportError,
	withTimeout,
} from "./socket-transport.ts";

const FORWARDED_EVENT_SCHEMA = "aidr.siem.forwarded_event/v1" as const;
/** CEF/LEEF device version: the forwarded-event schema revision. */
const SIEM_DEVICE_VERSION = "1.0";
const USER_AGENT = "Singularity-AIDR-SIEM/1.0";
const DELIVERY_TIMEOUT_MS = 15_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const UDP_MAX_DATAGRAM_BYTES = 8_192;
const SYSLOG_MAX_BYTES = 64 * 1024;

const SEVERITIES = ["info", "warning", "high", "critical"] as const;
type Severity = (typeof SEVERITIES)[number];
const KINDS = ["incident", "decision", "browser", "test"] as const;
type Kind = (typeof KINDS)[number];

const IDENT = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SLUG = /^[a-z0-9][a-z0-9-]{0,31}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

// ── Event envelope ────────────────────────────────────────────────────────

interface ForwardedEventFields {
	type: string;
	occurred_at: string;
	event_row_id: string | null;
	client_timestamp?: string;
	source_event_id?: string;
	agent_id?: string;
	agent_iid?: string;
	connector?: string;
	decision?: "allow" | "ask" | "deny";
	severity?: Severity;
	status?: string;
	threat_id?: string;
	incident_id?: string;
	session_id?: string;
	tool_name?: string;
	source?: string;
	plugin_key?: string;
	policy_id?: string;
	findings_count?: number;
	user_override?: boolean;
	tool_input_digest?: string;
	site?: string;
	action?: string;
	channel?: string;
	service_id?: string;
	count?: number;
	entity_counts?: Record<string, number>;
}

/** Body of the JSON format (schema aidr.siem.forwarded_event/v1). */
export interface ForwardedEvent {
	schema_version: typeof FORWARDED_EVENT_SCHEMA;
	event_id: string;
	observed_at: string;
	source: { vendor: "Singularity"; product: "AIDR"; component: "control_plane" };
	tenant_id: string;
	kind: Kind;
	event: ForwardedEventFields;
}

export interface ClaimedSiemDelivery {
	deliveryId: string;
	leaseToken: string;
	kind: Kind;
	payload: Record<string, unknown>;
	attempts: number;
	maxAttempts: number;
	createdAt: string;
}

function isoOr(value: unknown, fallback: string): string {
	const parsed = typeof value === "string" && value.length <= 64 ? Date.parse(value) : Number.NaN;
	if (Number.isFinite(parsed)) return new Date(parsed).toISOString();
	const second = Date.parse(fallback);
	return new Date(Number.isFinite(second) ? second : 0).toISOString();
}

function count(value: unknown, max: number): number | undefined {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= max ? value : undefined;
}

function pick(value: unknown, pattern: RegExp): string | undefined {
	return typeof value === "string" && pattern.test(value) ? value : undefined;
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[]): T | undefined {
	return typeof value === "string" && (allowed as readonly string[]).includes(value) ? (value as T) : undefined;
}

/** Allow-list projection of an outbox row into the forwarded event. */
export function buildForwardedEvent(tenantId: string, row: ClaimedSiemDelivery): ForwardedEvent {
	const p = row.payload;
	const entityCounts: Record<string, number> = {};
	if (isRecord(p.entity_counts)) {
		for (const [key, value] of Object.entries(p.entity_counts).slice(0, 32)) {
			const n = count(value, 1_000_000);
			if (/^[A-Z][A-Z_]{1,31}$/.test(key) && n !== undefined) entityCounts[key] = n;
		}
	}
	const rowId = typeof p.event_row_id === "string" && /^[0-9]{1,19}$/.test(p.event_row_id) ? p.event_row_id : null;
	const fields: ForwardedEventFields = {
		type: pick(p.type, /^[a-z][a-z0-9_]{0,63}$/) ?? "unknown",
		occurred_at: isoOr(p.occurred_at, row.createdAt),
		event_row_id: rowId,
	};
	const optional: Partial<ForwardedEventFields> = {
		client_timestamp: typeof p.client_timestamp === "string" && Number.isFinite(Date.parse(p.client_timestamp))
			? new Date(Date.parse(p.client_timestamp)).toISOString()
			: undefined,
		source_event_id: pick(p.event_id, IDENT),
		agent_id: typeof p.agent_id === "string" && UUID.test(p.agent_id) ? p.agent_id.toLowerCase() : undefined,
		agent_iid: pick(p.agent_iid, IDENT),
		connector: pick(p.connector, IDENT),
		decision: oneOf(p.decision, ["allow", "ask", "deny"] as const),
		severity: oneOf(p.severity, SEVERITIES),
		status: oneOf(p.status, ["open", "acknowledged", "contained", "resolved", "suppressed"] as const),
		threat_id: pick(p.threat_id, IDENT),
		incident_id: pick(p.incident_id, IDENT),
		session_id: pick(p.session_id, IDENT),
		tool_name: pick(p.tool_name, IDENT),
		source: pick(p.source, IDENT),
		plugin_key: pick(p.plugin_key, IDENT),
		policy_id: pick(p.policy_id, IDENT),
		findings_count: count(p.findings_count, 10_000_000),
		user_override: typeof p.user_override === "boolean" ? p.user_override : undefined,
		tool_input_digest: pick(p.tool_input_digest, /^sha256:[a-f0-9]{64}$/),
		site: pick(p.site, SLUG),
		action: oneOf(p.action, ["masked", "warned", "blocked", "allowed", "visited"] as const),
		channel: oneOf(p.channel, ["prompt", "paste", "file"] as const),
		service_id: pick(p.service_id, SLUG),
		count: count(p.count, 1_000_000),
		entity_counts: Object.keys(entityCounts).length > 0 ? entityCounts : undefined,
	};
	for (const [key, value] of Object.entries(optional)) {
		if (value !== undefined) (fields as unknown as Record<string, unknown>)[key] = value;
	}
	return {
		schema_version: FORWARDED_EVENT_SCHEMA,
		event_id: row.kind === "test" || rowId === null ? `aidr_test_${row.deliveryId}` : `aidr_evt_${rowId}`,
		observed_at: fields.occurred_at,
		source: { vendor: "Singularity", product: "AIDR", component: "control_plane" },
		tenant_id: tenantId.toLowerCase(),
		kind: row.kind,
		event: fields,
	};
}

function severityOf(event: ForwardedEvent): Severity {
	if (event.event.severity) return event.event.severity;
	if (event.kind === "browser") return event.event.action === "blocked" ? "high" : "warning";
	if (event.kind === "decision") return event.event.decision === "deny" ? "high" : event.event.decision === "ask" ? "warning" : "info";
	return "info";
}

// ── CEF / LEEF (same conventions as packages/core/src/siem-export.ts) ─────

/** AIDR severity on the CEF/LEEF 0-10 scale (core CEF_SEVERITY). */
const CEF_SEVERITY: Record<Severity, number> = { info: 2, warning: 5, high: 8, critical: 10 };

/** Core `escapeCefValue`: backslash, pipe, equals and CR/LF (no record forging). */
export function escapeCefValue(raw: string): string {
	return raw.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/=/g, "\\=").replace(/\r/g, "\\r").replace(/\n/g, "\\n");
}

/** Core `escapeLeefHeader`. */
function escapeLeefHeader(raw: string): string {
	return raw.replace(/\|/g, "\\|").replace(/\r/g, "\\r").replace(/\n/g, "\\n");
}

/** Core `escapeLeefValue`. */
function escapeLeefValue(raw: string): string {
	return raw.replace(/\t/g, "\\t").replace(/\\/g, "\\\\").replace(/\r/g, "\\r").replace(/\n/g, "\\n");
}

/** Ordered key/value pairs shared by CEF and LEEF. */
function eventPairs(event: ForwardedEvent): Array<[string, string | number | boolean]> {
	const e = event.event;
	const pairs: Array<[string, string | number | boolean | undefined]> = [
		["tenant_id", event.tenant_id],
		["kind", event.kind],
		["type", e.type],
		["event_row_id", e.event_row_id ?? undefined],
		["source_event_id", e.source_event_id],
		["incident_id", e.incident_id],
		["status", e.status],
		["decision", e.decision],
		["severity", severityOf(event)],
		["threat_id", e.threat_id],
		["session_id", e.session_id],
		["agent_id", e.agent_id],
		["agent_iid", e.agent_iid],
		["connector", e.connector],
		["tool_name", e.tool_name],
		["source", e.source],
		["plugin_key", e.plugin_key],
		["policy_id", e.policy_id],
		["findings_count", e.findings_count],
		["user_override", e.user_override],
		["tool_input_digest", e.tool_input_digest],
		["site", e.site],
		["action", e.action],
		["channel", e.channel],
		["service_id", e.service_id],
		["count", e.count],
		["entity_counts", e.entity_counts ? Object.entries(e.entity_counts).map(([k, v]) => `${k}:${v}`).join(",") : undefined],
	];
	return pairs.filter((pair): pair is [string, string | number | boolean] => pair[1] !== undefined && pair[1] !== null);
}

function eventName(event: ForwardedEvent): string {
	const severity = severityOf(event);
	switch (event.kind) {
		case "incident":
			return `AIDR ${severity} incident`;
		case "decision":
			return `AIDR ${event.event.decision ?? "unknown"} decision${event.event.threat_id ? ` - ${event.event.threat_id}` : ""}`;
		case "browser":
			return `AIDR browser ${event.event.action ?? "event"}${event.event.site ? ` - ${event.event.site}` : ""}`;
		default:
			return "AIDR SIEM test event";
	}
}

/** `AIDR/<severity>/<KIND>[/<decision>]`, the CEF Signature ID and LEEF EventID stem. */
function signatureId(event: ForwardedEvent): string {
	const base = `AIDR/${severityOf(event)}/${event.kind.toUpperCase()}`;
	if (event.kind === "decision" && event.event.decision) return `${base}/${event.event.decision.toUpperCase()}`;
	if (event.kind === "browser" && event.event.action) return `${base}/${event.event.action.toUpperCase()}`;
	return base;
}

export function formatCef(event: ForwardedEvent): string {
	const e = event.event;
	const extension = [
		`rt=${Date.parse(event.observed_at)}`,
		`externalId=${escapeCefValue(event.event_id)}`,
		`cat=${escapeCefValue(event.kind)}`,
		...(e.decision ? [`act=${escapeCefValue(e.decision)}`] : []),
		...(e.threat_id ? [`cs1Label=threat_id`, `cs1=${escapeCefValue(e.threat_id)}`] : []),
		...eventPairs(event).map(([key, value]) => `${key}=${escapeCefValue(String(value))}`),
	].join(" ");
	return `CEF:0|Singularity|AIDR|${SIEM_DEVICE_VERSION}|${escapeCefValue(signatureId(event))}|${escapeCefValue(eventName(event))}|${CEF_SEVERITY[severityOf(event)]}|${extension}`;
}

export function formatLeef(event: ForwardedEvent): string {
	const eventId = escapeLeefHeader(signatureId(event).replaceAll("/", "-").toUpperCase());
	const attributes = [
		`cat=${escapeLeefValue(event.kind)}`,
		`sev=${CEF_SEVERITY[severityOf(event)]}`,
		`devTime=${Date.parse(event.observed_at)}`,
		`externalId=${escapeLeefValue(event.event_id)}`,
		`name=${escapeLeefValue(eventName(event))}`,
		...eventPairs(event).map(([key, value]) => `${key}=${escapeLeefValue(String(value))}`),
	].join("\t");
	return `LEEF:1.0|Singularity|AIDR|${SIEM_DEVICE_VERSION}|${eventId}|${attributes}`;
}

// ── Syslog framing ────────────────────────────────────────────────────────

const SYSLOG_SEVERITY: Record<Severity, number> = { critical: 2, high: 3, warning: 4, info: 6 };
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function headerField(value: string | undefined, max: number, fallback: string): string {
	const cleaned = (value ?? "").replace(/[^\x21-\x7e]/g, "_").slice(0, max);
	return cleaned.length > 0 ? cleaned : fallback;
}

function sdValue(value: string): string {
	return value.replace(/[\p{Cc}]/gu, " ").replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/]/g, "\\]").slice(0, 256);
}

/**
 * One syslog message for an event. JSON uses RFC 5424 (structured data plus a
 * BOM-prefixed single-line JSON MSG, like the endpoint syslog adapter). CEF and
 * LEEF use the RFC 3164 header QRadar, ArcSight and Wazuh expect in front of
 * those formats.
 */
export function formatSyslogMessage(event: ForwardedEvent, format: SiemFormat, config: SyslogDestinationConfig): string {
	const facility = config.facility ?? 16;
	const pri = `<${facility * 8 + SYSLOG_SEVERITY[severityOf(event)]}>`;
	const hostname = headerField(config.hostname, 255, "aidr-control-plane");
	const app = headerField(config.app_name, 48, "aidr");
	const when = new Date(Date.parse(event.observed_at));
	if (format === "json") {
		const sd = `[aidr@32473 eventId="${sdValue(event.event_id)}" kind="${event.kind}" severity="${severityOf(event)}"${
			event.event.decision ? ` decision="${event.event.decision}"` : ""
		} tenant="${sdValue(event.tenant_id)}"]`;
		return `${pri}1 ${when.toISOString()} ${hostname} ${app} - ${event.kind.toUpperCase()} ${sd} \uFEFF${JSON.stringify(event)}`;
	}
	const day = String(when.getUTCDate()).padStart(2, " ");
	const time = when.toISOString().slice(11, 19);
	const line = format === "cef" ? formatCef(event) : formatLeef(event);
	return `${pri}${MONTHS[when.getUTCMonth()]} ${day} ${time} ${hostname} ${app}: ${line}`;
}

// ── Outcomes ──────────────────────────────────────────────────────────────

interface ForwardOutcome {
	outcome: "delivered" | "retry" | "failed";
	error: string | null;
	statusCode: number | null;
	retryAfterSeconds?: number | null;
}

const ok = (statusCode: number | null = null): ForwardOutcome => ({ outcome: "delivered", error: null, statusCode });
const retry = (error: string, statusCode: number | null = null, retryAfterSeconds: number | null = null): ForwardOutcome =>
	({ outcome: "retry", error, statusCode, retryAfterSeconds });
const failed = (error: string, statusCode: number | null = null): ForwardOutcome => ({ outcome: "failed", error, statusCode });

function errorOutcome(error: unknown): ForwardOutcome {
	if (error instanceof TransportError) {
		if (error.code === "udp_unsupported" || error.code === "socket_unsupported") return failed(error.code);
		return retry(error.code === "timeout" ? "timeout" : "network_error");
	}
	const text = `${(error as { name?: unknown })?.name ?? ""} ${(error as { code?: unknown })?.code ?? ""} ${
		error instanceof Error ? error.message : ""
	}`.toLowerCase();
	if (/cert|tls|ssl|issuer|verify|handshake|self.signed|hostname|altname/.test(text)) return retry("tls_verification_failed");
	return retry("network_error");
}

// ── HTTPS over the socket transport ───────────────────────────────────────

export interface ForwardDeps {
	transport: SocketTransport;
	resolveDns: DnsResolver;
	now: () => number;
	/** Deployment switch AIDR_SIEM_ALLOW_PRIVATE_NETWORKS. */
	allowPrivateNetworks: boolean;
	timeoutMs?: number;
}

interface HttpResponse {
	status: number;
	headers: Map<string, string>;
	body: Uint8Array;
}

function decodeChunked(raw: Uint8Array): Uint8Array {
	const out: number[] = [];
	let offset = 0;
	const text = new TextDecoder("latin1");
	for (;;) {
		const lineEnd = raw.indexOf(0x0a, offset);
		if (lineEnd < 0) break;
		const size = Number.parseInt(text.decode(raw.subarray(offset, lineEnd)).trim().split(";")[0], 16);
		if (!Number.isFinite(size) || size <= 0) break;
		const start = lineEnd + 1;
		for (let i = start; i < Math.min(start + size, raw.length); i += 1) out.push(raw[i]);
		offset = start + size + 2;
	}
	return Uint8Array.from(out);
}

async function httpsPost(
	url: URL,
	headers: Record<string, string>,
	body: string,
	options: { caCerts?: string[]; allowPrivate: boolean },
	deps: ForwardDeps,
): Promise<HttpResponse | ForwardOutcome> {
	const host = url.hostname.replace(/^\[|\]$/g, "");
	const resolved = await resolveCollector(host, deps.resolveDns, options.allowPrivate);
	if (!resolved.ok) return resolved.error === "destination_policy_rejected" ? failed(resolved.error) : retry(resolved.error);
	const port = url.port ? Number(url.port) : 443;
	const bytes = new TextEncoder().encode(body);
	const request = [
		`POST ${url.pathname}${url.search} HTTP/1.1`,
		`Host: ${url.host}`,
		`User-Agent: ${USER_AGENT}`,
		`Content-Length: ${bytes.length}`,
		"Connection: close",
		...Object.entries(headers).map(([name, value]) => `${name}: ${value.replace(/[\r\n]/g, "")}`),
		"",
		"",
	].join("\r\n");
	let connection: StreamConnection | null = null;
	const run = async (): Promise<HttpResponse> => {
		connection = await deps.transport.connect({ hostname: resolved.addresses[0], port });
		connection = await deps.transport.startTls(connection, { serverName: host, caCerts: options.caCerts });
		await connection.write(new TextEncoder().encode(request));
		await connection.write(bytes);
		const reader = new StreamReader(connection);
		const status = /^HTTP\/1\.[01] ([0-9]{3})/.exec((await reader.readLine(8192)) ?? "");
		if (!status) throw new TransportError("connection_closed");
		const responseHeaders = new Map<string, string>();
		for (let i = 0; i < 100; i += 1) {
			const line = await reader.readLine(8192);
			if (line === null || line === "") break;
			const colon = line.indexOf(":");
			if (colon > 0) responseHeaders.set(line.slice(0, colon).trim().toLowerCase(), line.slice(colon + 1).trim());
		}
		const length = Number(responseHeaders.get("content-length"));
		let responseBody: Uint8Array;
		if (/chunked/i.test(responseHeaders.get("transfer-encoding") ?? "")) {
			responseBody = decodeChunked(await reader.readToEnd(MAX_RESPONSE_BYTES));
		} else if (Number.isSafeInteger(length) && length >= 0) {
			if (length > MAX_RESPONSE_BYTES) throw new RangeError("body_too_large");
			responseBody = await reader.readExact(length);
		} else {
			responseBody = await reader.readToEnd(MAX_RESPONSE_BYTES);
		}
		return { status: Number(status[1]), headers: responseHeaders, body: responseBody };
	};
	try {
		return await withTimeout(run(), deps.timeoutMs ?? DELIVERY_TIMEOUT_MS, () => (connection as StreamConnection | null)?.close());
	} catch (error) {
		return errorOutcome(error);
	} finally {
		(connection as StreamConnection | null)?.close();
	}
}

function retryAfter(headers: Map<string, string>, nowMs: number): number | null {
	const value = headers.get("retry-after");
	if (!value) return null;
	if (/^[0-9]{1,6}$/.test(value)) return Number(value);
	const date = Date.parse(value);
	return Number.isFinite(date) ? Math.max(0, Math.ceil((date - nowMs) / 1000)) : null;
}

/** Status-code policy shared by every HTTP provider. Redirects are never followed. */
function httpOutcome(response: HttpResponse, nowMs: number): ForwardOutcome {
	const status = response.status;
	if (status >= 200 && status < 300) return ok(status);
	if (status >= 300 && status < 400) return failed("redirect_refused", status);
	if (status === 429) return retry("receiver_rate_limited", status, retryAfter(response.headers, nowMs));
	if (status === 408 || status >= 500) return retry("receiver_unavailable", status, retryAfter(response.headers, nowMs));
	return failed("receiver_rejected", status);
}

function caOf(config: { ca_pem?: string }): string[] | undefined {
	return config.ca_pem ? pemCertificates(config.ca_pem) : undefined;
}

// ── Providers ─────────────────────────────────────────────────────────────

type BatchResult = ForwardOutcome[];

async function sendSyslog(
	config: SyslogDestinationConfig,
	format: SiemFormat,
	events: ForwardedEvent[],
	deps: ForwardDeps,
): Promise<BatchResult> {
	const messages = events.map((event) => formatSyslogMessage(event, format, config));
	const resolved = await resolveCollector(config.host, deps.resolveDns, deps.allowPrivateNetworks && config.allow_private_network === true);
	if (!resolved.ok) {
		const outcome = resolved.error === "destination_policy_rejected" ? failed(resolved.error) : retry(resolved.error);
		return events.map(() => outcome);
	}
	const address = resolved.addresses[0];
	const encoder = new TextEncoder();
	if (config.transport === "udp") {
		const results: BatchResult = [];
		for (const message of messages) {
			const datagram = encoder.encode(message);
			if (datagram.length > UDP_MAX_DATAGRAM_BYTES) {
				results.push(failed("syslog_message_too_large_for_udp"));
				continue;
			}
			try {
				await deps.transport.sendDatagram({ hostname: address, port: config.port, data: datagram });
				// UDP has no acknowledgement: "handed to the network", never proof of receipt.
				results.push(ok());
			} catch (error) {
				results.push(errorOutcome(error));
			}
		}
		return results;
	}
	const frames: Uint8Array[] = [];
	const results: Array<ForwardOutcome | null> = messages.map((message) => {
		const body = encoder.encode(message);
		if (body.length > SYSLOG_MAX_BYTES) return failed("syslog_message_too_large");
		// RFC 6587 octet counting.
		const frame = encoder.encode(`${body.length} `);
		const joined = new Uint8Array(frame.length + body.length);
		joined.set(frame);
		joined.set(body, frame.length);
		frames.push(joined);
		return null;
	});
	if (frames.length === 0) return results as BatchResult;
	let connection: StreamConnection | null = null;
	const run = async () => {
		connection = await deps.transport.connect({ hostname: address, port: config.port });
		if (config.transport === "tls") {
			connection = await deps.transport.startTls(connection, { serverName: config.host, caCerts: caOf(config) });
		}
		for (const frame of frames) await connection.write(frame);
		// Delivered only once every byte is flushed and the collector closed cleanly.
		await connection.closeWrite();
		while ((await connection.read()) !== null) {
			// Drain until the collector closes.
		}
	};
	let outcome: ForwardOutcome;
	try {
		await withTimeout(run(), deps.timeoutMs ?? DELIVERY_TIMEOUT_MS, () => (connection as StreamConnection | null)?.close());
		outcome = ok();
	} catch (error) {
		outcome = errorOutcome(error);
	} finally {
		(connection as StreamConnection | null)?.close();
	}
	return results.map((result) => result ?? outcome);
}

async function sendSplunk(config: Extract<SiemDestinationConfig, { provider: "splunk_hec" }>, events: ForwardedEvent[], deps: ForwardDeps): Promise<BatchResult> {
	const body = events
		.map((event) =>
			JSON.stringify({
				time: Date.parse(event.observed_at) / 1000,
				host: "aidr-control-plane",
				source: config.source ?? "aidr",
				sourcetype: config.sourcetype ?? "aidr:event",
				...(config.index ? { index: config.index } : {}),
				event,
			}),
		)
		.join("\n");
	const response = await httpsPost(
		new URL("/services/collector/event", config.url),
		{ Authorization: `Splunk ${config.token}`, "Content-Type": "application/json", "X-Splunk-Request-Channel": crypto.randomUUID() },
		body,
		{ caCerts: caOf(config), allowPrivate: deps.allowPrivateNetworks && config.allow_private_network === true },
		deps,
	);
	const outcome = "outcome" in response ? response : httpOutcome(response, deps.now());
	return events.map(() => outcome);
}

async function sendElastic(config: Extract<SiemDestinationConfig, { provider: "elastic" }>, events: ForwardedEvent[], deps: ForwardDeps): Promise<BatchResult> {
	const body = `${events
		.map((event) => `${JSON.stringify({ create: { _index: config.index, _id: event.event_id } })}\n${JSON.stringify({ "@timestamp": event.observed_at, ...event })}`)
		.join("\n")}\n`;
	const auth = config.api_key
		? `ApiKey ${config.api_key}`
		: `Basic ${btoa(String.fromCharCode(...new TextEncoder().encode(`${config.username}:${config.password}`)))}`;
	const response = await httpsPost(
		new URL("/_bulk", config.url),
		{ Authorization: auth, "Content-Type": "application/x-ndjson" },
		body,
		{ caCerts: caOf(config), allowPrivate: deps.allowPrivateNetworks && config.allow_private_network === true },
		deps,
	);
	if ("outcome" in response) return events.map(() => response);
	const overall = httpOutcome(response, deps.now());
	if (overall.outcome !== "delivered") return events.map(() => overall);
	// _bulk answers 200 even when items fail: judge every item.
	let parsed: unknown;
	try {
		parsed = JSON.parse(new TextDecoder().decode(response.body));
	} catch {
		return events.map(() => retry("receiver_invalid_response", response.status));
	}
	const items = isRecord(parsed) && Array.isArray(parsed.items) ? parsed.items : null;
	if (!items || items.length !== events.length) return events.map(() => retry("receiver_invalid_response", response.status));
	return items.map((item) => {
		const result = isRecord(item) && isRecord(item.create) ? item.create : null;
		const status = result && Number.isSafeInteger(result.status) ? (result.status as number) : 0;
		if (status >= 200 && status < 300) return ok(status);
		// A duplicate _id: an earlier attempt already stored this event.
		if (status === 409) return ok(409);
		if (status === 429 || status >= 500) return retry("receiver_unavailable", status);
		return failed("receiver_rejected", status >= 100 && status <= 599 ? status : null);
	});
}

interface CachedToken {
	token: string;
	expiresAt: number;
}
const sentinelTokens = new Map<string, CachedToken>();

async function sentinelToken(
	config: Extract<SiemDestinationConfig, { provider: "sentinel" }>,
	deps: ForwardDeps,
): Promise<string | ForwardOutcome> {
	const authority = config.endpoint.endsWith(".azure.us") ? "login.microsoftonline.us"
		: config.endpoint.endsWith(".azure.cn") ? "login.chinacloudapi.cn" : "login.microsoftonline.com";
	const scope = config.endpoint.endsWith(".azure.us") ? "https://monitor.azure.us//.default"
		: config.endpoint.endsWith(".azure.cn") ? "https://monitor.azure.cn//.default" : "https://monitor.azure.com//.default";
	const cacheKey = `${config.azure_tenant_id}:${config.client_id}:${scope}`;
	const cached = sentinelTokens.get(cacheKey);
	if (cached && cached.expiresAt > deps.now() + 60_000) return cached.token;
	const form = new URLSearchParams({
		grant_type: "client_credentials",
		client_id: config.client_id,
		client_secret: config.client_secret,
		scope,
	}).toString();
	const response = await httpsPost(
		new URL(`/${config.azure_tenant_id}/oauth2/v2.0/token`, `https://${authority}`),
		{ "Content-Type": "application/x-www-form-urlencoded" },
		form,
		{ allowPrivate: false },
		deps,
	);
	if ("outcome" in response) return response;
	if (response.status !== 200) {
		const outcome = httpOutcome(response, deps.now());
		return outcome.outcome === "failed" ? failed("sentinel_auth_rejected", response.status) : outcome;
	}
	try {
		const body = JSON.parse(new TextDecoder().decode(response.body)) as { access_token?: unknown; expires_in?: unknown };
		if (typeof body.access_token !== "string" || body.access_token === "") throw new Error("token");
		const ttl = typeof body.expires_in === "number" && body.expires_in > 0 ? body.expires_in : 300;
		sentinelTokens.set(cacheKey, { token: body.access_token, expiresAt: deps.now() + ttl * 1000 });
		return body.access_token;
	} catch {
		return retry("sentinel_auth_invalid_response", response.status);
	}
}

async function sendSentinel(config: Extract<SiemDestinationConfig, { provider: "sentinel" }>, events: ForwardedEvent[], deps: ForwardDeps): Promise<BatchResult> {
	const token = await sentinelToken(config, deps);
	if (typeof token !== "string") return events.map(() => token);
	const records = events.map((event) => ({
		TimeGenerated: event.observed_at,
		EventId: event.event_id,
		TenantId: event.tenant_id,
		Kind: event.kind,
		Severity: severityOf(event),
		...Object.fromEntries(Object.entries(event.event).map(([key, value]) => [key, value])),
	}));
	const response = await httpsPost(
		new URL(`/dataCollectionRules/${config.dcr_immutable_id}/streams/${config.stream_name}?api-version=2023-01-01`, config.endpoint),
		{ Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
		JSON.stringify(records),
		{ allowPrivate: false },
		deps,
	);
	const outcome = "outcome" in response ? response : httpOutcome(response, deps.now());
	return events.map(() => outcome);
}

async function sendWebhook(config: Extract<SiemDestinationConfig, { provider: "webhook" }>, events: ForwardedEvent[], deps: ForwardDeps): Promise<BatchResult> {
	const results: BatchResult = [];
	for (const event of events) {
		const body = JSON.stringify(event);
		const response = await httpsPost(
			new URL(config.url),
			{
				"Content-Type": "application/json",
				"X-AIDR-Event": `siem.${event.kind}`,
				"X-AIDR-Delivery-ID": event.event_id,
				"Idempotency-Key": event.event_id,
				"X-AIDR-Signature": await signatureHeader(config.secret, Math.floor(deps.now() / 1000), body),
			},
			body,
			{ caCerts: caOf(config), allowPrivate: deps.allowPrivateNetworks && config.allow_private_network === true },
			deps,
		);
		results.push("outcome" in response ? response : httpOutcome(response, deps.now()));
	}
	return results;
}

/** Deliver a batch to one decrypted destination. Never throws; one outcome per event. */
export async function deliverSiemBatch(
	config: SiemDestinationConfig,
	format: SiemFormat,
	events: ForwardedEvent[],
	deps: ForwardDeps,
): Promise<BatchResult> {
	try {
		switch (config.provider) {
			case "syslog":
				return await sendSyslog(config, format, events, deps);
			case "splunk_hec":
				return await sendSplunk(config, events, deps);
			case "elastic":
				return await sendElastic(config, events, deps);
			case "sentinel":
				return await sendSentinel(config, events, deps);
			case "webhook":
				return await sendWebhook(config, events, deps);
		}
	} catch {
		return events.map(() => retry("delivery_error"));
	}
}

// ── Forwarder loop ────────────────────────────────────────────────────────

interface ClaimedDestination {
	destinationId: string;
	tenantId: string;
	provider: SiemProvider;
	format: SiemFormat;
	configCiphertext: string;
	deliveries: ClaimedSiemDelivery[];
}

/** Validate the claim RPC's answer; null when it is not the contract. */
function parseClaimedDestinations(value: unknown): ClaimedDestination[] | null {
	if (!Array.isArray(value)) return null;
	const groups: ClaimedDestination[] = [];
	for (const group of value) {
		if (
			!isRecord(group) ||
			typeof group.destination_id !== "string" || !UUID.test(group.destination_id) ||
			typeof group.tenant_id !== "string" || !UUID.test(group.tenant_id) ||
			!SIEM_PROVIDERS.includes(group.provider as SiemProvider) ||
			!["json", "cef", "leef"].includes(group.format as string) ||
			typeof group.config_ciphertext !== "string" ||
			!Array.isArray(group.deliveries)
		) {
			return null;
		}
		const deliveries: ClaimedSiemDelivery[] = [];
		for (const row of group.deliveries) {
			if (
				!isRecord(row) ||
				typeof row.delivery_id !== "string" || !/^[0-9]{1,19}$/.test(row.delivery_id) ||
				typeof row.lease_token !== "string" || !UUID.test(row.lease_token) ||
				!KINDS.includes(row.kind as Kind) ||
				!isRecord(row.payload) ||
				!Number.isSafeInteger(row.attempts) || !Number.isSafeInteger(row.max_attempts) ||
				typeof row.created_at !== "string"
			) {
				return null;
			}
			deliveries.push({
				deliveryId: row.delivery_id,
				leaseToken: row.lease_token,
				kind: row.kind as Kind,
				payload: row.payload,
				attempts: row.attempts as number,
				maxAttempts: row.max_attempts as number,
				createdAt: row.created_at,
			});
		}
		groups.push({
			destinationId: group.destination_id.toLowerCase(),
			tenantId: group.tenant_id.toLowerCase(),
			provider: group.provider as SiemProvider,
			format: group.format as SiemFormat,
			configCiphertext: group.config_ciphertext,
			deliveries,
		});
	}
	return groups;
}

interface RpcClient {
	rpc(name: string, args: Record<string, unknown>): PromiseLike<{ data: unknown; error: unknown }>;
}

export interface SiemForwardOptions extends ForwardDeps {
	keyring: NotificationKeyring;
	random: () => number;
	/** Tenant entitlement check; "unavailable" retries, "denied" dead-letters. */
	entitled: (tenantId: string) => Promise<"ok" | "denied" | "unavailable">;
	maxRounds?: number;
	destinationsPerClaim?: number;
	perDestination?: number;
	leaseSeconds?: number;
	deadlineMs?: number;
	concurrency?: number;
	/** Claim exactly this delivery (the dashboard test send). */
	deliveryId?: string;
}

export interface SiemForwardSummary {
	claimed: number;
	delivered: number;
	retrying: number;
	dead: number;
	leaseLost: number;
	results: Array<{ deliveryId: string; outcome: ForwardOutcome["outcome"]; error: string | null; statusCode: number | null }>;
}

export class SiemForwardError extends Error {
	constructor(readonly code: "claim_failed" | "complete_failed") {
		super(code);
	}
}

async function forwardGroup(
	group: ClaimedDestination,
	options: SiemForwardOptions,
	entitlement: Map<string, Promise<"ok" | "denied" | "unavailable">>,
): Promise<Array<{ row: ClaimedSiemDelivery; outcome: ForwardOutcome }>> {
	if (!entitlement.has(group.tenantId)) entitlement.set(group.tenantId, options.entitled(group.tenantId).catch(() => "unavailable" as const));
	const plan = await entitlement.get(group.tenantId);
	if (plan !== "ok") {
		const outcome = plan === "denied" ? failed("plan_feature_required") : retry("plan_entitlement_unavailable");
		return group.deliveries.map((row) => ({ row, outcome }));
	}
	const config = await decryptSiemConfig(
		options.keyring,
		{ tenantId: group.tenantId, destinationId: group.destinationId, provider: group.provider },
		group.configCiphertext,
	);
	if (!config) return group.deliveries.map((row) => ({ row, outcome: failed("decrypt_failed") }));
	const events = group.deliveries.map((row) => buildForwardedEvent(group.tenantId, row));
	const outcomes = await deliverSiemBatch(config, group.format, events, options);
	return group.deliveries.map((row, index) => ({ row, outcome: outcomes[index] ?? retry("delivery_error") }));
}

/**
 * Claim due deliveries per destination and forward them with limited
 * concurrency. A claim or completion failure stops the run (leased rows are
 * reclaimed when their lease expires); a collector failure never does.
 */
export async function runSiemForwarding(db: RpcClient, options: SiemForwardOptions): Promise<SiemForwardSummary> {
	const rounds = options.deliveryId ? 1 : (options.maxRounds ?? 10);
	const deadline = options.now() + (options.deadlineMs ?? 40_000);
	const summary: SiemForwardSummary = { claimed: 0, delivered: 0, retrying: 0, dead: 0, leaseLost: 0, results: [] };
	const entitlement = new Map<string, Promise<"ok" | "denied" | "unavailable">>();
	for (let round = 0; round < rounds && options.now() < deadline; round += 1) {
		const { data, error } = await db.rpc("claim_siem_deliveries", {
			p_destinations: options.deliveryId ? 1 : (options.destinationsPerClaim ?? 20),
			p_per_destination: options.deliveryId ? 1 : (options.perDestination ?? 200),
			p_lease_seconds: options.leaseSeconds ?? 120,
			p_delivery_id: options.deliveryId ?? null,
		});
		const groups = error ? null : parseClaimedDestinations(data);
		if (!groups) throw new SiemForwardError("claim_failed");
		if (groups.length === 0) break;
		let next = 0;
		const finished: Array<{ row: ClaimedSiemDelivery; outcome: ForwardOutcome }> = [];
		const worker = async () => {
			while (next < groups.length) {
				const group = groups[next++];
				finished.push(...(await forwardGroup(group, options, entitlement)));
			}
		};
		await Promise.all(Array.from({ length: Math.min(options.concurrency ?? 4, groups.length) }, worker));
		summary.claimed += finished.length;
		const { data: completed, error: completeError } = await db.rpc("complete_siem_deliveries", {
			p_results: finished.map(({ row, outcome }) => ({
				delivery_id: row.deliveryId,
				lease_token: row.leaseToken,
				outcome: outcome.outcome,
				error: outcome.error,
				status_code: outcome.statusCode,
				retry_in_seconds: outcome.outcome === "retry"
					? backoffSeconds(row.attempts, options.random, outcome.retryAfterSeconds ?? null)
					: null,
			})),
		});
		if (completeError || !isRecord(completed)) throw new SiemForwardError("complete_failed");
		summary.delivered += Number(completed.delivered) || 0;
		summary.retrying += Number(completed.pending) || 0;
		summary.dead += Number(completed.dead) || 0;
		summary.leaseLost += Number(completed.lease_lost) || 0;
		for (const { row, outcome } of finished) {
			summary.results.push({ deliveryId: row.deliveryId, outcome: outcome.outcome, error: outcome.error, statusCode: outcome.statusCode });
		}
		const perDestination = options.perDestination ?? 200;
		if (groups.every((group) => group.deliveries.length < perDestination)) break;
	}
	return summary;
}
