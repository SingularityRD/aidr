import { frameworkRefLabels, frameworkRefsFromJson } from "./framework-mappings.js";
import type { Incident, IncidentSeverity } from "./incidents/types.js";
import type { FrameworkRefs, FrameworkRefsJson } from "./types.js";
import { VERSION } from "./version.js";

/**
 * Union of the framework IDs carried by an incident's events (OWASP LLM 2025,
 * OWASP Agentic 2026, MITRE ATLAS), or null when no event carried any.
 */
function incidentFrameworks(incident: Incident): FrameworkRefs | null {
	const merged: FrameworkRefsJson = { owasp_llm: [], owasp_agentic: [], mitre_atlas: [] };
	for (const event of incident.events) {
		if (!event.frameworks) continue;
		merged.owasp_llm.push(...event.frameworks.owasp_llm);
		merged.owasp_agentic.push(...event.frameworks.owasp_agentic);
		merged.mitre_atlas.push(...event.frameworks.mitre_atlas);
	}
	// Re-validates the IDs, de-duplicates and sorts.
	return frameworkRefsFromJson(merged);
}

/** `LLM01:2025,ASI01:2026,AML.T0051`, or undefined when no event carried IDs. */
function incidentFrameworkLabels(incident: Incident): string | undefined {
	const refs = incidentFrameworks(incident);
	return refs ? frameworkRefLabels(refs).join(",") : undefined;
}

function frameworksRecordField(incident: Incident): { frameworks?: FrameworkRefsJson } {
	const refs = incidentFrameworks(incident);
	if (!refs) return {};
	return {
		frameworks: {
			owasp_llm: refs.owaspLlm,
			owasp_agentic: refs.owaspAgentic,
			mitre_atlas: refs.mitreAtlas,
		},
	};
}

// ---------------------------------------------------------------------------
// Public filter
// ---------------------------------------------------------------------------

export interface SiemExportFilter {
	/** Include incidents opened at or after this timestamp (ms). */
	fromMs?: number;
	/** Include incidents opened at or before this timestamp (ms). */
	toMs?: number;
	/** Only include incidents matching one (or more) of the given severities. */
	severity?: IncidentSeverity | IncidentSeverity[];
	/** Only include incidents for the given agent IID. */
	agentIid?: string;
}

// ---------------------------------------------------------------------------
// CEF helpers
// ---------------------------------------------------------------------------

/**
 * Severity scale used in CEF (0–10).
 *
 * | AIDR severity | CEF severity |
 * |---------------|--------------|
 * | info          | 2            |
 * | warning       | 5            |
 * | high          | 8            |
 * | critical      | 10           |
 */
const CEF_SEVERITY: Record<IncidentSeverity, number> = {
	info: 2,
	warning: 5,
	high: 8,
	critical: 10,
};

/**
 * Vendor/product string used in the CEF / LEEF header.
 */
const VENDOR = "Singularity";
const PRODUCT = "AIDR";

/**
 * Escape a value for use inside a CEF extension block.
 *
 * ArcSight CEF implementation guide:
 *   - `\` → `\\`
 *   - `|` → `\|`
 *   - `=` → `\=`
 *   - `\n` → `\n` (preserved as literal control char)
 */
function escapeCefValue(raw: string): string {
	// CR/LF are escaped so a field value can never terminate the record and
	// forge a second CEF line (log injection).
	return raw
		.replace(/\\/g, "\\\\")
		.replace(/\|/g, "\\|")
		.replace(/=/g, "\\=")
		.replace(/\r/g, "\\r")
		.replace(/\n/g, "\\n");
}

/**
 * Build a single CEF extension key=value pair.
 */
function cefKv(key: string, value: string | number | boolean | undefined | null): string {
	if (value === undefined || value === null) return "";
	return `${key}=${escapeCefValue(String(value))}`;
}

/**
 * Map an {@link Incident} to a CEF extension string.
 */
function buildCefExtension(incident: Incident): string {
	const parts: string[] = [];

	parts.push(cefKv("incident_id", incident.incident_id));
	parts.push(cefKv("opened_at_ms", incident.opened_at_ms));
	parts.push(cefKv("last_seen_ms", incident.last_seen_ms));
	parts.push(cefKv("status", incident.status));

	if (incident.session_id) parts.push(cefKv("session_id", incident.session_id));
	if (incident.agent_iid) parts.push(cefKv("agent_iid", incident.agent_iid));
	if (incident.connector) parts.push(cefKv("connector", incident.connector));
	if (incident.plugin_key) parts.push(cefKv("plugin_key", incident.plugin_key));
	if (incident.package_name) parts.push(cefKv("package_name", incident.package_name));
	if (incident.domain) parts.push(cefKv("domain", incident.domain));
	if (incident.file_path) parts.push(cefKv("file_path", incident.file_path));

	parts.push(cefKv("frameworks", incidentFrameworkLabels(incident)));

	// Include a count of correlated events.
	parts.push(cefKv("event_count", incident.events.length));

	// Include event summaries (pipe-joined to keep it parseable).
	if (incident.events.length > 0) {
		const summaries = incident.events.map((e) => e.summary).join("|");
		parts.push(cefKv("event_summaries", summaries));
	}

	return parts.filter(Boolean).join(" ");
}

/**
 * Map an {@link Incident} to a CEF signature-id string.
 */
function cefSignatureId(incident: Incident): string {
	// Use a concise identifier based on severity and correlation keys.
	const prefix = `AIDR/${incident.severity}`;
	if (incident.plugin_key) return `${prefix}/PLUGIN`;
	if (incident.package_name) return `${prefix}/PACKAGE`;
	if (incident.domain) return `${prefix}/DOMAIN`;
	if (incident.file_path) return `${prefix}/FILE`;
	return `${prefix}/INCIDENT`;
}

/**
 * Map an {@link Incident} to a human-readable CEF name.
 */
function cefName(incident: Incident): string {
	const eventCount = incident.events.length;
	const base = `AIDR ${incident.severity} incident`;
	if (incident.plugin_key) return `${base} - ${incident.plugin_key}`;
	if (incident.package_name) return `${base} - ${incident.package_name}`;
	if (incident.domain) return `${base} - ${incident.domain}`;
	return `${base} (${eventCount} event${eventCount !== 1 ? "s" : ""})`;
}

// ---------------------------------------------------------------------------
// LEEF helpers
// ---------------------------------------------------------------------------

/**
 * Escape a value for the LEEF header segment (pipe-delimited).
 *
 * Per the IBM QRadar LEEF guide any `|` in a header field must be escaped
 * with a leading `\`.
 */
function escapeLeefHeader(raw: string): string {
	return raw.replace(/\|/g, "\\|").replace(/\r/g, "\\r").replace(/\n/g, "\\n");
}

/**
 * Escape a value for the LEEF extension segment (tab-delimited key=value).
 *
 * Tab characters in values are replaced with `\t` to preserve the structure.
 */
function escapeLeefValue(raw: string): string {
	return raw
		.replace(/\t/g, "\\t")
		.replace(/\\/g, "\\\\")
		.replace(/\r/g, "\\r")
		.replace(/\n/g, "\\n");
}

/**
 * Build a single LEEF extension key=value pair.
 */
function leefKv(key: string, value: string | number | boolean | undefined | null): string {
	if (value === undefined || value === null) return "";
	return `${key}=${escapeLeefValue(String(value))}`;
}

/**
 * Map an {@link Incident} to a LEEF extension string (tab-separated).
 */
function buildLeefExtension(incident: Incident): string {
	const pairs: string[] = [];

	pairs.push(leefKv("incident_id", incident.incident_id));
	pairs.push(leefKv("opened_at_ms", incident.opened_at_ms));
	pairs.push(leefKv("last_seen_ms", incident.last_seen_ms));
	pairs.push(leefKv("severity", incident.severity));
	pairs.push(leefKv("status", incident.status));

	if (incident.session_id) pairs.push(leefKv("session_id", incident.session_id));
	if (incident.agent_iid) pairs.push(leefKv("agent_iid", incident.agent_iid));
	if (incident.connector) pairs.push(leefKv("connector", incident.connector));
	if (incident.plugin_key) pairs.push(leefKv("plugin_key", incident.plugin_key));
	if (incident.package_name) pairs.push(leefKv("package_name", incident.package_name));
	if (incident.domain) pairs.push(leefKv("domain", incident.domain));
	if (incident.file_path) pairs.push(leefKv("file_path", incident.file_path));

	const frameworks = incidentFrameworkLabels(incident);
	if (frameworks) pairs.push(leefKv("frameworks", frameworks));
	pairs.push(leefKv("event_count", incident.events.length));

	return pairs.join("\t");
}

/**
 * Build the LEEF payload string (name portion in the header).
 */
function leefName(incident: Incident): string {
	return `AIDR ${incident.severity} incident`;
}

/**
 * Build the LEEF event-id portion of the header.
 */
function leefEventId(incident: Incident): string {
	return `AIDR-${incident.severity.toUpperCase()}`;
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

/**
 * Serialize an incident for JSON SIEM output — a flat envelope with metadata.
 */
export function incidentToSiemRecord(incident: Incident): Record<string, unknown> {
	return {
		siem_type: "aidr_incident",
		incident_id: incident.incident_id,
		opened_at_ms: incident.opened_at_ms,
		last_seen_ms: incident.last_seen_ms,
		severity: incident.severity,
		status: incident.status,
		session_id: incident.session_id ?? null,
		agent_iid: incident.agent_iid ?? null,
		connector: incident.connector ?? null,
		plugin_key: incident.plugin_key ?? null,
		package_name: incident.package_name ?? null,
		domain: incident.domain ?? null,
		file_path: incident.file_path ?? null,
		event_count: incident.events.length,
		events: incident.events.map((e) => ({
			signal_id: e.signal_id,
			timestamp_ms: e.timestamp_ms,
			signal_type: e.signal_type,
			severity: e.severity,
			summary: e.summary,
			...(e.frameworks ? { frameworks: e.frameworks } : {}),
		})),
		...frameworksRecordField(incident),
	};
}

// ---------------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------------

function matchesTimeRange(inc: Incident, filter: SiemExportFilter): boolean {
	if (filter.fromMs !== undefined && inc.opened_at_ms < filter.fromMs) return false;
	if (filter.toMs !== undefined && inc.opened_at_ms > filter.toMs) return false;
	return true;
}

function matchesSeverity(inc: Incident, filter: SiemExportFilter): boolean {
	if (filter.severity === undefined) return true;
	const allowed = Array.isArray(filter.severity) ? filter.severity : [filter.severity];
	return allowed.includes(inc.severity);
}

function matchesAgentIid(inc: Incident, filter: SiemExportFilter): boolean {
	if (filter.agentIid === undefined) return true;
	return inc.agent_iid === filter.agentIid;
}

/**
 * Apply an optional {@link SiemExportFilter} and return only the incidents
 * that match all of the specified criteria.
 */
function applyFilter(incidents: Incident[], filter?: SiemExportFilter): Incident[] {
	if (!filter) return incidents;

	return incidents.filter(
		(inc) =>
			matchesTimeRange(inc, filter) && matchesSeverity(inc, filter) && matchesAgentIid(inc, filter),
	);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Export an array of {@link Incident} objects as a string of newline-separated
 * **CEF** (Common Event Format) records, formatted for ingestion by Splunk or
 * any CEF-compatible SIEM.
 *
 * @param incidents - The incidents to export.
 * @param filter    - Optional criteria to narrow the exported set.
 * @returns A string where each line is a single CEF record.
 *
 * @example
 * ```ts
 * const cef = exportToCEF(incidents, { severity: "critical" });
 * ```
 */
export function exportToCEF(incidents: Incident[], filter?: SiemExportFilter): string {
	const matched = applyFilter(incidents, filter);
	if (matched.length === 0) return "";

	return matched
		.map((inc) => {
			const sev = CEF_SEVERITY[inc.severity];
			const sig = escapeCefValue(cefSignatureId(inc));
			const name = escapeCefValue(cefName(inc));
			const ext = buildCefExtension(inc);

			return `CEF:0|${VENDOR}|${PRODUCT}|${VERSION}|${sig}|${name}|${sev}|${ext}`;
		})
		.join("\n");
}

/**
 * Export an array of {@link Incident} objects as a string of newline-separated
 * **LEEF** (Log Event Extended Format) records, formatted for ingestion by
 * IBM QRadar or any LEEF-compatible SIEM.
 *
 * @param incidents - The incidents to export.
 * @param filter    - Optional criteria to narrow the exported set.
 * @returns A string where each line is a single LEEF record.
 *
 * @example
 * ```ts
 * const leef = exportToLEEF(incidents, { severity: ["high", "critical"] });
 * ```
 */
export function exportToLEEF(incidents: Incident[], filter?: SiemExportFilter): string {
	const matched = applyFilter(incidents, filter);
	if (matched.length === 0) return "";

	return matched
		.map((inc) => {
			const name = escapeLeefHeader(leefName(inc));
			const eventId = escapeLeefHeader(leefEventId(inc));
			const ext = buildLeefExtension(inc);

			return `LEEF:1.0|${VENDOR}|${PRODUCT}|${VERSION}|${eventId}|${name}|${CEF_SEVERITY[inc.severity]}|${ext}`;
		})
		.join("\n");
}

/**
 * Export an array of {@link Incident} objects as a JSON string containing a
 * **JSON** array of SIEM-friendly incident records, suitable for any SIEM that
 * accepts structured JSON event input.
 *
 * The output is a **compact** JSON array (no pretty-print) to minimise wire
 * size.  Each element is a flat envelope that includes all incident-level
 * fields and a nested `events` array.
 *
 * @param incidents - The incidents to export.
 * @param filter    - Optional criteria to narrow the exported set.
 * @returns A JSON string — either `"[]"` or an array of incident records.
 *
 * @example
 * ```ts
 * const json = exportToJSON(incidents, { agentIid: "agent-abc" });
 * ```
 */
export function exportToJSON(incidents: Incident[], filter?: SiemExportFilter): string {
	const matched = applyFilter(incidents, filter);
	return JSON.stringify(matched.map(incidentToSiemRecord));
}

// ---------------------------------------------------------------------------
// Syslog (RFC 5424)
// ---------------------------------------------------------------------------

/** RFC 5424 severity (0 = emergency ... 7 = debug) for each AIDR severity. */
const SYSLOG_SEVERITY: Record<IncidentSeverity, number> = {
	critical: 2,
	high: 3,
	warning: 4,
	info: 6,
};

const DEFAULT_SYSLOG_FACILITY = 16; // local0
const DEFAULT_SYSLOG_APP_NAME = "aidr";
const DEFAULT_SYSLOG_MSG_ID = "INCIDENT";
const DEFAULT_SYSLOG_SD_ID = "aidr@32473"; // 32473 is the IANA documentation enterprise number
const DEFAULT_SYSLOG_MAX_BYTES = 64 * 1024;
const SYSLOG_SD_ID_PATTERN = /^[A-Za-z0-9_.-]{1,32}@[0-9]{1,10}$/;

export class SyslogMessageTooLargeError extends RangeError {
	readonly code = "syslog_message_too_large";

	constructor() {
		super("Syslog message exceeds the configured size limit");
		this.name = "SyslogMessageTooLargeError";
	}
}

export interface SyslogFormatOptions {
	/** RFC 5424 facility 0-23. Defaults to 16 (local0). */
	facility?: number;
	/** HOSTNAME field. Printable ASCII only; anything else is replaced. Defaults to NILVALUE. */
	hostname?: string;
	/** APP-NAME field (max 48). Defaults to `aidr`. */
	appName?: string;
	/** MSGID field (max 32). Defaults to `INCIDENT`. */
	msgId?: string;
	/** STRUCTURED-DATA ID in `name@enterprise-number` form. */
	structuredDataId?: string;
	/** Upper bound for the whole UTF-8 message. Events are truncated to fit. */
	maxBytes?: number;
}

export interface SyslogMessageInput {
	timestampMs: number;
	severity: IncidentSeverity;
	eventId: string;
	incidentId: string;
	status?: string;
	connector?: string | null;
	agentIid?: string | null;
	/** JSON-serialisable body whose `events` (or `incident.events`) array may be truncated to fit. */
	payload: Record<string, unknown>;
}

function syslogHeaderField(value: string | undefined, maxLength: number): string {
	if (!value) return "-";
	// PRINTUSASCII (33-126): no spaces, controls or non-ASCII.
	const cleaned = value.replace(/[^\x21-\x7e]/g, "_").slice(0, maxLength);
	return cleaned.length > 0 ? cleaned : "-";
}

function syslogParamValue(value: string): string {
	// Control characters would let a value forge a new line or frame.
	return value
		.replace(/[\p{Cc}\p{Zl}\p{Zp}]/gu, " ")
		.replace(/\\/g, "\\\\")
		.replace(/"/g, '\\"')
		.replace(/]/g, "\\]")
		.slice(0, 256);
}

function syslogStructuredData(
	sdId: string,
	params: Array<[string, string | null | undefined]>,
): string {
	const body = params
		.filter((entry): entry is [string, string] => typeof entry[1] === "string" && entry[1] !== "")
		.map(([name, value]) => ` ${name}="${syslogParamValue(value)}"`)
		.join("");
	return `[${sdId}${body}]`;
}

function eventHolder(payload: Record<string, unknown>): Record<string, unknown> | undefined {
	if (Array.isArray(payload.events)) return payload;
	const incident = payload.incident;
	return incident && typeof incident === "object" && !Array.isArray(incident)
		? eventHolder(incident as Record<string, unknown>)
		: undefined;
}

function withEventLimit(payload: Record<string, unknown>, keep: number): Record<string, unknown> {
	if (Array.isArray(payload.events)) {
		return { ...payload, events: payload.events.slice(0, keep), events_truncated: true };
	}
	const incident = payload.incident;
	if (incident && typeof incident === "object" && !Array.isArray(incident)) {
		return { ...payload, incident: withEventLimit(incident as Record<string, unknown>, keep) };
	}
	return payload;
}

/**
 * Format one RFC 5424 syslog message (no framing, no trailing newline). The MSG
 * is a UTF-8 BOM followed by single-line JSON, so a receiver need not guess the
 * encoding and no value can inject a second record.
 */
export function formatSyslogMessage(
	input: SyslogMessageInput,
	options: SyslogFormatOptions = {},
): string {
	const facility = options.facility ?? DEFAULT_SYSLOG_FACILITY;
	if (!Number.isInteger(facility) || facility < 0 || facility > 23)
		throw new RangeError("Syslog facility must be an integer from 0 to 23");
	const sdId = options.structuredDataId ?? DEFAULT_SYSLOG_SD_ID;
	if (!SYSLOG_SD_ID_PATTERN.test(sdId))
		throw new TypeError("Syslog structured-data ID must look like name@enterprise-number");
	const maxBytes = options.maxBytes ?? DEFAULT_SYSLOG_MAX_BYTES;
	if (!Number.isSafeInteger(maxBytes) || maxBytes < 480)
		throw new RangeError("Syslog maxBytes must be at least 480");
	if (!Number.isSafeInteger(input.timestampMs) || input.timestampMs < 0)
		throw new RangeError("Syslog timestamp must be a non-negative safe integer");

	const header = [
		`<${facility * 8 + SYSLOG_SEVERITY[input.severity]}>1`,
		new Date(input.timestampMs).toISOString(),
		syslogHeaderField(options.hostname, 255),
		syslogHeaderField(options.appName ?? DEFAULT_SYSLOG_APP_NAME, 48),
		"-",
		syslogHeaderField(options.msgId ?? DEFAULT_SYSLOG_MSG_ID, 32),
		syslogStructuredData(sdId, [
			["eventId", input.eventId],
			["incidentId", input.incidentId],
			["severity", input.severity],
			["status", input.status],
			["connector", input.connector],
			["agent", input.agentIid],
		]),
	].join(" ");

	const full = `${header} ﻿${JSON.stringify(input.payload)}`;
	if (Buffer.byteLength(full, "utf8") <= maxBytes) return full;
	// Halve the event list until the message fits; the event count stays in the payload.
	const events = eventHolder(input.payload)?.events;
	let remaining = Array.isArray(events) ? Math.floor(events.length / 2) : 0;
	for (;;) {
		const message = `${header} ﻿${JSON.stringify(withEventLimit(input.payload, remaining))}`;
		if (Buffer.byteLength(message, "utf8") <= maxBytes) return message;
		if (remaining === 0) throw new SyslogMessageTooLargeError();
		remaining = Math.floor(remaining / 2);
	}
}

/**
 * Export incidents as newline-separated RFC 5424 syslog messages, one per
 * incident, for file-based collectors. Network delivery uses the same
 * formatter through the `syslog` SIEM delivery adapter.
 */
export function exportToSyslog(
	incidents: Incident[],
	filter?: SiemExportFilter,
	options?: SyslogFormatOptions,
): string {
	return applyFilter(incidents, filter)
		.map((incident) =>
			formatSyslogMessage(
				{
					timestampMs: incident.last_seen_ms,
					severity: incident.severity,
					eventId: incident.incident_id,
					incidentId: incident.incident_id,
					status: incident.status,
					connector: incident.connector,
					agentIid: incident.agent_iid,
					payload: incidentToSiemRecord(incident),
				},
				options,
			),
		)
		.join("\n");
}
