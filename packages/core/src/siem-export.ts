import type { Incident, IncidentSeverity } from "./incidents/types.js";
import { VERSION } from "./version.js";

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
	return raw.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/=/g, "\\=");
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
	return raw.replace(/\|/g, "\\|");
}

/**
 * Escape a value for the LEEF extension segment (tab-delimited key=value).
 *
 * Tab characters in values are replaced with `\t` to preserve the structure.
 */
function escapeLeefValue(raw: string): string {
	return raw.replace(/\t/g, "\\t").replace(/\\/g, "\\\\");
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
function toJsonRecord(incident: Incident): Record<string, unknown> {
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
		})),
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
	return JSON.stringify(matched.map(toJsonRecord));
}
