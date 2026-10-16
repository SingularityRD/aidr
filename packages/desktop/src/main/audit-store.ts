import type {
	AuditEvent,
	IncidentDetail,
	IncidentEventView,
	IncidentSummary,
} from "../shared/contract.js";
import { type AuditRecord, originOf, toLogRecord } from "./audit.js";

/**
 * Everything the app shows from the audit log, built from its records.
 *
 * Incidents are the `incident_record` entries core's correlator appends
 * (packages/core/src/incidents/persist.ts, `toIncidentRecordV1`): every update
 * appends a new snapshot of the whole incident, so the snapshot with the
 * latest `last_seen_ms` per `incident_id` is the incident's current state
 * (the same rule as core's own last-seen index). An incident event that came
 * from a verdict carries that verdict's session and millisecond timestamp; the
 * verdict record itself (rule, reason, masked artifact) is joined on those two.
 */

const MAX_ROWS = 5000;
const CLOSED = new Set(["resolved", "suppressed", "contained"]);

interface IncidentEvent {
	signal_id?: unknown;
	timestamp_ms?: unknown;
	signal_type?: unknown;
	severity?: unknown;
	summary?: unknown;
}

interface IncidentSnapshot {
	incident_id: string;
	opened_at_ms: number;
	last_seen_ms: number;
	severity?: unknown;
	status?: unknown;
	session_id?: unknown;
	connector?: unknown;
	events: IncidentEvent[];
	[key: string]: unknown;
}

const CORRELATION_KEYS = [
	"session_id",
	"agent_iid",
	"connector",
	"plugin_key",
	"package_name",
	"domain",
	"file_path",
];

function str(value: unknown): string | null {
	return typeof value === "string" && value.length > 0 ? value : null;
}

function iso(ms: number): string {
	return new Date(ms).toISOString();
}

function snapshotOf(record: AuditRecord): IncidentSnapshot | null {
	if (record.type !== "incident_record" || Number(record.schema_version) !== 1) return null;
	const incident = record.incident as Record<string, unknown> | undefined;
	if (!incident || typeof incident !== "object") return null;
	const id = str(incident.incident_id);
	const opened = incident.opened_at_ms;
	const last = incident.last_seen_ms;
	if (!id || typeof opened !== "number" || typeof last !== "number") return null;
	if (!Number.isFinite(opened) || !Number.isFinite(last)) return null;
	const events = Array.isArray(incident.events)
		? (incident.events.filter((event) => event && typeof event === "object") as IncidentEvent[])
		: [];
	return { ...incident, incident_id: id, opened_at_ms: opened, last_seen_ms: last, events };
}

export class AuditStore {
	private rows: AuditEvent[] = [];
	private readonly incidents = new Map<string, IncidentSnapshot>();
	/** Verdict rows by `${session}|${epoch ms}`, for joining incident events. */
	private readonly verdicts = new Map<string, AuditEvent>();
	private sequence = 0;

	/** Add records in log order; returns the new rows and whether any incident changed. */
	ingest(records: AuditRecord[]): { rows: AuditEvent[]; incidentsChanged: boolean } {
		const fresh: AuditEvent[] = [];
		let incidentsChanged = false;
		for (const record of records) {
			this.sequence += 1;
			const row = toLogRecord(record, `${this.sequence}`);
			if (row) {
				fresh.push(row);
				if (row.recordType === "runtime_verdict" && row.sessionId) {
					this.verdicts.set(`${row.sessionId}|${Date.parse(row.at)}`, row);
				}
			}
			const snapshot = snapshotOf(record);
			if (snapshot) {
				const known = this.incidents.get(snapshot.incident_id);
				if (!known || snapshot.last_seen_ms >= known.last_seen_ms) {
					this.incidents.set(snapshot.incident_id, snapshot);
					incidentsChanged = true;
				}
			}
		}
		this.rows.push(...fresh);
		if (this.rows.length > MAX_ROWS) this.rows.splice(0, this.rows.length - MAX_ROWS);
		return { rows: fresh, incidentsChanged };
	}

	allRows(): AuditEvent[] {
		return [...this.rows];
	}

	/** The latest verdict of an agent (tool call, prompt or output check). */
	lastVerdict(): AuditEvent | null {
		for (let index = this.rows.length - 1; index >= 0; index--) {
			const row = this.rows[index] as AuditEvent;
			if (row.recordType === "runtime_verdict" && row.decision) return row;
		}
		return null;
	}

	private summary(snapshot: IncidentSnapshot): IncidentSummary {
		const status = str(snapshot.status) ?? "open";
		const sessionId = str(snapshot.session_id);
		return {
			id: snapshot.incident_id,
			severity: str(snapshot.severity) ?? "info",
			status,
			open: !CLOSED.has(status),
			sessionId,
			connector: str(snapshot.connector),
			firstSeen: iso(snapshot.opened_at_ms),
			lastSeen: iso(snapshot.last_seen_ms),
			eventCount: snapshot.events.length,
			origin: sessionId ? originOf(sessionId) : null,
		};
	}

	/** Newest first. */
	incidentList(): IncidentSummary[] {
		return [...this.incidents.values()]
			.sort((a, b) => b.last_seen_ms - a.last_seen_ms)
			.map((snapshot) => this.summary(snapshot));
	}

	incidentDetail(id: string): IncidentDetail | null {
		const snapshot = this.incidents.get(id);
		if (!snapshot) return null;
		const session = str(snapshot.session_id);
		const events: IncidentEventView[] = snapshot.events.map((event) => {
			const ms = typeof event.timestamp_ms === "number" ? event.timestamp_ms : Number.NaN;
			const signalType = str(event.signal_type) ?? "unknown";
			const verdict =
				signalType === "runtime_verdict" && session
					? this.verdicts.get(`${session}|${ms}`)
					: undefined;
			return {
				signalId: str(event.signal_id) ?? "",
				at: Number.isFinite(ms) ? iso(ms) : "",
				signalType,
				severity: str(event.severity) ?? "info",
				summary: str(event.summary) ?? "",
				verdict: verdict
					? {
							decision: verdict.decision,
							tool: verdict.tool,
							ruleId: verdict.ruleId,
							reason: verdict.reason,
							artifact: verdict.summary,
						}
					: null,
			};
		});
		const correlation = CORRELATION_KEYS.flatMap((key): Array<[string, string]> => {
			const value = str(snapshot[key]);
			return value ? [[key, value]] : [];
		});
		return { ...this.summary(snapshot), correlation, events };
	}
}
