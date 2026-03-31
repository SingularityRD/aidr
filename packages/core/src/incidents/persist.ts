import { logIncident } from "../audit-log.js";
import { resolvePath } from "../config.js";
import type { LoggingConfig } from "../types.js";
import { toIncidentRecordV1 } from "./records.js";
import type { Incident } from "./types.js";

function getIncidentRecordLastSeenMs(
	entry: unknown,
): { incidentId: string; lastSeenMs: number } | null {
	if (!entry || typeof entry !== "object") return null;
	const e = entry as Record<string, unknown>;
	if (String(e.type ?? "") !== "incident_record") return null;
	if (Number(e.schema_version) !== 1) return null;

	const incident = e.incident;
	if (!incident || typeof incident !== "object") return null;
	const i = incident as Record<string, unknown>;

	const incidentId = typeof i.incident_id === "string" ? i.incident_id : "";
	const lastSeenMs = typeof i.last_seen_ms === "number" ? i.last_seen_ms : NaN;
	if (!incidentId || !Number.isFinite(lastSeenMs)) return null;
	return { incidentId, lastSeenMs };
}

function computeLastSeenIndex(recentEntries: unknown[]): Map<string, number> {
	const index = new Map<string, number>();
	for (const e of recentEntries) {
		const rec = getIncidentRecordLastSeenMs(e);
		if (!rec) continue;
		const prev = index.get(rec.incidentId);
		if (prev === undefined || rec.lastSeenMs > prev) index.set(rec.incidentId, rec.lastSeenMs);
	}
	return index;
}

async function upsertIncidentsToSqlite(dbPath: string, incidents: Incident[]): Promise<void> {
	// Optional dependency: Node.js SQLite. If missing, caller should fallback to JSONL.
	const sqlite = (await import("node:sqlite")) as unknown as {
		DatabaseSync: new (
			path: string,
		) => {
			exec: (sql: string) => void;
			prepare: (sql: string) => { run: (...args: unknown[]) => void };
			close: () => void;
		};
	};
	const db = new sqlite.DatabaseSync(dbPath);
	try {
		db.exec(
			`CREATE TABLE IF NOT EXISTS incidents (
				incident_id TEXT PRIMARY KEY,
				opened_at_ms INTEGER NOT NULL,
				last_seen_ms INTEGER NOT NULL,
				severity TEXT NOT NULL,
				status TEXT NOT NULL,
				payload_json TEXT NOT NULL
			);`,
		);

		db.exec(
			`CREATE TABLE IF NOT EXISTS incident_events (
				incident_id TEXT NOT NULL,
				signal_id TEXT NOT NULL,
				timestamp_ms INTEGER NOT NULL,
				signal_type TEXT NOT NULL,
				severity TEXT NOT NULL,
				summary TEXT NOT NULL,
				PRIMARY KEY (incident_id, signal_id)
			);`,
		);
		db.exec(
			`CREATE INDEX IF NOT EXISTS idx_incident_events_incident_id ON incident_events(incident_id);`,
		);

		const upsertIncident = db.prepare(
			`INSERT INTO incidents (incident_id, opened_at_ms, last_seen_ms, severity, status, payload_json)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT(incident_id) DO UPDATE SET
			   opened_at_ms=excluded.opened_at_ms,
			   last_seen_ms=excluded.last_seen_ms,
			   severity=excluded.severity,
			   status=excluded.status,
			   payload_json=excluded.payload_json
			 WHERE excluded.last_seen_ms >= incidents.last_seen_ms;`,
		);

		const deleteEvents = db.prepare(`DELETE FROM incident_events WHERE incident_id=?;`);
		const insertEvent = db.prepare(
			`INSERT OR REPLACE INTO incident_events
			 (incident_id, signal_id, timestamp_ms, signal_type, severity, summary)
			 VALUES (?, ?, ?, ?, ?, ?);`,
		);

		for (const incident of incidents) {
			upsertIncident.run(
				incident.incident_id,
				incident.opened_at_ms,
				incident.last_seen_ms,
				incident.severity,
				incident.status,
				JSON.stringify(incident),
			);

			deleteEvents.run(incident.incident_id);
			for (const ev of incident.events) {
				insertEvent.run(
					incident.incident_id,
					ev.signal_id,
					ev.timestamp_ms,
					ev.signal_type,
					ev.severity,
					ev.summary,
				);
			}
		}
	} finally {
		db.close();
	}
}

export interface PersistIncidentRecordsOptions {
	/**
	 * A small window of recent log entries used for JSONL de-duplication.
	 * It is safe to pass the same `recent` array used for correlation input.
	 */
	recent_entries?: unknown[];
	/**
	 * SQLite path. Only used when store === "sqlite".
	 * Defaults to ~/.singularity-aidr/incidents.db
	 */
	sqlite_path?: string;
}

/**
 * Persist correlated incident records for consumption by dashboards and forensics.
 * - jsonl: appends `incident_record` objects into the audit JSONL (best-effort, de-duped by incident_id+last_seen_ms)
 * - sqlite: upserts incident snapshots into a local SQLite DB (best-effort, optional runtime backend)
 */
export async function persistIncidentRecords(
	params: {
		store: "jsonl" | "sqlite";
		logging: LoggingConfig;
	},
	incidents: Incident[],
	options: PersistIncidentRecordsOptions = {},
): Promise<void> {
	if (incidents.length === 0) return;

	if (params.store === "sqlite") {
		try {
			const sqlitePath = resolvePath(options.sqlite_path ?? "~/.singularity-aidr/incidents.db");
			await upsertIncidentsToSqlite(sqlitePath, incidents);
			return;
		} catch {
			// If SQLite backend isn't available (or fails), fallback to JSONL.
		}
	}

	const recent = options.recent_entries ?? [];
	const index = computeLastSeenIndex(recent);

	for (const incident of incidents) {
		const prevLastSeen = index.get(incident.incident_id) ?? -1;
		if (incident.last_seen_ms <= prevLastSeen) continue;
		const record = toIncidentRecordV1(incident) as unknown as Record<string, unknown>;
		await logIncident(params.logging, record);
		index.set(incident.incident_id, incident.last_seen_ms);
	}
}
