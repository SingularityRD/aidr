import { createHash } from "node:crypto";
import { stat } from "node:fs/promises";

import { logIncident } from "../audit-log.js";
import { resolvePath } from "../config.js";
import {
	produceConfiguredSiemIncident,
	reportSiemProducerFailure,
} from "../siem-incident-producer.js";
import type { LoggingConfig } from "../types.js";
import { toIncidentRecordV1 } from "./records.js";
import type { Incident } from "./types.js";

const GENESIS_HASH = "0".repeat(64);

type SqliteStatement = {
	run: (...args: unknown[]) => { changes: number };
	get: (...args: unknown[]) => unknown;
	all: (...args: unknown[]) => unknown[];
};
type SqliteDatabase = {
	exec: (sql: string) => void;
	prepare: (sql: string) => SqliteStatement;
	close: () => void;
};

async function openSqlite(path: string, readOnly = false): Promise<SqliteDatabase> {
	const sqlite = (await import("node:sqlite")) as unknown as {
		DatabaseSync: new (path: string, options?: { readOnly?: boolean }) => SqliteDatabase;
	};
	return new sqlite.DatabaseSync(path, { readOnly });
}

function revisionHash(
	incidentId: string,
	revisionNumber: number,
	previousHash: string,
	payloadJson: string,
): string {
	return createHash("sha256")
		.update(`aidr.incident.revision.v1\0${incidentId}\0${revisionNumber}\0${previousHash}\0`)
		.update(payloadJson)
		.digest("hex");
}

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
	const db = await openSqlite(dbPath);
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
		// Revisions are append-only at the application layer. Hashes detect local
		// corruption and unsynchronized snapshot/event edits; they are not a remote
		// attestation because the database and digest are on the same host.
		db.exec(
			`CREATE TABLE IF NOT EXISTS incident_revisions (
				incident_id TEXT NOT NULL,
				revision_number INTEGER NOT NULL,
				previous_hash TEXT NOT NULL,
				record_hash TEXT NOT NULL,
				payload_json TEXT NOT NULL,
				PRIMARY KEY (incident_id, revision_number)
			);`,
		);

		const selectCurrent = db.prepare(
			`SELECT last_seen_ms, payload_json FROM incidents WHERE incident_id=?;`,
		);
		const selectLatestRevision = db.prepare(
			`SELECT revision_number, previous_hash, record_hash, payload_json FROM incident_revisions
			 WHERE incident_id=? ORDER BY revision_number DESC LIMIT 1;`,
		);
		const insertRevision = db.prepare(
			`INSERT INTO incident_revisions
			 (incident_id, revision_number, previous_hash, record_hash, payload_json)
			 VALUES (?, ?, ?, ?, ?);`,
		);
		const upsertIncident = db.prepare(
			`INSERT INTO incidents (incident_id, opened_at_ms, last_seen_ms, severity, status, payload_json)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT(incident_id) DO UPDATE SET
			   opened_at_ms=excluded.opened_at_ms,
			   last_seen_ms=excluded.last_seen_ms,
			   severity=excluded.severity,
			   status=excluded.status,
			   payload_json=excluded.payload_json;`,
		);

		const deleteEvents = db.prepare(`DELETE FROM incident_events WHERE incident_id=?;`);
		const insertEvent = db.prepare(
			`INSERT OR REPLACE INTO incident_events
			 (incident_id, signal_id, timestamp_ms, signal_type, severity, summary)
			 VALUES (?, ?, ?, ?, ?, ?);`,
		);

		db.exec("BEGIN IMMEDIATE;");
		try {
			for (const incident of incidents) {
				const payloadJson = JSON.stringify(incident);
				const current = selectCurrent.get(incident.incident_id) as
					| { last_seen_ms: number; payload_json: string }
					| undefined;
				const latest = selectLatestRevision.get(incident.incident_id) as
					| {
							revision_number: number;
							previous_hash: string;
							record_hash: string;
							payload_json: string;
					  }
					| undefined;
				if (
					latest &&
					(current?.payload_json !== latest.payload_json ||
						latest.record_hash !==
							revisionHash(
								incident.incident_id,
								latest.revision_number,
								latest.previous_hash,
								latest.payload_json,
							))
				)
					throw new Error(`Incident evidence integrity mismatch: ${incident.incident_id}`);
				// A stale replay must not erase the newer event index. Identical
				// snapshots are idempotent and do not grow the revision chain.
				if (
					current &&
					(current.last_seen_ms > incident.last_seen_ms ||
						(latest && current.payload_json === payloadJson))
				)
					continue;

				const revisionNumber = (latest?.revision_number ?? 0) + 1;
				const previousHash = latest?.record_hash ?? GENESIS_HASH;
				insertRevision.run(
					incident.incident_id,
					revisionNumber,
					previousHash,
					revisionHash(incident.incident_id, revisionNumber, previousHash, payloadJson),
					payloadJson,
				);
				upsertIncident.run(
					incident.incident_id,
					incident.opened_at_ms,
					incident.last_seen_ms,
					incident.severity,
					incident.status,
					payloadJson,
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
			db.exec("COMMIT;");
		} catch (error) {
			db.exec("ROLLBACK;");
			throw error;
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

async function persistToJsonl(
	logging: LoggingConfig,
	incidents: Incident[],
	recentEntries: unknown[],
): Promise<void> {
	const index = computeLastSeenIndex(recentEntries);
	for (const incident of incidents) {
		const prevLastSeen = index.get(incident.incident_id) ?? -1;
		if (incident.last_seen_ms <= prevLastSeen) continue;
		const record = toIncidentRecordV1(incident) as unknown as Record<string, unknown>;
		await logIncident(logging, record);
		index.set(incident.incident_id, incident.last_seen_ms);
	}
}

async function deliverToSiem(incidents: Incident[]): Promise<void> {
	for (const incident of incidents) {
		try {
			const result = await produceConfiguredSiemIncident(incident);
			if (result.status === "degraded")
				reportSiemProducerFailure(result.lastErrorCode ?? "sink_unavailable");
		} catch (error) {
			const code =
				error instanceof Error && "code" in error && typeof error.code === "string"
					? error.code
					: "producer_unavailable";
			reportSiemProducerFailure(code);
		}
	}
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

	let persistedToSqlite = false;
	if (params.store === "sqlite") {
		try {
			const sqlitePath = resolvePath(options.sqlite_path ?? "~/.singularity-aidr/incidents.db");
			await upsertIncidentsToSqlite(sqlitePath, incidents);
			persistedToSqlite = true;
		} catch {
			// If SQLite backend isn't available (or fails), fallback to JSONL.
		}
	}

	if (!persistedToSqlite)
		await persistToJsonl(params.logging, incidents, options.recent_entries ?? []);

	// Both local backends feed the explicit SIEM sink. A delivery failure is
	// visible in diagnostics but never changes the tool verdict or local log.
	await deliverToSiem(incidents);
}

export interface IncidentStoreVerification {
	valid: boolean;
	checked_incidents: number;
	checked_revisions: number;
	/** Local consistency only: the chain head needs independent anchoring for forensic provenance. */
	heads: Array<{ incident_id: string; revision_number: number; record_hash: string }>;
	findings: Array<{ incident_id: string; code: string }>;
}

/**
 * Check SQLite incident snapshots, indexed events and local revision chains.
 * This detects accidental corruption or edits that do not recompute the chain;
 * it cannot prove completeness or withstand an attacker who controls the DB.
 */
export async function verifyIncidentSqliteStore(
	dbPath: string,
): Promise<IncidentStoreVerification> {
	const result: IncidentStoreVerification = {
		valid: false,
		checked_incidents: 0,
		checked_revisions: 0,
		heads: [],
		findings: [],
	};
	let db: SqliteDatabase | undefined;
	try {
		await stat(dbPath);
		db = await openSqlite(dbPath, true);
		const incidentRows = db
			.prepare(
				"SELECT incident_id, opened_at_ms, last_seen_ms, severity, status, payload_json FROM incidents ORDER BY incident_id;",
			)
			.all() as Array<{
			incident_id: string;
			opened_at_ms: number;
			last_seen_ms: number;
			severity: string;
			status: string;
			payload_json: string;
		}>;
		const revisionRows = db
			.prepare(
				"SELECT incident_id, revision_number, previous_hash, record_hash, payload_json FROM incident_revisions ORDER BY incident_id, revision_number;",
			)
			.all() as Array<{
			incident_id: string;
			revision_number: number;
			previous_hash: string;
			record_hash: string;
			payload_json: string;
		}>;
		const eventRows = db
			.prepare(
				"SELECT incident_id, signal_id, timestamp_ms, signal_type, severity, summary FROM incident_events ORDER BY incident_id, signal_id;",
			)
			.all() as Array<{
			incident_id: string;
			signal_id: string;
			timestamp_ms: number;
			signal_type: string;
			severity: string;
			summary: string;
		}>;
		result.checked_incidents = incidentRows.length;
		result.checked_revisions = revisionRows.length;

		const incidentById = new Map(incidentRows.map((row) => [row.incident_id, row]));
		const latest = new Map<string, (typeof revisionRows)[number]>();
		for (const row of revisionRows) {
			const prior = latest.get(row.incident_id);
			if (row.revision_number !== (prior?.revision_number ?? 0) + 1)
				result.findings.push({ incident_id: row.incident_id, code: "revision_gap" });
			if (row.previous_hash !== (prior?.record_hash ?? GENESIS_HASH))
				result.findings.push({ incident_id: row.incident_id, code: "chain_link_mismatch" });
			if (
				row.record_hash !==
				revisionHash(row.incident_id, row.revision_number, row.previous_hash, row.payload_json)
			)
				result.findings.push({ incident_id: row.incident_id, code: "revision_hash_mismatch" });
			try {
				const payload = JSON.parse(row.payload_json) as { incident_id?: unknown };
				if (payload?.incident_id !== row.incident_id)
					result.findings.push({
						incident_id: row.incident_id,
						code: "revision_identity_mismatch",
					});
			} catch {
				result.findings.push({ incident_id: row.incident_id, code: "revision_payload_invalid" });
			}
			latest.set(row.incident_id, row);
		}
		for (const [incidentId, row] of latest) {
			result.heads.push({
				incident_id: incidentId,
				revision_number: row.revision_number,
				record_hash: row.record_hash,
			});
			if (!incidentById.has(incidentId))
				result.findings.push({ incident_id: incidentId, code: "snapshot_missing" });
		}

		const eventsByIncident = new Map<string, typeof eventRows>();
		for (const event of eventRows) {
			const events = eventsByIncident.get(event.incident_id) ?? [];
			events.push(event);
			eventsByIncident.set(event.incident_id, events);
			if (!incidentById.has(event.incident_id))
				result.findings.push({ incident_id: event.incident_id, code: "orphan_event" });
		}
		for (const row of incidentRows) {
			const head = latest.get(row.incident_id);
			if (!head) {
				result.findings.push({ incident_id: row.incident_id, code: "legacy_untracked_snapshot" });
				continue;
			}
			if (row.payload_json !== head.payload_json)
				result.findings.push({ incident_id: row.incident_id, code: "snapshot_hash_mismatch" });
			try {
				const incident = JSON.parse(row.payload_json) as Incident;
				if (
					incident.incident_id !== row.incident_id ||
					incident.opened_at_ms !== row.opened_at_ms ||
					incident.last_seen_ms !== row.last_seen_ms ||
					incident.severity !== row.severity ||
					incident.status !== row.status ||
					!Array.isArray(incident.events)
				) {
					result.findings.push({ incident_id: row.incident_id, code: "snapshot_index_mismatch" });
					continue;
				}
				const expected = new Map(incident.events.map((event) => [event.signal_id, event]));
				const actual = eventsByIncident.get(row.incident_id) ?? [];
				if (expected.size !== incident.events.length || actual.length !== expected.size) {
					result.findings.push({ incident_id: row.incident_id, code: "event_index_mismatch" });
					continue;
				}
				for (const event of actual) {
					const ref = expected.get(event.signal_id);
					if (
						!ref ||
						ref.timestamp_ms !== event.timestamp_ms ||
						ref.signal_type !== event.signal_type ||
						ref.severity !== event.severity ||
						ref.summary !== event.summary
					)
						result.findings.push({ incident_id: row.incident_id, code: "event_index_mismatch" });
				}
			} catch {
				result.findings.push({ incident_id: row.incident_id, code: "snapshot_payload_invalid" });
			}
		}
		result.valid = result.findings.length === 0;
	} catch {
		result.findings.push({ incident_id: "*", code: "store_unavailable" });
	} finally {
		db?.close();
	}
	return result;
}
