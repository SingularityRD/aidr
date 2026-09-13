import { stat } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";
import {
	correlateIncidents,
	persistIncidentRecords,
	verifyIncidentSqliteStore,
} from "../incidents/index.js";
import { makeTmpDir } from "./test-utils.js";

describe("incidents sqlite store (optional)", () => {
	it("writes incident snapshots to a sqlite db when node:sqlite is available", async () => {
		let sqliteAvailable = true;
		try {
			await import("node:sqlite");
		} catch {
			sqliteAvailable = false;
		}
		if (!sqliteAvailable) return;

		const base = Date.now();
		const incidents = correlateIncidents([
			{
				signal_id: `sig_runtime_verdict_${base}_a`,
				signal_type: "runtime_verdict",
				timestamp_ms: base,
				session_id: "s1",
				decision: "deny",
				severity: "critical",
				artifact: "https://evil.example",
				domain: "evil.example",
			},
		]);
		expect(incidents.length).toBe(1);

		const dir = await makeTmpDir();
		const dbPath = join(dir, "incidents.db");

		await persistIncidentRecords(
			{
				store: "sqlite",
				logging: {
					enabled: false,
					log_clean: false,
					path: join(dir, "audit.jsonl"),
					max_bytes: 0,
					max_files: 0,
				},
			},
			incidents,
			{ sqlite_path: dbPath },
		);

		const s = await stat(dbPath);
		expect(s.size).toBeGreaterThan(0);
		const verification = await verifyIncidentSqliteStore(dbPath);
		expect(verification.valid).toBe(true);
		expect(verification.checked_incidents).toBe(1);
		expect(verification.checked_revisions).toBe(1);
	});

	it("keeps snapshots and event indexes atomic across stale replays, and detects local edits", async () => {
		let sqlite: typeof import("node:sqlite");
		try {
			sqlite = await import("node:sqlite");
		} catch {
			return;
		}
		const base = 1_700_000_000_000;
		const signal = (id: string, offset: number) => ({
			signal_id: id,
			signal_type: "runtime_verdict" as const,
			timestamp_ms: base + offset,
			session_id: "evidence-session",
			decision: "deny" as const,
			severity: "high" as const,
		});
		const first = correlateIncidents([signal("first", 0)]);
		const updated = correlateIncidents([signal("first", 0), signal("second", 1_000)]);
		const dir = await makeTmpDir();
		const dbPath = join(dir, "incidents.db");
		const params = {
			store: "sqlite" as const,
			logging: {
				enabled: false,
				log_clean: false,
				path: join(dir, "audit.jsonl"),
				max_bytes: 0,
				max_files: 0,
			},
		};
		await persistIncidentRecords(params, first, { sqlite_path: dbPath });
		await persistIncidentRecords(params, updated, { sqlite_path: dbPath });
		await persistIncidentRecords(params, first, { sqlite_path: dbPath });
		await persistIncidentRecords(params, updated, { sqlite_path: dbPath });
		const verified = await verifyIncidentSqliteStore(dbPath);
		expect(verified.valid).toBe(true);
		expect(verified.checked_revisions).toBe(2);
		expect(verified.heads).toHaveLength(1);

		const db = new sqlite.DatabaseSync(dbPath);
		try {
			const events = db.prepare("SELECT signal_id FROM incident_events ORDER BY signal_id").all();
			expect(events.map((event) => event.signal_id)).toEqual(["first", "second"]);
			db.prepare("UPDATE incident_events SET summary='modified' WHERE signal_id='first'").run();
		} finally {
			db.close();
		}
		const altered = await verifyIncidentSqliteStore(dbPath);
		expect(altered.valid).toBe(false);
		expect(altered.findings.some((finding) => finding.code === "event_index_mismatch")).toBe(true);

		const chainDb = new sqlite.DatabaseSync(dbPath);
		try {
			chainDb
				.prepare("UPDATE incident_revisions SET payload_json='{}' WHERE revision_number=1")
				.run();
		} finally {
			chainDb.close();
		}
		const brokenChain = await verifyIncidentSqliteStore(dbPath);
		expect(brokenChain.findings.some((finding) => finding.code === "revision_hash_mismatch")).toBe(
			true,
		);
	});
});
