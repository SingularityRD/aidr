import { stat } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";
import { correlateIncidents, persistIncidentRecords } from "../incidents/index.js";
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
	});
});
