import { createHash, createPrivateKey, generateKeyPairSync, sign } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";
import {
	correlateIncidents,
	persistIncidentRecords,
	verifyIncidentSqliteStore,
	verifySignedIncidentAnchorReceipt,
	writeSignedIncidentAnchorReceipt,
} from "../incidents/index.js";
import { makeTmpDir } from "./test-utils.js";

async function fixture(extraSessions: string[] = []) {
	try {
		await import("node:sqlite");
	} catch {
		return null;
	}
	const dir = await makeTmpDir();
	const dbPath = join(dir, "incidents.db");
	const receiptPath = join(dir, "incident-anchor.json");
	const privateKeyPath = join(dir, "incident-anchor-private.pem");
	const publicKeyPath = join(dir, "incident-anchor-public.pem");
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	await writeFile(privateKeyPath, privateKey.export({ type: "pkcs8", format: "pem" }), {
		mode: 0o600,
	});
	await writeFile(publicKeyPath, publicKey.export({ type: "spki", format: "pem" }));
	const incidents = correlateIncidents([
		{
			signal_id: "evidence-signal",
			signal_type: "runtime_verdict",
			timestamp_ms: 1_700_000_000_000,
			session_id: "evidence-session",
			decision: "deny",
			severity: "high",
		},
		...extraSessions.map((session_id, index) => ({
			signal_id: `evidence-signal-${index}`,
			signal_type: "runtime_verdict" as const,
			timestamp_ms: 1_700_000_000_000,
			session_id,
			decision: "deny" as const,
			severity: "high" as const,
		})),
	]);
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
	return { dbPath, receiptPath, privateKeyPath, publicKeyPath };
}

describe("incident anchor receipts", () => {
	it("orders signed chain heads by stable code units across locales", async () => {
		const paths = await fixture(["A", "a"]);
		if (!paths) return;
		const local = await verifyIncidentSqliteStore(paths.dbPath);
		expect(local).toMatchObject({ valid: true, checked_incidents: 3 });
		const expectedHeads = [...local.heads].sort((a, b) =>
			a.incident_id < b.incident_id ? -1 : a.incident_id > b.incident_id ? 1 : 0,
		);
		const expectedDigest = createHash("sha256").update("aidr.incident.heads.v1\0");
		for (const head of expectedHeads)
			expectedDigest
				.update(JSON.stringify([head.incident_id, head.revision_number, head.record_hash]))
				.update("\n");
		const receipt = await writeSignedIncidentAnchorReceipt({
			sqlite_path: paths.dbPath,
			receipt_path: paths.receiptPath,
			private_key_path: paths.privateKeyPath,
			scope: "tenant-a/pilot-v6",
		});
		const payload = JSON.parse(Buffer.from(receipt.payload_base64, "base64").toString("utf8"));
		expect(payload.head_order).toBe("utf16");
		expect(payload.heads_sha256).toBe(expectedDigest.digest("hex"));

		// Receipts issued before the ordering marker remain verifiable on the
		// original host, even when their locale digest differs from UTF-16 order.
		const legacyDigest = createHash("sha256").update("aidr.incident.heads.v1\0");
		for (const head of [...local.heads].sort((a, b) => a.incident_id.localeCompare(b.incident_id)))
			legacyDigest
				.update(JSON.stringify([head.incident_id, head.revision_number, head.record_hash]))
				.update("\n");
		delete payload.head_order;
		payload.heads_sha256 = legacyDigest.digest("hex");
		const legacyPayloadBytes = Buffer.from(JSON.stringify(payload), "utf8");
		const privateKey = createPrivateKey(await readFile(paths.privateKeyPath));
		await writeFile(
			paths.receiptPath,
			JSON.stringify({
				...receipt,
				payload_base64: legacyPayloadBytes.toString("base64"),
				signature_base64: sign(null, legacyPayloadBytes, privateKey).toString("base64"),
			}),
		);
		expect(
			await verifySignedIncidentAnchorReceipt({
				sqlite_path: paths.dbPath,
				receipt_path: paths.receiptPath,
				public_key_path: paths.publicKeyPath,
				expected_scope: "tenant-a/pilot-v6",
			}),
		).toMatchObject({ valid: true, code: "valid", checked_incidents: 3 });
	});

	it("writes an exclusive Ed25519 receipt and verifies it with a separate public key", async () => {
		const paths = await fixture();
		if (!paths) return;
		const scope = "tenant-a/pilot-v6";
		const receipt = await writeSignedIncidentAnchorReceipt({
			sqlite_path: paths.dbPath,
			receipt_path: paths.receiptPath,
			private_key_path: paths.privateKeyPath,
			scope,
		});
		expect(receipt.algorithm).toBe("Ed25519");
		expect(
			await verifySignedIncidentAnchorReceipt({
				sqlite_path: paths.dbPath,
				receipt_path: paths.receiptPath,
				public_key_path: paths.publicKeyPath,
				expected_scope: scope,
			}),
		).toMatchObject({ valid: true, code: "valid", checked_incidents: 1 });
		await expect(
			writeSignedIncidentAnchorReceipt({
				sqlite_path: paths.dbPath,
				receipt_path: paths.receiptPath,
				private_key_path: paths.privateKeyPath,
				scope,
			}),
		).rejects.toThrow();
		expect(
			await verifySignedIncidentAnchorReceipt({
				sqlite_path: paths.dbPath,
				receipt_path: paths.receiptPath,
				public_key_path: paths.publicKeyPath,
				expected_scope: "tenant-b/pilot-v6",
			}),
		).toMatchObject({ valid: false, code: "scope_mismatch" });

		const changed = JSON.parse(await readFile(paths.receiptPath, "utf8")) as typeof receipt;
		changed.signature_base64 = Buffer.alloc(64).toString("base64");
		await writeFile(paths.receiptPath, JSON.stringify(changed));
		expect(
			await verifySignedIncidentAnchorReceipt({
				sqlite_path: paths.dbPath,
				receipt_path: paths.receiptPath,
				public_key_path: paths.publicKeyPath,
				expected_scope: scope,
			}),
		).toMatchObject({ valid: false, code: "signature_invalid" });
	});

	it("detects a DB rewrite even when the attacker recomputes its local SHA-256 chain", async () => {
		const paths = await fixture();
		if (!paths) return;
		const scope = "tenant-a/pilot-v6";
		await writeSignedIncidentAnchorReceipt({
			sqlite_path: paths.dbPath,
			receipt_path: paths.receiptPath,
			private_key_path: paths.privateKeyPath,
			scope,
		});
		const sqlite = await import("node:sqlite");
		const db = new sqlite.DatabaseSync(paths.dbPath);
		try {
			const row = db
				.prepare(
					`SELECT i.incident_id, i.payload_json, r.revision_number, r.previous_hash
					 FROM incidents i JOIN incident_revisions r USING (incident_id)`,
				)
				.get() as {
				incident_id: string;
				payload_json: string;
				revision_number: number;
				previous_hash: string;
			};
			const payload = JSON.parse(row.payload_json) as { severity: string };
			payload.severity = "critical";
			const changedPayload = JSON.stringify(payload);
			const newHash = createHash("sha256")
				.update(
					`aidr.incident.revision.v1\0${row.incident_id}\0${row.revision_number}\0${row.previous_hash}\0`,
				)
				.update(changedPayload)
				.digest("hex");
			db.exec("BEGIN IMMEDIATE;");
			db.prepare(
				"UPDATE incidents SET severity='critical', payload_json=? WHERE incident_id=?",
			).run(changedPayload, row.incident_id);
			db.prepare(
				"UPDATE incident_revisions SET payload_json=?, record_hash=? WHERE incident_id=? AND revision_number=?",
			).run(changedPayload, newHash, row.incident_id, row.revision_number);
			db.exec("COMMIT;");
		} finally {
			db.close();
		}
		expect((await verifyIncidentSqliteStore(paths.dbPath)).valid).toBe(true);
		expect(
			await verifySignedIncidentAnchorReceipt({
				sqlite_path: paths.dbPath,
				receipt_path: paths.receiptPath,
				public_key_path: paths.publicKeyPath,
				expected_scope: scope,
			}),
		).toMatchObject({ valid: false, code: "anchor_state_mismatch" });
	});
});
