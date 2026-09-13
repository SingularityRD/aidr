/**
 * AIDR-030 end-to-end demonstration: a destructive-but-ALLOWED operation is
 * snapshotted, actually rolled back, and recorded in the tamper-evident chain.
 *
 * This drives the REAL `guardToolCall` against the connector's shipped threat
 * bundle — no mocks, no stubbed verdicts. It is a demonstration script rather
 * than a test: run it with `npx tsx scripts/demo-response-rollback.mts`.
 *
 * Stages:
 *   0. everything OFF (shipped default)  -> nothing is copied, nothing is recorded
 *   1. rollback snapshot ON              -> the target is preserved before the delete
 *   2. the destructive operation runs    -> the file is genuinely gone
 *   3. rollback                          -> byte-identical restore from the snapshot
 *   4. the signed chain                  -> signed, hash-chained, independently verified
 */

import { existsSync, realpathSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ApprovalStore } from "../src/approval-store.js";
import { extractFromDelete } from "../src/extractors.js";
import { guardToolCall, rollbackSnapshotFromGuardResult } from "../src/guard.js";
import { ResponseAuditor } from "../src/response-audit.js";

const PRIOR_CONTENT = "the only copy of the deployment manifest\n";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..", "..", "..");
const threatsDir = join(repoRoot, "packages", "claude-code", "resources", "threats");
const allowlistsDir = join(repoRoot, "packages", "claude-code", "resources", "allowlists");

function rule(title: string) {
	console.log(`\n${"─".repeat(78)}\n${title}\n${"─".repeat(78)}`);
}

async function main() {
	const home = realpathSync.native(await mkdtemp(join(tmpdir(), "aidr-demo-")));
	process.env.HOME = home;
	process.env.USERPROFILE = home;

	const stateDir = join(home, ".singularity-aidr");
	const configPath = join(home, "config.json");
	const protectDir = join(home, "srv", "app");
	const target = join(protectDir, "manifest.yaml");
	const chainPath = join(stateDir, "response-audit.jsonl");
	const auditPath = join(stateDir, "audit.jsonl");

	await mkdir(protectDir, { recursive: true });
	await writeFile(target, PRIOR_CONTENT, "utf8");
	console.log(`HOME (sandboxed)     : ${home}`);
	console.log(`protected directory  : ${protectDir}`);
	console.log(`target file          : ${target}`);
	console.log(`target contents      : ${JSON.stringify(PRIOR_CONTENT)}`);

	// ── Stage 0: shipped defaults ────────────────────────────────────
	rule("STAGE 0 — OFF BY DEFAULT (this is what a fresh install does)");
	await writeFile(
		configPath,
		JSON.stringify({
			mode: "local",
			url_check: { enabled: false },
			file_check: { enabled: false },
			package_check: { enabled: false },
			cache: { enabled: false },
			control_plane: { enabled: false },
		}),
		"utf8",
	);

	const defaultCall = { file_path: target };
	const offResult = await guardToolCall(
		{
			sessionId: "demo",
			toolName: "Delete",
			toolInput: defaultCall,
			artifacts: extractFromDelete(defaultCall),
		},
		{ configPath, threatsDir, allowlistsDir },
		new ApprovalStore(),
	);
	console.log(`verdict                                  : ${offResult.verdict.decision}`);
	console.log(`response actions                         : ${JSON.stringify(offResult.responseActions)}`);
	console.log(`snapshot                                 : ${String(offResult.snapshot)}`);
	console.log(`signed chain entry                       : ${JSON.stringify(offResult.signedChain)}`);
	console.log(`snapshot root created                    : ${existsSync(join(stateDir, "snapshots"))}`);
	console.log(`signed chain file created                : ${existsSync(chainPath)}`);

	// ── Stage 1: the feature, explicitly enabled ─────────────────────
	rule("STAGE 1 — ENABLED: snapshot_before_destructive + protect_paths + signed chain");
	await writeFile(
		configPath,
		JSON.stringify({
			mode: "local",
			response: {
				actions: {
					snapshot_before_destructive: true,
					protect_paths: [protectDir],
					snapshot_max_bytes: 1024 * 1024,
				},
				audit: { signed_chain: true },
			},
			url_check: { enabled: false },
			file_check: { enabled: false },
			package_check: { enabled: false },
			cache: { enabled: false },
			control_plane: { enabled: false },
		}),
		"utf8",
	);

	const onResult = await guardToolCall(
		{
			sessionId: "demo",
			toolName: "Delete",
			toolInput: defaultCall,
			artifacts: extractFromDelete(defaultCall),
		},
		{ configPath, threatsDir, allowlistsDir },
		new ApprovalStore(),
	);
	console.log(`verdict                                  : ${onResult.verdict.decision}`);
	console.log(`response actions                         : ${JSON.stringify(onResult.responseActions, null, 2)}`);
	console.log(`snapshot id                              : ${onResult.snapshot?.id}`);
	console.log(`signed chain write                       : ${JSON.stringify(onResult.signedChain)}`);

	const preserved = await readFile(target, "utf8");
	console.log(`target still byte-identical after guard  : ${preserved === PRIOR_CONTENT}`);

	// ── Stage 2: the allowed destructive operation actually runs ─────
	rule("STAGE 2 — the operation the guard ALLOWED now runs (a real delete)");
	await rm(target);
	console.log(`target exists after the delete           : ${existsSync(target)}`);

	// ── Stage 3: a genuine rollback ──────────────────────────────────
	rule("STAGE 3 — rollback restores the target from the pre-operation snapshot");
	const rolledBack = await rollbackSnapshotFromGuardResult(onResult, {
		toolName: "Delete",
		toolInput: defaultCall,
		sessionId: "demo",
		configPath,
	});
	console.log(`rollback record                          : ${JSON.stringify(rolledBack, null, 2)}`);
	const restored = await readFile(target, "utf8");
	console.log(`restored contents                        : ${JSON.stringify(restored)}`);
	console.log(`RESTORED BYTE-IDENTICAL                  : ${restored === PRIOR_CONTENT}`);

	// ── Stage 4: the signed chain ────────────────────────────────────
	rule("STAGE 4 — response records on the tamper-evident signed chain");
	const chain = (await readFile(chainPath, "utf8"))
		.trim()
		.split("\n")
		.filter(Boolean)
		.map((line) => JSON.parse(line) as Record<string, unknown>);

	for (const [index, record] of chain.entries()) {
		console.log(`\nrecord ${index + 1}:`);
		console.log(`  action          : ${record.action}`);
		console.log(`  response_taken  : ${record.response_taken}`);
		console.log(`  tool            : ${record.tool}`);
		console.log(`  outcome         : ${record.outcome}`);
		console.log(`  metadata        : ${JSON.stringify(record.metadata)}`);
		console.log(`  _prev_hash      : ${record._prev_hash}`);
		console.log(`  _entry_hash     : ${record._entry_hash}`);
		console.log(`  _signature      : ${String(record._signature).slice(0, 48)}…`);
	}
	console.log(`\nchain links correctly (record2.prev == record1.hash): ${
		chain.length === 2 && chain[1]?._prev_hash === chain[0]?._entry_hash
	}`);

	const verifier = new ResponseAuditor(chainPath, { signEntries: true });
	console.log(`independent verifyIntegrity()            : ${JSON.stringify(await verifier.verifyIntegrity())}`);

	// Tamper check: flip a signed field and re-verify.
	const tampered = { ...chain[0], outcome: "failure" };
	await writeFile(chainPath, `${JSON.stringify(tampered)}\n${JSON.stringify(chain[1])}\n`, "utf8");
	const afterTamper = await verifier.verifyIntegrity();
	console.log(`after tampering record 1                 : ${JSON.stringify(afterTamper)}`);

	// ── Plain audit log (paths and outcomes only) ────────────────────
	rule("PLAIN AUDIT LOG — paths and outcomes, never contents");
	const plain = await readFile(auditPath, "utf8");
	const entries = plain
		.trim()
		.split("\n")
		.filter(Boolean)
		.map((line) => JSON.parse(line) as Record<string, unknown>)
		.filter((entry) => String(entry.type).startsWith("response_action"));
	console.log(JSON.stringify(entries, null, 2));
	console.log(`\nplain log leaks file contents            : ${plain.includes("only copy of the deployment")}`);

	await rm(home, { recursive: true, force: true });
}

main().catch((error) => {
	console.error("demo failed:", error);
	process.exitCode = 1;
});
