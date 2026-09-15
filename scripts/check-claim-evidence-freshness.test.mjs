import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { checkClaimEvidenceFreshness, listClaimEvidenceFiles, main, sha256File } from "./check-claim-evidence-freshness.mjs";
import { CANDIDATE_DIGEST_SOURCE } from "./generate-v8-evidence-index.mjs";

const registrySha256 = sha256File("docs/production-readiness/commercial-go-evidence-registry.json");
const sourceCommit = "a".repeat(40);
const candidate = { digest: "b".repeat(64), source: CANDIDATE_DIGEST_SOURCE };

function freshnessOptions(evidenceDir) {
	return { root: process.cwd(), evidenceDir, source_commit: sourceCommit, candidate };
}

async function evidenceDirFor(t, records) {
	const evidenceDir = await mkdtemp(join(tmpdir(), "aidr-claim-freshness-"));
	t.after(() => rm(evidenceDir, { recursive: true, force: true }));
	for (const [name, content] of Object.entries(records)) {
		const fullPath = join(evidenceDir, name);
		await mkdir(dirname(fullPath), { recursive: true });
		await writeFile(fullPath, content);
	}
	return evidenceDir;
}

test("a checkout with no recorded claim scan has nothing stale to gate", async (t) => {
	const evidenceDir = await evidenceDirFor(t, {});
	const result = checkClaimEvidenceFreshness({ root: process.cwd(), evidenceDir });
	assert.deepEqual(result.failures, []);
	assert.deepEqual(result.checked, []);
	assert.equal(main(["--evidence-dir", evidenceDir]), 0);
});

test("a recorded claim scan bound to the current registry, source and candidate passes", async (t) => {
	const evidenceDir = await evidenceDirFor(t, {
		"v9-claim-gate-final.json": JSON.stringify({
			mode: "gate",
			registrySha256,
			source_commit: sourceCommit,
			candidate_digest: candidate.digest,
			candidate_digest_source: candidate.source,
		}),
		"v9-claim-inventory-final.json": JSON.stringify({
			mode: "inventory",
			registrySha256: registrySha256.toUpperCase(),
			source_commit: sourceCommit.toUpperCase(),
			candidate_digest: candidate.digest.toUpperCase(),
			candidate_digest_source: candidate.source,
		}),
	});
	const result = checkClaimEvidenceFreshness(freshnessOptions(evidenceDir));
	assert.deepEqual(result.failures, []);
	assert.deepEqual(listClaimEvidenceFiles(evidenceDir), ["v9-claim-gate-final.json", "v9-claim-inventory-final.json"]);
});

test("a claim scan from another source commit or candidate cannot pass freshness", async (t) => {
	const evidenceDir = await evidenceDirFor(t, {
		"v9-claim-stale.json": JSON.stringify({
			mode: "gate",
			registrySha256,
			source_commit: "c".repeat(40),
			candidate_digest: "d".repeat(64),
			candidate_digest_source: candidate.source,
		}),
	});
	const result = checkClaimEvidenceFreshness(freshnessOptions(evidenceDir));
	assert.match(result.failures.join("\n"), /recorded source_commit .*does not match/);
	assert.match(result.failures.join("\n"), /recorded candidate_digest .*does not match/);
});

test("a recorded claim scan without a usable digest cannot prove freshness", async (t) => {
	const evidenceDir = await evidenceDirFor(t, {
		"v9-claim-inventory.json": JSON.stringify({ mode: "inventory" }),
		"v9-claim-gate.json": "{ not json",
	});
	const failures = checkClaimEvidenceFreshness({ root: process.cwd(), evidenceDir }).failures.join("\n");
	assert.match(failures, /v9-claim-inventory\.json: recorded claim scan has no valid registrySha256 digest/);
	assert.match(failures, /v9-claim-gate\.json: cannot parse the recorded claim scan/);
	assert.equal(main(["--evidence-dir", evidenceDir]), 1);
});

test("only top-level claim scan records are gated", async (t) => {
	const evidenceDir = await evidenceDirFor(t, {
		"dependency-audit.json": JSON.stringify({ registrySha256: "0".repeat(64) }),
		"v8-logs/17-claim-inventory.json": JSON.stringify({ mode: "inventory", registrySha256: "0".repeat(64) }),
	});
	assert.deepEqual(listClaimEvidenceFiles(evidenceDir), []);
	assert.deepEqual(checkClaimEvidenceFreshness({ root: process.cwd(), evidenceDir }).failures, []);
});

test("an unknown command-line argument fails closed", () => {
	assert.equal(main(["--evidence-dir"]), 2);
	assert.equal(main(["--unknown"]), 2);
	assert.equal(main(["--help"]), 0);
});
