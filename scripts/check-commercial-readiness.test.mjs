import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { checkClaimEvidenceFreshness, sha256File } from "./check-claim-evidence-freshness.mjs";
import { CANDIDATE_DIGEST_SOURCE, gitCommitSha } from "./generate-v8-evidence-index.mjs";
import { validateClaimSurfaces, validateCommercialReadiness, validateConnectorScope, validateFirstReleaseScope } from "./check-commercial-readiness.mjs";

const [inventory, gaps, registry, releaseSource, supportMatrix, readme] = await Promise.all([
	readFile("FEATURE_INVENTORY.json", "utf8").then(JSON.parse),
	readFile("PRODUCTION_SALES_GAPS.json", "utf8").then(JSON.parse),
	readFile("docs/production-readiness/commercial-go-evidence-registry.json", "utf8").then(JSON.parse),
	readFile("scripts/release-artifact-manifests.mjs", "utf8"),
	readFile("deploy/native/support-matrix.json", "utf8").then(JSON.parse),
	readFile("README.md", "utf8"),
]);
const fixture = () => ({
	inventory: structuredClone(inventory),
	gaps: structuredClone(gaps),
	registry: structuredClone(registry),
	releaseSource,
	supportMatrix: structuredClone(supportMatrix),
	readme,
	now: new Date("2026-09-13T12:00:00Z"),
});

test("current commercial inventory matches the release scope", () => {
	assert.deepEqual(validateCommercialReadiness(fixture()), []);
});

test("omitting a release artifact fails the commercial check", () => {
	const input = fixture();
	input.registry.artifactRoots = input.registry.artifactRoots.filter((root) => root !== "packages/codex/dist");
	assert.match(validateCommercialReadiness(input).join("\n"), /missing release artifact root packages\/codex\/dist/);
});

test("adding a release target without registry coverage fails", () => {
	const input = fixture();
	input.releaseSource = input.releaseSource.replace(
		/const targets = \[/,
		'const targets = [\n\t{ pkg: "packages/new-connector/package.json", dir: "packages/new-connector/dist", artifactId: "new-connector/dist" },',
	);
	assert.match(validateCommercialReadiness(input).join("\n"), /missing release artifact root packages\/new-connector\/dist/);
});

test("feature and work-package counts cannot drift from their inventories", () => {
	const input = fixture();
	input.gaps.feature_status_counts.wired += 1;
	input.gaps.work_package_count -= 1;
	const failures = validateCommercialReadiness(input).join("\n");
	assert.match(failures, /gaps\.feature_status_counts\.wired/);
	assert.match(failures, /work package count differs/);
});

test("an expired Sales Approved claim is rejected", () => {
	const input = fixture();
	input.registry.releaseCandidate = "rc-test";
	Object.assign(input.registry.claims[0], {
		status: "closed",
		maturity: "approved",
		salesApproved: true,
		releaseCandidate: "rc-test",
		expiresAt: "2026-09-12",
	});
	assert.match(validateCommercialReadiness(input).join("\n"), /CLAIM-001: Sales Approved claim is expired/);
});

test("a recorded claim scan digest that differs from the current registry fails", async (t) => {
	const evidenceDir = await mkdtemp(join(tmpdir(), "aidr-claim-evidence-"));
	t.after(() => rm(evidenceDir, { recursive: true, force: true }));
	const registrySha256 = sha256File("docs/production-readiness/commercial-go-evidence-registry.json");
	const sourceCommit = gitCommitSha(process.cwd());
	const candidate = { digest: "a".repeat(64), source: CANDIDATE_DIGEST_SOURCE };
	const recordPath = join(evidenceDir, "v9-claim-gate-final.json");
	const currentBinding = {
		mode: "gate",
		source_commit: sourceCommit,
		candidate_digest: candidate.digest,
		candidate_digest_source: candidate.source,
	};
	await writeFile(recordPath, JSON.stringify({ ...currentBinding, registrySha256: "0".repeat(64) }));
	const stale = checkClaimEvidenceFreshness({ root: process.cwd(), evidenceDir, source_commit: sourceCommit, candidate });
	assert.equal(stale.failures.length, 1);
	assert.match(stale.failures.join("\n"), new RegExp(`v9-claim-gate-final\\.json: recorded registrySha256 0{64} does not match the current registry digest ${registrySha256}`));
	assert.equal(stale.registrySha256, registrySha256);
	await writeFile(recordPath, JSON.stringify({ ...currentBinding, registrySha256 }));
	assert.deepEqual(checkClaimEvidenceFreshness({ root: process.cwd(), evidenceDir, source_commit: sourceCommit, candidate }).failures, []);
});

test("implemented and direct-GA connector scopes stay distinct and consistent", () => {
	assert.deepEqual(validateConnectorScope(fixture()), []);
	const { supportMatrix: matrix, registry: claimRegistry } = fixture();
	const readmeScope = "... via hook systems in [Claude Code](a), [Cursor / VS Code](b), [OpenClaw](c), [OpenCode](d) and [Codex](e), and checks them against:";
	assert.match(
		validateConnectorScope({ supportMatrix: matrix, registry: claimRegistry, readme: readmeScope.replace("[Codex](e)", "") }).join("\n"),
		/README connector scope omits sold connector codex/,
	);
	assert.match(
		validateConnectorScope({ supportMatrix: matrix, registry: claimRegistry, readme: readmeScope.replace("[OpenCode](d)", "[Zed](d)") }).join("\n"),
		/README connector scope sentence names an unknown connector: Zed/,
	);
	assert.equal(matrix.soldConnectorScope.length, 6);
	assert.equal(claimRegistry.hardGates.find((gate) => gate.id === "COM-010").directGaConnectorScope.length, 6);
	const widenedClaim = fixture();
	widenedClaim.registry.claims.find((claim) => claim.id === "CLAIM-010").exactText = "All seven connectors are directly GA-supported.";
	assert.match(validateConnectorScope(widenedClaim).join("\n"), /CLAIM-010: declares 7 direct-GA connectors but COM-010 declares 6/);
	const unlistedDirectGa = fixture();
	unlistedDirectGa.registry.hardGates.find((gate) => gate.id === "COM-010").directGaConnectorScope.push("zed");
	assert.match(validateConnectorScope(unlistedDirectGa).join("\n"), /COM-010 direct-GA connector zed is absent from soldConnectorScope/);
	const narrowedMatrix = fixture();
	narrowedMatrix.supportMatrix.soldConnectorScope = narrowedMatrix.supportMatrix.soldConnectorScope.filter((connector) => connector !== "codex");
	assert.match(validateConnectorScope(narrowedMatrix).join("\n"), /README advertises connector codex outside the sold support matrix/);
});

test("COM-010 cannot close ahead of all six native connector acceptances", () => {
	const input = fixture();
	input.registry.hardGates.find((gate) => gate.id === "COM-010").status = "closed";
	const failures = validateConnectorScope(input).join("\n");
	assert.match(failures, /COM-010 cannot close while native support matrix is not GO/);
	// Cursor and VS Code have no real-host acceptance record at all.
	for (const connector of ["cursor", "vscode"]) {
		assert.match(failures, new RegExp(`COM-010 cannot close without native acceptance evidence for ${connector}`));
	}
	// Without any named evidence every direct-GA connector is reported.
	for (const row of input.supportMatrix.rows) row.acceptanceEvidence = [];
	const withoutEvidence = validateConnectorScope(input).join("\n");
	for (const connector of ["claude-code", "cursor", "vscode", "openclaw", "opencode", "codex"]) {
		assert.match(withoutEvidence, new RegExp(`COM-010 cannot close without native acceptance evidence for ${connector}`));
	}
	input.supportMatrix.rows = null;
	assert.match(validateConnectorScope(input).join("\n"), /native support matrix must declare connector rows/);
});

test("every claim surface is either scan-covered or absent", () => {
	assert.deepEqual(validateClaimSurfaces({ registry: fixture().registry }), []);
	const missingSales = fixture();
	missingSales.registry.scanRoots = missingSales.registry.scanRoots.filter((root) => root !== "docs/sales");
	assert.match(validateClaimSurfaces(missingSales).join("\n"), /claim registry must scan docs\/sales/);
	const missingPublicPages = fixture();
	missingPublicPages.registry.scanRoots = missingPublicPages.registry.scanRoots.filter((root) => root !== "packages/dashboard/src/ui/pages/public");
	assert.match(validateClaimSurfaces(missingPublicPages).join("\n"), /claim registry must scan dashboard public page sources/);
	const unscanned = fixture();
	unscanned.registry.scanRoots = unscanned.registry.scanRoots.filter((root) => root !== "docs/configuration.md");
	assert.match(validateClaimSurfaces(unscanned).join("\n"), /CLAIM-008: declared surface docs\/configuration\.md exists but no scan root covers it/);
	const absent = fixture();
	absent.registry.claims.find((claim) => claim.id === "CLAIM-007").surfaces = ["sales/investor materials"];
	assert.match(validateClaimSurfaces(absent).join("\n"), /CLAIM-007: declared surface sales\/investor materials is not present in the repository/);
	const phantomRoot = fixture();
	phantomRoot.registry.scanRoots = [...phantomRoot.registry.scanRoots, "sales"];
	assert.match(validateClaimSurfaces(phantomRoot).join("\n"), /scan root sales does not exist and is not a build artifact root/);
});

test("the CLI labels its PASS as consistency-only and keeps the launch decision visible", () => {
	const result = spawnSync(process.execPath, ["scripts/check-commercial-readiness.mjs"], { cwd: process.cwd(), encoding: "utf8" });
	assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
	assert.match(result.stdout, /Commercial consistency checks: PASS \(not a launch approval;/);
	assert.match(result.stdout, /registry decision=/);
	assert.match(result.stdout, /open hard gates=/);
	assert.match(result.stdout, /recorded claim scans=/);
});

test("first-release scope: an unqualified claim for a not-sold or unsupported capability fails", () => {
	const check = (rel, text) => validateFirstReleaseScope({ inventory, registry, files: [{ rel, text }] });
	assert.deepEqual(check("README.md", "Optional native host for NER and OCR.\n\nRules only."), [
		'README.md:1: FRS-11 (not-sold) "NER" is named without a first-release scope qualifier',
		'README.md:1: FRS-12 (not-sold) "OCR" is named without a first-release scope qualifier',
	]);
	assert.deepEqual(check("README.md", "The native host for NER/OCR ships without a model and is not part of the first-release scope."), []);
	assert.match(check("docs/sales/x.html", "<li>Scanned PDF pages are OCR'd and masked.</li>").join("\n"), /FRS-03/);
	assert.match(check("docs/sales/x.md", "Syncs SharePoint libraries.").join("\n"), /FRS-08/);
	assert.match(check("docs/sales/x.md", "Exact data fingerprints catch paraphrased copies.").join("\n"), /FRS-09 \(supported\)/);
	assert.deepEqual(check("docs/sales/x.md", "The native-ner key and the word winner are not claims."), []);
});

test("first-release scope: the declaration is required and its counts must match", () => {
	assert.match(validateFirstReleaseScope({ inventory: { ...inventory, first_release_scope: [] }, registry, files: [] }).join("\n"), /non-empty first_release_scope/);
	const tampered = structuredClone(inventory);
	tampered.first_release_scope.find((entry) => entry.id === "FRS-11").status = "supported";
	assert.match(validateFirstReleaseScope({ inventory: tampered, registry, files: [] }).join("\n"), /first_release_scope_counts/);
	for (const entry of inventory.first_release_scope) {
		assert.ok(entry.reason_codes.length > 0, entry.id);
		if (entry.status !== "supported") assert.ok(entry.runtime_behavior, entry.id);
	}
	assert.equal(inventory.first_release_scope.find((entry) => entry.id === "FRS-11").status, "not-sold");
});
