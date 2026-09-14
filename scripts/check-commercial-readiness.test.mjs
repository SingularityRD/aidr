import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { checkClaimEvidenceFreshness, sha256File } from "./check-claim-evidence-freshness.mjs";
import { validateClaimSurfaces, validateCommercialReadiness, validateConnectorScope } from "./check-commercial-readiness.mjs";

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
	const recordPath = join(evidenceDir, "v9-claim-gate-final.json");
	await writeFile(recordPath, JSON.stringify({ mode: "gate", registrySha256: "0".repeat(64) }));
	const stale = checkClaimEvidenceFreshness({ root: process.cwd(), evidenceDir });
	assert.equal(stale.failures.length, 1);
	assert.match(stale.failures.join("\n"), new RegExp(`v9-claim-gate-final\\.json: recorded registrySha256 0{64} does not match the current registry digest ${registrySha256}`));
	assert.equal(stale.registrySha256, registrySha256);
	await writeFile(recordPath, JSON.stringify({ mode: "gate", registrySha256 }));
	assert.deepEqual(checkClaimEvidenceFreshness({ root: process.cwd(), evidenceDir }).failures, []);
});

test("the advertised connector scope agrees across README, the support matrix and the claim registry", () => {
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
	const narrowedClaim = fixture();
	narrowedClaim.registry.claims.find((claim) => claim.id === "CLAIM-010").exactText = "All five connectors are directly GA-supported.";
	assert.match(validateConnectorScope(narrowedClaim).join("\n"), /CLAIM-010: declares 5 connectors but the support matrix sells 6/);
	const narrowedMatrix = fixture();
	narrowedMatrix.supportMatrix.soldConnectorScope = narrowedMatrix.supportMatrix.soldConnectorScope.filter((connector) => connector !== "codex");
	assert.match(validateConnectorScope(narrowedMatrix).join("\n"), /README advertises connector codex outside the sold support matrix/);
});

test("every claim surface is either scan-covered or absent", () => {
	assert.deepEqual(validateClaimSurfaces({ registry: fixture().registry }), []);
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
