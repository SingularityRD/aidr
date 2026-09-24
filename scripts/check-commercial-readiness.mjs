// Static commercial inventory checks. External approvals remain independent gates.
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkClaimEvidenceFreshness } from "./check-claim-evidence-freshness.mjs";

// Connector names as a reader sees them on a release-facing surface, mapped to
// the identifiers deploy/native/support-matrix.json sells. "Cursor / VS Code"
// is one surface label for two sold connectors.
const CONNECTOR_ALIASES = new Map([
	["claude code", "claude-code"],
	["cursor", "cursor"],
	["vs code", "vscode"],
	["vscode", "vscode"],
	["openclaw", "openclaw"],
	["opencode", "opencode"],
	["codex", "codex"],
]);

const CONNECTOR_COUNT_WORDS = new Map([
	["one", 1],
	["two", 2],
	["three", 3],
	["four", 4],
	["five", 5],
	["six", 6],
	["seven", 7],
	["eight", 8],
	["nine", 9],
	["ten", 10],
]);

function releaseArtifactRoots(source) {
	const block = source.match(/\bconst targets\s*=\s*\[([\s\S]*?)\]\s*;/);
	if (!block) throw new Error("release artifact target list is missing or unreadable");
	const entries = [...block[1].matchAll(/\{([^{}]*)\}/g)];
	const residue = block[1].replace(/\{[^{}]*\}/g, "").replace(/[\s,]/g, "");
	if (!entries.length || residue) throw new Error("release artifact target list must contain only literal target objects");
	const roots = [];
	for (const entry of entries) {
		const fields = Object.fromEntries([...entry[1].matchAll(/(pkg|dir|artifactId)\s*:\s*(["'])(.*?)\2/g)].map((match) => [match[1], match[3]]));
		if (Object.keys(fields).length !== 3 || fields.pkg.replace(/package\.json$/, "dist") !== fields.dir || !/^packages\/[a-z0-9-]+\/dist$/.test(fields.dir)) {
			throw new Error(`invalid release artifact target: ${entry[0]}`);
		}
		roots.push(fields.dir);
	}
	if (new Set(roots).size !== roots.length) throw new Error("release artifact target list contains duplicate package roots");
	return roots;
}

function compareCounts(label, actual, declared, failures) {
	// A category with zero members is normally omitted from the generated JSON.
	// Absent and explicit zero mean the same thing here; only a real disagreement
	// is a failure.
	for (const status of new Set([...Object.keys(actual), ...Object.keys(declared ?? {})])) {
		const actualValue = actual[status] ?? 0;
		const declaredValue = declared?.[status] ?? 0;
		if (actualValue !== declaredValue) failures.push(`${label}.${status}: declared ${declaredValue}, actual ${actualValue}`);
	}
}

function normalizeRepoPath(value) {
	return String(value).replaceAll("\\", "/").replace(/\/+$/, "");
}

function isPathShaped(surface) {
	// A surface that opens with a path segment names a repository location, not a
	// descriptive channel label such as "Order Form" or "release notes".
	return /^[A-Za-z0-9._-]+\//.test(surface);
}

/**
 * The README/support matrix inventory may include implemented connectors that
 * are not in the initial direct-GA order. Keep the two scopes explicit and
 * require COM-010/CLAIM-010 to describe the direct-GA subset.
 */
export function validateConnectorScope({ supportMatrix, readme, registry }) {
	const failures = [];
	const sold = supportMatrix?.soldConnectorScope;
	if (!Array.isArray(sold) || sold.length === 0) {
		failures.push("native support matrix must declare a non-empty soldConnectorScope");
		return failures;
	}
	if (new Set(sold).size !== sold.length) failures.push("native support matrix soldConnectorScope contains duplicates");
	const matrixRows = Array.isArray(supportMatrix?.rows) ? supportMatrix.rows : [];
	const rows = matrixRows.map((row) => row?.connector);
	if (rows.length === 0) failures.push("native support matrix must declare connector rows");
	if (new Set(rows).size !== rows.length) failures.push("native support matrix contains duplicate connector rows");
	for (const connector of sold) if (!rows.includes(connector)) failures.push(`native support matrix has no row for sold connector ${connector}`);
	for (const connector of rows) if (!sold.includes(connector)) failures.push(`native support matrix row ${connector} is absent from soldConnectorScope`);
	const connectorGate = registry?.hardGates?.find((gate) => gate?.id === "COM-010");
	const directGa = connectorGate?.directGaConnectorScope;
	if (!Array.isArray(directGa) || directGa.length === 0) {
		failures.push("COM-010 must declare a non-empty directGaConnectorScope");
	} else {
		if (new Set(directGa).size !== directGa.length) failures.push("COM-010 directGaConnectorScope contains duplicates");
		for (const connector of directGa) {
			if (!sold.includes(connector)) failures.push(`COM-010 direct-GA connector ${connector} is absent from soldConnectorScope`);
			if (!rows.includes(connector)) failures.push(`COM-010 direct-GA connector ${connector} has no support-matrix row`);
		}
		if (connectorGate.status === "closed") {
			if (supportMatrix.decision !== "GO") failures.push("COM-010 cannot close while native support matrix is not GO");
			for (const connector of directGa) {
				if (!matrixRows.find((row) => row?.connector === connector)?.acceptanceEvidence?.length) {
					failures.push(`COM-010 cannot close without native acceptance evidence for ${connector}`);
				}
			}
		}
	}

	if (typeof readme !== "string" || readme.trim() === "") {
		failures.push("README must be readable to check the advertised connector scope");
	} else {
		const scopeSentence = readme.split(/\r?\n/).find((line) => line.includes("hook systems in"));
		if (!scopeSentence) {
			failures.push('README must declare the advertised connector scope in a sentence containing "hook systems in"');
		} else {
			const labels = [...scopeSentence.matchAll(/\[([^\]]+)\]\([^)]*\)/g)].map((match) => match[1]);
			if (labels.length === 0) failures.push("README connector scope sentence must link every advertised connector");
			const advertised = new Set();
			for (const label of labels) {
				for (const part of label.split("/").map((value) => value.trim()).filter(Boolean)) {
					const connector = CONNECTOR_ALIASES.get(part.toLowerCase());
					if (!connector) failures.push(`README connector scope sentence names an unknown connector: ${part}`);
					else advertised.add(connector);
				}
			}
			for (const connector of sold) if (!advertised.has(connector)) failures.push(`README connector scope omits sold connector ${connector}`);
			for (const connector of advertised) if (!sold.includes(connector)) failures.push(`README advertises connector ${connector} outside the sold support matrix`);
		}
	}

	const scopeClaims = (registry?.claims ?? []).filter((claim) => claim?.decisionId === "COM-010" || claim?.id === "CLAIM-010");
	if (scopeClaims.length !== 1) {
		failures.push(`claim registry must contain exactly one connector-scope claim bound to COM-010, found ${scopeClaims.length}`);
	} else {
		const text = scopeClaims[0].exactText;
		const match = typeof text === "string" ? text.match(/\b(one|two|three|four|five|six|seven|eight|nine|ten|\d+)\b/i) : null;
		const declared = match ? (CONNECTOR_COUNT_WORDS.get(match[1].toLowerCase()) ?? Number(match[1])) : Number.NaN;
		if (!Number.isInteger(declared)) failures.push(`${scopeClaims[0].id}: connector-scope claim must declare how many connectors are sold`);
		else if (Array.isArray(directGa) && declared !== directGa.length) failures.push(`${scopeClaims[0].id}: declares ${declared} direct-GA connectors but COM-010 declares ${directGa.length}`);
	}
	return failures;
}

/**
 * A claim may only declare a surface that the registry actually scans, or a
 * descriptive label that names no repository location. Every scan root must
 * exist or be a build artifact root, so the scan configuration cannot point at
 * material that is not there.
 */
export function validateClaimSurfaces({ registry, root = process.cwd(), exists = (value) => existsSync(resolve(root, value)) }) {
	const failures = [];
	const scanRoots = registry?.scanRoots;
	if (!Array.isArray(scanRoots) || scanRoots.length === 0) {
		failures.push("claim registry must declare a non-empty scanRoots list");
		return failures;
	}
	const normalizedRoots = scanRoots.map(normalizeRepoPath);
	if (!normalizedRoots.includes("docs/sales")) failures.push("claim registry must scan docs/sales");
	if (!normalizedRoots.includes("packages/dashboard/src/ui/pages/public")) failures.push("claim registry must scan dashboard public page sources");
	const artifactRoots = (registry?.artifactRoots ?? []).map(normalizeRepoPath);
	for (const scanRoot of normalizedRoots) {
		if (!exists(scanRoot) && !artifactRoots.includes(scanRoot)) failures.push(`scan root ${scanRoot} does not exist and is not a build artifact root`);
	}
	for (const claim of registry?.claims ?? []) {
		const surfaces = claim?.surfaces;
		if (!Array.isArray(surfaces) || surfaces.length === 0) {
			failures.push(`${claim?.id ?? "claim"}: every claim must declare at least one surface`);
			continue;
		}
		for (const surface of surfaces) {
			if (typeof surface !== "string" || surface.trim() === "") {
				failures.push(`${claim.id}: claim surface entries must be non-empty strings`);
				continue;
			}
			const normalized = normalizeRepoPath(surface);
			const covered = normalizedRoots.some((scanRoot) => normalized === scanRoot || normalized.startsWith(`${scanRoot}/`));
			if (exists(normalized)) {
				if (!covered) failures.push(`${claim.id}: declared surface ${surface} exists but no scan root covers it`);
			} else if (isPathShaped(surface)) {
				failures.push(`${claim.id}: declared surface ${surface} is not present in the repository, so it can never be scanned`);
			}
		}
	}
	return failures;
}

export function validateCommercialReadiness({ inventory, gaps, registry, releaseSource, supportMatrix, readme, root = process.cwd(), exists, now = new Date() }) {
	const failures = [];
	let expectedRoots = [];
	try {
		expectedRoots = releaseArtifactRoots(releaseSource);
	} catch (error) {
		failures.push(`release artifacts: ${error.message}`);
	}
	const actualRoots = registry.artifactRoots;
	if (!Array.isArray(actualRoots)) {
		failures.push("commercial registry artifactRoots must be an array");
	} else if (expectedRoots.length) {
		for (const expected of expectedRoots) if (!actualRoots.includes(expected)) failures.push(`commercial registry is missing release artifact root ${expected}`);
		for (const actual of actualRoots) if (!expectedRoots.includes(actual)) failures.push(`commercial registry has unlisted release artifact root ${actual}`);
		if (new Set(actualRoots).size !== actualRoots.length) failures.push("commercial registry artifactRoots contains duplicates");
	}

	const features = inventory.features ?? [];
	const coverage = gaps.feature_coverage ?? [];
	const actualCounts = {};
	for (const feature of features) actualCounts[feature.status] = (actualCounts[feature.status] ?? 0) + 1;
	compareCounts("inventory.status_counts", actualCounts, inventory.status_counts, failures);
	compareCounts("gaps.feature_status_counts", actualCounts, gaps.feature_status_counts, failures);
	if (features.length !== coverage.length) failures.push(`feature coverage count differs: inventory ${features.length}, gaps ${coverage.length}`);
	const featureById = new Map(features.map((feature) => [feature.id, feature]));
	if (featureById.size !== features.length) failures.push("feature inventory contains duplicate ids");
	for (const feature of coverage) if (featureById.get(feature.id)?.status !== feature.status) failures.push(`feature coverage differs for ${feature.id}`);
	if (new Set(coverage.map((feature) => feature.id)).size !== coverage.length) failures.push("gap feature coverage contains duplicate ids");

	const workPackages = [...(gaps.engineering_and_operations ?? []), ...(gaps.commercial_and_external ?? [])];
	if (gaps.work_package_count !== workPackages.length) failures.push(`work package count differs: declared ${gaps.work_package_count}, actual ${workPackages.length}`);
	if (new Set(workPackages.map((item) => item.id)).size !== workPackages.length) failures.push("work packages contain duplicate ids");
	const commercialIds = new Set((gaps.commercial_and_external ?? []).map((item) => item.id));
	const gateIds = new Set((registry.hardGates ?? []).map((item) => item.id));
	for (const id of commercialIds) if (!gateIds.has(id)) failures.push(`commercial work package ${id} has no registry hard gate`);
	for (const id of gateIds) if (!commercialIds.has(id)) failures.push(`registry hard gate ${id} has no commercial work package`);
	if (gateIds.size !== (registry.hardGates ?? []).length) failures.push("commercial registry hardGates contains duplicate ids");
	for (const [profile, declared] of Object.entries(gaps.open_hard_gates_by_profile ?? {})) {
		const actual = (registry.hardGates ?? []).filter((gate) => gate.class === "hard" && gate.status !== "closed" && gate.decisionProfiles?.includes(profile)).length;
		if (actual !== declared) failures.push(`open hard gates for ${profile}: declared ${declared}, actual ${actual}`);
	}
	if (inventory.decision !== gaps.decision || gaps.decision !== registry.decision) failures.push("inventory, gap audit, and commercial registry decisions differ");
	for (const claim of registry.claims ?? []) {
		if (claim.salesApproved !== true) continue;
		if (claim.status !== "closed" || claim.maturity !== "approved") failures.push(`${claim.id}: Sales Approved claim must be closed and mature`);
		if (!registry.releaseCandidate || claim.releaseCandidate !== registry.releaseCandidate) failures.push(`${claim.id}: Sales Approved claim is not bound to the registry release candidate`);
		const expiry = typeof claim.expiresAt === "string" && /^\d{4}-\d{2}-\d{2}$/.test(claim.expiresAt) ? Date.parse(`${claim.expiresAt}T23:59:59.999Z`) : NaN;
		if (!Number.isFinite(expiry) || expiry < now.getTime()) failures.push(`${claim.id}: Sales Approved claim is expired or has no valid expiresAt date`);
	}
	failures.push(...validateConnectorScope({ supportMatrix, readme, registry }));
	failures.push(...validateClaimSurfaces({ registry, root, exists }));
	return failures;
}

// CLI entry point. Reads the real repository files so a stale claim scan or a
// connector-scope disagreement fails the command instead of staying invisible.
function main({ root = process.cwd() } = {}) {
	const readJson = (value) => JSON.parse(readFileSync(resolve(root, value), "utf8"));
	const readText = (value) => readFileSync(resolve(root, value), "utf8");
	const registry = readJson("docs/production-readiness/commercial-go-evidence-registry.json");
	const failures = validateCommercialReadiness({
		inventory: readJson("FEATURE_INVENTORY.json"),
		gaps: readJson("PRODUCTION_SALES_GAPS.json"),
		registry,
		releaseSource: readText("scripts/release-artifact-manifests.mjs"),
		supportMatrix: readJson("deploy/native/support-matrix.json"),
		readme: readText("README.md"),
		root,
	});
	const freshness = checkClaimEvidenceFreshness({ root });
	failures.push(...freshness.failures);
	if (failures.length > 0) {
		console.error("Commercial readiness: FAIL");
		for (const failure of failures) console.error(`- ${failure}`);
		return 1;
	}
	const openHardGates = (registry.hardGates ?? []).filter((gate) => gate.status !== "closed").length;
	console.log(
		`Commercial consistency checks: PASS (not a launch approval; registry decision=${registry.decision}, open hard gates=${openHardGates}, recorded claim scans=${freshness.checked.length}).`,
	);
	return 0;
}

const invokedDirectly = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
	try {
		process.exitCode = main();
	} catch (error) {
		console.error(`Commercial readiness error: ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 2;
	}
}
