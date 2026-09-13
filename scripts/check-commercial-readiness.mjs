// Static commercial inventory checks. External approvals remain independent gates.
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
	for (const status of new Set([...Object.keys(actual), ...Object.keys(declared ?? {})])) {
		if (actual[status] !== declared?.[status]) failures.push(`${label}.${status}: declared ${declared?.[status] ?? "missing"}, actual ${actual[status] ?? 0}`);
	}
}

export function validateCommercialReadiness({ inventory, gaps, registry, releaseSource, now = new Date() }) {
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
	return failures;
}
