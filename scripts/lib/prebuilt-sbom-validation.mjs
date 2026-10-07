import { createHash } from "node:crypto";
import { cycloneDxHashFromSri, parseLockIntegrities } from "./release-evidence-digests.mjs";
import { BRIDGE_PYTHON_SOURCE, buildPythonSbomComponents, pythonSourceProperties } from "./python-sbom-components.mjs";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const fail = (message) => { throw new Error(`Prebuilt SBOM: ${message}`); };
const equal = (actual, expected) => JSON.stringify(actual) === JSON.stringify(expected);
function property(properties, name, expected) {
	const matches = (properties ?? []).filter((entry) => entry?.name === name);
	if (matches.length !== 1 || matches[0].value !== expected) fail(`${name} is missing, duplicated, or stale`);
}

/** The expected digest comes from the upstream build job, never the artifact's sidecar. */
export function assertPrebuiltSbomDigest(bytes, expectedDigest, { required = true } = {}) {
	if (!expectedDigest) {
		if (required) fail("trusted build-job SBOM digest is required before reuse");
		return false;
	}
	if (!/^[a-f0-9]{64}$/.test(expectedDigest) || digest(bytes) !== expectedDigest) fail("bytes differ from the trusted build-job SBOM digest");
	return true;
}

/** Validate before rebinding signed data; this is inventory assurance, not Legal approval. */
export function assertCurrentPrebuiltSbom(payload, { pnpmLockBytes, pythonLockBytes, pythonEvidenceJson, extraPythonSources = [], sourceDigest, workspacePackages = [] }) {
	if (payload?.bomFormat !== "CycloneDX" || payload?.specVersion !== "1.5" || !Array.isArray(payload?.components)) fail("not a CycloneDX 1.5 document");
	const pythonLockDigest = digest(pythonLockBytes);
	property(payload.metadata?.properties, "aidr:lockfile-sha256", digest(pnpmLockBytes));
	property(payload.metadata?.properties, "aidr:python-runtime-lockfile-sha256", pythonLockDigest);
	property(payload.metadata?.properties, "aidr:pypi-license-evidence-sha256", digest(pythonEvidenceJson));
	property(payload.metadata?.properties, "aidr:source-digest", sourceDigest);
	for (const source of extraPythonSources) {
		for (const binding of pythonSourceProperties(source)) property(payload.metadata?.properties, binding.name, binding.value);
	}
	// Re-derive every Python component exactly as generate-sbom.mjs does.
	const python = buildPythonSbomComponents([
		{ ...BRIDGE_PYTHON_SOURCE, lockBytes: pythonLockBytes, evidenceJson: pythonEvidenceJson },
		...extraPythonSources,
	]);
	if (python.problems.length) fail(python.problems.join("; "));
	if (python.missingLicenses.length) fail(`${python.missingLicenses.join(", ")} has no declared licence`);
	const npmIntegrities = parseLockIntegrities(pnpmLockBytes.toString("utf8"));
	const workspaceRefs = new Map(workspacePackages.map((pkg) => [`pkg:npm/${encodeURIComponent(pkg.name)}@${encodeURIComponent(pkg.version)}`, pkg]));
	const components = new Map();
	for (const component of payload.components) {
		const ref = component?.["bom-ref"];
		if (typeof ref !== "string" || !ref || components.has(ref)) fail("component identity is missing or duplicated");
		components.set(ref, component);
		if (component.type !== "library") {
			const workspace = workspaceRefs.get(ref);
			const isWorkspace = workspace && component.name === workspace.name && component.version === workspace.version && component.purl === ref;
			const isBridge = ref === "urn:aidr:aig-bridge" && component.name === "AIDR AIG Bridge";
			if (component.type !== "application" || !(isWorkspace || isBridge)) fail(`${ref} is not a current workspace application`);
			continue;
		}
		if (ref !== component.purl) fail(`${ref} differs from its package identity`);
		// Python components are compared field by field with current evidence below.
		if (ref.startsWith("pkg:pypi/")) continue;
		if (!Array.isArray(component.licenses) || !component.licenses.length || component.licenses.some((entry) => {
			const value = entry?.license?.id ?? entry?.license?.name ?? entry?.license?.expression ?? entry?.expression;
			return typeof value !== "string" || !value.trim() || /^(UNKNOWN|NOASSERTION)$/i.test(value.trim());
		})) fail(`${ref} has no declared licence`);
		if (ref.startsWith("pkg:npm/")) {
			if (ref !== `pkg:npm/${encodeURIComponent(component.name)}@${encodeURIComponent(component.version)}`) fail(`${ref} has an inconsistent name/version`);
			const lockKeys = (component.properties ?? []).filter((entry) => entry?.name === "pnpm:lock-key");
			const key = lockKeys.length === 1 ? lockKeys[0].value : "";
			const prefix = `${component.name}@${component.version}`;
			if (typeof key !== "string" || !(key === prefix || key.startsWith(`${prefix}(`) || key.startsWith(`${prefix}_`))) fail(`${ref} has no matching npm lock identity`);
			const hash = cycloneDxHashFromSri(npmIntegrities.get(key));
			if (!hash || !equal(component.hashes, [hash])) fail(`${ref} integrity differs from the npm lock`);
		} else fail(`${ref} has an unsupported library identity`);
	}
	for (const [ref, expected] of python.components) {
		const component = components.get(ref);
		if (component?.type !== "library" || component.name !== expected.name || component.version !== expected.version) fail(`${ref} is missing or inconsistent`);
		if (!equal(component.licenses, expected.licenses)) fail(`${ref} licence differs from current wheel evidence`);
		if (!equal(component.hashes, expected.hashes)) fail(`${ref} integrity differs from the Python lock`);
		if (!equal(component.properties, expected.properties)) fail(`${ref} licence/source properties are missing, duplicated, or stale`);
	}
	for (const ref of components.keys()) {
		if (ref.startsWith("pkg:pypi/") && !python.components.has(ref)) fail(`${ref} is not in the Python runtime lock`);
	}
	for (const ref of workspaceRefs.keys()) if (!components.has(ref)) fail(`${ref} workspace application is missing`);
	const rootRef = payload.metadata?.component?.["bom-ref"];
	if (typeof rootRef !== "string" || !Array.isArray(payload.dependencies)) fail("dependency coverage is missing");
	const graph = new Map();
	for (const edge of payload.dependencies) {
		if (graph.has(edge?.ref) || !(edge?.ref === rootRef || components.has(edge?.ref)) || !Array.isArray(edge.dependsOn)) fail("invalid dependency graph");
		for (const child of edge.dependsOn) if (!components.has(child)) fail(`dependency ${child} is missing`);
		graph.set(edge.ref, edge.dependsOn);
	}
	const reached = new Set();
	const pending = [rootRef];
	while (pending.length) {
		const ref = pending.pop();
		if (reached.has(ref)) continue;
		reached.add(ref);
		pending.push(...(graph.get(ref) ?? []));
	}
	for (const ref of components.keys()) if (!reached.has(ref)) fail(`${ref} is absent from dependency coverage`);
}
