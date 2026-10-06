import { createHash } from "node:crypto";
import { cycloneDxHashFromSri, parseLockIntegrities } from "./release-evidence-digests.mjs";
import { parseHashLockedRequirements } from "./python-requirements-sbom.mjs";
import { bindPypiLicenseEvidence, cycloneDxLicenses, resolvePypiLicense } from "./pypi-license-data.mjs";

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
export function assertCurrentPrebuiltSbom(payload, { pnpmLockBytes, pythonLockBytes, pythonEvidenceJson, sourceDigest, workspacePackages = [] }) {
	if (payload?.bomFormat !== "CycloneDX" || payload?.specVersion !== "1.5" || !Array.isArray(payload?.components)) fail("not a CycloneDX 1.5 document");
	const pythonLockDigest = digest(pythonLockBytes);
	property(payload.metadata?.properties, "aidr:lockfile-sha256", digest(pnpmLockBytes));
	property(payload.metadata?.properties, "aidr:python-runtime-lockfile-sha256", pythonLockDigest);
	property(payload.metadata?.properties, "aidr:pypi-license-evidence-sha256", digest(pythonEvidenceJson));
	property(payload.metadata?.properties, "aidr:source-digest", sourceDigest);
	const locked = parseHashLockedRequirements(pythonLockBytes.toString("utf8"));
	const evidence = bindPypiLicenseEvidence(pythonEvidenceJson, pythonLockDigest, locked);
	if (evidence.problems.length) fail(evidence.problems.join("; "));
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
		if (!Array.isArray(component.licenses) || !component.licenses.length || component.licenses.some((entry) => {
			const value = entry?.license?.id ?? entry?.license?.name ?? entry?.license?.expression ?? entry?.expression;
			return typeof value !== "string" || !value.trim() || /^(UNKNOWN|NOASSERTION)$/i.test(value.trim());
		})) fail(`${ref} has no declared licence`);
		if (ref !== component.purl) fail(`${ref} differs from its package identity`);
		if (ref.startsWith("pkg:npm/")) {
			if (ref !== `pkg:npm/${encodeURIComponent(component.name)}@${encodeURIComponent(component.version)}`) fail(`${ref} has an inconsistent name/version`);
			const lockKeys = (component.properties ?? []).filter((entry) => entry?.name === "pnpm:lock-key");
			const key = lockKeys.length === 1 ? lockKeys[0].value : "";
			const prefix = `${component.name}@${component.version}`;
			if (typeof key !== "string" || !(key === prefix || key.startsWith(`${prefix}(`) || key.startsWith(`${prefix}_`))) fail(`${ref} has no matching npm lock identity`);
			const hash = cycloneDxHashFromSri(npmIntegrities.get(key));
			if (!hash || !equal(component.hashes, [hash])) fail(`${ref} integrity differs from the npm lock`);
		} else if (!ref.startsWith("pkg:pypi/")) fail(`${ref} has an unsupported library identity`);
	}
	const expectedPythonRefs = new Set();
	for (const pkg of locked) {
		const ref = `pkg:pypi/${pkg.name}@${encodeURIComponent(pkg.version)}`;
		expectedPythonRefs.add(ref);
		const component = components.get(ref);
		if (component?.type !== "library" || component.name !== pkg.name || component.version !== pkg.version) fail(`${ref} is missing or inconsistent`);
		const resolved = resolvePypiLicense(evidence.byName.get(pkg.name));
		const licenses = cycloneDxLicenses(resolved);
		if (!licenses || !equal(component.licenses, licenses)) fail(`${ref} licence differs from current wheel evidence`);
		if (!equal(component.hashes, pkg.hashes.map((content) => ({ alg: "SHA-256", content })))) fail(`${ref} integrity differs from the Python lock`);
		property(component.properties, "aidr:source-lockfile", "services/aig-bridge/requirements-runtime.lock");
		property(component.properties, "aidr:license-obligation", resolved.obligation);
		property(component.properties, "aidr:license-basis", resolved.basis);
		if (resolved.flags.length) property(component.properties, "aidr:license-flags", resolved.flags.join("; "));
		else if (component.properties?.some((entry) => entry?.name === "aidr:license-flags")) fail(`${ref} has unexpected licence flags`);
	}
	for (const ref of components.keys()) {
		if (ref.startsWith("pkg:pypi/") && !expectedPythonRefs.has(ref)) fail(`${ref} is not in the Python runtime lock`);
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
