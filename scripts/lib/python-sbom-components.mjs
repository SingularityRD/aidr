/**
 * Expected CycloneDX components for every hash-locked Python set AIDR ships.
 *
 * Shared by scripts/generate-sbom.mjs (which writes them) and
 * scripts/lib/prebuilt-sbom-validation.mjs (which re-derives and compares them),
 * so the generator and the reuse validator cannot drift.
 *
 * A package pinned by several locks at the same version is one component: its
 * hashes are the union of the locked wheel digests and `aidr:source-lockfile`
 * names every lock. Licence terms come only from each lock's wheel evidence; if
 * the locks' evidence disagrees on the licence the package stays unknown.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { parseHashLockedRequirements } from "./python-requirements-sbom.mjs";
import { bindPypiLicenseEvidence, cycloneDxLicenses, resolvePypiLicense } from "./pypi-license-data.mjs";

export const BRIDGE_PYTHON_SOURCE = {
	lock: "services/aig-bridge/requirements-runtime.lock",
	evidence: "services/aig-bridge/pypi-runtime-licenses.json",
	licenceRequired: true,
};

/**
 * Privacy workers shipped in @singularity/aidr-privacy (NER, OCR/vision,
 * document parsers). The package is not part of the connector release bundle,
 * so a licence its wheel metadata cannot fix stays `unknown` and is reported as
 * pending review instead of failing commercial generation; stale or unbound
 * evidence still fails.
 */
export const PRIVACY_PYTHON_SOURCES = [
	{ lock: "packages/privacy/ner/requirements.linux-py311.lock.txt", evidence: "packages/privacy/sbom/ner-linux.pypi-licenses.json", licenceRequired: false },
	{ lock: "packages/privacy/ner/requirements.windows-py312.lock.txt", evidence: "packages/privacy/sbom/ner-windows.pypi-licenses.json", licenceRequired: false },
	{ lock: "packages/privacy/vision/requirements.lock.txt", evidence: "packages/privacy/sbom/vision.pypi-licenses.json", licenceRequired: false },
	{ lock: "packages/privacy/parsers/requirements.lock.txt", evidence: "packages/privacy/sbom/parsers.pypi-licenses.json", licenceRequired: false },
];

const OBLIGATION_RANK = { permissive: 0, "weak-copyleft": 1, "strong-copyleft": 2, unknown: 3 };
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** Read lock and evidence bytes for the given sources (evidence may be absent). */
export function readPythonSources(repoRoot, sources) {
	return sources.map((source) => {
		let evidenceJson = "";
		try {
			evidenceJson = readFileSync(path.join(repoRoot, source.evidence), "utf8");
		} catch {
			// Missing evidence is reported by bindPypiLicenseEvidence as a problem.
		}
		return { ...source, lockBytes: readFileSync(path.join(repoRoot, source.lock)), evidenceJson };
	});
}

/**
 * @param {Array<{ lock: string, lockBytes: Buffer, evidenceJson: string }>} sources
 */
export function buildPythonSbomComponents(sources) {
	const problems = [];
	const merged = new Map();
	const refsByLock = new Map();
	const lockDigests = new Map();
	for (const source of sources) {
		const lockDigest = sha256(source.lockBytes);
		lockDigests.set(source.lock, lockDigest);
		const packages = parseHashLockedRequirements(source.lockBytes.toString("utf8"));
		const evidence = bindPypiLicenseEvidence(source.evidenceJson, lockDigest, packages);
		for (const problem of evidence.problems) problems.push(sources.length > 1 ? `${source.lock}: ${problem}` : problem);
		const refs = new Set();
		for (const pkg of packages) {
			const ref = `pkg:pypi/${pkg.name}@${encodeURIComponent(pkg.version)}`;
			refs.add(ref);
			const entry = merged.get(ref) ?? { name: pkg.name, version: pkg.version, hashes: new Set(), locks: [], resolved: [], licenceRequired: false };
			if (source.licenceRequired !== false) entry.licenceRequired = true;
			for (const hash of pkg.hashes) entry.hashes.add(hash);
			entry.locks.push(source.lock);
			const record = evidence.byName.get(pkg.name);
			entry.resolved.push(record ? resolvePypiLicense(record) : undefined);
			merged.set(ref, entry);
		}
		refsByLock.set(source.lock, refs);
	}

	const components = new Map();
	const missingLicenses = [];
	const pendingLicenseReview = [];
	const copyleftFindings = [];
	const licenseFlags = [];
	for (const [ref, entry] of merged) {
		const id = `${entry.name}@${entry.version}`;
		const candidates = entry.resolved.map((resolved) => (resolved ? cycloneDxLicenses(resolved) : undefined));
		const agreed = candidates.every((licenses) => licenses && JSON.stringify(licenses) === JSON.stringify(candidates[0]));
		const licenses = agreed ? candidates[0] : undefined;
		if (!agreed && candidates.filter(Boolean).length > 1) problems.push(`${id}: licence evidence differs between ${entry.locks.join(", ")}`);
		const known = entry.resolved.filter(Boolean);
		const reason = known.find((resolved) => resolved.reason)?.reason;
		if (!licenses) {
			const detail = `${id} (PyPI ${entry.locks.join(", ")}${reason ? `: ${reason}` : ""})`;
			(entry.licenceRequired ? missingLicenses : pendingLicenseReview).push(detail);
		}
		const obligation = known.length === entry.resolved.length
			? known.reduce((worst, resolved) => (OBLIGATION_RANK[resolved.obligation] > OBLIGATION_RANK[worst] ? resolved.obligation : worst), "permissive")
			: "unknown";
		if (obligation !== "permissive" && obligation !== "unknown") {
			const first = known.find((resolved) => resolved.obligation === obligation);
			copyleftFindings.push(`${id}: ${obligation} (${first.expression ?? (first.spdx.join(", ") || first.name)})`);
		}
		const flags = [...new Set(known.flatMap((resolved) => resolved.flags))];
		for (const flag of flags) licenseFlags.push(`${id}: ${flag}`);
		const basis = [...new Set(known.map((resolved) => resolved.basis))].join("; ");
		components.set(ref, {
			type: "library",
			"bom-ref": ref,
			name: entry.name,
			version: entry.version,
			purl: ref,
			...(licenses ? { licenses } : {}),
			hashes: [...entry.hashes].sort(compare).map((content) => ({ alg: "SHA-256", content })),
			properties: [
				{ name: "aidr:source-lockfile", value: entry.locks.join(", ") },
				{ name: "aidr:license-obligation", value: obligation },
				...(licenses ? [{ name: "aidr:license-basis", value: basis }] : []),
				...(flags.length ? [{ name: "aidr:license-flags", value: flags.join("; ") }] : []),
			],
		});
	}
	return { components, refsByLock, lockDigests, problems, missingLicenses, pendingLicenseReview, copyleftFindings, licenseFlags };
}

/** SBOM metadata binding names for a non-bridge lock and its evidence. */
export function pythonSourceProperties(source) {
	return [
		{ name: `aidr:python-lockfile-sha256:${source.lock}`, value: sha256(source.lockBytes) },
		{ name: `aidr:pypi-license-evidence-sha256:${source.lock}`, value: sha256(source.evidenceJson) },
	];
}
