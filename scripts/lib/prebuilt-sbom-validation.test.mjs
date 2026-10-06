import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { assertCurrentPrebuiltSbom, assertPrebuiltSbomDigest } from "./prebuilt-sbom-validation.mjs";
import { parseHashLockedRequirements } from "./python-requirements-sbom.mjs";
import { cycloneDxLicenses, resolvePypiLicense } from "./pypi-license-data.mjs";
import { parseLockIntegrities } from "./release-evidence-digests.mjs";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const npmHash = { alg: "SHA-256", content: "ab".repeat(32) };
const npmRef = "pkg:npm/example@1.0.0";
const inputs = {
	pnpmLockBytes: Buffer.from(`lockfileVersion: '9.0'\npackages:\n  example@1.0.0:\n    resolution: {integrity: sha256-${Buffer.from(npmHash.content, "hex").toString("base64")}}\nsnapshots:\n  example@1.0.0: {}\n`),
	pythonLockBytes: readFileSync(new URL("../../services/aig-bridge/requirements-runtime.lock", import.meta.url)),
	pythonEvidenceJson: readFileSync(new URL("../../services/aig-bridge/pypi-runtime-licenses.json", import.meta.url), "utf8"),
	sourceDigest: `sha256:${"cd".repeat(32)}`,
};
const evidence = JSON.parse(inputs.pythonEvidenceJson);
const locked = parseHashLockedRequirements(inputs.pythonLockBytes.toString("utf8"));
function fixture() {
	const components = [{
		type: "library", "bom-ref": npmRef, purl: npmRef, name: "example", version: "1.0.0",
		licenses: [{ license: { id: "MIT" } }], hashes: [npmHash], properties: [{ name: "pnpm:lock-key", value: "example@1.0.0" }],
	}, ...locked.map((pkg) => {
		const resolved = resolvePypiLicense(evidence.packages.find((entry) => entry.name === pkg.name));
		const ref = `pkg:pypi/${pkg.name}@${encodeURIComponent(pkg.version)}`;
		return {
			type: "library", "bom-ref": ref, purl: ref, name: pkg.name, version: pkg.version,
			licenses: cycloneDxLicenses(resolved), hashes: pkg.hashes.map((content) => ({ alg: "SHA-256", content })),
			properties: [
				{ name: "aidr:source-lockfile", value: "services/aig-bridge/requirements-runtime.lock" },
				{ name: "aidr:license-obligation", value: resolved.obligation },
				{ name: "aidr:license-basis", value: resolved.basis },
				...(resolved.flags.length ? [{ name: "aidr:license-flags", value: resolved.flags.join("; ") }] : []),
			],
		};
	})];
	return structuredClone({
		bomFormat: "CycloneDX", specVersion: "1.5",
		metadata: { component: { "bom-ref": "urn:aidr:workspace" }, properties: [
			{ name: "aidr:lockfile-sha256", value: digest(inputs.pnpmLockBytes) },
			{ name: "aidr:python-runtime-lockfile-sha256", value: digest(inputs.pythonLockBytes) },
			{ name: "aidr:pypi-license-evidence-sha256", value: digest(inputs.pythonEvidenceJson) },
			{ name: "aidr:source-digest", value: inputs.sourceDigest },
			{ name: "aidr:data-digest", value: `sha256:${"ef".repeat(32)}` },
		] },
		components,
		dependencies: [{ ref: "urn:aidr:workspace", dependsOn: components.map((entry) => entry["bom-ref"]) }],
	});
}
const python = (payload, name) => payload.components.find((component) => component.name === name);

test("independent build-job digest passes exact bytes and rejects any mutated inventory before rebind", () => {
	const original = fixture();
	const bytes = Buffer.from(JSON.stringify(original));
	const expected = digest(bytes);
	assert.equal(assertPrebuiltSbomDigest(bytes, expected), true);
	const bitFlipped = Buffer.from(bytes);
	bitFlipped[bitFlipped.length - 3] ^= 1;
	assert.throws(() => assertPrebuiltSbomDigest(bitFlipped, expected), /trusted build-job SBOM digest/);
	const omitted = structuredClone(original);
	omitted.components = omitted.components.filter((component) => component["bom-ref"] !== npmRef);
	omitted.dependencies[0].dependsOn = omitted.dependencies[0].dependsOn.filter((ref) => ref !== npmRef);
	const omittedBytes = Buffer.from(JSON.stringify(omitted));
	// An attacker can update the artifact-local sidecar, but not the required
	// digest delivered independently by needs.build-rc.outputs.sbom_sha256.
	assert.notEqual(digest(omittedBytes), expected);
	assert.throws(() => assertPrebuiltSbomDigest(omittedBytes, expected), /trusted build-job SBOM digest/);
});

test("commercial reuse requires an independent digest; developer absence is explicitly untrusted", () => {
	const bytes = Buffer.from(JSON.stringify(fixture()));
	assert.throws(() => assertPrebuiltSbomDigest(bytes, undefined), /digest is required/);
	assert.throws(() => assertPrebuiltSbomDigest(bytes, "not-a-sha256"), /trusted build-job SBOM digest/);
	assert.equal(assertPrebuiltSbomDigest(bytes, undefined, { required: false }), false);
});

test("current exact wheel inventory passes without rewriting copyleft or native obligations", () => {
	const payload = fixture();
	const original = structuredClone(payload);
	assert.doesNotThrow(() => assertCurrentPrebuiltSbom(payload, inputs));
	assert.deepEqual(payload, original, "validation must precede and not perform the legitimate signed-data rebind");
	assert.equal(python(payload, "psycopg").licenses[0].license.name, "GNU Lesser General Public License v3 (LGPLv3)");
	assert.match(python(payload, "psycopg-binary").properties.find((entry) => entry.name === "aidr:license-flags").value, /14 native libraries/);
});

test("stale, missing and duplicated lock, wheel-manifest or source bindings fail", () => {
	for (const name of ["aidr:lockfile-sha256", "aidr:python-runtime-lockfile-sha256", "aidr:pypi-license-evidence-sha256", "aidr:source-digest"]) {
		for (const mutation of ["stale", "missing", "duplicate"]) {
			const payload = fixture();
			const entry = payload.metadata.properties.find((property) => property.name === name);
			if (mutation === "stale") entry.value = "0".repeat(64);
			if (mutation === "missing") payload.metadata.properties = payload.metadata.properties.filter((property) => property !== entry);
			if (mutation === "duplicate") payload.metadata.properties.push({ ...entry });
			assert.throws(() => assertCurrentPrebuiltSbom(payload, inputs), /missing, duplicated, or stale/, `${name}: ${mutation}`);
		}
	}
});

test("omitted Python packages and omitted referenced npm components fail", () => {
	for (const name of ["certifi", "example"]) {
		const payload = fixture();
		payload.components = payload.components.filter((component) => component.name !== name);
		assert.throws(() => assertCurrentPrebuiltSbom(payload, inputs), /missing/, name);
	}
});

test("missing licence or changed npm lock identity/integrity cannot bypass fresh generation", () => {
	for (const mutation of ["license", "hash", "key", "identity", "relabel"]) {
		const payload = fixture();
		const component = payload.components[0];
		if (mutation === "license") delete component.licenses;
		if (mutation === "hash") component.hashes[0].content = "0".repeat(64);
		if (mutation === "key") component.properties[0].value = "example@9.0.0";
		if (mutation === "identity") component.version = "9.0.0";
		if (mutation === "relabel") {
			component.type = "application";
			delete component.licenses;
			delete component.hashes;
			delete component.properties;
		}
		assert.throws(() => assertCurrentPrebuiltSbom(payload, inputs), /licence|integrity|identity|name\/version|workspace application/, mutation);
	}
});

test("application exemptions require actual workspace package identities and complete presence", () => {
	const workspace = { name: "@aidr/workspace", version: "1.0.0" };
	const ref = "pkg:npm/%40aidr%2Fworkspace@1.0.0";
	const payload = fixture();
	payload.components.push({ type: "application", "bom-ref": ref, purl: ref, ...workspace });
	payload.dependencies[0].dependsOn.push(ref);
	const options = { ...inputs, workspacePackages: [workspace] };
	assert.doesNotThrow(() => assertCurrentPrebuiltSbom(payload, options));
	const changed = structuredClone(payload);
	changed.components.at(-1).name = "forged-workspace";
	assert.throws(() => assertCurrentPrebuiltSbom(changed, options), /workspace application/);
	assert.throws(() => assertCurrentPrebuiltSbom(fixture(), options), /workspace application is missing/);
});

test("Python licence, wheel hashes, basis, obligation and native flags must match current evidence", () => {
	for (const mutation of ["license", "hash", "basis", "obligation", "flags"]) {
		const payload = fixture();
		const component = python(payload, "psycopg-binary");
		if (mutation === "license") component.licenses = [{ license: { id: "MIT" } }];
		if (mutation === "hash") component.hashes.pop();
		const propertyName = { basis: "aidr:license-basis", obligation: "aidr:license-obligation", flags: "aidr:license-flags" }[mutation];
		if (propertyName) component.properties = component.properties.filter((entry) => entry.name !== propertyName);
		assert.throws(() => assertCurrentPrebuiltSbom(payload, inputs), /licence|integrity|missing, duplicated, or stale/, mutation);
	}
});

test("unknown or mismatched wheel evidence is blocked even when its new manifest digest is declared", () => {
	for (const mutation of ["unknown", "wheel", "lock"]) {
		const changed = structuredClone(evidence);
		if (mutation === "unknown") changed.packages[0].core_metadata.license_expression = "LicenseRef-Unreviewed";
		if (mutation === "wheel") changed.packages[0].wheel_sha256 = "0".repeat(64);
		if (mutation === "lock") changed.source_lock_sha256 = "0".repeat(64);
		const pythonEvidenceJson = JSON.stringify(changed);
		const payload = fixture();
		payload.metadata.properties.find((entry) => entry.name === "aidr:pypi-license-evidence-sha256").value = digest(pythonEvidenceJson);
		assert.throws(() => assertCurrentPrebuiltSbom(payload, { ...inputs, pythonEvidenceJson }), /licence|lock|wheel/, mutation);
	}
});

test("duplicate, unexpected and disconnected components cannot silently alter coverage", () => {
	for (const mutation of ["duplicate", "unexpected", "disconnected", "no-graph"]) {
		const payload = fixture();
		if (mutation === "duplicate") payload.components.push(structuredClone(payload.components[0]));
		if (mutation === "unexpected") {
			const extra = structuredClone(python(payload, "certifi"));
			extra["bom-ref"] = extra.purl = "pkg:pypi/unlocked@1.0.0";
			payload.components.push(extra);
		}
		if (mutation === "disconnected") payload.dependencies[0].dependsOn.pop();
		if (mutation === "no-graph") delete payload.dependencies;
		assert.throws(() => assertCurrentPrebuiltSbom(payload, inputs), /duplicated|not in|coverage/, mutation);
	}
});

test("shared lock integrity parser supports quoted inline and nested resolutions, excludes snapshots", () => {
	const sri = `sha256-${Buffer.from(npmHash.content, "hex").toString("base64")}`;
	const result = parseLockIntegrities(`packages:\n  '@scope/pkg@2.0.0':\n    resolution: {integrity: '${sri}'}\n  plain@1.0.0:\n    resolution:\n      integrity: ${sri}\nsnapshots:\n  bogus@1.0.0:\n    resolution: {integrity: ignored}\n`);
	assert.deepEqual([...result], [["@scope/pkg@2.0.0", sri], ["plain@1.0.0", sri]]);
});

test("release reuse validates before rebinding and SBOM generation includes the manifest digest", () => {
	const wrapper = readFileSync(new URL("../release-artifact-manifests.mjs", import.meta.url), "utf8");
	const reuse = wrapper.slice(wrapper.indexOf("async function reuseSbomEvidence("), wrapper.indexOf("async function copySbomEvidence("));
	assert.ok(reuse.indexOf("assertCurrentPrebuiltSbom(payload") < reuse.indexOf("payload.metadata ="));
	assert.ok(reuse.indexOf("assertPrebuiltSbomDigest(sourceBytes") < reuse.indexOf("JSON.parse("));
	assert.match(reuse, /AIDR_EXPECTED_PREBUILT_SBOM_SHA256, \{ required: requireSbom \}/);
	assert.match(reuse, /not accepted production evidence/);
	assert.match(reuse, /pnpm-lock\.yaml/);
	assert.match(reuse, /requirements-runtime\.lock/);
	assert.match(reuse, /pypi-runtime-licenses\.json/);
	const generator = readFileSync(new URL("../generate-sbom.mjs", import.meta.url), "utf8");
	assert.match(generator, /name: "aidr:pypi-license-evidence-sha256", value: createHash\("sha256"\)\.update\(pythonLicenseEvidenceJson\)/);
});
