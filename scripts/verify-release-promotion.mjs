#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, rm } from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { systemTar } from "./lib/tar-path.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));

export async function verifyReleasePromotion(options) {
	const bundle = path.resolve(options.bundle);
	const policyPath = path.resolve(options.policy);
	const statePath = path.resolve(options.state);
	const receiptPath = path.resolve(options.receipt);
	const lockfile = path.resolve(options.lockfile);
	const firstReceipt = options.record ? `${receiptPath}.preflight` : receiptPath;

	runNode(path.join(scriptDir, "release-verify.mjs"), [
		"--bundle",
		bundle,
		"--policy",
		policyPath,
		"--state",
		statePath,
		"--receipt",
		firstReceipt,
	]);

	const metadata = await readJson(path.join(bundle, "release-metadata.json"), "release metadata");
	assertEqual(metadata.release_tag, options.expectedTag, "release tag");
	assertEqual(metadata.release_version, options.expectedVersion, "release version");
	assertEqual(String(metadata.git_sha).toLowerCase(), options.expectedSha.toLowerCase(), "release commit");

	await verifySbom(bundle);
	await verifyProvenance(bundle, lockfile, options);

	if (options.record) {
		runNode(path.join(scriptDir, "release-verify.mjs"), [
			"--bundle",
			bundle,
			"--policy",
			policyPath,
			"--state",
			statePath,
			"--receipt",
			receiptPath,
			"--record",
		]);
		await rm(firstReceipt, { force: true });
	}
}

function runNode(script, args) {
	const result = spawnSync(process.execPath, [script, ...args], {
		encoding: "utf8",
		stdio: "inherit",
		env: process.env,
	});
	if (result.error) throw result.error;
	if (result.status !== 0) throw new Error(`${path.basename(script)} failed with status ${result.status}`);
}

async function readJson(file, label) {
	try {
		return JSON.parse(await readFile(file, "utf8"));
	} catch (error) {
		throw new Error(`cannot read ${label}: ${formatError(error)}`);
	}
}

function assertEqual(actual, expected, label) {
	if (actual !== expected) throw new Error(`${label} mismatch: ${String(actual)} != ${String(expected)}`);
}

export async function verifySbom(bundle) {
	const sbomPath = path.join(bundle, "aidr-sbom.cdx.json");
	const sbomRaw = await readFile(sbomPath, "utf8");
	const sbom = JSON.parse(sbomRaw);
	if (sbom?.bomFormat !== "CycloneDX" || sbom.specVersion !== "1.5" || !Array.isArray(sbom.components) || sbom.components.length === 0) {
		throw new Error("release SBOM is not a non-empty CycloneDX 1.5 document");
	}
	const references = new Set();
	const rootReference = sbom.metadata?.component?.["bom-ref"];
	if (typeof rootReference === "string") references.add(rootReference);
	for (const component of sbom.components) {
		const reference = component?.["bom-ref"];
		if (typeof reference !== "string" || references.has(reference)) throw new Error("release SBOM contains an invalid or duplicate component reference");
		references.add(reference);
		if (component.type === "library" && (!Array.isArray(component.licenses) || component.licenses.length === 0)) {
			throw new Error(`release SBOM library has no license metadata: ${component.name ?? reference}`);
		}
		if (component.type === "library" && (!Array.isArray(component.hashes) || component.hashes.length === 0)) {
			throw new Error(`release SBOM library has no integrity hash: ${component.name ?? reference}`);
		}
	}
	for (const dependency of sbom.dependencies ?? []) {
		if (!references.has(dependency?.ref)) throw new Error(`release SBOM dependency references an unknown component: ${String(dependency?.ref)}`);
		for (const child of dependency.dependsOn ?? []) {
			if (!references.has(child)) throw new Error(`release SBOM dependency references an unknown child: ${String(child)}`);
		}
	}
	const sidecar = (await readFile(`${sbomPath}.sha256`, "utf8")).trim().split(/\s+/, 2);
	if (!/^[0-9a-f]{64}$/i.test(sidecar[0] ?? "") || sidecar[1] !== "aidr-sbom.cdx.json") throw new Error("release SBOM checksum sidecar is invalid");
	assertEqual(sha256(sbomRaw), sidecar[0].toLowerCase(), "release SBOM checksum");
}

export async function verifyProvenance(bundle, lockfile, options) {
	const statement = await readJson(path.join(bundle, "aidr-provenance.intoto.json"), "release provenance");
	assertEqual(statement._type, "https://in-toto.io/Statement/v0.1", "provenance statement type");
	assertEqual(statement.predicateType, "https://slsa.dev/provenance/v0.2", "provenance predicate type");
	assertEqual(statement.predicate?.buildType, "https://singularityrd.dev/aidr/release-artifact-manifests/v1", "provenance build type");
	if (typeof statement.predicate?.builder?.id !== "string" || statement.predicate.builder.id.length === 0) throw new Error("provenance builder id is missing");
	if (!Array.isArray(statement.subject) || statement.subject.length === 0) throw new Error("provenance declares no subjects");
	const subjectNames = new Set();
	for (const subject of statement.subject) {
		if (typeof subject?.name !== "string" || subjectNames.has(subject.name) || !/^[0-9a-f]{64}$/i.test(subject.digest?.sha256 ?? "")) {
			throw new Error("provenance subject schema is invalid");
		}
		subjectNames.add(subject.name);
	}
	const inventory = await readJson(path.join(bundle, "release-inventory.json"), "release inventory");
	const archives = inventory.artifacts?.filter((entry) => typeof entry.staged_path === "string" && entry.staged_path.endsWith(".tgz"));
	if (!Array.isArray(archives) || archives.length === 0) throw new Error("release inventory declares no package archives");
	const actualSubjects = new Map();
	for (const archive of archives) {
		if (!/^[a-zA-Z0-9._-]+\.tgz$/.test(archive.staged_path)) throw new Error("release package archive path is invalid");
		const result = spawnSync(systemTar(), ["-xOzf", path.join(bundle, archive.staged_path), "package/dist/aidr-artifact.manifest.json"], {
			encoding: null,
			maxBuffer: 1024 * 1024,
		});
		if (result.error || result.status !== 0) throw new Error(`cannot read signed package manifest from ${archive.staged_path}`);
		let manifest;
		try {
			manifest = JSON.parse(result.stdout.toString("utf8"));
		} catch {
			throw new Error(`invalid signed package manifest in ${archive.staged_path}`);
		}
		if (typeof manifest?.artifact_id !== "string" || !manifest.artifact_id || actualSubjects.has(manifest.artifact_id)) {
			throw new Error(`missing or duplicate package artifact ID in ${archive.staged_path}`);
		}
		actualSubjects.set(manifest.artifact_id, sha256(result.stdout));
	}
	if (actualSubjects.size !== subjectNames.size) throw new Error("provenance subjects do not match release package manifests");
	for (const subject of statement.subject) {
		if (actualSubjects.get(subject.name) !== subject.digest.sha256.toLowerCase()) {
			throw new Error(`provenance subject digest does not match signed package manifest: ${subject.name}`);
		}
	}
	const parameters = statement.predicate?.invocation?.parameters;
	assertEqual(parameters?.release_version, options.expectedVersion, "provenance release version");
	assertEqual(String(parameters?.git_sha).toLowerCase(), options.expectedSha.toLowerCase(), "provenance commit");
	assertEqual(String(parameters?.ci_run_id), options.runId, "provenance workflow run");
	assertEqual(statement.predicate?.invocation?.environment?.build_host, "github_actions", "provenance build host");
	const materials = statement.predicate?.materials;
	if (!Array.isArray(materials) || materials.length === 0) throw new Error("provenance declares no build materials");
	const lockMaterial = materials.find((entry) => uriBasename(entry?.uri) === path.basename(lockfile));
	if (!lockMaterial) throw new Error("provenance does not declare the pnpm lockfile");
	assertEqual(lockMaterial.digest?.sha256, sha256(await readFile(lockfile)), "provenance lockfile digest");
	const sbomPath = path.join(bundle, "aidr-sbom.cdx.json");
	const sbomByproduct = (statement.predicate?.byproducts ?? []).find((entry) => uriBasename(entry?.uri) === "aidr-sbom.cdx.json");
	if (!sbomByproduct) throw new Error("provenance does not declare the release SBOM");
	assertEqual(sbomByproduct.digest?.sha256, sha256(await readFile(sbomPath)), "provenance SBOM digest");
}

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function uriBasename(value) {
	return String(value ?? "").replaceAll("\\", "/").split("/").at(-1);
}

function parseArguments(argv) {
	const flags = new Set(["--record"]);
	const valued = new Set([
		"--bundle",
		"--policy",
		"--state",
		"--receipt",
		"--lockfile",
		"--expected-tag",
		"--expected-version",
		"--expected-sha",
		"--run-id",
	]);
	const values = {};
	for (let index = 0; index < argv.length; index += 1) {
		const flag = argv[index];
		if (flags.has(flag)) {
			values.record = true;
			continue;
		}
		if (!valued.has(flag) || !argv[index + 1]) throw new Error(`unknown or incomplete option: ${flag}`);
		values[flag.slice(2).replaceAll("-", "_")] = argv[++index];
	}
	for (const name of ["bundle", "policy", "state", "receipt", "lockfile", "expected_tag", "expected_version", "expected_sha", "run_id"]) {
		if (!values[name]) throw new Error(`--${name.replaceAll("_", "-")} is required`);
	}
	if (!/^v\d+\.\d+\.\d+-rc\.0$/.test(values.expected_tag)) throw new Error("--expected-tag is invalid");
	if (!/^\d+\.\d+\.\d+$/.test(values.expected_version)) throw new Error("--expected-version is invalid");
	if (!/^[0-9a-f]{40,64}$/i.test(values.expected_sha)) throw new Error("--expected-sha is invalid");
	if (!/^\d+$/.test(values.run_id)) throw new Error("--run-id is invalid");
	return {
		bundle: values.bundle,
		policy: values.policy,
		state: values.state,
		receipt: values.receipt,
		lockfile: values.lockfile,
		expectedTag: values.expected_tag,
		expectedVersion: values.expected_version,
		expectedSha: values.expected_sha,
		runId: values.run_id,
		record: values.record === true,
	};
}

function formatError(error) {
	return error instanceof Error ? error.message : String(error);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
	try {
		await verifyReleasePromotion(parseArguments(process.argv.slice(2)));
	} catch (error) {
		console.error(formatError(error));
		process.exitCode = 1;
	}
}
