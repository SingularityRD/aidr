#!/usr/bin/env node
/**
 * Release-image bookkeeping for .github/workflows/release-images.yml: turns the
 * images deploy/helm/build-images.mjs pushed into a digest manifest, pins the
 * Helm chart values to those digests, and gates the Trivy scan.
 *
 *   node scripts/release-images.mjs digests --images <images.json> --out <release-images.json>
 *       Resolve every pushed ref to its registry digest
 *       (`docker buildx imagetools inspect`) and write the release manifest.
 *   node scripts/release-images.mjs pin-chart --manifest <release-images.json> --values <values.yaml>
 *       Rewrite a STAGED COPY of deploy/helm/aidr/values.yaml so every AIDR
 *       image defaults to registry + tag + digest (comments are preserved).
 *   node scripts/release-images.mjs scan-plan --manifest <release-images.json> --out <plan.json>
 *       Plan for `scripts/scan-runtime-images.mjs scan` (digest refs only).
 *   node scripts/release-images.mjs gate --summary <summary.json>
 *       Fail when a scan did not complete or an image has a CRITICAL finding
 *       with a fixed version available.
 *
 * The tracked chart is never modified; the packaged chart carries the pins.
 */

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const { parseDocument } = createRequire(join(root, "packages/core/package.json"))("yaml");

/** Chart values paths that run each build-images.mjs component. */
export const COMPONENT_VALUE_PATHS = Object.freeze({
	dashboard: [
		["dashboard", "image"],
		["notifications", "dispatcher", "image"],
	],
	"edge-functions": [["functions", "image"]],
	migrations: [
		["migrations", "image"],
		["backup", "image"],
	],
	"posture-scanner-server": [["postureScanner", "server", "image"]],
	"posture-scanner-agent": [["postureScanner", "agent", "image"]],
	"posture-scanner-bridge": [["postureScanner", "bridge", "image"]],
	"privacy-gateway": [["privacyGateway", "image"]],
});

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const REF = /^([a-z0-9][a-z0-9.:-]*(?:\/[a-z0-9._-]+)*)\/(aidr\/[a-z0-9-]+):([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})$/u;

/** Split `registry/aidr/<name>:<tag>` as build-images.mjs writes it. */
export function parseImageRef(ref) {
	const match = REF.exec(ref);
	if (!match) throw new Error(`unexpected image reference: ${ref}`);
	const [, registry, repository, tag] = match;
	if (tag === "latest") throw new Error(`${ref}: release images need an immutable tag`);
	return { registry, repository, tag };
}

/** Digest of the pushed image index/manifest from `imagetools inspect --format '{{json .Manifest}}'`. */
export function parseImagetoolsDigest(json) {
	const digest = JSON.parse(json)?.digest;
	if (!DIGEST.test(digest ?? "")) throw new Error("imagetools returned no sha256 digest");
	return digest;
}

/** Build the release manifest from images.json and a ref -> digest map. */
export function buildReleaseManifest(imagesJson, digests, { sourceCommit = null } = {}) {
	if (imagesJson?.kind !== "aidr-helm-images") throw new Error("not a build-images.mjs images.json");
	const images = imagesJson.images.map(({ component, ref }) => {
		if (!COMPONENT_VALUE_PATHS[component]) throw new Error(`no chart values mapping for component ${component}`);
		const digest = digests[ref];
		if (!DIGEST.test(digest ?? "")) throw new Error(`${ref}: missing pushed digest`);
		return { component, ref, ...parseImageRef(ref), digest, pinned_ref: `${ref}@${digest}` };
	});
	if (new Set(images.map((image) => image.component)).size !== images.length) throw new Error("duplicate component in images.json");
	return { schema_version: 1, kind: "aidr-release-images", tag: imagesJson.tag, source_commit: sourceCommit, images };
}

/** Pin the chart values (YAML text) to the manifest's registry, tag and digest. */
export function pinChartValues(valuesText, manifest) {
	const document = parseDocument(valuesText);
	if (document.errors.length > 0) throw new Error(`values.yaml does not parse: ${document.errors[0]}`);
	for (const image of manifest.images) {
		for (const path of COMPONENT_VALUE_PATHS[image.component]) {
			const current = document.getIn([...path, "repository"]);
			if (current !== image.repository) throw new Error(`${path.join(".")}.repository is ${current}, expected ${image.repository}`);
			document.setIn([...path, "registry"], image.registry);
			document.setIn([...path, "tag"], image.tag);
			document.setIn([...path, "digest"], image.digest);
		}
	}
	return String(document);
}

/** Plan input for scripts/scan-runtime-images.mjs (role "candidate", digest refs). */
export function scanPlan(manifest) {
	return {
		images: manifest.images.map((image) => ({
			name: image.component,
			service: image.component,
			role: "candidate",
			image: image.ref,
			ref: image.pinned_ref,
		})),
	};
}

/** Release gate over scan-runtime-images.mjs summary.json. */
export function assessScanSummary(summary) {
	const failures = [];
	if (!summary || !Array.isArray(summary.images) || summary.images.length === 0) return ["scan summary has no images"];
	if (summary.completed !== true) failures.push("image scan did not complete for every image");
	for (const image of summary.images) {
		if (!image.succeeded) {
			failures.push(`${image.name}: scan failed (${image.failure ?? "no result"})`);
			continue;
		}
		const fixable = image.counts?.CRITICAL?.fixed_available;
		if (!Number.isInteger(fixable)) failures.push(`${image.name}: scan summary has no CRITICAL counts`);
		else if (fixable > 0) failures.push(`${image.name}: ${fixable} CRITICAL finding(s) with a fixed version available`);
	}
	return failures;
}

function inspectDigest(ref) {
	const result = spawnSync("docker", ["buildx", "imagetools", "inspect", ref, "--format", "{{json .Manifest}}"], { encoding: "utf8" });
	if (result.status !== 0) throw new Error(`imagetools inspect failed for ${ref}: ${(result.stderr ?? "").trim().slice(0, 300)}`);
	return parseImagetoolsDigest(result.stdout);
}

const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const writeJson = (path, value) => writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);

export function main(argv = process.argv.slice(2)) {
	const [command, ...rest] = argv;
	const { values } = parseArgs({
		args: rest,
		options: { images: { type: "string" }, out: { type: "string" }, manifest: { type: "string" }, values: { type: "string" }, summary: { type: "string" } },
	});
	const need = (...names) => {
		for (const name of names) if (!values[name]) throw new Error(`--${name} is required for ${command}`);
	};
	if (command === "digests") {
		need("images", "out");
		const imagesJson = readJson(values.images);
		const digests = Object.fromEntries(imagesJson.images.map(({ ref }) => [ref, inspectDigest(ref)]));
		const manifest = buildReleaseManifest(imagesJson, digests, { sourceCommit: process.env.GITHUB_SHA ?? null });
		writeJson(values.out, manifest);
		for (const image of manifest.images) console.log(image.pinned_ref);
	} else if (command === "pin-chart") {
		need("manifest", "values");
		writeFileSync(values.values, pinChartValues(readFileSync(values.values, "utf8"), readJson(values.manifest)));
	} else if (command === "scan-plan") {
		need("manifest", "out");
		writeJson(values.out, scanPlan(readJson(values.manifest)));
	} else if (command === "gate") {
		need("summary");
		const failures = assessScanSummary(readJson(values.summary));
		if (failures.length > 0) {
			console.error("Release image scan gate failed:");
			for (const failure of failures) console.error(`- ${failure}`);
			return 1;
		}
		console.log("Release image scan gate passed.");
	} else {
		throw new Error("usage: release-images.mjs <digests|pin-chart|scan-plan|gate> ...");
	}
	return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	try {
		process.exitCode = main();
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode = 2;
	}
}
