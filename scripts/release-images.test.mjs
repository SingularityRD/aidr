/**
 * Release image bookkeeping (OPS-5): digest manifest, chart value pinning and
 * the scan gate used by .github/workflows/release-images.yml.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { COMPONENTS } from "../deploy/helm/build-images.mjs";
import {
	COMPONENT_VALUE_PATHS,
	assessScanSummary,
	buildReleaseManifest,
	parseImageRef,
	parseImagetoolsDigest,
	pinChartValues,
	scanPlan,
} from "./release-images.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { parse } = createRequire(path.join(root, "packages/core/package.json"))("yaml");
const valuesText = readFileSync(path.join(root, "deploy/helm/aidr/values.yaml"), "utf8");
const digest = (char) => `sha256:${char.repeat(64)}`;
const REGISTRY = "ghcr.io/singularityrd";

function imagesJson(components = COMPONENTS) {
	return {
		schema_version: 1,
		kind: "aidr-helm-images",
		tag: "0.6.0-rc.0",
		images: components.map((component) => ({ component, ref: `${REGISTRY}/aidr/${component}:0.6.0-rc.0` })),
	};
}

function manifestFor(components = COMPONENTS) {
	const input = imagesJson(components);
	const digests = Object.fromEntries(input.images.map(({ ref }, index) => [ref, digest("abcdef0"[index % 7])]));
	return buildReleaseManifest(input, digests, { sourceCommit: "c".repeat(40) });
}

function chartImages(values) {
	const found = [];
	const walk = (node, at) => {
		if (!node || typeof node !== "object") return;
		if (typeof node.repository === "string" && "digest" in node) found.push({ path: at, repository: node.repository });
		for (const [key, child] of Object.entries(node)) walk(child, [...at, key]);
	};
	walk(values, []);
	return found;
}

test("every first-party chart image and every build-images.mjs component has a values mapping", () => {
	assert.deepEqual(Object.keys(COMPONENT_VALUE_PATHS).sort(), [...COMPONENTS].sort());
	const mapped = new Set(Object.values(COMPONENT_VALUE_PATHS).flat().map((at) => at.join(".")));
	const firstParty = chartImages(parse(valuesText)).filter((image) => image.repository.startsWith("aidr/"));
	assert.ok(firstParty.length >= 9, `found ${firstParty.length} first-party images`);
	for (const image of firstParty) assert.ok(mapped.has(image.path.join(".")), `${image.path.join(".")} (${image.repository}) is not pinned by release-images.mjs`);
});

test("pinning sets registry, tag and digest on every AIDR image and leaves upstream images alone", () => {
	const manifest = manifestFor();
	const pinned = parse(pinChartValues(valuesText, manifest));
	for (const image of manifest.images) {
		for (const at of COMPONENT_VALUE_PATHS[image.component]) {
			const node = at.reduce((value, key) => value[key], pinned);
			assert.deepEqual({ registry: node.registry, repository: node.repository, tag: node.tag, digest: node.digest }, {
				registry: REGISTRY,
				repository: image.repository,
				tag: "0.6.0-rc.0",
				digest: image.digest,
			});
		}
	}
	const upstream = chartImages(pinned).filter((image) => !image.repository.startsWith("aidr/"));
	const original = chartImages(parse(valuesText)).filter((image) => !image.repository.startsWith("aidr/"));
	assert.deepEqual(upstream, original);
	assert.equal(pinned.apiGateway.image.registry, "docker.io");
	assert.equal(pinned.global.imageRegistry, "");
	// Comments survive, so the packaged values stay readable.
	assert.match(pinChartValues(valuesText, manifest), /# Registry prefix applied to EVERY image/u);
});

test("pinning refuses a manifest whose repository does not match the chart", () => {
	const manifest = manifestFor(["dashboard"]);
	manifest.images[0].repository = "aidr/other";
	assert.throws(() => pinChartValues(valuesText, manifest), /dashboard\.image\.repository is aidr\/dashboard, expected aidr\/other/u);
});

test("the release manifest requires a pushed digest, an immutable tag and a known component", () => {
	const input = imagesJson(["migrations"]);
	assert.throws(() => buildReleaseManifest(input, {}), /missing pushed digest/u);
	assert.throws(() => buildReleaseManifest({ ...input, kind: "other" }, {}), /images\.json/u);
	assert.throws(() => parseImageRef(`${REGISTRY}/aidr/dashboard:latest`), /immutable tag/u);
	assert.throws(() => buildReleaseManifest({ ...input, images: [{ component: "unknown", ref: `${REGISTRY}/aidr/unknown:1` }] }, {}), /no chart values mapping/u);
	const manifest = manifestFor(["migrations"]);
	assert.equal(manifest.images[0].pinned_ref, `${REGISTRY}/aidr/migrations:0.6.0-rc.0@${digest("a")}`);
	assert.deepEqual(scanPlan(manifest).images[0], {
		name: "migrations",
		service: "migrations",
		role: "candidate",
		image: `${REGISTRY}/aidr/migrations:0.6.0-rc.0`,
		ref: `${REGISTRY}/aidr/migrations:0.6.0-rc.0@${digest("a")}`,
	});
	assert.equal(parseImagetoolsDigest(JSON.stringify({ mediaType: "application/vnd.oci.image.index.v1+json", digest: digest("b") })), digest("b"));
	assert.throws(() => parseImagetoolsDigest("{}"), /no sha256 digest/u);
});

test("scan gate fails on incomplete scans and on fixable CRITICAL findings", () => {
	const image = (name, criticalFixable, succeeded = true) => ({ name, succeeded, counts: { CRITICAL: { findings: criticalFixable, fixed_available: criticalFixable }, HIGH: { findings: 3, fixed_available: 1 } } });
	assert.deepEqual(assessScanSummary({ completed: true, images: [image("dashboard", 0), image("migrations", 0)] }), []);
	assert.deepEqual(assessScanSummary({ completed: true, images: [image("dashboard", 2)] }), ["dashboard: 2 CRITICAL finding(s) with a fixed version available"]);
	assert.deepEqual(assessScanSummary({ completed: false, images: [{ name: "x", succeeded: false, failure: "timeout" }] }), [
		"image scan did not complete for every image",
		"x: scan failed (timeout)",
	]);
	assert.deepEqual(assessScanSummary({ images: [] }), ["scan summary has no images"]);
});
