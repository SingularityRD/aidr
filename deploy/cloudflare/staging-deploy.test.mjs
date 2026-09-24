import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { parseArgs, validateStagingPlan, verifyDashboardAssets, wranglerArgs } from "./staging-deploy.mjs";

const sha = "a".repeat(40);
const origin = "https://aidr-pilot-staging.example.workers.dev";
const manifest = { release_version: "1.2.3-rc.1", git_sha: sha };
const distManifest = { artifact_id: "dashboard/dist", artifact_version: manifest.release_version,
	provenance: { git_sha: sha, rc_version: manifest.release_version } };
const digest = "b".repeat(64);

test("staging preflight rejects default, live, and unapproved deployments", () => {
	for (const env of ["default", "production", "pilot"]) {
		assert.throws(() => parseArgs(["--env", env, "--bundle", "signed", "--origin", origin, "--mode", "dry-run"]), /--env staging/);
	}
	assert.throws(() => parseArgs(["--env", "staging", "--bundle", "signed", "--origin", origin, "--mode", "deploy"]), /approval file/);
	assert.equal(parseArgs(["--env", "staging", "--bundle", "signed", "--origin", origin, "--mode", "dry-run"])["--env"], "staging");
});

test("staging config and release identity stay isolated from the live pilot", async () => {
	const config = JSON.parse(await readFile(new URL("./wrangler.jsonc", import.meta.url), "utf8"));
	const input = { config, manifest, distManifest, verifiedDigest: digest, headSha: sha, dirty: false, origin };
	const plan = validateStagingPlan(input);
	assert.equal(plan.worker, "aidr-pilot-staging");
	const args = wranglerArgs(plan, true);
	assert.deepEqual(args.slice(args.indexOf("--env"), args.indexOf("--env") + 2), ["--env", "staging"]);
	assert.ok(args.includes(`AIDR_RELEASE_SHA:${sha}`));
	assert.ok(args.includes("--dry-run"));
	assert.throws(() => validateStagingPlan({ ...input, headSha: "c".repeat(40) }), /Unknown release SHA/);
	assert.throws(() => validateStagingPlan({ ...input, dirty: true }), /dirty source checkout/);
	assert.throws(() => validateStagingPlan({ ...input, origin: "https://aidr-pilot.example.workers.dev" }), /separate staging/);
	assert.throws(() => validateStagingPlan({ ...input, config: { ...config, route: "live.example.com/*" } }), /staging isolation/);
	assert.throws(() => validateStagingPlan({ ...input, config: { ...config, env: { ...config.env, staging: { ...config.env.staging, vars: { ...config.env.staging.vars, AIDR_SIGNUP_MODE: "cloud" } } } } }), /staging isolation/);
});

test("staging rejects dashboard bytes that differ from the signed archive", async (t) => {
	const temporary = await mkdtemp(path.join(tmpdir(), "aidr-staging-"));
	t.after(() => rm(temporary, { recursive: true, force: true }));
	const dist = path.join(temporary, "packages/dashboard/dist");
	const bundle = path.join(temporary, "bundle");
	await mkdir(dist, { recursive: true });
	await mkdir(bundle);
	const html = Buffer.from("<html>signed</html>");
	const fileHash = createHash("sha256").update(html).digest("hex");
	const signedManifest = { files: [{ path: "index.html", sha256: fileHash }] };
	const rawManifest = Buffer.from(JSON.stringify(signedManifest));
	await writeFile(path.join(dist, "index.html"), html);
	await writeFile(path.join(dist, "aidr-artifact.manifest.json"), rawManifest);
	await writeFile(path.join(dist, "aidr-artifact.manifest.sig"), "signature");
	const archiveName = `aidr-dashboard-dist-${manifest.release_version}.tar.gz`;
	const archivePath = path.join(bundle, archiveName);
	const result = spawnSync("tar", ["-czf", archivePath, "-C", temporary, "packages/dashboard/dist"]);
	assert.equal(result.status, 0);
	const archiveHash = createHash("sha256").update(await readFile(archivePath)).digest("hex");
	await writeFile(path.join(bundle, "release-metadata.json"), JSON.stringify({ artifacts: [{ path: archiveName, sha256: archiveHash }] }));
	await verifyDashboardAssets(bundle, manifest.release_version, signedManifest, rawManifest, dist);
	await writeFile(path.join(dist, "index.html"), "<html>changed</html>");
	await assert.rejects(verifyDashboardAssets(bundle, manifest.release_version, signedManifest, rawManifest, dist), /asset digest mismatch/);
});
