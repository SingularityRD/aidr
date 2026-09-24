import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { verifyDeployedDashboard } from "./verify-deployed-dashboard.mjs";

const VERSION = "1.2.3";
const SHA = "a".repeat(40);
const baseUrl = "https://dashboard.example";
const assets = new Map([
	["index.html", Buffer.from("<html><div id=\"root\"></div></html>")],
	["assets/app.js", Buffer.from("console.log('AIDR')")],
	["assets/app.css", Buffer.from("body{color:black}")],
]);

async function fixture(manifestFile = "assets/app.js") {
	const directory = await mkdtemp(path.join(tmpdir(), "aidr-dashboard-verify-"));
	const dist = path.join(directory, "packages/dashboard/dist");
	await mkdir(path.join(dist, "assets"), { recursive: true });
	for (const [name, bytes] of assets) await writeFile(path.join(dist, name), bytes);
	const manifest = {
		artifact_id: "dashboard/dist",
		artifact_version: VERSION,
		provenance: { rc_version: VERSION, git_sha: SHA },
		files: [...assets].map(([name, bytes]) => ({ path: name === "assets/app.js" ? manifestFile : name, sha256: createHash("sha256").update(bytes).digest("hex") })),
	};
	await writeFile(path.join(dist, "aidr-artifact.manifest.json"), JSON.stringify(manifest));
	await writeFile(path.join(dist, "aidr-artifact.manifest.sig"), "fixture-signature");
	const archive = path.join(directory, "dashboard.tar.gz");
	const packed = spawnSync("tar", ["-czf", archive, "-C", directory, "packages/dashboard/dist"], { encoding: "utf8" });
	assert.equal(packed.status, 0, packed.stderr);
	return { directory, archive };
}

function serve(url) {
	if (new URL(url).pathname === "/demo") return new Response(null, { status: 302, headers: { location: "/login?returnTo=%2Fonboarding", "cache-control": "no-store" } });
	const name = new URL(url).pathname === "/" ? "index.html" : new URL(url).pathname.slice(1);
	const body = assets.get(name);
	return new Response(body ?? "missing", { status: body ? 200 : 404, headers: { "content-type": name.endsWith(".html") ? "text/html" : name.endsWith(".css") ? "text/css" : "text/javascript" } });
}

test("verifies dashboard archive provenance and every deployed SPA byte", async () => {
	const { directory, archive } = await fixture();
	try {
		const checked = [];
		const result = await verifyDeployedDashboard({ archive, baseUrl, expectedVersion: VERSION, expectedSha: SHA, fetchImpl: async (url) => { checked.push(url); return serve(url); } });
		assert.equal(result.status, "passed");
		assert.equal(result.verified_files, 3);
		assert.deepEqual(checked.sort(), [...assets.keys()].map((name) => `${baseUrl}/${name === "index.html" ? "" : name}`).concat(`${baseUrl}/demo`).sort());
		await assert.rejects(verifyDeployedDashboard({ archive, baseUrl, expectedVersion: VERSION, expectedSha: "b".repeat(40), fetchImpl: serve }), /provenance/);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("rejects SPA fallback, changed bytes, and redirects", async () => {
	const { directory, archive } = await fixture();
	try {
		for (const fetchImpl of [
			async (url) => url.endsWith("/assets/app.js") ? new Response("<html>fallback</html>", { headers: { "content-type": "text/html" } }) : serve(url),
			async (url) => url.endsWith("/assets/app.js") ? new Response("changed", { headers: { "content-type": "text/javascript" } }) : serve(url),
			async (url) => url.endsWith("/assets/app.js") ? new Response(null, { status: 302, headers: { location: "/" } }) : serve(url),
		]) {
			await assert.rejects(verifyDeployedDashboard({ archive, baseUrl, expectedVersion: VERSION, expectedSha: SHA, fetchImpl }), /fallback|differ|redirect/);
		}
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("rejects unsafe archive manifest paths", async () => {
	const { directory, archive } = await fixture("assets/../app.js");
	try {
		await assert.rejects(verifyDeployedDashboard({ archive, baseUrl, expectedVersion: VERSION, expectedSha: SHA, fetchImpl: serve }), /Unsafe dashboard archive path/);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("requires /demo to redirect to onboarding login without caching", async () => {
	const { directory, archive } = await fixture();
	try {
		for (const demo of [
			new Response("<html>demo</html>", { headers: { "content-type": "text/html" } }),
			new Response(null, { status: 302, headers: { location: "/dashboard", "cache-control": "no-store" } }),
			new Response(null, { status: 302, headers: { location: "/login?returnTo=%2Fonboarding" } }),
		]) {
			await assert.rejects(verifyDeployedDashboard({ archive, baseUrl, expectedVersion: VERSION, expectedSha: SHA, fetchImpl: async (url) => url.endsWith("/demo") ? demo : serve(url) }), /demo route/);
		}
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});
