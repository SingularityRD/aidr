#!/usr/bin/env node
/** Compare the served dashboard with the already verified RC dashboard archive. */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";

const DIST_PREFIX = "packages/dashboard/dist/";
const MANIFEST = `${DIST_PREFIX}aidr-artifact.manifest.json`;
const MAX_ARCHIVE_BYTES = 128 * 1024 * 1024;
const MAX_TAR_BYTES = 256 * 1024 * 1024;
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_FILES = 256;
const DEADLINE_MS = 90_000;

function tar(archiveBytes, args, maxBuffer = 4 * 1024 * 1024) {
	const result = spawnSync(process.env.AIDR_TAR_BIN ?? "tar", [...args, "-"], { input: archiveBytes, maxBuffer, timeout: 20_000 });
	if (result.error || result.status !== 0) throw new Error(`Cannot read dashboard archive: ${result.error?.message ?? result.stderr?.toString("utf8").trim()}`);
	return result.stdout;
}

function member(archiveBytes, name, maxBytes = MAX_FILE_BYTES) {
	const result = spawnSync(process.env.AIDR_TAR_BIN ?? "tar", ["-xOf", "-", "--", name], { input: archiveBytes, maxBuffer: maxBytes + 1, timeout: 20_000 });
	if (result.error || result.status !== 0 || result.stdout.length > maxBytes) throw new Error(`Invalid or oversized dashboard archive member: ${name}`);
	return result.stdout;
}

function safeName(name) {
	const value = name.replace(/^\.\//, "");
	if (!/^[A-Za-z0-9._/-]+$/.test(value) || value.startsWith("/") || value.includes("//") || value.split("/").some((part) => part === "." || part === "..")) {
		throw new Error(`Unsafe dashboard archive path: ${name}`);
	}
	return value;
}

function digest(bytes) {
	return createHash("sha256").update(bytes).digest("hex");
}

function origin(value) {
	const url = new URL(value);
	if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") {
		throw new Error("--base-url must be an HTTPS origin");
	}
	return url.origin;
}

async function remoteBytes(url, fetchImpl, remainingMs, htmlExpected) {
	const response = await fetchImpl(url, { redirect: "manual", signal: AbortSignal.timeout(Math.min(10_000, remainingMs)), headers: { "cache-control": "no-cache" } });
	if (response.status !== 200 || (response.url && response.url !== url)) throw new Error(`Dashboard asset did not return HTTP 200 without redirect: ${url}`);
	const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
	if (htmlExpected && !contentType.includes("text/html")) throw new Error(`Dashboard root is not HTML: ${url}`);
	if (!htmlExpected && contentType.includes("text/html")) {
		throw new Error(`Dashboard asset returned an SPA fallback: ${url}`);
	}
	const declared = Number(response.headers.get("content-length"));
	if (declared > MAX_FILE_BYTES) throw new Error(`Dashboard asset exceeds the size limit: ${url}`);
	if (!response.body) throw new Error(`Dashboard asset has no response body: ${url}`);
	const chunks = [];
	let size = 0;
	for await (const chunk of response.body) {
		size += chunk.byteLength;
		if (size > MAX_FILE_BYTES) throw new Error(`Dashboard asset exceeds the size limit: ${url}`);
		chunks.push(chunk);
	}
	return Buffer.concat(chunks, size);
}

export async function verifyDeployedDashboard({ archive, baseUrl, expectedVersion, expectedSha, fetchImpl = fetch }) {
	if (!/^\d+\.\d+\.\d+$/.test(expectedVersion ?? "")) throw new Error("--expected-version must be a stable x.y.z version");
	if (!/^[0-9a-f]{40}$/.test(expectedSha ?? "")) throw new Error("--expected-sha must be a 40-character commit SHA");
	const base = origin(baseUrl);
	const archivePath = path.resolve(archive);
	if ((await stat(archivePath)).size > MAX_ARCHIVE_BYTES) throw new Error("Dashboard archive exceeds the size limit");
	const archiveFile = await readFile(archivePath);
	if (archiveFile.length > MAX_ARCHIVE_BYTES) throw new Error("Dashboard archive exceeds the size limit");
	const archiveBytes = gunzipSync(archiveFile, { maxOutputLength: MAX_TAR_BYTES });
	const listing = tar(archiveBytes, ["-tf"]).toString("utf8").trim().split("\n").map((name) => safeName(name.trimEnd()));
	const files = listing.filter((name) => !name.endsWith("/"));
	if (files.length !== new Set(files).size || !files.includes(MANIFEST)) throw new Error("Dashboard archive has duplicate files or no manifest");
	const manifest = JSON.parse(member(archiveBytes, MANIFEST, 2 * 1024 * 1024).toString("utf8"));
	if (manifest.artifact_id !== "dashboard/dist" || manifest.artifact_version !== expectedVersion ||
		manifest.provenance?.rc_version !== expectedVersion || manifest.provenance?.git_sha !== expectedSha) {
		throw new Error("Dashboard archive provenance does not match the candidate version and commit");
	}
	if (!Array.isArray(manifest.files)) throw new Error("Dashboard archive manifest has no files");
	const entries = new Map();
	for (const entry of manifest.files) {
		const name = safeName(entry.path);
		if (name !== entry.path || name.endsWith("/") || !/^[0-9a-f]{64}$/.test(entry.sha256 ?? "") || entries.has(name)) {
			throw new Error("Dashboard archive manifest has an invalid or duplicate file");
		}
		entries.set(name, entry.sha256);
	}
	const archivedDistFiles = files.filter((name) => name.startsWith(DIST_PREFIX) && ![MANIFEST, `${DIST_PREFIX}aidr-artifact.manifest.sig`].includes(name));
	if (archivedDistFiles.length !== entries.size || archivedDistFiles.some((name) => !entries.has(name.slice(DIST_PREFIX.length)))) {
		throw new Error("Dashboard archive files differ from its manifest");
	}
	const deployed = [...entries].filter(([name]) => name === "index.html" || name.startsWith("assets/"));
	if (!entries.has("index.html") || !deployed.some(([name]) => name.startsWith("assets/")) || deployed.length > MAX_FILES) {
		throw new Error("Dashboard archive must contain index.html and a bounded asset set");
	}
	const deadline = Date.now() + DEADLINE_MS;
	for (const [name, expectedDigest] of deployed) {
		if (Date.now() >= deadline) throw new Error("Dashboard remote verification timed out");
		const fileBytes = member(archiveBytes, `${DIST_PREFIX}${name}`);
		if (digest(fileBytes) !== expectedDigest) throw new Error(`Dashboard archive member does not match its manifest: ${name}`);
		const remainingMs = deadline - Date.now();
		if (remainingMs <= 0) throw new Error("Dashboard remote verification timed out");
		const url = new URL(name === "index.html" ? "/" : `/${name}`, base).href;
		const liveBytes = await remoteBytes(url, fetchImpl, remainingMs, name === "index.html");
		if (digest(liveBytes) !== expectedDigest) throw new Error(`Deployed dashboard bytes differ from the signed candidate: ${name}`);
	}
	const remainingMs = deadline - Date.now();
	if (remainingMs <= 0) throw new Error("Dashboard remote verification timed out");
	const demo = await fetchImpl(`${base}/demo`, { redirect: "manual", signal: AbortSignal.timeout(Math.min(10_000, remainingMs)), headers: { "cache-control": "no-cache" } });
	if (demo.status !== 302 || demo.headers.get("location") !== "/login?returnTo=%2Fonboarding" ||
		!demo.headers.get("cache-control")?.toLowerCase().includes("no-store")) {
		throw new Error("Deployed /demo route must redirect to onboarding login without caching");
	}
	return { status: "passed", version: expectedVersion, git_sha: expectedSha, archive_sha256: digest(archiveFile), verified_files: deployed.length, origin: base };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
	try {
		const args = {};
		for (let i = 2; i < process.argv.length; i += 2) {
			if (!["--archive", "--base-url", "--expected-version", "--expected-sha"].includes(process.argv[i]) || !process.argv[i + 1]) throw new Error(`Unknown or incomplete option: ${process.argv[i]}`);
			args[process.argv[i].slice(2).replaceAll("-", "_")] = process.argv[i + 1];
		}
		if (Object.keys(args).length !== 4) throw new Error("--archive, --base-url, --expected-version and --expected-sha are required");
		console.log(JSON.stringify(await verifyDeployedDashboard({ archive: args.archive, baseUrl: args.base_url, expectedVersion: args.expected_version, expectedSha: args.expected_sha })));
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode = 1;
	}
}
