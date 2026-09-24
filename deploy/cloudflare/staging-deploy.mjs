#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const configPath = path.join(root, "deploy/cloudflare/wrangler.jsonc");
const workerName = "aidr-pilot-staging";
const requiredSecrets = ["AIDR_PUBLIC_ORIGIN", "AIDR_SUPABASE_ORIGIN", "AIDR_SUPABASE_ANON_KEY", "AIDR_DEVICE_START_INGRESS_SECRET"];

function command(binary, args) {
	const result = spawnSync(binary, args, { cwd: root, encoding: "utf8" });
	if (result.error || result.status !== 0) throw new Error(`${binary} preflight failed`);
	return result.stdout.trim();
}

export function parseArgs(args) {
	const options = {};
	for (let i = 0; i < args.length; i += 2) {
		const key = args[i];
		if (!["--env", "--bundle", "--origin", "--mode", "--approval"].includes(key) || !args[i + 1] || options[key]) throw new Error(`Unknown or incomplete option: ${key}`);
		options[key] = args[i + 1];
	}
	if (options["--env"] !== "staging") throw new Error("Explicit --env staging is required; default and live deployments are refused");
	if (!["dry-run", "deploy"].includes(options["--mode"])) throw new Error("--mode must be dry-run or deploy");
	if (!options["--bundle"] || !options["--origin"]) throw new Error("--bundle and --origin are required");
	if (options["--mode"] === "deploy" && !options["--approval"]) throw new Error("Deployment requires a candidate-bound domain and SMTP approval file");
	if (process.env.CLOUDFLARE_ENV && process.env.CLOUDFLARE_ENV !== "staging") throw new Error("CLOUDFLARE_ENV conflicts with staging");
	return options;
}

export function validateStagingPlan({ config, manifest, distManifest, verifiedDigest, headSha, dirty, origin }) {
	const url = new URL(origin);
	if (url.origin !== origin || !new RegExp(`^${workerName}\\.[a-z0-9-]+\\.workers\\.dev$`).test(url.hostname) || url.protocol !== "https:") {
		throw new Error("Origin must be the separate staging workers.dev HTTPS origin");
	}
	const staging = config.env?.staging;
	if (config.name !== "aidr-pilot" || staging?.name !== workerName || staging.workers_dev !== true ||
		config.route || config.routes || staging.route || staging.routes || staging.vars?.AIDR_ENABLE_AZURE_AUTH !== "false" ||
		staging.vars?.AIDR_SIGNUP_MODE !== "closed" ||
		config.assets?.binding !== "ASSETS" || config.main !== "./worker.mjs" ||
		!requiredSecrets.every((name) => staging.secrets?.required?.includes(name)) ||
		!["/livez", "/healthz", "/readyz", "/metrics", "/version", "/functions/v1*"].every((route) => config.assets.run_worker_first?.includes(route))) {
		throw new Error("Wrangler staging isolation or Worker routing is invalid");
	}
	if (!/^[a-f0-9]{64}$/.test(verifiedDigest ?? "")) throw new Error("Signed release verification is required");
	if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(manifest.release_version ?? "") ||
		!/^[a-f0-9]{40}$/.test(manifest.git_sha ?? "") || manifest.git_sha !== headSha || dirty) {
		throw new Error("Unknown release SHA, version, or dirty source checkout");
	}
	if (distManifest.artifact_id !== "dashboard/dist" || distManifest.artifact_version !== manifest.release_version ||
		distManifest.provenance?.git_sha !== manifest.git_sha || distManifest.provenance?.rc_version !== manifest.release_version) {
		throw new Error("Dashboard build does not match the verified release candidate");
	}
	return { version: manifest.release_version, sha: manifest.git_sha, worker: workerName, origin };
}

export function wranglerArgs(plan, dryRun) {
	return ["dlx", "wrangler@4.137.0", "deploy", "--config", "deploy/cloudflare/wrangler.jsonc", "--env", "staging",
		"--strict", "--var", `AIDR_RELEASE_VERSION:${plan.version}`, "--var", `AIDR_RELEASE_SHA:${plan.sha}`,
		...(dryRun ? ["--dry-run"] : [])];
}

export async function verifyDashboardAssets(bundle, version, manifest, rawManifest, dist = path.join(root, "packages/dashboard/dist")) {
	const archiveName = `aidr-dashboard-dist-${version}.tar.gz`;
	const metadata = JSON.parse(await readFile(path.join(bundle, "release-metadata.json"), "utf8"));
	const expectedArchive = metadata.artifacts?.find((item) => item.path === archiveName);
	const archive = await readFile(path.join(bundle, archiveName));
	if (!expectedArchive || createHash("sha256").update(archive).digest("hex") !== expectedArchive.sha256) {
		throw new Error("Signed dashboard archive digest is missing or invalid");
	}
	const extracted = spawnSync("tar", ["-xOf", "-", "packages/dashboard/dist/aidr-artifact.manifest.json"], {
		input: archive, maxBuffer: 2 * 1024 * 1024,
	});
	if (extracted.error || extracted.status !== 0 || !extracted.stdout.equals(rawManifest)) {
		throw new Error("Dashboard manifest differs from the signed archive");
	}
	const expected = new Map();
	for (const file of manifest.files ?? []) {
		if (typeof file.path !== "string" || !/^[A-Za-z0-9._/-]+$/.test(file.path) ||
			file.path.split("/").some((part) => part === "." || part === ".." || part === "") ||
			!/^[a-f0-9]{64}$/.test(file.sha256 ?? "") || expected.has(file.path)) {
			throw new Error("Dashboard file manifest is invalid");
		}
		expected.set(file.path, file.sha256);
	}
	const found = [];
	async function visit(directory, prefix = "") {
		for (const entry of await readdir(directory, { withFileTypes: true })) {
			const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
			const absolute = path.join(directory, entry.name);
			const info = await lstat(absolute);
			if (info.isSymbolicLink()) throw new Error("Dashboard asset symlink is not allowed");
			if (info.isDirectory()) await visit(absolute, relative);
			else if (info.isFile()) found.push(relative);
			else throw new Error("Dashboard asset type is invalid");
		}
	}
	await visit(dist);
	const unsigned = found.filter((file) => !["aidr-artifact.manifest.json", "aidr-artifact.manifest.sig"].includes(file));
	if (unsigned.length !== expected.size || unsigned.some((file) => !expected.has(file))) {
		throw new Error("Dashboard assets differ from the signed manifest inventory");
	}
	for (const [file, digest] of expected) {
		const bytes = await readFile(path.join(dist, file));
		if (createHash("sha256").update(bytes).digest("hex") !== digest) throw new Error("Dashboard asset digest mismatch");
	}
}

async function main() {
	const options = parseArgs(process.argv.slice(2));
	const bundle = path.resolve(options["--bundle"]);
	const raw = await readFile(path.join(bundle, "aidr-release.manifest.json"));
	const digest = createHash("sha256").update(raw).digest("hex");
	if (digest !== process.env.AIDR_VERIFIED_RELEASE_MANIFEST_SHA256 ||
		process.env.AIDR_VERIFIED_RELEASE_VERSION !== JSON.parse(raw).release_version) {
		throw new Error("Release bundle was not verified in this process chain");
	}
	const [config, rawDistManifest] = await Promise.all([
		readFile(configPath, "utf8").then(JSON.parse),
		readFile(path.join(root, "packages/dashboard/dist/aidr-artifact.manifest.json")),
	]);
	const distManifest = JSON.parse(rawDistManifest);
	const plan = validateStagingPlan({
		config, manifest: JSON.parse(raw), distManifest, verifiedDigest: digest,
		headSha: command("git", ["rev-parse", "HEAD"]),
		dirty: Boolean(command("git", ["status", "--porcelain=v1", "--untracked-files=all"])),
		origin: options["--origin"],
	});
	await verifyDashboardAssets(bundle, plan.version, distManifest, rawDistManifest);
	if (options["--mode"] === "deploy") {
		const approval = JSON.parse(await readFile(options["--approval"], "utf8"));
		const named = (value) => typeof value === "string" && value.trim().length >= 3 && !/[<>]/.test(value);
		if (approval.release_sha !== plan.sha || approval.manifest_sha256 !== digest || approval.origin !== plan.origin ||
			!named(approval.domain_approved_by) || !named(approval.smtp_approved_by) || !named(approval.smtp_delivery_receipt) ||
			!/^[a-z0-9]{20}$/.test(approval.staging_supabase_project_ref ?? "") ||
			!Number.isFinite(Date.parse(approval.approved_at_utc))) {
			throw new Error("Domain, SMTP, and isolated Supabase approvals do not match this candidate");
		}
	}
	const args = wranglerArgs(plan, options["--mode"] === "dry-run");
	console.log(JSON.stringify({ mode: options["--mode"], ...plan }));
	const result = spawnSync(process.platform === "win32" ? "pnpm.cmd" : "pnpm", args, {
		cwd: root, stdio: "inherit", shell: process.platform === "win32",
	});
	if (result.error || result.status !== 0) throw new Error("Staging Wrangler command failed");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	main().catch((error) => { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; });
}
