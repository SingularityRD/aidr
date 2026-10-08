#!/usr/bin/env node
// Runtime image vulnerability scan for the self-hosted deployment kit.
//
//   node scripts/scan-runtime-images.mjs resolve --plan <in.json> --out <plan.json>
//     Resolves each `image` (repo:tag) to its multi-arch index digest via the
//     anonymous Docker Hub registry API and writes a plan with `ref` = repo:tag@sha256:...
//
//   node scripts/scan-runtime-images.mjs scan --plan <plan.json> --output <dir>
//        [--engine trivy|docker] [--platform linux/amd64] [--cache-dir <dir>] [--skip-db-update]
//     Scans every digest-pinned ref with Trivy (HIGH,CRITICAL, no ignore file, no config
//     file, remote image source) and writes a compact per-image report plus summary.json.
//
// Plan format: { "images": [{ "name": "realtime-current", "service": "realtime",
//   "role": "current" | "candidate", "image": "supabase/realtime:v2.134.10",
//   "ref": "supabase/realtime:v2.134.10@sha256:..." }] }
//
// The pure helpers (compactFindings, countFindings, buildSummary, compareImages) are
// exported for tests. Nothing here downgrades a failed scan to a clean result: a failed
// image carries `succeeded: false` and no counts.
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";

const SEVERITIES = ["CRITICAL", "HIGH"];
const DIGEST_REF = /^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$/;
const NAME = /^[a-z0-9][a-z0-9_-]*$/;

/** Flatten a Trivy JSON report into compact HIGH/CRITICAL findings. */
export function compactFindings(report) {
	return (report?.Results ?? []).flatMap((result) =>
		(result.Vulnerabilities ?? [])
			.filter((v) => SEVERITIES.includes(v.Severity))
			.map((v) => ({
				id: v.VulnerabilityID,
				severity: v.Severity,
				pkg: v.PkgName,
				installed: v.InstalledVersion,
				fixed: v.FixedVersion || null,
				status: v.Status ?? null,
				target: result.Target,
				type: result.Type ?? null,
			})),
	).sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.id.localeCompare(b.id) || a.pkg.localeCompare(b.pkg) || a.target.localeCompare(b.target));
}

/** Count findings (every package/target occurrence) and unique CVE ids, with fixed-available splits. */
export function countFindings(findings) {
	const counts = {};
	for (const severity of SEVERITIES) {
		const rows = findings.filter((f) => f.severity === severity);
		const fixed = rows.filter((f) => f.fixed);
		counts[severity] = {
			findings: rows.length,
			unique_ids: new Set(rows.map((f) => f.id)).size,
			fixed_available: fixed.length,
			fixed_available_unique_ids: new Set(fixed.map((f) => f.id)).size,
		};
	}
	counts.total_findings = counts.CRITICAL.findings + counts.HIGH.findings;
	return counts;
}

/** Compare a candidate's counts to the current image of the same service. */
export function compareImages(current, candidate) {
	if (!current?.succeeded || !candidate?.succeeded) return { eligible: false, reason: "scan missing or failed" };
	const currentCriticalIds = new Set(current.findings.filter((f) => f.severity === "CRITICAL").map((f) => f.id));
	const newCritical = [...new Set(candidate.findings.filter((f) => f.severity === "CRITICAL" && !currentCriticalIds.has(f.id)).map((f) => f.id))].sort();
	const delta = candidate.counts.total_findings - current.counts.total_findings;
	const eligible = delta < 0 && newCritical.length === 0;
	const reason = eligible ? "strictly fewer CRITICAL+HIGH findings and no new CRITICAL" : newCritical.length ? `introduces new CRITICAL: ${newCritical.join(", ")}` : `CRITICAL+HIGH not reduced (delta ${delta >= 0 ? "+" : ""}${delta})`;
	return { eligible, delta_critical_high: delta, new_critical_ids: newCritical, reason };
}

/** Build the summary document from per-image records. */
export function buildSummary({ scanner, platform, startedAt, finishedAt, images }) {
	const strip = ({ findings, ...rest }) => rest;
	const comparisons = [];
	for (const candidate of images.filter((i) => i.role === "candidate")) {
		const current = images.find((i) => i.role === "current" && i.service === candidate.service);
		comparisons.push({ service: candidate.service, current: current?.ref ?? null, candidate: candidate.ref, ...compareImages(current, candidate) });
	}
	const ok = images.filter((i) => i.succeeded);
	const totals = (role) => {
		const rows = ok.filter((i) => i.role === role);
		return { images: rows.length, CRITICAL: rows.reduce((n, i) => n + i.counts.CRITICAL.findings, 0), HIGH: rows.reduce((n, i) => n + i.counts.HIGH.findings, 0) };
	};
	return {
		schema_version: 1,
		started_at: startedAt,
		finished_at: finishedAt,
		completed: images.every((i) => i.succeeded),
		scanner,
		platform,
		policy: { severities: SEVERITIES, ignore_file: "none (empty file)", config_file: "none (empty file)", scanners: "vuln", counting: "findings = every package/target occurrence reported by Trivy; unique_ids = distinct vulnerability ids" },
		totals: { current: totals("current"), candidate: totals("candidate") },
		images: images.map(strip),
		comparisons,
	};
}

function run(command, args, options = {}) {
	const result = spawnSync(command, args, { encoding: "utf8", windowsHide: true, maxBuffer: 64 * 1024 * 1024, ...options });
	return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "", error: result.error?.code ?? null };
}

function readPlan(path) {
	const plan = JSON.parse(readFileSync(path, "utf8"));
	const images = Array.isArray(plan) ? plan : plan.images;
	if (!Array.isArray(images) || images.length === 0) throw new Error("plan has no images");
	for (const image of images) {
		if (!NAME.test(image.name ?? "")) throw new Error(`invalid image name: ${image.name}`);
		if (!["current", "candidate"].includes(image.role)) throw new Error(`${image.name}: role must be current or candidate`);
	}
	if (new Set(images.map((i) => i.name)).size !== images.length) throw new Error("duplicate image names in plan");
	return images;
}

async function resolveDigest(image) {
	const match = /^(?:docker\.io\/)?([a-z0-9][a-z0-9._/-]*):([A-Za-z0-9._-]+)$/.exec(image);
	if (!match) throw new Error(`unsupported image reference (Docker Hub repo:tag only): ${image}`);
	const repo = match[1].includes("/") ? match[1] : `library/${match[1]}`;
	const tokenResponse = await fetch(`https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull`);
	if (!tokenResponse.ok) throw new Error(`token request failed for ${repo}: ${tokenResponse.status}`);
	const { token } = await tokenResponse.json();
	const accept = ["application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"].join(", ");
	const response = await fetch(`https://registry-1.docker.io/v2/${repo}/manifests/${match[2]}`, { headers: { Authorization: `Bearer ${token}`, Accept: accept } });
	if (!response.ok) throw new Error(`manifest request failed for ${image}: ${response.status}`);
	const digest = response.headers.get("docker-content-digest");
	const body = await response.json();
	if (!/^sha256:[a-f0-9]{64}$/.test(digest ?? "")) throw new Error(`no content digest for ${image}`);
	const amd64 = (body.manifests ?? []).find((m) => m.platform?.os === "linux" && m.platform?.architecture === "amd64");
	return { digest, media_type: response.headers.get("content-type"), linux_amd64_manifest: amd64?.digest ?? (body.manifests ? null : digest) };
}

async function resolveCommand(values) {
	const images = readPlan(values.plan);
	for (const image of images) {
		const resolved = await resolveDigest(image.image);
		Object.assign(image, { ref: `${image.image}@${resolved.digest}`, index_media_type: resolved.media_type, linux_amd64_manifest: resolved.linux_amd64_manifest, resolved_at: new Date().toISOString() });
		console.log(`${image.name}\t${image.ref}`);
	}
	writeFileSync(values.out, `${JSON.stringify({ images }, null, 2)}\n`);
}

function scannerCommand(engine, cacheDir) {
	if (engine === "trivy") return { command: "trivy", prefix: [], cache: cacheDir };
	// Docker engine: run the official Trivy image with a mounted cache, no host config visible.
	return { command: "docker", prefix: ["run", "--rm", "--read-only", "--tmpfs", "/tmp", "--mount", `type=bind,src=${cacheDir},dst=/cache`, "aquasec/trivy:latest"], cache: "/cache" };
}

function scanCommand(values) {
	const images = readPlan(values.plan);
	for (const image of images) if (!DIGEST_REF.test(image.ref ?? "")) throw new Error(`${image.name}: ref must be repo:tag@sha256:<digest>`);
	const engine = values.engine ?? (run("trivy", ["--version"]).status === 0 ? "trivy" : "docker");
	const output = resolve(values.output);
	const cacheDir = resolve(values["cache-dir"] ?? join(output, ".trivy-cache"));
	mkdirSync(output, { recursive: true });
	mkdirSync(cacheDir, { recursive: true });
	const scanner = scannerCommand(engine, cacheDir);
	// Empty working dir + empty ignore/config files so no ambient .trivyignore or trivy.yaml applies.
	const work = mkdtempSync(join(tmpdir(), "aidr-image-scan-"));
	try {
		writeFileSync(join(work, "empty.trivyignore"), "");
		writeFileSync(join(work, "empty-trivy.yaml"), "{}\n");
		const hostFiles = engine === "trivy";
		const common = ["--cache-dir", scanner.cache, "--quiet", "--no-progress"];
		if (hostFiles) common.push("--config", join(work, "empty-trivy.yaml"));
		if (!values["skip-db-update"]) {
			const update = run(scanner.command, [...scanner.prefix, "image", "--download-db-only", ...common], { cwd: work, timeout: 900_000 });
			if (update.status !== 0) throw new Error(`trivy DB download failed: ${update.error ?? update.status} ${update.stderr.slice(-500)}`);
		}
		const version = run(scanner.command, [...scanner.prefix, "version", "--format", "json", "--cache-dir", scanner.cache], { cwd: work });
		if (version.status !== 0) throw new Error(`trivy version failed: ${version.stderr.slice(-500)}`);
		const versionInfo = JSON.parse(version.stdout);
		const scannerInfo = { engine, version: versionInfo.Version, vulnerability_db: versionInfo.VulnerabilityDB ?? null, java_db: versionInfo.JavaDB ?? null };
		const platform = values.platform ?? "linux/amd64";
		const startedAt = new Date().toISOString();
		const records = [];
		for (const image of images) {
			const reportPath = join(work, `${image.name}.json`);
			const flags = ["image", "--image-src", "remote", "--platform", platform, "--scanners", "vuln", "--severity", SEVERITIES.join(","), "--skip-db-update", "--format", "json", "--output", engine === "trivy" ? reportPath : "/dev/stdout", "--timeout", "30m", ...common];
			if (hostFiles) flags.push("--ignorefile", join(work, "empty.trivyignore"));
			const record = { name: image.name, service: image.service, role: image.role, image: image.image, ref: image.ref, linux_amd64_manifest: image.linux_amd64_manifest ?? null, started_at: new Date().toISOString(),
				flags: flags.map((flag) => flag.replace(work, "<tmp>").replace(scanner.cache, "<cache-dir>")) };
			console.error(`scanning ${image.name} (${image.ref})`);
			const result = run(scanner.command, [...scanner.prefix, ...flags, image.ref], { cwd: work, timeout: 2_400_000 });
			record.exit_code = result.status;
			try {
				if (result.status !== 0) throw new Error(`scanner exit ${result.error ?? result.status}: ${result.stderr.slice(-800)}`);
				const report = JSON.parse(engine === "trivy" ? readFileSync(reportPath, "utf8") : result.stdout);
				record.os = report.Metadata?.OS ?? null;
				record.scanned_image_id = report.Metadata?.ImageID ?? null;
				record.repo_digests = report.Metadata?.RepoDigests ?? [];
				record.findings = compactFindings(report);
				record.counts = countFindings(record.findings);
				record.succeeded = true;
			} catch (error) {
				record.succeeded = false;
				record.failure = error.message;
			}
			record.finished_at = new Date().toISOString();
			writeFileSync(join(output, `${image.name}.json`), `${JSON.stringify(record, null, 1)}\n`);
			records.push(record);
			console.error(`  ${record.succeeded ? `CRITICAL=${record.counts.CRITICAL.findings} HIGH=${record.counts.HIGH.findings}` : `FAILED ${record.failure}`}`);
		}
		const summary = buildSummary({ scanner: scannerInfo, platform, startedAt, finishedAt: new Date().toISOString(), images: records });
		writeFileSync(join(output, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
		return summary.completed ? 0 : 1;
	} finally {
		rmSync(work, { recursive: true, force: true });
	}
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
	const [command, ...rest] = process.argv.slice(2);
	const { values } = parseArgs({ args: rest, options: {
		plan: { type: "string" }, out: { type: "string" }, output: { type: "string" }, engine: { type: "string" },
		platform: { type: "string" }, "cache-dir": { type: "string" }, "skip-db-update": { type: "boolean" },
	} });
	try {
		if (!values.plan) throw new Error("--plan is required");
		if (command === "resolve") {
			if (!values.out) throw new Error("--out is required");
			await resolveCommand(values);
		} else if (command === "scan") {
			if (!values.output) throw new Error("--output is required");
			if (values.engine && !["trivy", "docker"].includes(values.engine)) throw new Error("--engine must be trivy or docker");
			process.exitCode = scanCommand(values);
		} else throw new Error("usage: scan-runtime-images.mjs <resolve|scan> --plan <file> ...");
	} catch (error) {
		console.error(error.message);
		process.exitCode = 2;
	}
}
