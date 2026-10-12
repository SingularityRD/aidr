/**
 * GO-chain rehearsal for .github/workflows/release-promote.yml:
 * dry-run → promote → rollback, driven by a FAKE GO record.
 *
 *   node --test scripts/release-go-chain-simulation.test.mjs
 *
 * ┌──────────────────────────────────────────────────────────────────────────┐
 * │ LOCAL SIMULATION. NOT A GITHUB ACTIONS RUN. NOT A PRODUCTION GO.          │
 * │ Every GO record here is synthetic. It is written only into a disposable   │
 * │ copy of the trusted verifier checkout under the OS temp directory. The    │
 * │ real commercial-go-evidence-registry.json and commercial-gate-receipts.json│
 * │ are read, never written.                                                  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * GitHub Actions is disabled for this repository, and `act` cannot run these
 * jobs faithfully. The jobs download artifacts from other workflow runs by
 * run ID, verify GitHub/Sigstore build attestations and use production
 * environment secrets (see docs/production-readiness/go-chain-simulation-2026-10-11.md).
 * So this file is a small workflow runner. It parses release-promote.yml and
 * runs each job's steps in order:
 *
 *   - every `run:` step is executed VERBATIM with `bash --noprofile --norc -eo
 *     pipefail`, using the step's own `env:` (with `${{ }}` expressions
 *     resolved) and the runner files GITHUB_OUTPUT/GITHUB_ENV/GITHUB_PATH. This
 *     covers verify-release-run, verify-release-promotion,
 *     stage-verified-artifact-roots, verify-production-go --record / --rollback,
 *     find-release-state-run and the npm publication plan;
 *   - GitHub API calls (RC run identity, artifact lookup) go to a loopback
 *     HTTPS fake of the GitHub REST API with a throwaway self-signed CA
 *     (NODE_EXTRA_CA_CERTS). The trusted-API-origin check is not bypassed;
 *   - `uses:` actions are emulated: checkout clones the fixture RC repository
 *     at the tag and the trusted verifier repository at github.workflow_sha,
 *     and upload/download-artifact use
 *     an in-memory artifact store keyed by run ID;
 *   - publication is stubbed. `npm` is a PATH shim that records every call
 *     and never contacts a registry. Dashboard deploy, rollback retag and the
 *     GitHub release are recorded, not performed;
 *   - NOT simulated: `gh attestation verify` (needs GitHub's attestation API
 *     and Sigstore) and the pinned gh download. Both are listed as stubs.
 *
 * The RC bundle is built and signed locally: Ed25519 via
 * scripts/release-sign.mjs, with SBOM, provenance, npm tarballs and dist
 * archives for every registry artifactRoot. The trusted verifier is a git copy
 * of this working tree. A fake GO overlay is committed on top of it: decision
 * GO, every hard gate closed, receipts and investor metrics bound to the
 * candidate digest, all with fixture evidence. The real claim-check gate and
 * receipt verifier then judge it.
 */

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { appendFileSync, copyFileSync, cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:https";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, delimiter, dirname, join, resolve } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { CANDIDATE_DIGEST_SOURCE } from "./generate-v8-evidence-index.mjs";
import { REGISTRY_FILE } from "./verify-commercial-gate-receipts.mjs";
import { LEDGER_GENESIS, LEDGER_SCHEMA, ledgerEntryDigest, verifyLedgerChain } from "./verify-production-go.mjs";
import { DICTIONARY_FILE, TEMPLATE_FILE } from "./validate-investor-metric-dictionary.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WORKFLOW_FILE = ".github/workflows/release-promote.yml";
const { parse: parseYaml } = createRequire(join(ROOT, "packages/core/package.json"))("yaml");
const WORKFLOW = parseYaml(readFileSync(join(ROOT, WORKFLOW_FILE), "utf8"));

const REPOSITORY = "singularityrd/aidr";
const DEFAULT_BRANCH = "main";
const TOKEN = "go-chain-simulation-token";
const LEDGER_NAME = "production-go-ledger.json";
const STATE_ARTIFACT = "aidr-promotion-anti-rollback-state";
const GO_STEP = "Require candidate-bound production GO (trusted verifier)";
const ROLLBACK_GO_STEP = "Require a recorded production GO for the rollback candidate (trusted verifier)";
const FIRST_PUBLISH_STEP = "Publish verified npm packages under rc dist-tag";
// The npm packages release-promote.yml publishes; every other registry
// artifactRoot ships as an aidr-<name>-dist-<version>.tar.gz archive.
const NPM_PACKAGES = ["core", "openclaw", "opencode", "sdk", "cli", "codex"];
const MARK = "LOCAL SIMULATION FIXTURE (scripts/release-go-chain-simulation.test.mjs) - not evidence, not an approval";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const iso = (ms) => new Date(Math.floor(ms / 1000) * 1000).toISOString();
const DAY = 86_400_000;

// `run:` steps the simulation records instead of executing, with the reason.
// Each name must exist in the workflow (asserted below), so renaming a step
// fails this file instead of silently dropping it.
const STUBBED_RUN_STEPS = {
	"Install pinned GitHub CLI for attestation verification": { reason: "downloads gh from github.com; only needed for attestation verification, which is not simulated", mutation: null },
	"Verify GitHub build attestations for every release file": { reason: "NOT SIMULATED: needs GitHub's attestation API and Sigstore trust roots for real release-rc.yml provenance", mutation: null },
	"Promote the exact dashboard commit and run remote smoke": { reason: "calls the production dashboard deploy hook, version endpoint and smoke URLs", mutation: "dashboard-deploy (stubbed)" },
	"Retag verified npm versions and dashboard deployment": { reason: "npm pack/dist-tag against the private registry and the dashboard rollback hook", mutation: "rollback-retag npm dist-tags + dashboard (stubbed)" },
};

const tools = ["bash", "git", "openssl", "tar", "sha256sum", "awk"].filter((tool) => spawnSync("sh", ["-c", `command -v ${tool}`]).status !== 0);
const SKIP = process.platform === "win32" ? "the workflow steps are bash on Linux" : tools.length > 0 ? `missing ${tools.join(", ")}` : false;

// ─── minimal deterministic tar writer (regular files only) ────────────────

function tarHeader(name, size, mode) {
	const header = Buffer.alloc(512);
	header.write(name, 0, 100, "utf8");
	header.write(`${mode.toString(8).padStart(7, "0")}\0`, 100, "ascii");
	header.write("0000000\0", 108, "ascii");
	header.write("0000000\0", 116, "ascii");
	header.write(`${size.toString(8).padStart(11, "0")}\0`, 124, "ascii");
	header.write("00000000000\0", 136, "ascii");
	header.write("        ", 148, "ascii");
	header.write("0", 156, "ascii");
	header.write("ustar\0", 257, "ascii");
	header.write("00", 263, "ascii");
	const sum = header.reduce((total, byte) => total + byte, 0);
	header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
	return header;
}

function tgz(entries) {
	const blocks = [];
	for (const [name, content] of entries) {
		const data = Buffer.from(content);
		blocks.push(tarHeader(name, data.length, 0o644), data, Buffer.alloc((512 - (data.length % 512)) % 512));
	}
	blocks.push(Buffer.alloc(1024));
	return gzipSync(Buffer.concat(blocks));
}

// ─── fixtures ─────────────────────────────────────────────────────────────

function git(cwd, ...args) {
	const result = spawnSync("git", ["-c", "user.name=go-chain-simulation", "-c", "user.email=simulation@invalid", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "init.defaultBranch=main", ...args], {
		cwd,
		encoding: "utf8",
		maxBuffer: 64 * 1024 * 1024,
		env: { PATH: process.env.PATH, HOME: cwd, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" },
	});
	if (result.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
	return result.stdout.trim();
}

function signingKeys() {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const fingerprint = `sha256:${sha256(publicKey.export({ type: "spki", format: "der" }))}`;
	const policy = {
		schema_version: 1,
		policy_id: "go-chain-simulation-policy",
		product_id: "singularity-aidr",
		allowed_channels: ["stable"],
		minimum_release_sequence: 1,
		maximum_signature_lifetime_seconds: 7200,
		trusted_signers: [
			{
				key_id: "simulation-release-key",
				public_key_pem: publicKey.export({ type: "spki", format: "pem" }).toString(),
				fingerprint_sha256: fingerprint,
				valid_from: iso(Date.now() - DAY),
				valid_until: iso(Date.now() + DAY),
			},
		],
		revoked_key_ids: [],
		revoked_fingerprints: [],
	};
	return { privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(), policyJson: JSON.stringify(policy) };
}

/**
 * A complete, signed RC bundle shaped like release-rc.yml's output: the six
 * npm tarballs the promote job publishes, a dist archive for every other
 * registry artifact root, a CycloneDX SBOM with checksum sidecar, release
 * provenance bound to the RC lockfile, commit and run ID, release metadata and
 * inventory, then a release-sign.mjs signature over all of it.
 */
function buildSignedBundle(dir, { version, tag, gitSha, runId, lockBytes, sequence, artifactRoots, privateKeyPath, variant = "" }) {
	mkdirSync(dir, { recursive: true });
	const files = new Map();
	const subjects = [];
	const roots = artifactRoots.map((root) => /^packages\/([a-z0-9-]+)\/dist$/u.exec(root)?.[1]);
	assert.ok(roots.every(Boolean), `unexpected artifact root in ${artifactRoots.join(", ")}`);
	for (const name of NPM_PACKAGES) assert.ok(roots.includes(name), `the registry no longer names packages/${name}/dist`);
	for (const name of roots) {
		const manifest = `${JSON.stringify({ artifact_id: `${name}/dist`, release_version: version, note: MARK })}\n`;
		const signature = `${MARK}\n`;
		const body = name === "dashboard" ? ["index.html", '<!doctype html><html><head><title>AIDR</title></head><body><div id="root"></div></body></html>\n'] : ["index.js", `export const fixture = ${JSON.stringify(`${name}@${version}${variant}`)};\n`];
		if (NPM_PACKAGES.includes(name)) {
			files.set(
				`singularityrd-aidr-${name}-${version}.tgz`,
				tgz([
					["package/package.json", `${JSON.stringify({ name: `@singularityrd/aidr-${name}`, version, license: "UNLICENSED" })}\n`],
					[`package/dist/${body[0]}`, body[1]],
					["package/dist/aidr-artifact.manifest.json", manifest],
					["package/dist/aidr-artifact.manifest.sig", signature],
				]),
			);
			subjects.push({ name: `${name}/dist`, digest: { sha256: sha256(manifest) } });
		} else {
			files.set(
				`aidr-${name}-dist-${version}.tar.gz`,
				tgz([
					[`packages/${name}/dist/${body[0]}`, body[1]],
					[`packages/${name}/dist/aidr-artifact.manifest.json`, manifest],
					[`packages/${name}/dist/aidr-artifact.manifest.sig`, signature],
				]),
			);
		}
	}
	const sbom = `${JSON.stringify({
		bomFormat: "CycloneDX",
		specVersion: "1.5",
		metadata: { component: { type: "application", "bom-ref": "urn:aidr:workspace", name: "AIDR" } },
		components: [{ type: "library", name: "simulation-fixture", "bom-ref": "pkg:npm/simulation-fixture@1.0.0", licenses: [{ license: { id: "MIT" } }], hashes: [{ alg: "SHA-256", content: "b".repeat(64) }] }],
		dependencies: [{ ref: "urn:aidr:workspace", dependsOn: ["pkg:npm/simulation-fixture@1.0.0"] }, { ref: "pkg:npm/simulation-fixture@1.0.0", dependsOn: [] }],
	})}\n`;
	files.set("aidr-sbom.cdx.json", sbom);
	files.set("aidr-sbom.cdx.json.sha256", `${sha256(sbom)}  aidr-sbom.cdx.json\n`);
	files.set(
		"aidr-provenance.intoto.json",
		`${JSON.stringify({
			_type: "https://in-toto.io/Statement/v0.1",
			predicateType: "https://slsa.dev/provenance/v0.2",
			subject: subjects,
			predicate: {
				builder: { id: "urn:aidr:go-chain-simulation" },
				buildType: "https://singularityrd.dev/aidr/release-artifact-manifests/v1",
				invocation: { parameters: { release_version: version, git_sha: gitSha, ci_run_id: String(runId) }, environment: { build_host: "github_actions" } },
				materials: [{ uri: "file:///workspace/pnpm-lock.yaml", digest: { sha256: sha256(lockBytes) } }],
				byproducts: [{ uri: "file:///workspace/aidr-sbom.cdx.json", digest: { sha256: sha256(sbom) } }],
			},
		})}\n`,
	);
	const rows = [...files].map(([name, content]) => ({ name, bytes: Buffer.from(content) }));
	for (const { name, bytes } of rows) writeFileSync(join(dir, name), bytes);
	writeFileSync(
		join(dir, "release-metadata.json"),
		`${JSON.stringify({ schema_version: 1, release_tag: tag, release_version: version, git_sha: gitSha, source_date_epoch: 1_789_167_600, worktree_dirty: false, artifacts: rows.map(({ name, bytes }) => ({ path: name, size: bytes.length, sha256: sha256(bytes) })) }, null, 2)}\n`,
	);
	const inventory = Buffer.from(`${JSON.stringify({ schema_version: 1, artifacts: rows.map(({ name, bytes }) => ({ source_path: `release-output/${name}`, staged_path: name, kind: "release-artifact", sha256: sha256(bytes) })) }, null, 2)}\n`);
	writeFileSync(join(dir, "release-inventory.json"), inventory);
	const signed = spawnSync(
		process.execPath,
		[join(ROOT, "scripts/release-sign.mjs"), "--bundle", dir, "--private-key", privateKeyPath, "--key-id", "simulation-release-key", "--sequence", String(sequence), "--issued-at", iso(Date.now() - 60_000), "--expires-at", iso(Date.now() + 3_600_000)],
		{ cwd: ROOT, encoding: "utf8" },
	);
	assert.equal(signed.status, 0, `release-sign.mjs failed: ${signed.stderr}`);
	return { dir, version, tag, gitSha, runId, digest: sha256(inventory), inventory };
}

/**
 * The trusted verifier checkout: a git copy of this working tree (tracked and
 * untracked-but-not-ignored files), without vendored sources or build output,
 * so the claim gate can only see artifact roots staged from the verified
 * bundle.
 */
function copyTrustedTree(destination) {
	const listed = spawnSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { cwd: ROOT, encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
	assert.equal(listed.status, 0, listed.stderr);
	for (const path of listed.stdout.split("\0")) {
		// Vendored trees keep only their top-level files (LICENSE/NOTICE are licence-check inputs).
		if (!path || /^vendor\/[^/]+\/[^/]+\//u.test(path) || /^(?:images|\.ci-local)\//u.test(path) || /(?:^|\/)(?:dist|node_modules|\.git)\//u.test(path)) continue;
		const source = join(ROOT, path);
		const info = lstatSync(source, { throwIfNoEntry: false });
		if (!info?.isFile()) continue;
		mkdirSync(dirname(join(destination, path)), { recursive: true });
		copyFileSync(source, join(destination, path));
	}
	git(destination, "init", "-q");
	git(destination, "add", "-A");
	git(destination, "commit", "-q", "-m", "trusted verifier (simulation copy of the working tree)");
	return git(destination, "rev-parse", "HEAD");
}

const writeJson = (path, value) => {
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
};

/**
 * Commit a FAKE GO record for one candidate on top of a copy of the trusted
 * tree. Every hard gate is closed. Each receipt and investor metric points at
 * fixture evidence under fixture-go-evidence/ that says it is a simulation.
 * Nothing here is copied back to the repository.
 */
function fakeGoVariant(base, destination, candidate) {
	git(dirname(destination), "clone", "-q", base, destination);
	const now = Date.now();
	const evidenceDir = "fixture-go-evidence";
	const put = (name, content) => {
		mkdirSync(join(destination, evidenceDir), { recursive: true });
		writeFileSync(join(destination, evidenceDir, name), content);
		return { path: `${evidenceDir}/${name}`, sha256: sha256(Buffer.from(content)) };
	};
	const evidence = put("gate-evidence.txt", `${MARK}\ncandidate ${candidate.digest}\n`);
	const report = put("assessment-report.txt", `${MARK}\nsigned report placeholder\n`);
	const retest = put("assessment-retest.txt", `${MARK}\nretest letter placeholder\n`);
	const assessment = put(
		"assessment.json",
		`${JSON.stringify({
			schema_version: 1,
			candidate_digest: candidate.digest,
			assessor_name: "simulation-assessor",
			scope: ["tenant", "identity", "runtime", "distribution", "secrets"],
			started_at_utc: iso(now - 10 * DAY),
			completed_at_utc: iso(now - 9 * DAY),
			retest_at_utc: iso(now - 8 * DAY),
			valid_until_utc: iso(now + 90 * DAY),
			unresolved_critical: 0,
			unresolved_high: 0,
			signed_report: report,
			retest_letter: retest,
		})}\n`,
	);
	const candidateRef = put("candidate-release-inventory.json", candidate.inventory);
	const metricEvidence = put("investor-metric-evidence.txt", `${MARK}\n`);

	const registryPath = join(destination, REGISTRY_FILE);
	const registry = JSON.parse(readFileSync(registryPath, "utf8"));
	registry.decision = "GO";
	registry.releaseCandidate = candidate.digest;
	registry.lastReviewed = iso(now - DAY).slice(0, 10);
	for (const gate of registry.hardGates) gate.status = "closed";
	writeJson(registryPath, registry);

	const receiptsPath = join(destination, registry.hardGateReceipts.receiptsPath);
	const receipts = JSON.parse(readFileSync(receiptsPath, "utf8")).map((receipt) => ({
		...receipt,
		decision: "closed",
		owner_name: "simulation-owner",
		evidence_path: receipt.gate_id === "SEC-EXT-001" ? assessment.path : evidence.path,
		evidence_sha256: receipt.gate_id === "SEC-EXT-001" ? assessment.sha256 : evidence.sha256,
		candidate_digest: candidate.digest,
		effective_version: candidate.version,
		recorded_at_utc: iso(now - 2 * DAY),
		reviewer_name: "simulation-reviewer",
		reviewer_role: "Independent Reviewer (simulation)",
	}));
	writeJson(receiptsPath, receipts);

	// INV-001 closes only when every investor metric is HELD and bound to the candidate.
	const dictionaryPath = join(destination, DICTIONARY_FILE);
	const dictionary = JSON.parse(readFileSync(dictionaryPath, "utf8"));
	dictionary.status = "HELD";
	dictionary.metrics = dictionary.metrics.map((metric) => ({
		...metric,
		...Object.fromEntries(["formula", "denominator", "source"].map((field) => [field, metric[field] === "unknown" ? `simulation ${field}` : metric[field]])),
		source_query: "simulation fixture query",
		candidate: candidate.tag,
		candidate_digest: candidate.digest,
		candidate_ref: candidateRef.path,
		environment: "go-chain-simulation",
		fixture_version: "simulation-1",
		window: "simulation window",
		sample_size: 1,
		target_actual_status: "target_not_set",
		confidence: "none (simulation)",
		owner: "simulation-owner",
		reviewer: "simulation-reviewer",
		evidence_ref: metricEvidence.path,
		evidence_sha256: metricEvidence.sha256,
		reviewed_at_utc: iso(now - 2 * DAY),
		limitations: ["Simulation fixture; not a measurement"],
		status: "HELD",
	}));
	writeJson(dictionaryPath, dictionary);
	const templatePath = join(destination, TEMPLATE_FILE);
	const byId = new Map(dictionary.metrics.map((metric) => [metric.metric_id, metric]));
	const cell = (value) => String(value).replaceAll("|", "\\|");
	const template = readFileSync(templatePath, "utf8")
		.split("\n")
		.map((line) => {
			const id = /^\|\s*(INV-M\d{3})\s*\|/u.exec(line)?.[1];
			const metric = id && byId.get(id);
			if (!metric) return line;
			const cells = [metric.metric_id, metric.name, metric.formula, metric.denominator, metric.source, metric.candidate, metric.environment, metric.window, metric.owner, metric.reviewer, metric.limitations.join("; "), metric.status];
			return `| ${cells.map(cell).join(" | ")} |`;
		})
		.join("\n");
	writeFileSync(templatePath, template);

	git(destination, "add", "-A");
	git(destination, "commit", "-q", "-m", `FAKE GO for ${candidate.digest} (local simulation fixture)`);
	return { dir: destination, sha: git(destination, "rev-parse", "HEAD"), registrySha256: sha256(readFileSync(registryPath)), receiptsSha256: sha256(readFileSync(receiptsPath)) };
}

// ─── fake GitHub: REST API (loopback HTTPS) and artifact store ────────────

function selfSignedCert(dir) {
	const result = spawnSync(
		"openssl",
		["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"), "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
		{ encoding: "utf8" },
	);
	assert.equal(result.status, 0, result.stderr);
	return { key: readFileSync(join(dir, "key.pem")), cert: readFileSync(join(dir, "cert.pem")), certPath: join(dir, "cert.pem") };
}

function startFakeGitHub(world, tls) {
	const prefix = `/api/v3/repos/${REPOSITORY}/actions`;
	const server = createServer({ key: tls.key, cert: tls.cert }, (request, response) => {
		const url = new URL(request.url, "https://127.0.0.1");
		const send = (status, body) => {
			response.writeHead(status, { "content-type": "application/json" });
			response.end(JSON.stringify(body));
		};
		world.apiCalls.push(url.pathname);
		if (request.headers.authorization !== `Bearer ${TOKEN}`) return send(401, { message: "Bad credentials" });
		const run = new RegExp(`^${prefix}/runs/(\\d+)$`, "u").exec(url.pathname);
		if (run) return world.runs.has(run[1]) ? send(200, world.runs.get(run[1])) : send(404, { message: "Not Found" });
		if (url.pathname === `${prefix}/artifacts`) {
			const name = url.searchParams.get("name");
			const artifacts = world.artifacts.filter((artifact) => !name || artifact.name === name).map((artifact) => ({ name: artifact.name, expired: false, created_at: artifact.createdAt, workflow_run: { id: Number(artifact.runId) } }));
			return send(200, { total_count: artifacts.length, artifacts });
		}
		return send(404, { message: "Not Found" });
	});
	return new Promise((resolvePromise) => server.listen(0, "127.0.0.1", () => resolvePromise(server)));
}

function storeArtifact(world, name, runId, sources) {
	const dir = join(world.tmp, "artifact-store", `${runId}-${name}`);
	rmSync(dir, { recursive: true, force: true });
	mkdirSync(dir, { recursive: true });
	let count = 0;
	for (const source of sources) {
		if (!existsSync(source)) continue;
		if (lstatSync(source).isDirectory()) {
			cpSync(source, dir, { recursive: true });
			count += readdirSync(source).length;
		} else {
			copyFileSync(source, join(dir, basename(source)));
			count += 1;
		}
	}
	world.artifacts = world.artifacts.filter((artifact) => !(artifact.name === name && artifact.runId === String(runId)));
	world.artifacts.push({ name, runId: String(runId), dir, createdAt: new Date(Date.UTC(2026, 0, 1) + world.clock++ * 60_000).toISOString() });
	return count;
}

const findArtifact = (world, name, runId) => world.artifacts.find((artifact) => artifact.name === name && artifact.runId === String(runId));
const latestState = (world) => world.artifacts.filter((artifact) => artifact.name === STATE_ARTIFACT).at(-1);

// ─── the workflow runner ──────────────────────────────────────────────────

function resolveExpression(expression, context) {
	const path = expression.trim();
	if (!/^[A-Za-z_][\w-]*(?:\.[\w-]+)*$/u.test(path)) throw new Error(`unsupported workflow expression \${{ ${expression} }}`);
	const [head, ...rest] = path.split(".");
	if (!["inputs", "secrets", "github", "runner", "env", "steps"].includes(head)) throw new Error(`unsupported expression context ${head}`);
	let value = context[head];
	for (const key of rest) value = value?.[key];
	if (value !== undefined && typeof value === "object") throw new Error(`expression ${path} resolves to an object`);
	return value === undefined || value === null ? "" : String(value);
}

const interpolate = (value, context) => String(value).replace(/\$\{\{([^}]*)\}\}/gu, (_, expression) => resolveExpression(expression, context));

function condition(expression, context) {
	const match = /^\s*([\w.-]+)\s*(==|!=)\s*'([^']*)'\s*$/u.exec(expression);
	if (!match) throw new Error(`unsupported if: ${expression}`);
	const actual = resolveExpression(match[1], context);
	return match[2] === "==" ? actual === match[3] : actual !== match[3];
}

function runBash(script, { cwd, env }) {
	return new Promise((resolvePromise) => {
		const child = spawn("bash", ["--noprofile", "--norc", "-eo", "pipefail", script], { cwd, env });
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk) => (stdout += chunk));
		child.stderr.on("data", (chunk) => (stderr += chunk));
		child.on("close", (code) => resolvePromise({ code, stdout, stderr }));
	});
}

function readRunnerFile(path) {
	const values = {};
	if (!existsSync(path)) return values;
	const lines = readFileSync(path, "utf8").split("\n");
	for (let index = 0; index < lines.length; index += 1) {
		const heredoc = /^([^=<]+)<<(.+)$/u.exec(lines[index]);
		if (heredoc) {
			const body = [];
			while (++index < lines.length && lines[index] !== heredoc[2]) body.push(lines[index]);
			values[heredoc[1]] = body.join("\n");
		} else if (lines[index].includes("=")) {
			values[lines[index].slice(0, lines[index].indexOf("="))] = lines[index].slice(lines[index].indexOf("=") + 1);
		}
	}
	return values;
}

function npmShim(dir) {
	mkdirSync(dir, { recursive: true });
	const path = join(dir, "npm");
	writeFileSync(
		path,
		[
			"#!/usr/bin/env bash",
			"# go-chain simulation: records npm calls, never contacts a registry.",
			'printf "%s\\tnpm %s\\n" "${AIDR_SIM_STEP}" "$*" >> "${AIDR_SIM_MUTATION_LOG}"',
			'case "$1" in',
			"  config|publish|dist-tag) exit 0 ;;",
			'  view) echo "npm error code E404" >&2; echo "npm error 404 Not Found (simulation: nothing is published)" >&2; exit 1 ;;',
			'  *) echo "npm shim: unsupported command $1" >&2; exit 1 ;;',
			"esac",
			"",
		].join("\n"),
		{ mode: 0o755 },
	);
	return dir;
}

/**
 * Run one job of release-promote.yml. Returns the step trace and the
 * mutation log: npm calls from the shim, plus stubbed deploy/release steps.
 */
async function runJob(world, jobId, { inputs, trusted }) {
	const job = WORKFLOW.jobs[jobId];
	assert.ok(job, `release-promote.yml has no ${jobId} job`);
	const runId = String(world.nextRunId++);
	const runDir = join(world.tmp, "runs", `${runId}-${jobId}`);
	const workspace = join(runDir, "workspace");
	const runnerTemp = join(runDir, "runner-temp");
	mkdirSync(workspace, { recursive: true });
	mkdirSync(runnerTemp, { recursive: true });
	const mutationLog = join(runDir, "mutations.log");
	writeFileSync(mutationLog, "");
	world.runs.set(runId, { id: Number(runId), status: "in_progress", conclusion: null, event: "workflow_dispatch", path: `${WORKFLOW_FILE}@refs/heads/${DEFAULT_BRANCH}`, head_branch: DEFAULT_BRANCH, head_sha: trusted.sha, repository: { full_name: REPOSITORY, default_branch: DEFAULT_BRANCH } });

	const context = {
		inputs,
		secrets: {
			GITHUB_TOKEN: TOKEN,
			AIDR_RELEASE_SIGNER_POLICY_JSON: world.policyJson,
			DASHBOARD_DEPLOY_HOOK_URL: "https://dashboard.invalid/deploy",
			DASHBOARD_ROLLBACK_HOOK_URL: "https://dashboard.invalid/rollback",
			DASHBOARD_VERSION_URL: "https://dashboard.invalid/version",
			DASHBOARD_SMOKE_BASE_URL: "https://dashboard.invalid",
		},
		github: { token: TOKEN, ref: `refs/heads/${DEFAULT_BRANCH}`, workflow_sha: trusted.sha, run_id: runId, event: { repository: { default_branch: DEFAULT_BRANCH } } },
		runner: { temp: runnerTemp },
		env: {},
		steps: {},
	};
	for (const [key, value] of Object.entries(WORKFLOW.env ?? {})) context.env[key] = interpolate(value, context);
	assert.ok(condition(job.if, context), `job ${jobId} would not run for ${JSON.stringify(inputs)}`);
	const addedPaths = [];
	const trace = [];
	let failed = null;

	for (const [index, step] of job.steps.entries()) {
		const entry = { name: step.name, kind: step.uses ? "action" : STUBBED_RUN_STEPS[step.name] ? "stub" : "run", outcome: "success", stdout: "", stderr: "" };
		trace.push(entry);
		if (failed) {
			entry.outcome = "not-run";
			continue;
		}
		if (step.if && !condition(step.if, context)) {
			entry.outcome = "skipped";
			continue;
		}
		try {
			if (step.uses) await runAction(world, step, { context, workspace, runId, trusted, mutationLog, entry });
			else if (STUBBED_RUN_STEPS[step.name]) {
				entry.stdout = `stubbed: ${STUBBED_RUN_STEPS[step.name].reason}`;
				if (STUBBED_RUN_STEPS[step.name].mutation) appendFileSync(mutationLog, `${step.name}\t${STUBBED_RUN_STEPS[step.name].mutation}\n`);
			} else {
				const files = Object.fromEntries(["GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_PATH"].map((name) => [name, join(runnerTemp, `${name.toLowerCase()}-${index}`)]));
				const script = join(runnerTemp, `step-${index}.sh`);
				writeFileSync(script, step.run);
				const stepEnv = Object.fromEntries(Object.entries(step.env ?? {}).map(([key, value]) => [key, interpolate(value, context)]));
				const result = await runBash(script, {
					cwd: workspace,
					env: {
						...world.baseEnv,
						PATH: [...addedPaths, world.shimDir, world.baseEnv.PATH].join(delimiter),
						GITHUB_WORKSPACE: workspace,
						RUNNER_TEMP: runnerTemp,
						GITHUB_RUN_ID: runId,
						GITHUB_SHA: trusted.sha,
						GITHUB_WORKFLOW_SHA: trusted.sha,
						AIDR_SIM_STEP: step.name,
						AIDR_SIM_MUTATION_LOG: mutationLog,
						...context.env,
						...stepEnv,
						...files,
					},
				});
				Object.assign(entry, { stdout: result.stdout, stderr: result.stderr });
				if (result.code !== 0) throw new Error(`exit ${result.code}`);
				if (step.id) context.steps[step.id] = { outputs: readRunnerFile(files.GITHUB_OUTPUT) };
				Object.assign(context.env, readRunnerFile(files.GITHUB_ENV));
				if (existsSync(files.GITHUB_PATH)) addedPaths.unshift(...readFileSync(files.GITHUB_PATH, "utf8").split("\n").filter(Boolean));
			}
		} catch (problem) {
			entry.outcome = "failure";
			entry.stderr += `\n${problem.message}`;
			failed = entry;
		}
	}
	world.runs.get(runId).status = "completed";
	world.runs.get(runId).conclusion = failed ? "failure" : "success";
	const mutations = readFileSync(mutationLog, "utf8").split("\n").filter(Boolean).map((line) => ({ step: line.split("\t")[0], action: line.split("\t")[1] }));
	return { runId, conclusion: failed ? "failure" : "success", failedStep: failed?.name ?? null, trace, mutations, runnerTemp, context, step: (name) => trace.find((candidate) => candidate.name === name) };
}

async function runAction(world, step, { context, workspace, runId, trusted, mutationLog, entry }) {
	const action = step.uses.split("@")[0];
	const options = Object.fromEntries(Object.entries(step.with ?? {}).map(([key, value]) => [key, interpolate(value, context)]));
	switch (action) {
		case "actions/checkout": {
			if (options.path === ".trusted-release-verifier") {
				assert.equal(options.ref, trusted.sha, "the trusted verifier must be checked out at github.workflow_sha");
				git(workspace, "clone", "-q", "--no-checkout", trusted.dir, options.path);
				git(join(workspace, options.path), "checkout", "-q", "--detach", options.ref);
			} else {
				assert.equal(options.path, undefined, `unexpected checkout path ${options.path}`);
				git(dirname(workspace), "clone", "-q", world.rcOrigin, workspace);
				git(workspace, "checkout", "-q", "--detach", `refs/tags/${options.ref}`);
			}
			entry.stdout = `emulated checkout of ${options.ref}`;
			return;
		}
		case "actions/setup-node":
			entry.stdout = `emulated: workflow pins Node ${options["node-version"]}; simulation runs ${process.version}`;
			return;
		case "actions/download-artifact": {
			const artifact = findArtifact(world, options.name, options["run-id"]);
			if (!artifact) throw new Error(`no artifact ${options.name} in run ${options["run-id"]}`);
			const destination = resolve(workspace, options.path);
			mkdirSync(destination, { recursive: true });
			cpSync(artifact.dir, destination, { recursive: true });
			entry.stdout = `emulated download of ${options.name} from run ${options["run-id"]}`;
			return;
		}
		case "actions/upload-artifact": {
			const sources = options.path.split("\n").map((line) => line.trim()).filter(Boolean).map((path) => resolve(workspace, path));
			const count = storeArtifact(world, options.name, runId, sources);
			if (count === 0 && options["if-no-files-found"] === "error") throw new Error(`no files found for artifact ${options.name}`);
			entry.stdout = `emulated upload of ${count} file(s) as ${options.name}`;
			return;
		}
		case "softprops/action-gh-release":
			appendFileSync(mutationLog, `${step.name}\tgithub-release ${options.tag_name} (stubbed)\n`);
			entry.stdout = "stubbed: would publish the GitHub release";
			return;
		default:
			throw new Error(`the simulation has no emulation for ${step.uses}`);
	}
}

// ─── the world ────────────────────────────────────────────────────────────

const world = { tmp: null, server: null, artifacts: [], runs: new Map(), apiCalls: [], nextRunId: 5001, clock: 0 };
const promoteInputs = (tag, rcRunId) => ({ action: "promote", tag, rc_run_id: String(rcRunId), rollback_version: "", bad_version: "", confirm: "" });
const rollbackInputs = (bundle) => ({ action: "rollback", tag: bundle.tag, rc_run_id: String(bundle.runId), rollback_version: bundle.version, bad_version: "", confirm: "" });
const npmCalls = (result, verb) => result.mutations.filter((mutation) => mutation.action.startsWith(`npm ${verb}`));
const stepLog = (entry) => `${entry?.stdout ?? ""}\n${entry?.stderr ?? ""}`;
const describeRun = (result) => result.trace.map((entry) => `${entry.outcome.padEnd(8)} ${entry.kind.padEnd(6)} ${entry.name}${entry.outcome === "failure" ? `\n${stepLog(entry)}` : ""}`).join("\n");

before(async () => {
	if (SKIP) return;
	world.tmp = mkdtempSync(join(tmpdir(), "aidr-go-chain-simulation-"));
	const keys = signingKeys();
	world.policyJson = keys.policyJson;
	const privateKeyPath = join(world.tmp, "offline-release-key.pem");
	writeFileSync(privateKeyPath, keys.privateKeyPem, { mode: 0o600 });

	// The RC repository the tags live in (the workflow reads only its commit
	// identity and pnpm-lock.yaml).
	world.rcOrigin = join(world.tmp, "rc-origin");
	mkdirSync(world.rcOrigin);
	git(world.rcOrigin, "init", "-q");
	const shas = {};
	for (const version of ["9.9.8", "9.9.9"]) {
		writeFileSync(join(world.rcOrigin, "pnpm-lock.yaml"), `lockfileVersion: '9.0'\n# ${MARK}: ${version}\n`);
		git(world.rcOrigin, "add", "-A");
		git(world.rcOrigin, "commit", "-q", "-m", `RC ${version} (simulation fixture)`);
		git(world.rcOrigin, "tag", `v${version}-rc.0`);
		shas[version] = { sha: git(world.rcOrigin, "rev-parse", "HEAD"), lock: readFileSync(join(world.rcOrigin, "pnpm-lock.yaml")) };
	}

	const artifactRoots = JSON.parse(readFileSync(join(ROOT, REGISTRY_FILE), "utf8")).artifactRoots;
	const rc = (version, runId, sequence, variant = "") => {
		const tag = `v${version}-rc.0`;
		const bundle = buildSignedBundle(join(world.tmp, "rc-bundles", `${runId}`), { version, tag, gitSha: shas[version].sha, runId, lockBytes: shas[version].lock, sequence, artifactRoots, privateKeyPath, variant });
		world.runs.set(String(runId), { id: runId, status: "completed", conclusion: "success", event: "push", path: ".github/workflows/release-rc.yml", head_branch: tag, head_sha: shas[version].sha, repository: { full_name: REPOSITORY, default_branch: DEFAULT_BRANCH } });
		storeArtifact(world, `aidr-release-${tag}`, runId, [bundle.dir]);
		return bundle;
	};
	world.rc998 = rc("9.9.8", 1001, 8);
	world.rc999 = rc("9.9.9", 1002, 9);
	// Same tag, commit and version as rc999, rebuilt: a different inventory digest.
	world.rc999rebuilt = rc("9.9.9", 1003, 9, "-rebuilt");
	assert.notEqual(world.rc999.digest, world.rc999rebuilt.digest);

	const trustedBase = join(world.tmp, "trusted", "no-go");
	world.trustedNoGo = { dir: trustedBase, sha: copyTrustedTree(trustedBase) };
	world.trustedGo999 = fakeGoVariant(trustedBase, join(world.tmp, "trusted", "go-9.9.9"), world.rc999);
	world.trustedGo998 = fakeGoVariant(trustedBase, join(world.tmp, "trusted", "go-9.9.8"), world.rc998);

	const tls = selfSignedCert(world.tmp);
	world.server = await startFakeGitHub(world, tls);
	const origin = `https://127.0.0.1:${world.server.address().port}`;
	world.shimDir = npmShim(join(world.tmp, "shims"));
	const home = join(world.tmp, "home");
	mkdirSync(home);
	world.baseEnv = {
		PATH: [dirname(process.execPath), ...(process.env.PATH ?? "").split(delimiter)].join(delimiter),
		HOME: home,
		LANG: "C.UTF-8",
		CI: "true",
		GITHUB_ACTIONS: "true",
		GITHUB_REPOSITORY: REPOSITORY,
		GITHUB_SERVER_URL: origin,
		GITHUB_API_URL: `${origin}/api/v3`,
		GITHUB_REF: `refs/heads/${DEFAULT_BRANCH}`,
		GIT_CONFIG_NOSYSTEM: "1",
		NODE_EXTRA_CA_CERTS: tls.certPath,
		NO_PROXY: "127.0.0.1,localhost",
	};
});

after(async () => {
	if (world.server) await new Promise((resolvePromise) => world.server.close(resolvePromise));
	// AIDR_GO_CHAIN_SIMULATION_KEEP=1 keeps the runs, workspaces and fake GO trees for inspection.
	if (world.tmp && process.env.AIDR_GO_CHAIN_SIMULATION_KEEP !== "1") rmSync(world.tmp, { recursive: true, force: true });
	else if (world.tmp) console.log(`go-chain simulation kept at ${world.tmp}`);
});

// ─── scenarios ────────────────────────────────────────────────────────────

test("the simulation covers every step of the promote, dry-run and rollback jobs", { skip: SKIP }, () => {
	for (const name of Object.keys(STUBBED_RUN_STEPS)) {
		assert.ok(Object.values(WORKFLOW.jobs).some((job) => job.steps.some((step) => step.name === name && step.run)), `stubbed step "${name}" is no longer a run: step of ${WORKFLOW_FILE}`);
	}
	const names = (jobId) => WORKFLOW.jobs[jobId].steps.map((step) => step.name);
	const promote = names("promote");
	const order = ["Verify RC identity, manifest, SBOM and signatures", "Stage signature-verified artifact roots for the claim gate", GO_STEP, "Persist anti-rollback state and verification receipt (pinned)", FIRST_PUBLISH_STEP];
	assert.deepEqual(order.map((name) => promote.indexOf(name)), [...order.map((name) => promote.indexOf(name))].sort((a, b) => a - b), "promote must verify, stage and pass GO before persisting state and publishing");
	assert.ok(order.every((name) => promote.includes(name)));
	const rollback = names("rollback");
	assert.ok(rollback.indexOf("Verify rollback RC signature and identity") < rollback.indexOf(ROLLBACK_GO_STEP));
	assert.ok(rollback.indexOf(ROLLBACK_GO_STEP) < rollback.indexOf("Retag verified npm versions and dashboard deployment"));
	const goRun = WORKFLOW.jobs.promote.steps.find((step) => step.name === GO_STEP).run;
	assert.match(goRun, /verify-production-go\.mjs[\s\S]*--ledger "\$\{RUNNER_TEMP\}\/aidr-promotion-state\/production-go-ledger\.json"[\s\S]*--record/u);
	assert.match(WORKFLOW.jobs.rollback.steps.find((step) => step.name === ROLLBACK_GO_STEP).run, /verify-production-go\.mjs[\s\S]*--rollback/u);
});

test("dry-run job: the signed fixture RC verifies and publication is only rehearsed", { skip: SKIP }, async () => {
	const result = await runJob(world, "dry-run", { inputs: { ...promoteInputs(world.rc999.tag, world.rc999.runId), action: "dry-run" }, trusted: world.trustedNoGo });
	assert.equal(result.conclusion, "success", describeRun(result));
	const publishes = npmCalls(result, "publish");
	assert.equal(publishes.length, NPM_PACKAGES.length);
	assert.ok(publishes.every((call) => / --dry-run /u.test(call.action)), "the dry-run job never publishes for real");
	assert.ok(world.apiCalls.includes(`/api/v3/repos/${REPOSITORY}/actions/runs/${world.rc999.runId}`), "verify-release-run queried the (fake) GitHub API for the RC run");
});

test("promote with the shipped NO-GO registry is refused at the GO gate, before any publish", { skip: SKIP }, async () => {
	const result = await runJob(world, "promote", { inputs: promoteInputs(world.rc999.tag, world.rc999.runId), trusted: world.trustedNoGo });
	assert.equal(result.conclusion, "failure");
	assert.equal(result.failedStep, GO_STEP, describeRun(result));
	assert.equal(result.step("Verify RC identity, manifest, SBOM and signatures").outcome, "success", "the RC itself verified; only the business decision refused it");
	assert.equal(result.step("Stage signature-verified artifact roots for the claim gate").outcome, "success");
	assert.equal(result.context.steps.verify.outputs.candidate_digest, world.rc999.digest);
	assert.match(stepLog(result.step(GO_STEP)), /registry decision is "NO-GO", not "GO"/u);
	assert.match(stepLog(result.step(GO_STEP)), /claim-check --mode=gate did not pass/u);
	assert.deepEqual(result.mutations, [], "nothing was published, tagged, deployed or released");
	assert.equal(result.step(FIRST_PUBLISH_STEP).outcome, "not-run");
	assert.equal(findArtifact(world, STATE_ARTIFACT, result.runId), undefined, "no promotion state or ledger is persisted");
	assert.equal(existsSync(join(result.runnerTemp, "aidr-promotion-state", LEDGER_NAME)), false);
});

test("promote is refused when the GO record names a different candidate digest", { skip: SKIP }, async () => {
	// The trusted registry says GO, for the 9.9.8 inventory; 9.9.9 is presented.
	const result = await runJob(world, "promote", { inputs: promoteInputs(world.rc999.tag, world.rc999.runId), trusted: world.trustedGo998 });
	assert.equal(result.failedStep, GO_STEP, describeRun(result));
	assert.match(stepLog(result.step(GO_STEP)), new RegExp(`registry releaseCandidate ${world.rc998.digest} is a different candidate than this bundle \\(${world.rc999.digest}\\)`, "u"));
	assert.deepEqual(result.mutations, []);
	assert.equal(findArtifact(world, STATE_ARTIFACT, result.runId), undefined);
});

test("promote with a fake GO for the exact digest passes the GO gate and records a hash-chained ledger entry", { skip: SKIP }, async () => {
	const result = await runJob(world, "promote", { inputs: promoteInputs(world.rc999.tag, world.rc999.runId), trusted: world.trustedGo999 });
	assert.equal(result.conclusion, "success", describeRun(result));
	assert.equal(result.step("Restore protected anti-rollback state (pinned)").outcome, "skipped", "first promotion: no earlier state exists");
	assert.match(result.step(GO_STEP).stdout, new RegExp(`Production GO \\(promote\\): GO for candidate ${world.rc999.digest}`, "u"));

	// Every mutation happens after the GO step, in workflow order.
	const steps = WORKFLOW.jobs.promote.steps.map((step) => step.name);
	assert.ok(result.mutations.length > 0);
	assert.ok(result.mutations.every((mutation) => steps.indexOf(mutation.step) > steps.indexOf(GO_STEP)), JSON.stringify(result.mutations));
	const published = npmCalls(result, "publish");
	assert.equal(published.length, NPM_PACKAGES.length, "every unpublished package is planned and published (stubbed npm)");
	assert.ok(published.every((call) => call.step === FIRST_PUBLISH_STEP && / --tag rc /u.test(call.action) && !/--dry-run/u.test(call.action)));
	assert.equal(npmCalls(result, "dist-tag").length, NPM_PACKAGES.length);
	assert.ok(result.mutations.some((mutation) => mutation.action === "dashboard-deploy (stubbed)"));
	assert.ok(result.mutations.some((mutation) => mutation.action.startsWith(`github-release ${world.rc999.tag}`)));

	const state = findArtifact(world, STATE_ARTIFACT, result.runId);
	assert.ok(state, "the protected state artifact was persisted");
	assert.deepEqual(readdirSync(state.dir).sort(), ["anti-rollback-state.json", LEDGER_NAME, "verification-receipt.json"]);
	const ledger = JSON.parse(readFileSync(join(state.dir, LEDGER_NAME), "utf8"));
	assert.deepEqual(verifyLedgerChain(ledger), [], "the ledger hash chain verifies");
	assert.equal(ledger.schema, LEDGER_SCHEMA);
	assert.equal(ledger.entries.length, 1);
	const [entry] = ledger.entries;
	assert.equal(entry.previous_entry_sha256, LEDGER_GENESIS);
	assert.equal(entry.entry_sha256, ledgerEntryDigest(entry));
	assert.equal(ledger.head_sha256, entry.entry_sha256);
	assert.deepEqual(
		{ decision: entry.decision, profile: entry.profile, candidate_digest: entry.candidate_digest, candidate_digest_source: entry.candidate_digest_source, release_version: entry.release_version, release_tag: entry.release_tag, git_sha: entry.git_sha },
		{ decision: "GO", profile: "production-ga", candidate_digest: world.rc999.digest, candidate_digest_source: CANDIDATE_DIGEST_SOURCE, release_version: "9.9.9", release_tag: "v9.9.9-rc.0", git_sha: world.rc999.gitSha },
	);
	assert.equal(entry.registry_sha256, world.trustedGo999.registrySha256, "bound to the exact GO registry bytes");
	assert.equal(entry.receipts_sha256, world.trustedGo999.receiptsSha256, "bound to the exact receipt bytes");
	assert.equal(entry.trusted_verifier_commit, world.trustedGo999.sha, "bound to the trusted verifier commit (github.workflow_sha)");
	world.promotedRunId = result.runId;
});

test("rollback to the GO-promoted version passes, even after the registry has gone back to NO-GO", { skip: SKIP }, async () => {
	assert.ok(world.promotedRunId, "depends on the promote scenario");
	const result = await runJob(world, "rollback", { inputs: rollbackInputs(world.rc999), trusted: world.trustedNoGo });
	assert.equal(result.conclusion, "success", describeRun(result));
	assert.equal(result.step("Restore protected promotion state (pinned)").outcome, "success", "the ledger came from the promote run's protected state");
	assert.match(result.step(ROLLBACK_GO_STEP).stdout, new RegExp(`Production GO \\(rollback\\): GO for candidate ${world.rc999.digest}`, "u"));
	assert.deepEqual(result.mutations.map((mutation) => mutation.step), ["Retag verified npm versions and dashboard deployment"]);
});

test("rollback to a validly signed but never-promoted version is refused before any retag", { skip: SKIP }, async () => {
	const result = await runJob(world, "rollback", { inputs: rollbackInputs(world.rc998), trusted: world.trustedNoGo });
	assert.equal(result.step("Verify rollback RC signature and identity").outcome, "success", "the 9.9.8 RC is authentic");
	assert.equal(result.failedStep, ROLLBACK_GO_STEP, describeRun(result));
	assert.match(stepLog(result.step(ROLLBACK_GO_STEP)), /has no production GO record in the promotion ledger/u);
	assert.deepEqual(result.mutations, []);
});

test("rollback to a rebuilt bundle of the promoted version (wrong digest) is refused", { skip: SKIP }, async () => {
	const result = await runJob(world, "rollback", { inputs: rollbackInputs(world.rc999rebuilt), trusted: world.trustedNoGo });
	assert.equal(result.step("Verify rollback RC signature and identity").outcome, "success", "the rebuilt RC is signed and bound to the same tag and commit");
	assert.equal(result.failedStep, ROLLBACK_GO_STEP, describeRun(result));
	assert.match(stepLog(result.step(ROLLBACK_GO_STEP)), new RegExp(`candidate ${world.rc999rebuilt.digest} \\(9\\.9\\.9\\) has no production GO record`, "u"));
	assert.deepEqual(result.mutations, []);
});

test("a tampered promotion ledger is refused for rollback and for a new promotion", { skip: SKIP }, async () => {
	const state = latestState(world);
	assert.equal(state?.runId, world.promotedRunId, "the latest protected state is the GO promotion's");
	const ledgerPath = join(state.dir, LEDGER_NAME);
	const ledger = JSON.parse(readFileSync(ledgerPath, "utf8"));
	// Re-point the GO entry at the rebuilt bundle without recomputing the chain.
	ledger.entries[0].candidate_digest = world.rc999rebuilt.digest;
	writeFileSync(ledgerPath, `${JSON.stringify(ledger, null, 2)}\n`);

	for (const bundle of [world.rc999rebuilt, world.rc999]) {
		const result = await runJob(world, "rollback", { inputs: rollbackInputs(bundle), trusted: world.trustedNoGo });
		assert.equal(result.failedStep, ROLLBACK_GO_STEP, describeRun(result));
		assert.match(stepLog(result.step(ROLLBACK_GO_STEP)), /does not verify; refusing to use it: ledger entry 0 entry_sha256 does not match its contents/u);
		assert.deepEqual(result.mutations, [], `no retag for ${bundle.version} (${bundle.digest})`);
	}

	const promote = await runJob(world, "promote", { inputs: promoteInputs(world.rc999.tag, world.rc999.runId), trusted: world.trustedGo999 });
	assert.equal(promote.failedStep, GO_STEP, describeRun(promote));
	assert.match(stepLog(promote.step(GO_STEP)), /could not record the GO decision: ledger .* does not verify/u);
	assert.deepEqual(promote.mutations, [], "a GO registry is not enough when the ledger it must extend is tampered");
	assert.equal(findArtifact(world, STATE_ARTIFACT, promote.runId), undefined);
});
