#!/usr/bin/env node
/**
 * Verify the pinned Tencent AI-Infra-Guard source and the generated consumer
 * bundle before a demo/release.  This is dependency-free and intentionally
 * fail-closed for signed release mode.
 */

import { createHash, createVerify } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const aigRoot = join(root, "vendor", "ai-infra-guard");
const generatedRoot = join(root, "packages", "core", "src", "generated");
const expectedCommit = "31c72a9799c8b19d89bcb331d4f8038f05462b8f";
const strict = process.env.AIG_STRICT_CASE === "true" || process.env.AIG_RELEASE === "true";
const requireSignature = process.env.AIG_REQUIRE_SIGNED === "true" || process.env.AIG_RELEASE === "true";

function git(args) {
  return execFileSync("git", ["-C", aigRoot, ...args], {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function walkFiles(dir, suffix = "") {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const file = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkFiles(file, suffix));
    else if (entry.isFile() && (!suffix || entry.name.endsWith(suffix))) out.push(file);
  }
  return out;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonical(value) {
  return JSON.stringify(value);
}

function fail(message) {
  console.error(`[aig] ${message}`);
  process.exit(1);
}

if (!existsSync(join(aigRoot, ".git")) && !existsSync(join(aigRoot, "HEAD"))) {
  fail("vendor/ai-infra-guard is not initialized as a git checkout");
}

const commit = git(["rev-parse", "HEAD"]);
const describe = git(["describe", "--tags", "--always"]);
if (commit !== expectedCommit) {
  fail(`unexpected source commit: ${commit} (expected ${expectedCommit})`);
}

const sourceFiles = [
  ...walkFiles(join(aigRoot, "data", "vuln"), ".yaml"),
  ...walkFiles(join(aigRoot, "data", "vuln_en"), ".yaml"),
];
const fingerprintSourceFiles = walkFiles(join(aigRoot, "data", "fingerprints"), ".yaml");
const gitFiles = git(["ls-tree", "-r", "--name-only", "HEAD", "--", "data/vuln", "data/vuln_en"])
  .split(/\r?\n/)
  .filter((file) => file.endsWith(".yaml"));
const gitFingerprintFiles = git(["ls-tree", "-r", "--name-only", "HEAD", "--", "data/fingerprints"])
  .split(/\r?\n/)
  .filter((file) => file.endsWith(".yaml"));
const caseBuckets = new Map();
for (const file of [...gitFiles, ...gitFingerprintFiles]) {
  const key = file.toLowerCase();
  const bucket = caseBuckets.get(key) || [];
  bucket.push(file);
  caseBuckets.set(key, bucket);
}
const caseCollisions = [...caseBuckets.values()].filter((bucket) => bucket.length > 1);
if (caseCollisions.length > 0) {
  const message = `${caseCollisions.length} case-colliding source path group(s) detected; build on Linux for complete data`;
  if (strict) fail(message);
  console.warn(`WARN [aig] ${message}`);
}
if (strict && (sourceFiles.length !== gitFiles.length || fingerprintSourceFiles.length !== gitFingerprintFiles.length)) {
  fail(`working-tree source is incomplete (vuln=${sourceFiles.length}/${gitFiles.length}, fingerprints=${fingerprintSourceFiles.length}/${gitFingerprintFiles.length})`);
}

const files = [
  "aig-cve-index.json",
  "aig-fingerprints.json",
  "aig-mcp-categories.json",
  "aig-data-manifest.json",
];
for (const file of files) {
  if (!existsSync(join(generatedRoot, file))) fail(`generated index is missing: ${relative(root, join(generatedRoot, file))}`);
}

const cveIndex = JSON.parse(readFileSync(join(generatedRoot, "aig-cve-index.json"), "utf8"));
const fingerprintIndex = JSON.parse(readFileSync(join(generatedRoot, "aig-fingerprints.json"), "utf8"));
const mcpIndex = JSON.parse(readFileSync(join(generatedRoot, "aig-mcp-categories.json"), "utf8"));
const manifest = JSON.parse(readFileSync(join(generatedRoot, "aig-data-manifest.json"), "utf8"));

if (cveIndex.schema !== "aig-cve-index/v2" || cveIndex.version !== 2) fail("CVE index schema/version is not v2");
if (fingerprintIndex.schema !== "aig-fingerprint-index/v2" || fingerprintIndex.version !== 2) fail("fingerprint index schema/version is not v2");
if (mcpIndex.schema !== "aig-mcp-categories/v2" || mcpIndex.version !== 2) fail("MCP index schema/version is not v2");
if (manifest.schema !== "aig-data-manifest/v1") fail("AIG data manifest schema is invalid");
if (manifest.source?.commit !== commit) fail(`manifest source commit mismatch: ${manifest.source?.commit}`);

const cveCount = Array.isArray(cveIndex.cves) ? cveIndex.cves.length : 0;
const fingerprintCount = Array.isArray(fingerprintIndex.fingerprints) ? fingerprintIndex.fingerprints.length : 0;
const mcpCount = Array.isArray(mcpIndex.categories) ? mcpIndex.categories.length : 0;
if (cveCount === 0 || fingerprintCount === 0 || mcpCount === 0) {
  fail(`generated indexes must be non-empty (cves=${cveCount}, fingerprints=${fingerprintCount}, mcp=${mcpCount})`);
}

const invalidCves = cveIndex.cves.filter((entry) =>
  !entry || typeof entry.id !== "string" || typeof entry.p !== "string" ||
  entry.e !== "product" || entry.k !== "product" || !Array.isArray(entry.a) ||
  !["semver", "unsupported", "unscoped"].includes(entry.u) ||
  (entry.u === "semver" ? typeof entry.r !== "string" || !entry.r : entry.r !== null),
);
if (invalidCves.length) fail(`${invalidCves.length} CVE entries violate product/rule schema`);

const artifactNames = ["aig-cve-index.json", "aig-fingerprints.json", "aig-mcp-categories.json"];
for (const name of artifactNames) {
  const data = readFileSync(join(generatedRoot, name));
  const expected = manifest.artifacts?.[name];
  if (!expected || expected.sha256 !== sha256(data) || expected.bytes !== data.length) {
    fail(`manifest hash/size mismatch for ${name}`);
  }
}
const expectedBundleId = sha256(canonical(Object.fromEntries(artifactNames.map((name) => [name, manifest.artifacts[name]]))));
if (manifest.bundle_id !== expectedBundleId) fail("manifest bundle_id mismatch");

if (manifest.signature) {
  const publicKeyPath = process.env.AIG_SIGNING_PUBLIC_KEY_PATH;
  const publicKey = process.env.AIG_SIGNING_PUBLIC_KEY ||
    (publicKeyPath && existsSync(publicKeyPath) ? readFileSync(publicKeyPath, "utf8") : "");
  if (!publicKey) {
    if (requireSignature) fail("signed manifest has no verification key configured");
    console.warn("WARN [aig] manifest is signed but no public verification key was supplied");
  } else {
    const payload = { ...manifest };
    delete payload.signature;
    const verifier = createVerify("RSA-SHA256");
    verifier.update(canonical(payload));
    verifier.end();
    if (!verifier.verify(publicKey, manifest.signature.value, "base64")) fail("manifest signature verification failed");
  }
} else if (requireSignature) {
  fail("AIG release requires a signed data manifest (set AIG_SIGNING_PRIVATE_KEY_PATH during compile)");
} else {
  console.warn("WARN [aig] generated data manifest is unsigned; release mode requires a signature");
}

console.log(JSON.stringify({
  source: { commit, describe, expectedCommit },
  sourceYamlFiles: sourceFiles.length,
  gitYamlFiles: gitFiles.length,
  fingerprintSourceFiles: fingerprintSourceFiles.length,
  gitFingerprintFiles: gitFingerprintFiles.length,
  caseCollisionGroups: caseCollisions.length,
  generated: {
    cves: cveCount,
    fingerprints: fingerprintCount,
    mcpCategories: mcpCount,
    bundleId: manifest.bundle_id,
    signed: Boolean(manifest.signature),
    cveSha256: manifest.artifacts["aig-cve-index.json"].sha256,
    fingerprintSha256: manifest.artifacts["aig-fingerprints.json"].sha256,
    mcpSha256: manifest.artifacts["aig-mcp-categories.json"].sha256,
  },
}, null, 2));
