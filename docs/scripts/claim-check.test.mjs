import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = new URL("../../", import.meta.url);
const script = new URL("./claim-check.mjs", import.meta.url);
const registryPath = new URL("../production-readiness/commercial-go-evidence-registry.json", import.meta.url);
const digest = (value) => createHash("sha256").update(value).digest("hex");

function run(registry, roots = []) {
  const result = spawnSync(process.execPath, [fileURLToPath(script), "--mode=inventory", "--json", ...(registry ? ["--registry", registry] : []), ...roots.flatMap((path) => ["--root", path])], {
    cwd: fileURLToPath(root),
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
  });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("claim inventory scans current sales pages but not named historical snapshots", () => {
  const result = run();
  assert.ok(result.roots.includes("docs/sales"));
  assert.ok(result.roots.includes("packages/dashboard/src/ui/pages/public"));
  assert.deepEqual(result.registryErrors, []);
  const scanned = new Set(result.scans.map(scan => scan.path));
  for (const path of ["docs/sales/one-pager.md", "docs/sales/pricing.md", "docs/sales/commercial-decision-packet.md", "docs/sales/code-signing-guide.md", "packages/dashboard/src/ui/pages/public/LandingPage.tsx", "packages/dashboard/src/ui/pages/public/PricingPage.tsx"]) {
    assert.ok(scanned.has(path), `${path} must be scanned`);
  }
  for (const path of result.historicalScanExclusions) {
    assert.ok(!scanned.has(path), `${path} must not be treated as current sales copy`);
  }
});

test("superseded enterprise ICP is visibly historical and defers to current buyer gates", () => {
  const icp = readFileSync(new URL("../sales/ideal-customer-profile.md", import.meta.url), "utf8");
  const header = icp.slice(0, 1200);
  assert.match(header, /Historical snapshot — not current sales qualification/);
  assert.match(header, /BMC enterprise\/on-prem/);
  assert.match(header, /first-customer-buyer-handoff-2026-09-23\.md/);
  assert.match(header, /supported PoC or\s+> sale still needs/);
});

test("a sales page cannot be excluded without a visible historical label", () => {
  const registry = JSON.parse(readFileSync(registryPath, "utf8"));
  registry.historicalScanExclusions = ["docs/sales/one-pager.md"];
  const directory = mkdtempSync(join(tmpdir(), "aidr-claim-test-"));
  try {
    const path = join(directory, "registry.json");
    writeFileSync(path, JSON.stringify(registry));
    const result = run(path);
    assert.ok(result.registryErrors.some(error => error.includes("not visibly labelled")));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("the current two-channel billing and cloud trial decisions cannot silently regress", () => {
  const registry = JSON.parse(readFileSync(registryPath, "utf8"));
  registry.commercialDecision.billingModel = "enterprise-invoice";
  registry.commercialDecision.cloudTrial.agentLimit = 5;
  const directory = mkdtempSync(join(tmpdir(), "aidr-claim-decision-test-"));
  try {
    const path = join(directory, "registry.json");
    writeFileSync(path, JSON.stringify(registry));
    const errors = run(path).registryErrors.join("\n");
    assert.match(errors, /commercialDecision.billingModel/);
    assert.match(errors, /commercialDecision.cloudTrial/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("an approved pattern authorizes only its exact text on its listed surface", () => {
  const directory = mkdtempSync(join(tmpdir(), "aidr-claim-approval-test-"));
  try {
    const listed = join(directory, "listed.md");
    const other = join(directory, "other.md");
    const exactText = "Launch-ready security layer for AI agents.";
    writeFileSync(listed, `${exactText}\nLaunch-ready anything else.\n`);
    writeFileSync(other, `${exactText}\n`);
    const registry = JSON.parse(readFileSync(registryPath, "utf8"));
    registry.releaseCandidate = "test-candidate";
    Object.assign(registry.claims[0], {
      status: "closed", maturity: "approved", salesApproved: true,
      releaseCandidate: "test-candidate", expiresAt: "2999-12-31",
      surfaces: [relative(fileURLToPath(root), listed).replaceAll("\\", "/")],
      approvalEvidence: {
        reviewer: "Fixture reviewer", reviewedAt: "2026-09-23T00:00:00Z",
        exactTextSha256: digest(exactText), path: "README.md",
        sha256: digest(readFileSync(new URL("../../README.md", import.meta.url))),
      },
    });
    const registryFile = join(directory, "registry.json");
    writeFileSync(registryFile, JSON.stringify(registry));
    const result = run(registryFile, [listed, other]);
    assert.deepEqual(result.registryErrors, []);
    assert.ok(result.roots.includes("packages/dashboard/src/ui/pages/public"));
    assert.equal(result.hits.length, 3);
    assert.equal(result.hits.filter((hit) => hit.approved).length, 1);
    assert.equal(result.unapprovedHits.length, 2);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("a Sales Approved flag without matching claim evidence cannot authorize public wording", () => {
  const directory = mkdtempSync(join(tmpdir(), "aidr-claim-evidence-test-"));
  try {
    const page = join(directory, "page.md");
    writeFileSync(page, "Launch-ready security layer for AI agents.\n");
    const registry = JSON.parse(readFileSync(registryPath, "utf8"));
    registry.releaseCandidate = "test-candidate";
    Object.assign(registry.claims[0], {
      status: "closed", maturity: "approved", salesApproved: true,
      releaseCandidate: "test-candidate", expiresAt: "2999-12-31",
      surfaces: [relative(fileURLToPath(root), page).replaceAll("\\", "/")],
      approvalEvidence: {
        reviewer: "Fixture reviewer", reviewedAt: "2026-09-23T00:00:00Z",
        exactTextSha256: digest(registry.claims[0].exactText), path: "README.md",
        sha256: "0".repeat(64),
      },
    });
    const registryFile = join(directory, "registry.json");
    writeFileSync(registryFile, JSON.stringify(registry));
    const result = run(registryFile, [page]);
    assert.ok(result.registryErrors.some(error => error.includes("matching in-repository evidence SHA-256")));
    assert.equal(result.hits.filter((hit) => hit.approved).length, 0);
    assert.equal(result.unapprovedHits.length, 1);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("gate root arguments cannot replace the registry's required surfaces", () => {
  const result = spawnSync(process.execPath, [fileURLToPath(script), "--mode=gate", "--json", "--root", "README.md"], {
    cwd: fileURLToPath(root), encoding: "utf8", maxBuffer: 10 * 1024 * 1024,
  });
  assert.equal(result.status, 1, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.ok(report.roots.includes("packages/dashboard/src/ui/pages/public"));
  assert.ok(report.roots.includes("docs/sales"));
  assert.ok(report.openHardGates.length > 0);
});
