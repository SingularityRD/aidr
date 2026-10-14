#!/usr/bin/env node
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve, sep } from "node:path";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { parseArgs } from "node:util";
import { tarDirectory } from "./lib/tar-path.mjs";
import { loadReleaseBundle } from "./release-signing-lib.mjs";
import { validateSignedWindowsFleet } from "../.github/scripts/windows-authenticode-inputs.mjs";
import { verifyBundle as verifyOfflineBundle } from "./onprem-offline-bundle.mjs";
import {
  CUSTOMER_KIT_BENCHMARK_FILES,
  CUSTOMER_KIT_REQUIRED_FILES,
  CUSTOMER_KIT_RENDERED_GUIDES,
  CUSTOMER_KIT_REQUIRED_RELEASE_ARTIFACTS,
  renderCustomerKitDoc,
} from "./customer-kit-contract.mjs";
import { privacyGatewayPackageEntries } from "../deploy/privacy-gateway/privacy-gateway.mjs";

const { values } = parseArgs({ options: { output: { type: "string" }, "upstream-dir": { type: "string" }, "release-dir": { type: "string" }, "envelope-output": { type: "string" }, "windows-authenticode-receipt-sha256": { type: "string" }, "windows-code-signing-thumbprint": { type: "string" }, "airgap-bundle": { type: "string" } } });
if (!values.output || !values["upstream-dir"]) throw new Error("--output and --upstream-dir required");
if (values["envelope-output"] && !values["release-dir"]) throw new Error("--envelope-output requires --release-dir for candidate provenance");
const output = resolve(values.output); const root = process.cwd(); const upstream = resolve(values["upstream-dir"]);
const envelope = values["envelope-output"] ? resolve(values["envelope-output"]) : null;
let releaseSigned = false;
let gatewayBundled = false;
let gatewaySignaturePresent = false;
if (existsSync(output)) throw new Error("Customer kit output already exists; choose a new directory");
if (envelope && (existsSync(envelope) || envelope === output || envelope.startsWith(`${output}${sep}`) || output.startsWith(`${envelope}${sep}`))) throw new Error("Envelope output must be a new, separate directory");
const sourceCommit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const sourceDirty = !!execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" }).trim();
if (values["release-dir"] && sourceDirty) throw new Error("Release-bound customer kit requires a clean source tree; commit and review all changes before packaging");
const gatewaySource = join(root, "packages/mcp-gateway");
const gatewayDist = join(gatewaySource, "dist");
if (existsSync(gatewaySource) && !["aidr-mcp-gateway.mjs", "aidr-mcp-approve.mjs", "aidr-mcp-stdio.mjs", "aidr-artifact.manifest.json"].every((name) => existsSync(join(gatewayDist, name)))) {
  throw new Error("MCP gateway source is present but its self-contained release build is missing");
}
if (!existsSync(join(root, "packages/core/dist/siem-incident-producer.js"))) {
  throw new Error("SIEM delivery worker requires the compiled core producer; build core before assembling the kit");
}
const commit = execFileSync("git", ["-C", upstream, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
if (commit !== "8c7a4d9dbbaf8b552893822e89d7bf06f33f9220" || execFileSync("git", ["-C", upstream, "status", "--porcelain", "--", "docker", "LICENSE"], { encoding: "utf8" }).trim()) throw new Error("Upstream must match the clean reviewed commit");
function copy(source, target) {
	if (lstatSync(source).isSymbolicLink()) throw new Error("Customer kits cannot contain symbolic links");
	if ([".env", ".env.functions"].includes(source.split(/[\\/]/).pop())) throw new Error("Private deployment configuration cannot be packaged");
  if (statSync(source).isDirectory()) { mkdirSync(target, { recursive: true }); for (const name of readdirSync(source)) { if (["node_modules", "__tests__", ".git"].includes(name) || name.endsWith(".map")) continue; copy(join(source, name), join(target, name)); } }
  else { mkdirSync(dirname(target), { recursive: true }); copyFileSync(source, target); }
}
function files(path, prefix = "") {
  return readdirSync(path).sort().flatMap((name) => { const relative = prefix ? `${prefix}/${name}` : name; return statSync(join(path, name)).isDirectory() ? files(join(path, name), relative) : [{ path: relative, sha256: createHash("sha256").update(readFileSync(join(path, name))).digest("hex") }]; });
}
for (const path of ["deploy/backup", "deploy/dashboard", "deploy/fleet", "deploy/ha", "deploy/ingress", "deploy/maintenance", "deploy/monitoring", "deploy/onprem", "deploy/operations", "deploy/regions.manifest.json", "deploy/saml-config.mjs", "packages/dashboard/dist", "packages/dashboard/package.json", "supabase/config.toml", "supabase/functions", "supabase/migrations", "supabase/templates"]) copy(join(root, path), join(output, path));
// The interception catalogue's source checker requires the separately supplied
// checkout. Ship only the self-contained native operator assets here.
for (const path of ["deploy/native/README.md", "deploy/native/support-matrix.json", "deploy/native/support-matrix.schema.json", "deploy/native/interception-matrix.json", "deploy/native/run-support-matrix.mjs", "deploy/native/scenarios/TEMPLATE.json", "deploy/native/scenarios/README.md"]) copy(join(root, path), join(output, path));
copy(join(root, "scripts/benchmarks"), join(output, "scripts/benchmarks"));
// Kubernetes: the chart and its credential generator (deploy/vendor/yaml.cjs is its YAML runtime in the kit).
copy(join(root, "deploy/helm/aidr"), join(output, "deploy/helm/aidr"));
copy(join(root, "deploy/helm/generate-secrets.mjs"), join(output, "deploy/helm/generate-secrets.mjs"));
// Optional privacy gateway: the image definition plus only the compiled runtime
// it packages, so deployment-prepare --with-privacy-gateway works from the kit.
for (const file of ["Dockerfile", "healthcheck.mjs", "privacy-gateway.mjs", "README.md"]) copy(join(root, "deploy/privacy-gateway", file), join(output, "deploy/privacy-gateway", file));
for (const relative of privacyGatewayPackageEntries(root)) copy(join(root, "packages/privacy", relative), join(output, "packages/privacy", relative));
for (const file of [
  "deployment-prepare.mjs",
  "deployment-migrate.mjs",
	"lib/migration-contract.mjs",
	"lib/migration-hash-compat.mjs",
	"lib/atomic-write.mjs",
	"lib/deployment-credentials.mjs",
	"lib/deployment-input-copy.mjs",
	"lib/node-helper-image.mjs",
	"lib/node-helper.Dockerfile",
  "deployment-bootstrap.mjs",
  "license-verify.mjs",
	"deployment-backup.mjs",
	"deployment-backup-offsite.mjs",
	"deployment-restore-drill.mjs",
	"archive-boundary.mjs",
  "deployment-maintenance.mjs",
  "deployment-offboarding.mjs",
  "deployment-upgrade.mjs",
  "onprem-upgrade.mjs",
	"lib/onprem-language.mjs",
	// Copied, not bundled: it imports the kit's bundled import-offline-pack.mjs
	// (core verifier inlined) and two modules whose CLI guards must stay separate.
  "onprem-offline-bundle.mjs",
  "publish-installers.mjs",
	"lib/tar-path.mjs",
  "endpoint-install.mjs",
  "deployment-doctor.mjs",
  "deployment-tls-renew.mjs",
  "deployment-tls-renew.test.mjs",
  "build-airgap-images.mjs",
  "airgap-images.test.mjs",
  "generate-provenance.mjs",
  "provenance.test.mjs",
  "customer-kit-contract.mjs",
  "load-test.mjs",
  "release-signing-lib.mjs",
  "release-verify.mjs",
  "customer-kit-verify.mjs",
  "verify-customer-kit.mjs",
  "support-bundle.mjs",
  "saml-outage-recovery.mjs",
  "verify-load-test.mjs",
	"verify-native-host-matrix-v6.mjs",
  "verify-support-bundle.mjs",
  "verify-support-ticket-drill.mjs",
]) copy(join(root, "scripts", file), join(output, "scripts", file));
const claudePackage = join(root, "packages/claude-code");
const claudePackageManifest = join(claudePackage, "aidr-artifact.manifest.json");
const claudePackageSignature = join(claudePackage, "aidr-artifact.manifest.sig");
const claudeDistSignature = join(claudePackage, "dist", "aidr-artifact.manifest.sig");
const hasClaudePackageManifest = existsSync(claudePackageManifest);
const hasClaudePackageSignature = existsSync(claudePackageSignature);
const hasClaudeDistSignature = existsSync(claudeDistSignature);
if (hasClaudePackageManifest !== hasClaudePackageSignature || hasClaudePackageManifest !== hasClaudeDistSignature) {
  throw new Error("Claude Code package and dist must carry complete, matching signed evidence");
}
for (const file of ["package.json", "dist", "resources"]) copy(join(claudePackage, file), join(output, "packages/claude-code", file));
if (hasClaudePackageManifest) {
  for (const file of ["aidr-artifact.manifest.json", "aidr-artifact.manifest.sig"]) {
    copy(join(claudePackage, file), join(output, "packages/claude-code", file));
  }
}
copy(join(upstream, "docker"), join(output, "deploy/upstream/docker"));
writeFileSync(join(output, "deploy/upstream-manifest.json"), JSON.stringify({ commit, files: files(join(output, "deploy/upstream")) }, null, 2));
const requireCore = createRequire(join(root, "packages/core/package.json"));
const requireClaude = createRequire(join(root, "packages/claude-code/package.json"));
await requireClaude("esbuild").build({ entryPoints: [requireCore.resolve("yaml")], outfile: join(output, "deploy/vendor/yaml.cjs"), bundle: true, platform: "node", format: "cjs", sourcemap: false, legalComments: "inline" });
await requireClaude("esbuild").build({ entryPoints: [join(root, "scripts/siem-delivery-worker.mjs")], outfile: join(output, "scripts/siem-delivery-worker.mjs"), bundle: true, platform: "node", format: "esm", target: "node24", sourcemap: false, legalComments: "inline" });
await requireClaude("esbuild").build({ entryPoints: [join(root, "scripts/readiness-evidence-worker.mjs")], outfile: join(output, "scripts/readiness-evidence-worker.mjs"), bundle: true, platform: "node", format: "esm", target: "node24", sourcemap: false, legalComments: "inline" });
await requireClaude("esbuild").build({ entryPoints: [join(root, "scripts/import-offline-pack.mjs")], outfile: join(output, "scripts/import-offline-pack.mjs"), bundle: true, platform: "node", format: "esm", target: "node24", sourcemap: false, legalComments: "inline" });
await requireClaude("esbuild").build({ entryPoints: [join(root, "scripts/deployment-backup.mjs")], outfile: join(output, "scripts/deployment-backup.mjs"), bundle: true, platform: "node", format: "esm", target: "node24", sourcemap: false, legalComments: "inline", external: ["./lib/node-helper-image.mjs"] });
copy(resolve(dirname(requireCore.resolve("yaml")), "../LICENSE"), join(output, "deploy/vendor/YAML-LICENSE"));
if (existsSync(gatewaySource)) {
  const gatewayManifest = JSON.parse(readFileSync(join(gatewayDist, "aidr-artifact.manifest.json"), "utf8"));
  if (gatewayManifest.schema_version !== 1 || !Array.isArray(gatewayManifest.files)) throw new Error("Invalid MCP gateway artifact manifest");
  gatewaySignaturePresent = existsSync(join(gatewayDist, "aidr-artifact.manifest.sig"));
  if (gatewaySignaturePresent) {
    const gatewaySignature = readFileSync(join(gatewayDist, "aidr-artifact.manifest.sig"), "utf8").trim();
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(gatewaySignature) || Buffer.from(gatewaySignature, "base64").length !== 64) throw new Error("Invalid MCP gateway artifact signature");
  }
  const gatewayNames = new Set();
  for (const item of gatewayManifest.files) {
    if (!item || !/^[A-Za-z0-9_.-]+$/.test(item.path) || gatewayNames.has(item.path) || !/^[a-f0-9]{64}$/.test(item.sha256)) throw new Error("Invalid MCP gateway artifact entry");
    gatewayNames.add(item.path);
    const source = join(gatewayDist, item.path);
    if (createHash("sha256").update(readFileSync(source)).digest("hex") !== item.sha256) throw new Error(`MCP gateway artifact changed: ${item.path}`);
    copy(source, join(output, "deploy/gateway", item.path));
  }
  if (!["aidr-mcp-gateway.mjs", "aidr-mcp-approve.mjs", "aidr-mcp-stdio.mjs"].every((name) => gatewayNames.has(name))) throw new Error("MCP gateway binaries missing from artifact manifest");
  copy(join(gatewayDist, "aidr-artifact.manifest.json"), join(output, "deploy/gateway/aidr-artifact.manifest.json"));
  if (gatewaySignaturePresent) copy(join(gatewayDist, "aidr-artifact.manifest.sig"), join(output, "deploy/gateway/aidr-artifact.manifest.sig"));
  copy(join(root, "packages/mcp-gateway/README.md"), join(output, "deploy/gateway/README.md"));
  gatewayBundled = true;
}
copy(join(upstream, "LICENSE"), join(output, "deploy/upstream/LICENSE"));
for (const [source, target] of [
  ["deploy/FIRST_CUSTOMER.md", "START-HERE.md"],
  ["deploy/README.md", "INSTALLATION.md"],
  ["deploy/UPGRADE.md", "UPGRADE.md"],
  ["deploy/RESOURCE_REQUIREMENTS.md", "RESOURCE-REQUIREMENTS.md"],
	["docs/runbooks/support-v7.md", "SUPPORT-RUNBOOK.md"],
	["docs/runbooks/secrets-management.md", "SECRETS-RUNBOOK.md"],
	["docs/operations/licensing.md", "LICENSING.md"],
	["docs/operations/threat-sync.md", "THREAT-SYNC.md"],
  ["docs/runbooks/support-bundle.md", "SUPPORT-BUNDLE.md"],
	["docs/production-readiness/backup-restore-v6.md", "RESTORE-DRILL.md"],
	["docs/production-readiness/retention-holds.md", "RETENTION-HOLDS.md"],
  ["docs/operations/saml-outage-recovery.md", "SAML-RECOVERY.md"],
  ["docs/operations/response-playbooks.md", "RESPONSE-PLAYBOOKS.md"],
  ["docs/runbooks/cloud-discovery.md", "CLOUD-DISCOVERY.md"],
  ["docs/runbooks/behavioral-learning.md", "BEHAVIORAL-LEARNING.md"],
  ["docs/package-installation.md", "PACKAGE-INSTALLATION.md"],
  ["packages/codex/README.md", "CODEX-CONNECTOR.md"],
  ["supabase/README.md", "CONTROL-PLANE.md"],
  ["docs/operations/kubernetes.md", "KUBERNETES.md"],
  ["docs/production-readiness/native-host-matrix-v6.md", "NATIVE-HOST-ACCEPTANCE.md"],
	["docs/production-readiness/first-customer-buyer-handoff-2026-09-23.md", "FIRST-CUSTOMER-SALES-PACKET.md"],
  ["docs/production-readiness/first-customer-ready.md", "CANDIDATE-STATUS.md"],
  ["docs/release-evidence.md", "RELEASE-EVIDENCE.md"],
  ["docs/runbooks/portable-release-signing.md", "RELEASE-SIGNING.md"],
  ["FEATURE_INVENTORY.md", "FEATURE_INVENTORY.md"],
]) copy(join(root, source), join(output, target));
for (const name of CUSTOMER_KIT_RENDERED_GUIDES) {
  const path = join(output, name);
  writeFileSync(path, renderCustomerKitDoc(name, readFileSync(path, "utf8")));
}
for (const file of ["LICENSE", "NOTICE", "THIRD_PARTY_NOTICES"]) copy(join(root, file), join(output, file));
let releaseMetadata = null;
let releaseArtifactNames = new Set();
if (values["release-dir"]) {
  const release = resolve(values["release-dir"]);
  const manifestPath = join(release, "aidr-release.manifest.json");
  const signaturePath = join(release, "aidr-release.manifest.sig");
  if (existsSync(manifestPath) !== existsSync(signaturePath)) throw new Error("Signed release requires both manifest and detached signature");
  releaseSigned = existsSync(manifestPath);
  const checkedRelease = await loadReleaseBundle(release, { allowSignedControlFiles: releaseSigned });
  releaseMetadata = checkedRelease.metadata;
  if (releaseMetadata.git_sha !== sourceCommit) throw new Error("Release artifacts and customer kit source must share the same commit");
  releaseArtifactNames = new Set(checkedRelease.artifacts.map((item) => item.path));
  for (const required of CUSTOMER_KIT_REQUIRED_RELEASE_ARTIFACTS) {
    if (!releaseArtifactNames.has(required)) throw new Error(`Release bundle is missing required provenance artifact: ${required}`);
  }
  const releaseFiles = [...releaseArtifactNames, "release-inventory.json", "release-metadata.json"];
  if (existsSync(manifestPath)) releaseFiles.push("aidr-release.manifest.json", "aidr-release.manifest.sig");
  for (const name of releaseFiles) copy(join(release, name), join(output, "artifacts", name));
}
if (releaseSigned && !hasClaudePackageManifest) {
  throw new Error("Signed customer kits require signed Claude Code package and dist manifests");
}
if (releaseSigned && gatewayBundled && !gatewaySignaturePresent) throw new Error("Signed customer kits require the MCP gateway artifact signature");
if (releaseSigned) {
  const signedFleet = validateSignedWindowsFleet(root,
    values["windows-authenticode-receipt-sha256"] ?? process.env.AIDR_EXPECTED_WINDOWS_AUTHENTICODE_RECEIPT_SHA256,
    values["windows-code-signing-thumbprint"] ?? process.env.AIDR_WINDOWS_CODE_SIGNING_THUMBPRINT);
  // A signed kit must replace every source script with the independently pinned signed staging bytes.
  copy(signedFleet, join(output, "deploy/fleet/windows"));
  copy(join(root, ".release-evidence/windows-authenticode-receipt.json"), join(output, "deploy/fleet/windows/authenticode-receipt.json"));
}
// Optional vendor-signed air-gap image bundle (release-images.yml, job airgap-bundle):
// checked offline (SHA256SUMS, Ed25519 signature, every image tarball) before it
// enters the kit, so a disconnected customer never builds an image.
let airgapBundled = false;
if (values["airgap-bundle"]) {
  const bundleDir = resolve(values["airgap-bundle"]);
  const names = readdirSync(bundleDir).sort();
  const archives = names.filter((name) => /^aidr-offline-bundle-[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.tar$/.test(name));
  if (archives.length !== 1) throw new Error("--airgap-bundle must hold exactly one aidr-offline-bundle-<version>.tar");
  const expected = [archives[0], `${archives[0]}.cosign.bundle`, "offline-bundle-signing-public.pem", "SHA256SUMS"].sort();
  if (JSON.stringify(names) !== JSON.stringify(expected)) throw new Error(`--airgap-bundle must hold exactly: ${expected.join(", ")}`);
  const listed = new Map(readFileSync(join(bundleDir, "SHA256SUMS"), "utf8").trim().split(/\r?\n/).map((line) => {
    const match = /^([a-f0-9]{64}) {2}([A-Za-z0-9._-]+)$/.exec(line);
    if (!match) throw new Error("Air-gap bundle SHA256SUMS is malformed");
    return [match[2], match[1]];
  }));
  for (const name of expected.filter((entry) => entry !== "SHA256SUMS")) {
    if (listed.get(name) !== createHash("sha256").update(readFileSync(join(bundleDir, name))).digest("hex")) throw new Error(`Air-gap bundle file does not match SHA256SUMS: ${name}`);
  }
  const checked = await verifyOfflineBundle({ bundle: join(bundleDir, archives[0]), publicKey: join(bundleDir, "offline-bundle-signing-public.pem") });
  checked.cleanup();
  if (!checked.manifest.components?.images) throw new Error("Air-gap bundle carries no container images");
  for (const name of expected) copy(join(bundleDir, name), join(output, "airgap", name));
  airgapBundled = true;
}
for (const relative of CUSTOMER_KIT_REQUIRED_FILES) {
  const target = join(output, relative);
  const info = existsSync(target) ? lstatSync(target) : null;
  if (!info?.isFile() || info.isSymbolicLink()) throw new Error(`Customer kit is missing required delivery artifact: ${relative}`);
}
writeFileSync(join(output, "release-source.json"), JSON.stringify({
  commit: sourceCommit,
  dirty: sourceDirty,
  assembled_at: new Date().toISOString(),
  release_signed: releaseSigned,
  inline_mcp_gateway_bundled: gatewayBundled,
  inline_mcp_gateway_signature_present: gatewaySignaturePresent,
  device_start_ingress_bundled: true,
  privacy_gateway_runtime_bundled: true,
  region_manifest_bundled: true,
  tls_renewal_bundled: true,
  provenance_tool_bundled: true,
  airgap_tool_bundled: true,
  helm_chart_bundled: true,
  airgap_image_bundle_bundled: airgapBundled,
  benchmark_contract_bundled: CUSTOMER_KIT_BENCHMARK_FILES.every((relative) => existsSync(join(output, relative))),
  windows_authenticode_receipt_bundled: releaseSigned,
  provenance_statement_bundled: releaseArtifactNames.has("aidr-provenance.intoto.json"),
  assurance: releaseSigned
    ? "A detached release signature is present but unverified during kit assembly. Trust requires an independently distributed signer policy and successful release-verify execution."
    : "Unsigned customer installation candidate. Checksums detect changes; they do not authenticate the publisher.",
}, null, 2));
const inventory = files(output);
writeFileSync(join(output, "SHA256SUMS"), inventory.map((entry) => `${entry.sha256}  ${entry.path}`).join("\n") + "\n");
if (envelope) {
  mkdirSync(envelope, { recursive: true });
  const archive = "aidr-customer-kit.tar.gz";
  execFileSync("tar", ["-czf", archive, "-C", tarDirectory(dirname(output)), basename(output)], { cwd: envelope, stdio: "pipe" }); // relative archive + cwd: GNU tar on Windows parses "C:" as a host
  const bytes = readFileSync(join(envelope, archive));
  const digest = createHash("sha256").update(bytes).digest("hex");
  const artifact = { path: archive, size: bytes.length, sha256: digest };
  writeFileSync(join(envelope, "release-metadata.json"), `${JSON.stringify({
    schema_version: 1,
    release_tag: releaseMetadata.release_tag,
    release_version: releaseMetadata.release_version,
    git_sha: releaseMetadata.git_sha,
    source_date_epoch: releaseMetadata.source_date_epoch,
    worktree_dirty: releaseMetadata.worktree_dirty,
    artifacts: [artifact],
  }, null, 2)}\n`);
  writeFileSync(join(envelope, "release-inventory.json"), `${JSON.stringify({
    schema_version: 1,
    artifacts: [{ source_path: `release-output/${archive}`, staged_path: archive, kind: "release-artifact", sha256: digest }],
  }, null, 2)}\n`);
  await loadReleaseBundle(envelope);
  console.log(`Unsigned release envelope prepared at ${envelope}; sign it offline with release-sign.mjs after review. The detached signature authenticates the complete kit archive.`);
}
console.log(`Portable candidate assembled: ${inventory.length} files. Node 24, Docker Compose and tar required; no repository, Git, pnpm or build required on the customer's host.`);
