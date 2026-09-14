#!/usr/bin/env node
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve, sep } from "node:path";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { parseArgs } from "node:util";
import { loadReleaseBundle } from "./release-signing-lib.mjs";

const { values } = parseArgs({ options: { output: { type: "string" }, "upstream-dir": { type: "string" }, "release-dir": { type: "string" }, "envelope-output": { type: "string" } } });
if (!values.output || !values["upstream-dir"]) throw new Error("--output and --upstream-dir required");
if (values["envelope-output"] && !values["release-dir"]) throw new Error("--envelope-output requires --release-dir for candidate provenance");
const output = resolve(values.output); const root = process.cwd(); const upstream = resolve(values["upstream-dir"]);
const envelope = values["envelope-output"] ? resolve(values["envelope-output"]) : null;
let releaseSigned = false;
let gatewayBundled = false;
if (existsSync(output)) throw new Error("Customer kit output already exists; choose a new directory");
if (envelope && (existsSync(envelope) || envelope === output || envelope.startsWith(`${output}${sep}`) || output.startsWith(`${envelope}${sep}`))) throw new Error("Envelope output must be a new, separate directory");
const gatewaySource = join(root, "packages/mcp-gateway");
const gatewayDist = join(gatewaySource, "dist");
if (existsSync(gatewaySource) && !["aidr-mcp-gateway.mjs", "aidr-mcp-approve.mjs", "aidr-mcp-stdio.mjs", "aidr-artifact.manifest.json"].every((name) => existsSync(join(gatewayDist, name)))) {
  throw new Error("MCP gateway source is present but its self-contained release build is missing");
}
if (!existsSync(join(root, "packages/core/dist/siem-incident-producer.js"))) {
  throw new Error("SIEM delivery worker requires the compiled core producer; build core before assembling the kit");
}
const commit = execFileSync("git", ["-C", upstream, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
if (commit !== "8c7a4d9dbbaf8b552893822e89d7bf06f33f9220" || execFileSync("git", ["-C", upstream, "status", "--porcelain", "--", "docker"], { encoding: "utf8" }).trim()) throw new Error("Upstream must match the clean reviewed commit");
const sourceCommit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const sourceDirty = !!execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" }).trim();
function copy(source, target) {
	if (lstatSync(source).isSymbolicLink()) throw new Error("Customer kits cannot contain symbolic links");
	if ([".env", ".env.functions"].includes(source.split(/[\\/]/).pop())) throw new Error("Private deployment configuration cannot be packaged");
  if (statSync(source).isDirectory()) { mkdirSync(target, { recursive: true }); for (const name of readdirSync(source)) { if (["node_modules", "__tests__", ".git"].includes(name) || name.endsWith(".map")) continue; copy(join(source, name), join(target, name)); } }
  else { mkdirSync(dirname(target), { recursive: true }); copyFileSync(source, target); }
}
function files(path, prefix = "") {
  return readdirSync(path).sort().flatMap((name) => { const relative = prefix ? `${prefix}/${name}` : name; return statSync(join(path, name)).isDirectory() ? files(join(path, name), relative) : [{ path: relative, sha256: createHash("sha256").update(readFileSync(join(path, name))).digest("hex") }]; });
}
for (const path of ["deploy/backup", "deploy/dashboard", "deploy/fleet", "deploy/ha", "deploy/ingress", "deploy/maintenance", "deploy/monitoring", "deploy/regions.manifest.json", "packages/dashboard/dist", "supabase/config.toml", "supabase/functions", "supabase/migrations"]) copy(join(root, path), join(output, path));
copy(join(root, "scripts/benchmarks"), join(output, "scripts/benchmarks"));
for (const file of [
  "deployment-prepare.mjs",
  "deployment-migrate.mjs",
  "deployment-bootstrap.mjs",
  "deployment-backup.mjs",
  "deployment-backup-offsite.mjs",
	"deployment-restore-drill.mjs",
  "deployment-maintenance.mjs",
  "deployment-offboarding.mjs",
  "deployment-upgrade.mjs",
  "endpoint-install.mjs",
  "deployment-doctor.mjs",
  "deployment-tls-renew.mjs",
  "load-test.mjs",
  "release-signing-lib.mjs",
  "release-verify.mjs",
  "customer-kit-verify.mjs",
  "support-bundle.mjs",
  "verify-load-test.mjs",
	"verify-native-host-matrix-v6.mjs",
  "verify-support-bundle.mjs",
]) copy(join(root, "scripts", file), join(output, "scripts", file));
for (const file of ["package.json", "dist", "resources"]) copy(join(root, "packages/claude-code", file), join(output, "packages/claude-code", file));
copy(join(upstream, "docker"), join(output, "deploy/upstream/docker"));
writeFileSync(join(output, "deploy/upstream-manifest.json"), JSON.stringify({ commit, files: files(join(output, "deploy/upstream")) }, null, 2));
const requireCore = createRequire(join(root, "packages/core/package.json"));
const requireClaude = createRequire(join(root, "packages/claude-code/package.json"));
await requireClaude("esbuild").build({ entryPoints: [requireCore.resolve("yaml")], outfile: join(output, "deploy/vendor/yaml.cjs"), bundle: true, platform: "node", format: "cjs", sourcemap: false, legalComments: "inline" });
await requireClaude("esbuild").build({ entryPoints: [join(root, "scripts/siem-delivery-worker.mjs")], outfile: join(output, "scripts/siem-delivery-worker.mjs"), bundle: true, platform: "node", format: "esm", target: "node24", sourcemap: false, legalComments: "inline" });
copy(resolve(dirname(requireCore.resolve("yaml")), "../LICENSE"), join(output, "deploy/vendor/YAML-LICENSE"));
if (existsSync(gatewaySource)) {
  const gatewayManifest = JSON.parse(readFileSync(join(gatewayDist, "aidr-artifact.manifest.json"), "utf8"));
  if (gatewayManifest.schema_version !== 1 || !Array.isArray(gatewayManifest.files)) throw new Error("Invalid MCP gateway artifact manifest");
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
  ["docs/runbooks/support-bundle.md", "SUPPORT-BUNDLE.md"],
	["docs/production-readiness/backup-restore-v6.md", "RESTORE-DRILL.md"],
  ["docs/production-readiness/native-host-matrix-v6.md", "NATIVE-HOST-ACCEPTANCE.md"],
	["docs/production-readiness/first-customer-sales-packet-v7.md", "FIRST-CUSTOMER-SALES-PACKET.md"],
  ["docs/production-readiness/2026-09-13-customer-candidate-v7.md", "CANDIDATE-STATUS.md"],
  ["FEATURE_INVENTORY.md", "FEATURE_INVENTORY.md"],
]) copy(join(root, source), join(output, target));
for (const file of ["LICENSE", "NOTICE", "THIRD_PARTY_NOTICES"]) copy(join(root, file), join(output, file));
let releaseMetadata = null;
if (values["release-dir"]) {
  const release = resolve(values["release-dir"]);
  const manifestPath = join(release, "aidr-release.manifest.json");
  const signaturePath = join(release, "aidr-release.manifest.sig");
  if (existsSync(manifestPath) !== existsSync(signaturePath)) throw new Error("Signed release requires both manifest and detached signature");
  releaseSigned = existsSync(manifestPath);
  const checkedRelease = await loadReleaseBundle(release, { allowSignedControlFiles: releaseSigned });
  releaseMetadata = checkedRelease.metadata;
  if (releaseMetadata.git_sha !== sourceCommit) throw new Error("Release artifacts and customer kit source must share the same commit");
  const releaseFiles = [...checkedRelease.artifacts.map((item) => item.path), "release-inventory.json", "release-metadata.json"];
  if (existsSync(manifestPath)) releaseFiles.push("aidr-release.manifest.json", "aidr-release.manifest.sig");
  for (const name of releaseFiles) copy(join(release, name), join(output, "artifacts", name));
}
writeFileSync(join(output, "release-source.json"), JSON.stringify({
  commit: sourceCommit,
  dirty: sourceDirty,
  assembled_at: new Date().toISOString(),
  release_signed: releaseSigned,
  inline_mcp_gateway_bundled: gatewayBundled,
  device_start_ingress_bundled: true,
  assurance: releaseSigned
    ? "A detached release signature is present but unverified during kit assembly. Trust requires an independently distributed signer policy and successful release-verify execution."
    : "Unsigned customer installation candidate. Checksums detect changes; they do not authenticate the publisher.",
}, null, 2));
const inventory = files(output);
writeFileSync(join(output, "SHA256SUMS"), inventory.map((entry) => `${entry.sha256}  ${entry.path}`).join("\n") + "\n");
if (envelope) {
  mkdirSync(envelope, { recursive: true });
  const archive = "aidr-customer-kit.tar.gz";
  execFileSync("tar", ["-czf", join(envelope, archive), "-C", dirname(output), basename(output)], { stdio: "pipe" });
  const bytes = readFileSync(join(envelope, archive));
  const digest = createHash("sha256").update(bytes).digest("hex");
  const artifact = { path: archive, size: bytes.length, sha256: digest };
  writeFileSync(join(envelope, "release-metadata.json"), `${JSON.stringify({
    schema_version: 1,
    release_tag: releaseMetadata.release_tag,
    release_version: releaseMetadata.release_version,
    git_sha: releaseMetadata.git_sha,
    source_date_epoch: releaseMetadata.source_date_epoch,
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
