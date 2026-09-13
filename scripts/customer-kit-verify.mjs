#!/usr/bin/env node
// Portable integrity check for an extracted customer kit. Publisher identity
// comes from verifying the signed outer envelope before extraction.
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lstatSync, readFileSync, readdirSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { isWithin, loadReleaseBundle } from "./release-signing-lib.mjs";

try {
  const { values } = parseArgs({ options: {
    kit: { type: "string", default: "." },
    "release-policy": { type: "string" },
    "release-state": { type: "string" },
    "release-receipt": { type: "string" },
  } });
  const kit = resolve(values.kit);
  if (!lstatSync(kit).isDirectory() || lstatSync(kit).isSymbolicLink()) throw new Error("kit must be a regular directory");
  if (Boolean(values["release-policy"]) !== Boolean(values["release-state"])) throw new Error("--release-policy and --release-state must be supplied together");
  if (values["release-receipt"] && !values["release-policy"]) throw new Error("--release-receipt requires release policy and state");
  for (const key of ["release-policy", "release-state", "release-receipt"]) {
    if (values[key] && isWithin(resolve(values[key]), kit)) throw new Error(`${key} must be stored outside the customer kit`);
  }

  const checksumPath = join(kit, "SHA256SUMS");
  const checksumInfo = lstatSync(checksumPath);
  if (!checksumInfo.isFile() || checksumInfo.isSymbolicLink()) throw new Error("SHA256SUMS must be a regular file");
  const lines = readFileSync(checksumPath, "utf8").trimEnd().split(/\r?\n/);
  if (!lines.length || !lines[0]) throw new Error("SHA256SUMS is empty");
  const inventory = new Map();
  for (const line of lines) {
    const match = /^([a-f0-9]{64})  ([A-Za-z0-9_.@/-]+)$/.exec(line);
    if (!match) throw new Error("Invalid SHA256SUMS entry");
    const relative = match[2];
    if (relative.startsWith("/") || relative.split("/").some((part) => !part || part === "." || part === "..") || inventory.has(relative)) throw new Error(`Unsafe or duplicate kit path: ${relative}`);
    inventory.set(relative, match[1]);
  }
  const actual = [];
  function visit(dir, prefix = "") {
    for (const name of readdirSync(dir).sort()) {
      const full = join(dir, name);
      const relative = `${prefix}${name}`;
      const info = lstatSync(full);
      if (info.isSymbolicLink()) throw new Error(`Symlink is forbidden in kit: ${relative}`);
      if (info.isDirectory()) visit(full, `${relative}/`);
      else if (info.isFile()) actual.push(relative);
      else throw new Error(`Unsupported kit entry: ${relative}`);
    }
  }
  visit(kit);
  const expected = [...inventory.keys()].sort();
  const observed = actual.filter((entry) => entry !== "SHA256SUMS").sort();
  if (JSON.stringify(observed) !== JSON.stringify(expected)) throw new Error("Kit file set does not match SHA256SUMS");
  for (const [relative, expectedDigest] of inventory) {
    const digest = createHash("sha256").update(readFileSync(join(kit, relative))).digest("hex");
    if (digest !== expectedDigest) throw new Error(`Changed kit file: ${relative}`);
  }
  if (expected.some((entry) => /(^|\/)(?:\.env|\.env\.functions|node_modules)(?:\/|$)/.test(entry))) throw new Error("Private deployment data or dependencies found in kit");
  for (const required of ["scripts/deployment-restore-drill.mjs", "RESTORE-DRILL.md", "scripts/verify-native-host-matrix-v6.mjs", "NATIVE-HOST-ACCEPTANCE.md", "SUPPORT-RUNBOOK.md", "FIRST-CUSTOMER-SALES-PACKET.md", "CANDIDATE-STATUS.md", "scripts/benchmarks/evaluate.mjs", "scripts/benchmarks/attest.mjs", "supabase/config.toml"]) {
    if (!inventory.has(required)) throw new Error(`Required customer acceptance artifact is missing: ${required}`);
  }

  const source = JSON.parse(readFileSync(join(kit, "release-source.json"), "utf8"));
  const gatewayRuntime = ["deploy/gateway/aidr-mcp-gateway.mjs", "deploy/gateway/aidr-mcp-approve.mjs", "deploy/gateway/aidr-mcp-stdio.mjs", "deploy/gateway/aidr-artifact.manifest.json", "deploy/gateway/README.md"];
  if (source.inline_mcp_gateway_bundled !== gatewayRuntime.every((path) => inventory.has(path))) {
    throw new Error("MCP gateway delivery status does not match bundled runtime");
  }
  if (source.inline_mcp_gateway_bundled) {
    const manifest = JSON.parse(readFileSync(join(kit, "deploy/gateway/aidr-artifact.manifest.json"), "utf8"));
    if (manifest.schema_version !== 1 || !Array.isArray(manifest.files) || manifest.files.length < 3) throw new Error("Gateway artifact manifest is invalid");
    const names = new Set();
    for (const item of manifest.files) {
      if (!item || !/^[A-Za-z0-9_.-]+$/.test(item.path) || names.has(item.path) || !/^[a-f0-9]{64}$/.test(item.sha256) || !inventory.has(`deploy/gateway/${item.path}`)) throw new Error("Gateway artifact manifest entry is invalid");
      names.add(item.path);
      const digest = createHash("sha256").update(readFileSync(join(kit, "deploy/gateway", item.path))).digest("hex");
      if (digest !== item.sha256) throw new Error(`Gateway artifact digest mismatch: ${item.path}`);
    }
    if (!["aidr-mcp-gateway.mjs", "aidr-mcp-approve.mjs", "aidr-mcp-stdio.mjs"].every((name) => names.has(name))) throw new Error("Gateway binaries absent from manifest");
  }
  const ingressFiles = ["deploy/ingress/device-start.mjs", "deploy/ingress/device-start.test.mjs", "deploy/ingress/nginx.device-start.reference.conf", "deploy/ingress/aidr-device-start.service.reference", "deploy/ingress/README.md"];
  if (source.device_start_ingress_bundled !== ingressFiles.every((path) => inventory.has(path))) {
    throw new Error("Device-start ingress delivery status does not match bundled runtime");
  }
  const artifactDir = join(kit, "artifacts");
  const releasePresent = existsSync(join(artifactDir, "release-inventory.json"));
  const signaturePresent = existsSync(join(artifactDir, "aidr-release.manifest.json"));
  if (signaturePresent !== existsSync(join(artifactDir, "aidr-release.manifest.sig"))) throw new Error("Incomplete inner release signature");
  if (source.release_signed !== signaturePresent) throw new Error("release-source signature status mismatch");
  let artifacts = 0;
  if (releasePresent) {
    const release = await loadReleaseBundle(artifactDir, { allowSignedControlFiles: signaturePresent });
    artifacts = release.artifacts.length;
  } else if (values["release-policy"] || signaturePresent) {
    throw new Error("Inner release inventory is missing");
  }
  if (values["release-policy"]) {
    if (!signaturePresent) throw new Error("Inner release is unsigned");
    const args = [join(kit, "scripts", "release-verify.mjs"), "--bundle", artifactDir, "--policy", resolve(values["release-policy"]), "--state", resolve(values["release-state"])];
    if (values["release-receipt"]) args.push("--receipt", resolve(values["release-receipt"]));
    const result = spawnSync(process.execPath, args, { encoding: "utf8", windowsHide: true });
    if (result.status !== 0) throw new Error(`Inner signed release verification failed: ${(result.stderr || result.error?.message || "unknown error").trim()}`);
  }
  console.log(JSON.stringify({
    passed: true,
    files_verified: inventory.size,
    release_artifacts_verified: artifacts,
    inner_release_signature: values["release-policy"] ? "verified" : signaturePresent ? "present_unverified" : "absent",
    inline_mcp_gateway_bundled: source.inline_mcp_gateway_bundled,
    device_start_ingress_bundled: source.device_start_ingress_bundled,
    publisher_authenticated: false,
    note: "This extracted-kit check cannot authenticate the publisher. Verify the signed outer envelope with an independently delivered policy before extraction.",
  }));
} catch (error) {
  console.error(`Customer kit verification failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
