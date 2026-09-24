#!/usr/bin/env node
// Portable integrity check for an extracted customer kit. Publisher identity
// comes from verifying the signed outer envelope before extraction.
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lstatSync, readFileSync, readdirSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { isWithin, loadReleaseBundle } from "./release-signing-lib.mjs";
import {
  CUSTOMER_KIT_BENCHMARK_FILES,
  CUSTOMER_KIT_DELIVERY_FILES,
  CUSTOMER_KIT_REQUIRED_FILES,
  CUSTOMER_KIT_REQUIRED_RELEASE_ARTIFACTS,
  isMcpGatewayReleaseArtifact,
} from "./customer-kit-contract.mjs";

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
  for (const required of CUSTOMER_KIT_REQUIRED_FILES) {
    if (!inventory.has(required)) throw new Error(`Required customer acceptance artifact is missing: ${required}`);
  }

  verifyGuideLinks(kit, inventory);

  verifyRegionManifest(kit);
  verifyTlsDelivery(kit);
  verifyBenchmarkDelivery(kit);

  const source = JSON.parse(readFileSync(join(kit, "release-source.json"), "utf8"));
  verifyDeliveryStatus(source, inventory);
  const gatewayRuntime = ["deploy/gateway/aidr-mcp-gateway.mjs", "deploy/gateway/aidr-mcp-approve.mjs", "deploy/gateway/aidr-mcp-stdio.mjs", "deploy/gateway/aidr-artifact.manifest.json", "deploy/gateway/aidr-artifact.manifest.sig", "deploy/gateway/README.md"];
  const gatewayPaths = [...inventory.keys()].filter((path) => path.startsWith("deploy/gateway/"));
  if (typeof source.inline_mcp_gateway_bundled !== "boolean" || (source.inline_mcp_gateway_bundled ? !gatewayRuntime.every((path) => inventory.has(path)) : gatewayPaths.length !== 0)) {
    throw new Error("MCP gateway delivery status does not match bundled runtime");
  }
  if (source.inline_mcp_gateway_bundled) {
    const signature = readFileSync(join(kit, "deploy/gateway/aidr-artifact.manifest.sig"), "utf8").trim();
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signature) || Buffer.from(signature, "base64").length !== 64) throw new Error("Gateway artifact signature is invalid");
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
    const declared = new Set([...manifest.files.map((item) => `deploy/gateway/${item.path}`), "deploy/gateway/aidr-artifact.manifest.json", "deploy/gateway/aidr-artifact.manifest.sig", "deploy/gateway/README.md"]);
    if (gatewayPaths.length !== declared.size || gatewayPaths.some((path) => !declared.has(path))) throw new Error("MCP gateway contains files outside its signed artifact manifest");
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
    if (!source.inline_mcp_gateway_bundled && release.artifacts.some((item) => isMcpGatewayReleaseArtifact(item.path))) {
      throw new Error("Gateway-free kit cannot contain an MCP gateway release artifact");
    }
    const releaseArtifactNames = new Set(release.artifacts.map((entry) => entry.path));
    for (const required of CUSTOMER_KIT_REQUIRED_RELEASE_ARTIFACTS) {
      if (!releaseArtifactNames.has(required)) throw new Error(`Required release provenance artifact is missing: ${required}`);
    }
    verifyProvenanceArtifact(join(artifactDir, "aidr-provenance.intoto.json"));
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
    note: "This extracted-kit check cannot authenticate the publisher. Region residency is only an operator declaration, not proof of provider location. Verify the signed outer envelope with an independently delivered policy before extraction.",
  }));
} catch (error) {
  console.error(`Customer kit verification failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}

function verifyGuideLinks(kit, inventory) {
  for (const name of ["START-HERE.md", "INSTALLATION.md"]) {
    const content = readFileSync(join(kit, name), "utf8");
    for (const [, destination] of content.matchAll(/\]\(([^)]+)\)/g)) {
      if (/^[a-z][a-z0-9+.-]*:/i.test(destination) || destination.startsWith("#")) continue;
      const local = destination.split("#", 1)[0];
      if (!local || !isWithin(resolve(kit, local), kit) || !inventory.has(local)) {
        throw new Error(`Customer kit guide has an unresolved local link: ${name} -> ${destination}`);
      }
    }
  }
}

function verifyRegionManifest(kit) {
  const manifestPath = join(kit, CUSTOMER_KIT_DELIVERY_FILES.region_manifest);
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch (error) {
    throw new Error(`Deployment region manifest is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (manifest?.schema_version !== 1 || !manifest.regions || typeof manifest.regions !== "object" || Array.isArray(manifest.regions) || Object.keys(manifest.regions).length === 0) {
    throw new Error("Deployment region manifest must declare schema_version 1 and a non-empty regions object");
  }
  for (const [id, entry] of Object.entries(manifest.regions)) {
    if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(id) || !entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`Deployment region manifest contains an invalid region entry: ${id}`);
    }
    if (entry.supabase_url !== null) {
      let parsed;
      try { parsed = new URL(entry.supabase_url); } catch { parsed = null; }
      if (!parsed || parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== "/") {
        throw new Error(`Deployment region manifest contains an invalid HTTPS origin for ${id}`);
      }
    }
    const residency = entry.residency;
    if (!residency || typeof residency !== "object" || Array.isArray(residency) || typeof residency.declared !== "boolean" || typeof residency.location !== "string" || residency.location.length === 0) {
      throw new Error(`Deployment region manifest is missing residency declaration for ${id}`);
    }
    if (residency.declared !== true && !(id === "unassigned" && residency.declared === false && residency.location === "unassigned")) {
      throw new Error(`Deployment region "${id}" must have residency.declared=true; only the explicit unassigned sentinel may remain false`);
    }
  }
}

function verifyTlsDelivery(kit) {
  const service = readFileSync(join(kit, CUSTOMER_KIT_DELIVERY_FILES.tls_service), "utf8");
  const timer = readFileSync(join(kit, CUSTOMER_KIT_DELIVERY_FILES.tls_timer), "utf8");
  if (!/deployment-tls-renew\.mjs/.test(service)) throw new Error("TLS renewal service is not wired to deployment-tls-renew.mjs");
  if (!/^\s*Unit=aidr-tls-renew\.service\s*$/m.test(timer)) throw new Error("TLS renewal timer is not wired to aidr-tls-renew.service");
  const syntax = spawnSync(process.execPath, ["--check", join(kit, CUSTOMER_KIT_DELIVERY_FILES.tls_script)], { encoding: "utf8", windowsHide: true });
  if (syntax.status !== 0) throw new Error(`TLS renewal script is not valid JavaScript: ${(syntax.stderr || "").trim()}`);
}

function verifyBenchmarkDelivery(kit) {
  for (const relative of CUSTOMER_KIT_BENCHMARK_FILES.filter((entry) => entry.endsWith(".json"))) {
    try {
      JSON.parse(readFileSync(join(kit, relative), "utf8"));
    } catch (error) {
      throw new Error(`Benchmark contract is not valid JSON: ${relative} (${error instanceof Error ? error.message : String(error)})`);
    }
  }
  for (const relative of [CUSTOMER_KIT_DELIVERY_FILES.provenance_script, CUSTOMER_KIT_DELIVERY_FILES.airgap_script]) {
    const syntax = spawnSync(process.execPath, ["--check", join(kit, relative)], { encoding: "utf8", windowsHide: true });
    if (syntax.status !== 0) throw new Error(`Customer kit script is not valid JavaScript: ${relative}`);
  }
}

function verifyDeliveryStatus(source, inventory) {
  const statuses = {
    region_manifest_bundled: [CUSTOMER_KIT_DELIVERY_FILES.region_manifest],
    tls_renewal_bundled: [CUSTOMER_KIT_DELIVERY_FILES.tls_service, CUSTOMER_KIT_DELIVERY_FILES.tls_timer, CUSTOMER_KIT_DELIVERY_FILES.tls_script],
    provenance_tool_bundled: [CUSTOMER_KIT_DELIVERY_FILES.provenance_script],
    airgap_tool_bundled: [CUSTOMER_KIT_DELIVERY_FILES.airgap_script],
    benchmark_contract_bundled: CUSTOMER_KIT_BENCHMARK_FILES,
    provenance_statement_bundled: ["artifacts/aidr-provenance.intoto.json"],
  };
  for (const [field, paths] of Object.entries(statuses)) {
    if (source[field] !== undefined && source[field] !== paths.every((relative) => inventory.has(relative))) {
      throw new Error(`release-source ${field} does not match the bundled artifact set`);
    }
  }
}

function verifyProvenanceArtifact(provenancePath) {
  let statement;
  try {
    statement = JSON.parse(readFileSync(provenancePath, "utf8"));
  } catch (error) {
    throw new Error(`Bundled release provenance is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (statement?._type !== "https://in-toto.io/Statement/v0.1" || statement?.predicateType !== "https://slsa.dev/provenance/v0.2") {
    throw new Error("Bundled release provenance has an unexpected statement or predicate type");
  }
  if (!Array.isArray(statement.subject) || statement.subject.length === 0) throw new Error("Bundled release provenance declares no artifact subjects");
  for (const subject of statement.subject) {
    if (!subject || typeof subject.name !== "string" || !/^[a-f0-9]{64}$/.test(subject.digest?.sha256 ?? "")) throw new Error("Bundled release provenance has an invalid subject digest");
  }
  const predicate = statement.predicate;
  if (!predicate || typeof predicate.builder?.id !== "string" || !Array.isArray(predicate.materials) || predicate.materials.length === 0) throw new Error("Bundled release provenance is missing builder or materials");
  if (!Array.isArray(predicate.byproducts) || !predicate.byproducts.some((entry) => typeof entry?.uri === "string" && entry.uri.endsWith("aidr-sbom.cdx.json"))) {
    throw new Error("Bundled release provenance is missing the SBOM byproduct");
  }
}
