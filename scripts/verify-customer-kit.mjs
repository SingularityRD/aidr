#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { readFileSync, writeFileSync, readdirSync, lstatSync, mkdtempSync, rmSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { gunzipSync } from "node:zlib";
import {
  CUSTOMER_KIT_BENCHMARK_FILES,
  CUSTOMER_KIT_DELIVERY_FILES,
  CUSTOMER_KIT_REQUIRED_FILES,
  CUSTOMER_KIT_REQUIRED_RELEASE_ARTIFACTS,
  isMcpGatewayReleaseArtifact,
} from "./customer-kit-contract.mjs";
const kit=resolve(process.argv[2]||".aidr-customer-kit"), checks=[];
const inventory=readFileSync(join(kit,"SHA256SUMS"),"utf8").trim().split(/\r?\n/).map(line=>{
 const match=line.match(/^([a-f0-9]{64})  ([A-Za-z0-9_.@/-]+)$/);assert.ok(match,"Invalid checksum inventory");
 assert.ok(!match[2].startsWith("/") && !match[2].split("/").includes(".."));return{sha256:match[1],path:match[2]};
});
const expected=new Set(inventory.map(row=>row.path));assert.equal(expected.size,inventory.length);
function files(dir,prefix="") {return readdirSync(dir).flatMap(name=>{const full=join(dir,name);const entry=lstatSync(full);assert.ok(!entry.isSymbolicLink());return entry.isDirectory()?files(full,`${prefix}${name}/`):[`${prefix}${name}`];});}
assert.deepEqual(new Set(files(kit).filter(name=>name!=="SHA256SUMS")),expected);
for(const row of inventory)assert.equal(createHash("sha256").update(readFileSync(join(kit,row.path))).digest("hex"),row.sha256,`Changed kit file: ${row.path}`);
checks.push(`${inventory.length} declared files match SHA-256; no extra paths or symlinks`);
assert.ok(![...expected].some(path=>/(^|\/)(\.env|\.env\.functions|node_modules|private-ui-fixture)(\/|$)/.test(path)));
checks.push("kit excludes private deployment environment, test credentials and node_modules");
if(process.argv[3]) {
 const deployment=resolve(process.argv[3]);
 const secrets=[".env",".env.functions"].flatMap(file=>readFileSync(join(deployment,file),"utf8").split(/\r?\n/).filter(line=>/^[A-Z0-9_]*(?:PRIVATE|SECRET|PASSWORD|SERVICE_ROLE)[A-Z0-9_]*=/.test(line)).map(line=>line.slice(line.indexOf("=")+1)).filter(value=>value.length>=16 && !value.startsWith("REPLACE_")));
 assert.ok(secrets.length>0,"No rehearsal secrets found for the leakage check");
 for(const entry of inventory) {
  let bytes=readFileSync(join(kit,entry.path));
  if(/\.(?:tgz|tar\.gz)$/.test(entry.path))bytes=gunzipSync(bytes,{maxOutputLength:256*1024*1024});
  assert.ok(!secrets.some(secret=>bytes.includes(Buffer.from(secret))),"A private rehearsal secret leaked into the customer kit");
 }
 checks.push("private rehearsal credentials absent from kit files and decompressed release archives");
}
for (const required of CUSTOMER_KIT_REQUIRED_FILES) assert.ok(expected.has(required),`Required customer acceptance artifact is missing: ${required}`);
verifyRegionManifest();
verifyTlsDelivery();
verifyBenchmarkDelivery();
const source=JSON.parse(readFileSync(join(kit,"release-source.json"),"utf8"));
verifyDeliveryStatus(source);
const gatewayRuntime=["deploy/gateway/aidr-mcp-gateway.mjs","deploy/gateway/aidr-mcp-approve.mjs","deploy/gateway/aidr-mcp-stdio.mjs","deploy/gateway/aidr-artifact.manifest.json","deploy/gateway/README.md"];
const gatewaySignaturePresent=expected.has("deploy/gateway/aidr-artifact.manifest.sig");
assert.equal(source.inline_mcp_gateway_signature_present,gatewaySignaturePresent,"MCP gateway signature status does not match bundled runtime");
assert.ok(!source.release_signed||!source.inline_mcp_gateway_bundled||gatewaySignaturePresent,"Signed customer kits require the MCP gateway artifact signature");
const gatewayPaths=[...expected].filter((file)=>file.startsWith("deploy/gateway/"));
assert.equal(typeof source.inline_mcp_gateway_bundled,"boolean","MCP gateway delivery status is invalid");
assert.ok(source.inline_mcp_gateway_bundled?gatewayRuntime.every((file)=>expected.has(file)):gatewayPaths.length===0,"MCP gateway delivery status does not match bundled signed runtime");
if(source.inline_mcp_gateway_bundled){
 if(gatewaySignaturePresent){const signature=readFileSync(join(kit,"deploy/gateway/aidr-artifact.manifest.sig"),"utf8").trim();assert.ok(/^[A-Za-z0-9+/]+={0,2}$/.test(signature)&&Buffer.from(signature,"base64").length===64,"Gateway artifact signature is invalid");}
 const manifest=JSON.parse(readFileSync(join(kit,"deploy/gateway/aidr-artifact.manifest.json"),"utf8"));
 const names=new Set();
 assert.equal(manifest.schema_version,1,"Gateway artifact manifest is invalid");assert.ok(Array.isArray(manifest.files)&&manifest.files.length>=3,"Gateway artifact manifest is invalid");
 for(const item of manifest.files){assert.ok(item&&/^[A-Za-z0-9_.-]+$/.test(item.path)&&!names.has(item.path)&&/^[a-f0-9]{64}$/.test(item.sha256)&&expected.has(`deploy/gateway/${item.path}`),"Gateway artifact manifest entry is invalid");names.add(item.path);assert.equal(createHash("sha256").update(readFileSync(join(kit,"deploy/gateway",item.path))).digest("hex"),item.sha256,`Gateway artifact digest mismatch: ${item.path}`);}
 assert.ok(["aidr-mcp-gateway.mjs","aidr-mcp-approve.mjs","aidr-mcp-stdio.mjs"].every((name)=>names.has(name)),"Gateway binaries absent from manifest");
 const declared=new Set([...manifest.files.map((item)=>`deploy/gateway/${item.path}`),...gatewayRuntime,...(gatewaySignaturePresent?["deploy/gateway/aidr-artifact.manifest.sig"]:[])]);
 assert.ok(gatewayPaths.length===declared.size&&gatewayPaths.every((file)=>declared.has(file)),"MCP gateway contains files outside its signed artifact manifest");
}
const hasSignedManifest=expected.has("artifacts/aidr-release.manifest.json");
assert.equal(hasSignedManifest,expected.has("artifacts/aidr-release.manifest.sig"));
assert.equal(source.release_signed,hasSignedManifest);
assert.ok(source.assurance.includes(hasSignedManifest?"independently distributed signer policy":"Unsigned"));
checks.push(hasSignedManifest?"signed candidate requires independent signer policy verification":"unsigned candidate provenance remains explicit");
const release=JSON.parse(readFileSync(join(kit,"artifacts/release-inventory.json"),"utf8"));
for(const row of release.artifacts)assert.equal(createHash("sha256").update(readFileSync(join(kit,"artifacts",row.staged_path))).digest("hex"),row.sha256);
if(!source.inline_mcp_gateway_bundled)assert.ok(!release.artifacts.some((row)=>isMcpGatewayReleaseArtifact(row.staged_path)),"Gateway-free kit cannot contain an MCP gateway release artifact");
const releaseArtifactNames=new Set(release.artifacts.map((row)=>row.staged_path));
for(const required of CUSTOMER_KIT_REQUIRED_RELEASE_ARTIFACTS) assert.ok(releaseArtifactNames.has(required),`Required release provenance artifact is missing: ${required}`);
verifyProvenanceArtifact(join(kit,"artifacts/aidr-provenance.intoto.json"));
checks.push(`all ${release.artifacts.length} release artifacts preserve the checked release digests, including provenance`);
const outputs=mkdtempSync(join(tmpdir(),"aidr-kit-standalone-"));
const artifactPublicKey=join(outputs,"artifact-verification-public.pem");
writeFileSync(artifactPublicKey,generateKeyPairSync("ed25519").publicKey.export({type:"spki",format:"pem"}));
const isolatedEnv={...Object.fromEntries(Object.entries(process.env).filter(([key])=>key.toLowerCase()!=="path")),PATH:""};
const migrationCount=readdirSync(join(kit,"supabase/migrations")).filter(name=>name.endsWith(".sql")).length;
try {
 for(const mode of["self-hosted","cloud"]){
  const output=join(outputs,mode);
  try {
   const result=spawnSync(process.execPath,[join(kit,"scripts/deployment-prepare.mjs"),"--mode",mode,"--output",output,"--dashboard-url","https://console.customer.example","--supabase-url","https://api.customer.example","--region","self-hosted","--tenant-region","self-hosted","--artifact-verification-public-key-file",artifactPublicKey,"--telemetry-queue-root","/var/lib/aidr-telemetry"],{cwd:kit,env:isolatedEnv,encoding:"utf8",timeout:60000});
   assert.equal(result.status,0,result.stderr);
   const deployment=JSON.parse(readFileSync(join(output,"deployment.json"),"utf8"));assert.equal(deployment.mode,mode);assert.equal(deployment.development,false,"customer-kit production rehearsal must not use development mode");assert.equal(deployment.migrations.length,migrationCount);
   const config=JSON.parse(readFileSync(join(output,"agent-config.json"),"utf8"));assert.equal(config.control_plane.remote_policy_required,true);assert.equal(config.control_plane.remote_policy_offline_grace_seconds,3600);
   checks.push(`${mode} preparation works with empty PATH: no Git, package manager or build; ${migrationCount} migrations and required remote policy`);
  } finally { rmSync(output,{recursive:true,force:true}); }
 }
} finally { unlinkSync(artifactPublicKey); }
const evidence={passed:true,checked_at:new Date().toISOString(),checks,scope:"Unsigned portable preparation and checksums; residency is an operator declaration, not proof of provider location; not cloud provisioning, image air-gap delivery or production acceptance."};
writeFileSync(join(outputs,"kit-verification.json"),JSON.stringify(evidence,null,2));
console.log(JSON.stringify({passed:true,checks:checks.length,evidence_path:join(outputs,"kit-verification.json")}));

function verifyRegionManifest() {
 const file=CUSTOMER_KIT_DELIVERY_FILES.region_manifest;
 let manifest;
 try { manifest=JSON.parse(readFileSync(join(kit,file),"utf8")); } catch(error) { throw new Error(`Deployment region manifest is not valid JSON: ${error.message}`); }
 assert.equal(manifest?.schema_version,1,"Deployment region manifest schema_version must be 1");
 assert.ok(manifest.regions && typeof manifest.regions === "object" && !Array.isArray(manifest.regions) && Object.keys(manifest.regions).length > 0,"Deployment region manifest must declare regions");
 for(const [id,entry] of Object.entries(manifest.regions)) {
  assert.match(id,/^[a-z0-9][a-z0-9._-]{0,63}$/,"Deployment region id is invalid");
  assert.ok(entry && typeof entry === "object" && !Array.isArray(entry),`Deployment region entry is invalid: ${id}`);
  if(entry.supabase_url !== null) {
   let parsed;
   try { parsed=new URL(entry.supabase_url); } catch { parsed=null; }
   assert.ok(parsed?.protocol === "https:" && !parsed.username && !parsed.password && !parsed.search && !parsed.hash && parsed.pathname === "/",`Deployment region endpoint is not a valid HTTPS origin: ${id}`);
  }
  const residency=entry.residency;
  assert.ok(residency && typeof residency === "object" && !Array.isArray(residency) && typeof residency.declared === "boolean" && typeof residency.location === "string" && residency.location.length > 0,`Deployment region residency declaration is invalid: ${id}`);
  assert.ok(residency.declared === true || id === "unassigned" && residency.declared === false && residency.location === "unassigned",`Deployment region "${id}" must have residency.declared=true; only the explicit unassigned sentinel may remain false`);
 }
}

function verifyTlsDelivery() {
 const service=readFileSync(join(kit,CUSTOMER_KIT_DELIVERY_FILES.tls_service),"utf8");
 const timer=readFileSync(join(kit,CUSTOMER_KIT_DELIVERY_FILES.tls_timer),"utf8");
 assert.match(service,/deployment-tls-renew\.mjs/,"TLS renewal service is not wired to its script");
 assert.match(timer,/^Unit=aidr-tls-renew\.service$/m,"TLS renewal timer is not wired to its service");
 for(const file of [CUSTOMER_KIT_DELIVERY_FILES.tls_script]) {
  const result=spawnSync(process.execPath,["--check",join(kit,file)],{encoding:"utf8",windowsHide:true});
  assert.equal(result.status,0,`TLS renewal script is not valid JavaScript: ${file}`);
 }
}

function verifyBenchmarkDelivery() {
 for(const file of CUSTOMER_KIT_BENCHMARK_FILES.filter((entry)=>entry.endsWith(".json"))) {
  try { JSON.parse(readFileSync(join(kit,file),"utf8")); } catch(error) { throw new Error(`Benchmark contract is not valid JSON: ${file} (${error.message})`); }
 }
 for(const file of [CUSTOMER_KIT_DELIVERY_FILES.provenance_script,CUSTOMER_KIT_DELIVERY_FILES.airgap_script]) {
  const result=spawnSync(process.execPath,["--check",join(kit,file)],{encoding:"utf8",windowsHide:true});
  assert.equal(result.status,0,`Customer kit script is not valid JavaScript: ${file}`);
 }
}

function verifyDeliveryStatus(source) {
 const statuses={
  region_manifest_bundled:[CUSTOMER_KIT_DELIVERY_FILES.region_manifest],
  tls_renewal_bundled:[CUSTOMER_KIT_DELIVERY_FILES.tls_service,CUSTOMER_KIT_DELIVERY_FILES.tls_timer,CUSTOMER_KIT_DELIVERY_FILES.tls_script],
  provenance_tool_bundled:[CUSTOMER_KIT_DELIVERY_FILES.provenance_script],
  airgap_tool_bundled:[CUSTOMER_KIT_DELIVERY_FILES.airgap_script],
  benchmark_contract_bundled:CUSTOMER_KIT_BENCHMARK_FILES,
  provenance_statement_bundled:["artifacts/aidr-provenance.intoto.json"],
 };
 for(const [field,paths] of Object.entries(statuses)) if(source[field] !== undefined) assert.equal(source[field],paths.every((file)=>expected.has(file)),`release-source ${field} does not match the bundled artifact set`);
}

function verifyProvenanceArtifact(file) {
 let statement;
 try { statement=JSON.parse(readFileSync(file,"utf8")); } catch(error) { throw new Error(`Bundled release provenance is not valid JSON: ${error.message}`); }
 assert.equal(statement?._type,"https://in-toto.io/Statement/v0.1","Bundled release provenance has an unexpected statement type");
 assert.equal(statement?.predicateType,"https://slsa.dev/provenance/v0.2","Bundled release provenance has an unexpected predicate type");
 assert.ok(Array.isArray(statement.subject) && statement.subject.length > 0,"Bundled release provenance declares no artifact subjects");
 for(const subject of statement.subject) { assert.ok(typeof subject?.name === "string" && /^[a-f0-9]{64}$/.test(subject.digest?.sha256 ?? ""),"Bundled release provenance has an invalid subject digest"); }
 const predicate=statement.predicate;
 assert.ok(predicate && typeof predicate.builder?.id === "string" && Array.isArray(predicate.materials) && predicate.materials.length > 0,"Bundled release provenance is missing builder or materials");
 assert.ok(Array.isArray(predicate.byproducts) && predicate.byproducts.some((entry)=>typeof entry?.uri === "string" && entry.uri.endsWith("aidr-sbom.cdx.json")),"Bundled release provenance is missing the SBOM byproduct");
}
