#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, readdirSync, lstatSync, mkdtempSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { gunzipSync } from "node:zlib";
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
const source=JSON.parse(readFileSync(join(kit,"release-source.json"),"utf8"));
const hasSignedManifest=expected.has("artifacts/aidr-release.manifest.json");
assert.equal(hasSignedManifest,expected.has("artifacts/aidr-release.manifest.sig"));
assert.equal(source.release_signed,hasSignedManifest);
assert.ok(source.assurance.includes(hasSignedManifest?"independently distributed signer policy":"Unsigned"));
checks.push(hasSignedManifest?"signed candidate requires independent signer policy verification":"unsigned candidate provenance remains explicit");
const release=JSON.parse(readFileSync(join(kit,"artifacts/release-inventory.json"),"utf8"));
for(const row of release.artifacts)assert.equal(createHash("sha256").update(readFileSync(join(kit,"artifacts",row.staged_path))).digest("hex"),row.sha256);
assert.equal(release.artifacts.length,14);checks.push("all 14 release artifacts preserve the checked release digests");
const outputs=mkdtempSync(resolve(".release-evidence/kit-standalone-"));
const isolatedEnv={...Object.fromEntries(Object.entries(process.env).filter(([key])=>key.toLowerCase()!=="path")),PATH:""};
const migrationCount=readdirSync(join(kit,"supabase/migrations")).filter(name=>name.endsWith(".sql")).length;
for(const mode of["self-hosted","cloud"]){
 const output=join(outputs,mode);
 const result=spawnSync(process.execPath,[join(kit,"scripts/deployment-prepare.mjs"),"--mode",mode,"--output",output,"--dashboard-url","https://console.customer.example","--supabase-url","https://api.customer.example"],{cwd:kit,env:isolatedEnv,encoding:"utf8",timeout:60000});
 assert.equal(result.status,0,result.stderr);
 const deployment=JSON.parse(readFileSync(join(output,"deployment.json"),"utf8"));assert.equal(deployment.mode,mode);assert.equal(deployment.migrations.length,migrationCount);
 const config=JSON.parse(readFileSync(join(output,"agent-config.json"),"utf8"));assert.equal(config.control_plane.remote_policy_required,true);assert.equal(config.control_plane.remote_policy_offline_grace_seconds,3600);
 checks.push(`${mode} preparation works with empty PATH: no Git, package manager or build; ${migrationCount} migrations and required remote policy`);
}
const evidence={passed:true,checked_at:new Date().toISOString(),checks,scope:"Unsigned portable preparation and checksums; not cloud provisioning, image air-gap delivery or production acceptance."};
writeFileSync(join(outputs,"kit-verification.json"),JSON.stringify(evidence,null,2));
console.log(JSON.stringify({passed:true,checks:checks.length,evidence_path:join(outputs,"kit-verification.json")}));
