#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
const dir=resolve(process.argv[2]||".aidr-deploy"), manifest=JSON.parse(readFileSync(join(dir,"deployment.json"),"utf8")),base=new URL(manifest.supabase_url);
assert.ok(manifest.development && ["localhost","127.0.0.1"].includes(base.hostname));
const env=Object.fromEntries(readFileSync(join(dir,".env"),"utf8").split(/\r?\n/).filter(s=>s.includes("=")).map(s=>[s.slice(0,s.indexOf("=")),s.slice(s.indexOf("=")+1)]));
const credentials=JSON.parse(readFileSync(join(dir,"private-ui-fixture/login.json"),"utf8"));
const checks=[];
async function request(path,token=env.SERVICE_ROLE_KEY,body,method=body===undefined?"GET":"POST",headers={}) {
 const response=await fetch(new URL(path,base),{method,headers:{apikey:env.ANON_KEY,Authorization:`Bearer ${token}`,"Content-Type":"application/json",...headers},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(30000)});
 const text=await response.text();let data;try{data=JSON.parse(text);}catch{data={};}return{status:response.status,data};
}
const login=await request("/auth/v1/token?grant_type=password",env.ANON_KEY,{email:credentials.email,password:credentials.password});assert.equal(login.status,200);
const owner=login.data.user.id,jwt=login.data.access_token;
const created=await request("/rest/v1/rpc/create_team_tenant",jwt,{p_name:`Operations ${randomBytes(6).toString("hex")}`,p_request_id:randomUUID(),p_plan:"free"});assert.equal(created.status,200);
const tenant=created.data.id,headers={"X-AIDR-Tenant-ID":tenant};
assert.equal((await request("/rest/v1/entitlements",undefined,{user_id:owner,tenant_id:tenant,included_agents:1,extra_agents:0})).status,201);
const password=randomBytes(32).toString("hex"), email=`ops-${randomBytes(8).toString("hex")}@example.test`;
const user=await request("/auth/v1/admin/users",undefined,{email,password,email_confirm:true});assert.equal(user.status,200);
const session=await request("/auth/v1/token?grant_type=password",env.ANON_KEY,{email,password});assert.equal(session.status,200);const other=session.data.access_token;
const exportPage=(body,token=jwt)=>request("/functions/v1/audit-export",token,{team_id:tenant,format:"json",...body});
const timestamp=new Date(Date.now()-60000).toISOString();
const seed=Array.from({length:1005},(_,n)=>({id:randomUUID(),team_id:tenant,tenant_id:tenant,user_id:owner,action:`export-fixture-${n}`,created_at:timestamp,verdict:{decision:"deny"}}));
for(let i=0;i<seed.length;i+=200)assert.equal((await request("/rest/v1/audit_logs",undefined,seed.slice(i,i+200))).status,201);
let result=await exportPage({});assert.equal(result.status,200);assert.equal(result.data.rows,500);assert.ok(result.data.next_cursor);
const first=result.data, all=[];let pages=0;
const late={...seed[0],id:randomUUID(),created_at:new Date(Date.now()+1000).toISOString(),action:"after-export-snapshot"};
assert.equal((await request("/rest/v1/audit_logs",undefined,late)).status,201);
for(;;){
 const download=await fetch(result.data.url);assert.equal(download.status,200);const rows=await download.json();assert.equal(rows.length,result.data.rows);all.push(...rows);pages++;
 if(result.data.complete)break;
 result=await exportPage({cursor:result.data.next_cursor});assert.equal(result.status,200);assert.equal(result.data.snapshot,first.snapshot);assert.ok(pages<5);
}
assert.equal(all.length,1005);assert.equal(new Set(all.map(row=>row.id)).size,1005);assert.ok(!all.some(row=>row.id===late.id));
assert.deepEqual(new Set(all.map(row=>row.id)),new Set(seed.map(row=>row.id)));
checks.push("1005 same-timestamp records export over three pages without gaps or duplicates; later writes excluded");
assert.equal((await exportPage({cursor:first.next_cursor.slice(0,-2)+"xx"})).status,400);
assert.equal((await exportPage({cursor:first.next_cursor,format:"csv"})).status,400);
assert.equal((await exportPage({cursor:first.next_cursor},other)).status,403);
checks.push("modified, cross-format and unauthorized export cursors rejected");
const csv=await exportPage({format:"csv"});assert.equal(csv.status,200);assert.match(await(await fetch(csv.data.url)).text(),/^id,created_at,user_id,action,verdict/);
const privatePath=new URL(first.url).pathname.replace('/object/sign/','/object/');assert.notEqual((await fetch(new URL(privatePath,base))).status,200);
checks.push("CSV export and expiring private download work; unsigned object access rejected");
const expired=`${tenant}/${randomUUID()}.json`,current=`${tenant}/${randomUUID()}.json`;
for(const[path,expires_at]of[[expired,new Date(Date.now()-1000).toISOString()],[current,new Date(Date.now()+86400000).toISOString()]]){
 assert.equal((await request("/rest/v1/audit_export_objects",undefined,{path,tenant_id:tenant,created_by:owner,expires_at})).status,201);
 assert.equal((await request(`/storage/v1/object/aidr-audit-exports/${path}`,undefined,{fixture:true})).status,200);
}
const maintenance=apply=>spawnSync(process.execPath,[resolve("scripts/deployment-maintenance.mjs"),dir,...(apply?["--apply"]:[])],{encoding:"utf8",timeout:90000});
let task=maintenance(false);assert.equal(task.status,0,task.stderr);assert.equal((await request(`/storage/v1/object/aidr-audit-exports/${expired}`)).status,200);
task=maintenance(true);assert.equal(task.status,0,task.stderr);assert.notEqual((await request(`/storage/v1/object/aidr-audit-exports/${expired}`)).status,200);assert.equal((await request(`/storage/v1/object/aidr-audit-exports/${current}`)).status,200);
assert.equal((await request(`/rest/v1/audit_export_objects?path=eq.${expired}`)).data.length,0);
task=maintenance(true);assert.equal(task.status,0);assert.equal(JSON.parse(task.stdout).removed,0);
checks.push("retention dry run preserves files; apply removes expired bytes and ledger only; repeat is idempotent");
const ownerKey=await request("/functions/v1/api-keys",jwt,{action:"create",label:"owner-key"},"POST",headers);assert.equal(ownerKey.status,200);
const listing=await request("/functions/v1/api-keys",jwt,undefined,"GET",headers);const id=listing.data.keys.find(key=>key.label==="owner-key").id;
assert.equal((await request("/functions/v1/api-keys",other,undefined,"GET",headers)).status,403);
assert.equal((await request("/rest/v1/tenant_members",undefined,{tenant_id:tenant,user_id:user.data.id,role:"viewer"})).status,201);
for(const endpoint of["api-keys","enrollment-tokens"])assert.equal((await request(`/functions/v1/${endpoint}`,other,{action:"create"},"POST",headers)).status,403);
const sponsor=await request("/auth/v1/admin/users",undefined,{email:`sponsor-${randomBytes(8).toString("hex")}@example.test`,password:randomBytes(32).toString("hex"),email_confirm:true});assert.equal(sponsor.status,200);
assert.equal((await request("/rest/v1/pilot_applications",undefined,{user_id:sponsor.data.id,tenant_id:tenant,status:"approved"})).status,201);
const device=await request("/functions/v1/device-start",env.ANON_KEY,{});assert.equal(device.status,200);
assert.equal((await request("/functions/v1/device-verify",other,{user_code:device.data.user_code},"POST",headers)).status,403);
assert.equal((await request(`/rest/v1/tenant_members?tenant_id=eq.${tenant}&user_id=eq.${user.data.id}`,undefined,{role:"member"},"PATCH")).status,204);
assert.equal((await request("/functions/v1/pilot-status",other,undefined,"GET",headers)).data.status,"approved");
assert.equal((await request("/functions/v1/device-verify",other,{user_code:device.data.user_code},"POST",headers)).status,200);
await new Promise(done=>setTimeout(done,(device.data.interval_seconds+1)*1000));
const exchange=await request("/functions/v1/device-poll",env.ANON_KEY,{device_code:device.data.device_code});assert.equal(exchange.status,200);
const iid=`member-device-${randomBytes(8).toString("hex")}`;
const enrolled=await request("/functions/v1/enroll",exchange.data.enrollment_token,{iid,agent_runtime:"claude-code"});assert.equal(enrolled.status,200,enrolled.data.error);
const deviceRows=await request(`/rest/v1/agents?tenant_id=eq.${tenant}&iid=eq.${iid}`);assert.equal(deviceRows.data.length,1);assert.equal(deviceRows.data[0].user_id,user.data.id);
checks.push("team admission enrolls an authorized member without personal pilot approval; viewer cannot authorize");
assert.equal((await request("/functions/v1/api-keys",other,{action:"revoke",id},"POST",headers)).status,404);
assert.equal((await request("/functions/v1/api-keys",other,{action:"create",label:"member-key"},"POST",headers)).status,200);
assert.equal((await request(`/rest/v1/api_keys?id=eq.${id}`,other,{revoked:true},"PATCH",headers)).status,403);
assert.equal((await request("/functions/v1/api-keys",jwt,{action:"unknown"},"POST",headers)).status,400);
checks.push("team keys stay scoped; viewer writes, member revocation of owner keys and direct database mutation rejected");
assert.equal((await request(`/rest/v1/tenants?id=eq.${tenant}`,undefined,{status:"suspended"},"PATCH")).status,204);
try{for(const endpoint of["api-keys","enrollment-tokens"])assert.equal((await request(`/functions/v1/${endpoint}`,jwt,{action:"create"},"POST",headers)).status,403);}finally{await request(`/rest/v1/tenants?id=eq.${tenant}`,undefined,{status:"active"},"PATCH");}
checks.push("suspended tenants cannot issue keys or enrollment tokens");
assert.equal((await request("/functions/v1/api-keys",jwt,{action:"revoke",id},"POST",headers)).status,200);
assert.equal((await request("/functions/v1/policy",ownerKey.data.api_key)).status,401);
checks.push("owner revocation takes effect for native policy authentication");
writeFileSync(join(dir,"enterprise-operations-evidence.json"),JSON.stringify({passed:true,checked_at:new Date().toISOString(),checks,scope:"Isolated HTTP/database/storage fixtures; no external acceptance implied."},null,2));
console.log(`${checks.length} enterprise operations checks passed.`);
