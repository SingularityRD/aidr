#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFileSync,writeFileSync } from "node:fs";
import { resolve,join } from "node:path";
import { randomUUID,randomBytes } from "node:crypto";
const dir=resolve(process.argv[2]||".aidr-deploy"), manifest=JSON.parse(readFileSync(join(dir,"deployment.json"),"utf8")), base=new URL(manifest.supabase_url);
assert.ok(manifest.development&&["localhost","127.0.0.1"].includes(base.hostname));
const env=Object.fromEntries(readFileSync(join(dir,".env"),"utf8").split(/\r?\n/).filter(s=>s.includes("=")).map(s=>[s.slice(0,s.indexOf("=")),s.slice(s.indexOf("=")+1)]));
const c=JSON.parse(readFileSync(join(dir,"private-ui-fixture/login.json"),"utf8"));
async function request(path,token,body,method=body===undefined?"GET":"POST") {const r=await fetch(new URL(path,base),{method,headers:{apikey:env.ANON_KEY,Authorization:`Bearer ${token}`,"Content-Type":"application/json"},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(30000)});const s=await r.text();return{status:r.status,data:s?JSON.parse(s):null};}
const login=await request("/auth/v1/token?grant_type=password",env.ANON_KEY,{email:c.email,password:c.password});assert.equal(login.status,200);
const jwt=login.data.access_token, tenant=c.tenant_id, owner=login.data.user.id;
const manage=body=>request("/functions/v1/policy-management",jwt,{tenant_id:tenant,...body});
const baseline=(await manage({action:"read"})).data;
const latestRevision=(await manage({action:"history"})).data.revisions[0]?.version;
assert.ok(Number.isSafeInteger(latestRevision)&&latestRevision>=baseline.version);
const prefix=`fleet-page-${randomBytes(8).toString("hex")}`;
const fixtures=Array.from({length:501},(_,i)=>({id:randomUUID(),iid:`${prefix}-${i}`,tenant_id:tenant,user_id:owner,agent_runtime:"claude-code",display_name:"Pagination fixture"})).sort((a,b)=>a.id.localeCompare(b.id));
const checks=[];let staged=false;
try{
 for(let i=0;i<fixtures.length;i+=100)assert.equal((await request("/rest/v1/agents",env.SERVICE_ROLE_KEY,fixtures.slice(i,i+100))).status,201);
 const last=fixtures[fixtures.length-1];
 const stage=await manage({action:"stage",expected_version:baseline.version,expected_revision_version:latestRevision,policy:{mcp_unknown:"deny"},agent_ids:[last.id]});assert.equal(stage.status,200);staged=true;
 const first=await manage({action:"adoption"});assert.equal(first.status,200);assert.equal(first.data.agents.length,500);assert.ok(first.data.next_agent);
 const second=await manage({action:"adoption",after_agent:first.data.next_agent});assert.equal(second.status,200);assert.equal(second.data.next_agent,null);
 const rows=[...first.data.agents,...second.data.agents];assert.equal(new Set(rows.map(row=>row.id)).size,rows.length);
 assert.ok(fixtures.every(fixture=>rows.some(row=>row.id===fixture.id)));
 checks.push("501 synthetic fleet records traverse keyset pages without gaps or duplicate agents");
 const target=second.data.agents.find(row=>row.id===last.id);assert.ok(target);assert.equal(target.target_version,stage.data.version);assert.equal(target.state,"unknown");assert.equal(target.loaded_version,null);
 checks.push("targeted assignment on the second page is preserved and absent receipt remains unknown");
 assert.equal((await manage({action:"adoption",after_agent:"invalid),tenant_id.neq.value"})).status,400);
 checks.push("malformed fleet cursor rejected");
}finally{
 if(staged)assert.equal((await manage({action:"restore",expected_version:baseline.version,target_version:baseline.version})).status,200);
 for(let i=0;i<fixtures.length;i+=100){const ids=fixtures.slice(i,i+100).map(row=>row.id).join(",");assert.equal((await request(`/rest/v1/agents?tenant_id=eq.${tenant}&id=in.(${ids})`,env.SERVICE_ROLE_KEY,undefined,"DELETE")).status,204);}
}
checks.push("fixture-only rows removed and original policy restored through versioned publication");
writeFileSync(join(dir,"policy-fleet-pagination-evidence.json"),JSON.stringify({passed:true,checked_at:new Date().toISOString(),checks,scope:"501 synthetic DB rows for pagination, not a real 501-agent load or scale acceptance test."},null,2));
console.log(`${checks.length} fleet pagination checks passed.`);
