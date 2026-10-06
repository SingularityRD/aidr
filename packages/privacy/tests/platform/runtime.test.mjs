import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, chmodSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync} from 'node:crypto';
import {createPlatformRuntime} from '../../dist/platform/runtime.js';
import {signPolicy} from '../../dist/enterprise/policy.js';
import {PersistentAuditJournal} from '../../dist/platform/persistent-audit.js';
import {verifyAudit} from '../../dist/enterprise/audit.js';
import {policy, context, NOW} from '../enterprise/helpers.mjs';
import {privateDirectory} from './helpers.mjs';
function setup(){
 const root=mkdtempSync(join(tmpdir(),'aidr-runtime-'));privateDirectory(root);
 const keys=generateKeyPairSync('ed25519');const trust={issuer:'https://issuer.example.com',audience:'aidr',keys:new Map([['k1',keys.publicKey]])};
 const signed=signPolicy(policy(),'k1',keys.privateKey);
 const options={tenantId:'tenant-a',databasePath:join(root,'control.sqlite'),encryption:{active:'k1',keys:[{id:'k1',key:Buffer.alloc(32,18)}]},audit:{keyId:'audit1',key:Buffer.alloc(32,22)},identity:{user:trust,device:trust,provider:trust,roleGroups:{},scopes:[]},policy:{signed,keys:new Map([['k1',keys.publicKey]])},destinations:[],clock:()=>NOW};
 return {root,keys,options,clean(){rmSync(root,{recursive:true,force:true});}};
}
test('runtime: default defense profile rejects text without real NER; audit persisted',async()=>{const f=setup();let r;try{r=await createPlatformRuntime(f.options);const result=await r.gate.protect('Public text',context());assert.equal(result.output,null);const audit=new PersistentAuditJournal(r.state,'decisions','audit1',f.options.audit.key);assert(audit.records().length>0);assert(verifyAudit(audit.records(),audit.checkpoint(),f.options.audit.key));audit.dispose();}finally{r?.close();f.clean();}});
test('runtime: explicitly strict pilot masks PII and reopens durable audit/checkpoint',async()=>{const f=setup();let r;try{r=await createPlatformRuntime({...f.options,profile:'strict'});const first=await r.gate.protect('Email: jane@example.com',context());assert.equal(first.output,'Email: [EMAIL]');r.close();r=undefined;r=await createPlatformRuntime({...f.options,profile:'strict'});assert.equal(r.registry.checkpoint().revision,1);const audit=new PersistentAuditJournal(r.state,'decisions','audit1',f.options.audit.key);const before=audit.records().length;await r.gate.protect('Public status update',context());assert(audit.records().length>before);assert(verifyAudit(audit.records(),audit.checkpoint(),f.options.audit.key));audit.dispose();}finally{r?.close();f.clean();}});
test('runtime: same revision with changed signed policy is denied after restart',async()=>{const f=setup();try{const r=await createPlatformRuntime(f.options);r.close();const changed=signPolicy(policy({piiAction:'block'}),'k1',f.keys.privateKey);await assert.rejects(createPlatformRuntime({...f.options,policy:{...f.options.policy,signed:changed}}),/ROLLOUT/);}finally{f.clean();}});
