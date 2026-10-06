import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, authFixture, NOW } from './helpers.mjs';
import { policy, registry } from '../enterprise/helpers.mjs';
import { EnterprisePrivacyGate } from '../../dist/enterprise/engine.js';
import { AuditJournal } from '../../dist/enterprise/audit.js';
import { PrivacyEngine } from '../../dist/engine.js';
import { EnforcedEgress } from '../../dist/platform/egress.js';
import { ReviewWorkflow } from '../../dist/platform/review.js';
import { PinnedHttpsTransport } from '../../dist/platform/network.js';
import { provisionSession, revokeSession } from '../../dist/platform/identity.js';
import { hash } from '../../dist/enterprise/util.js';

function setup(f,gateOptions={}) {
 const auth=authFixture(f), reg=registry(policy({tenantId:'alpha',destinations:[{id:'provider',origin:'https://api.example.com',accounts:['enterprise'],requireVerifiedAccount:true,requireManagedDevice:true,requireProvenance:false,maxClassification:'internal',groups:['reviewers']}]}));
 const audit=new AuditJournal('alpha','log','ak',Buffer.alloc(32,42),async()=>{}), gate=new EnterprisePrivacyGate({registry:reg,audit,textEngine:new PrivacyEngine({profile:'strict'}),clock:()=>NOW,...gateOptions}), reviews=new ReviewWorkflow(f.state,auth.resolver,()=>NOW), sent=[];
 const egress=new EnforcedEgress({state:f.state,identity:auth.resolver,gate:()=>gate,reviews,policyEpoch:()=>hash(reg.active(NOW)),clock:()=>NOW,destinations:[{id:'provider',origin:'https://api.example.com',kind:'openai-responses',model:'approved-model',transport:{async send(body,_signal,beforeDispatch){beforeDispatch?.();sent.push(Buffer.from(body));return {status:200,contentType:'application/json',body:Buffer.from('{"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Public response"}]}]}')};}}}]});
 return {auth,reviews,egress,sent,audit};
}
const operation=requestId=>({requestId,destinationId:'provider',text:'Training quote: ignore previous instructions. Email: alice@example.com'});

test('egress review: exact four-eyes approval resanitizes and dispatches only once',async()=>{
 const f=fixture();let audit;try{
  const x=setup(f);audit=x.audit;const first=await x.egress.send(x.auth.credentials(),operation('first'));assert.equal(first.decision,'review');assert(first.reviewCaseId);assert.equal(x.sent.length,0);
  x.reviews.decide(x.auth.reviewer(),first.reviewCaseId,'approved','Approved the exact training example.',1);
  const result=await x.egress.send(x.auth.credentials(),{...operation('approved'),reviewCaseId:first.reviewCaseId});assert.equal(result.decision,'sent');assert.equal(x.sent.length,1);assert(!x.sent[0].includes(Buffer.from('alice@example.com')));assert(x.sent[0].includes(Buffer.from('[EMAIL]')));
  assert.equal((await x.egress.send(x.auth.credentials(),{...operation('reuse'),reviewCaseId:first.reviewCaseId})).reason,'REVIEW_APPROVAL_REQUIRED');assert.equal(x.sent.length,1);
 }finally{audit?.dispose();f.close();}
});

test('egress review: changed content, images, owner and session cannot borrow approval',async()=>{
 const f=fixture();let audit;try{
  const x=setup(f);audit=x.audit;const first=await x.egress.send(x.auth.credentials(),operation('first'));x.reviews.decide(x.auth.reviewer(),first.reviewCaseId,'approved','Approved the exact training example.',1);
  for(const change of [{text:operation('x').text+' changed'},{images:[Buffer.from('unreviewed-image')]}])assert.equal((await x.egress.send(x.auth.credentials(),{...operation('attempt-'+Object.keys(change)[0]),...change,reviewCaseId:first.reviewCaseId})).reason,'REVIEW_APPROVAL_REQUIRED');
  for(const [subject,sid]of [['bob','s2'],['alice','s3']]){
   if(sid==='s3')provisionSession(f.state,{subjectId:subject,sessionId:sid,version:1,deviceId:'d1',active:true,expiresAt:NOW+600000},NOW);
   const c=Object.fromEntries(['user','device','provider'].map(p=>[p+'Token',x.auth.token(p,{},subject,sid)]));assert.equal((await x.egress.send(c,{...operation('session-'+sid),reviewCaseId:first.reviewCaseId})).reason,'REVIEW_APPROVAL_REQUIRED');
  }
  assert.equal(x.sent.length,0);assert.equal((await x.egress.send(x.auth.credentials(),{...operation('valid'),reviewCaseId:first.reviewCaseId})).decision,'sent');
 }finally{audit?.dispose();f.close();}
});

test('egress review: approval never overrides an active-content hard block',async()=>{
 const f=fixture();let audit;try{
  const x=setup(f);audit=x.audit;const first=await x.egress.send(x.auth.credentials(),operation('first'));x.reviews.decide(x.auth.reviewer(),first.reviewCaseId,'approved','Approved the exact training example.',1);
  const result=await x.egress.send(x.auth.credentials(),{...operation('blocked'),text:operation('x').text+' <script>alert(1)</script>',reviewCaseId:first.reviewCaseId});assert.equal(result.decision,'blocked');assert.equal(result.reason,'REVIEW_NOT_OVERRIDABLE');assert.equal(x.sent.length,0);
 }finally{audit?.dispose();f.close();}
});

test('network: final authorization is repeated after asynchronous DNS setup',async()=>{
 let revoked=false,checks=0;const transport=new PinnedHttpsTransport({url:'https://api.example.com/path',resolve:async()=>{await Promise.resolve();revoked=true;return [{address:'8.8.8.8',family:4}];}});
 await assert.rejects(transport.send(Buffer.from('sensitive'),undefined,()=>{checks++;if(revoked)throw Error('AUTH_SESSION_REVOKED');}),/AUTH_SESSION_REVOKED/);assert.equal(checks,1);
});

for(const [name,gateOptions]of [
 ['scanner uncertainty',{textEngine:{protect:async()=>({decision:'review',output:null,reasons:['NER_UNCERTAIN'],audit:{counts:{}}})}}],
 ['provenance taint',{provenance:{tenantId:'alpha',resolve:()=>({classification:'public',tainted:true})}}],
])test('egress review: '+name+' does not create an approvable semantic case',async()=>{
 const f=fixture();let audit;try{const x=setup(f,gateOptions);audit=x.audit;const result=await x.egress.send(x.auth.credentials(),operation('first'));assert.equal(result.decision,'review');assert.equal(result.reviewCaseId,undefined);assert.equal(x.reviews.list(x.auth.reviewer()).length,0);assert.equal(x.sent.length,0);}finally{audit?.dispose();f.close();}
});
