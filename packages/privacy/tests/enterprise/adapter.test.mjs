import test from 'node:test';import assert from 'node:assert/strict';
import { SensitiveDataIndex } from '../../dist/enterprise/index.js';
import { fixture,context,key } from './helpers.mjs';
import { VisualPrivacyEngine } from '../../dist/visual/index.js';

test('TextResult adapter preserves original UTF-16 PII spans for image coordinates',async()=>{
 const f=fixture(),text='😀 E-posta: çağrı@example.com',r=await f.gate.textAdapter(context()).protect(text);
 assert.equal(r.decision,'redact');assert.equal(r.audit.coverage,'rules-only');
 const email=r.findings.find(x=>x.type==='EMAIL');assert.ok(email);assert.equal(text.slice(email.start,email.end),'çağrı@example.com');
 assert.ok(!r.output.includes('@'));assert.equal(f.records.length,1);
});
test('adapter context is captured before later caller mutation',async()=>{
 const f=fixture(),c=context(),adapter=f.gate.textAdapter(c);c.account='personal';c.subjectId='bad';
 const r=await adapter.protect('Public documentation');assert.equal(r.decision,'allow');
 assert.equal(f.records[0].event.actorRef,f.audit.actor('subject-1'));
});
test('EDM denial passes through standard TextResult with no original text',async()=>{
 const d=new SensitiveDataIndex('tenant-a','db','k',key());d.enrollRecord('r',{part:'PART-BRAVO',site:'ZONE-DELTA'},'restricted');
 const f=fixture({indexes:[d]}),r=await f.gate.textAdapter(context()).protect('PART-BRAVO ZONE-DELTA');
 assert.equal(r.decision,'block');assert.equal(r.output,null);assert.deepEqual(r.findings,[]);assert.ok(r.reasons.includes('CLASSIFICATION_DENIED'));
});
test('blocked account adapter supplies valid metadata without invoking scanner',async()=>{
 const f=fixture({textEngine:{protect:async()=>{throw Error('must not run');}}});
 const r=await f.gate.textAdapter(context({account:'personal'})).protect('a@example.com');
 assert.equal(r.decision,'block');assert.equal(r.output,null);assert.equal(r.audit.coverage,'rules-only');
 assert.deepEqual(r.findings,[]);assert.ok(r.reasons.includes('ACCOUNT_UNVERIFIED'));
});
test('concurrent request adapters do not share findings or text',async()=>{
 const f=fixture(),a=f.gate.textAdapter(context()),b=f.gate.textAdapter(context({subjectId:'subject-2'}));
 const [r,s]=await Promise.all([a.protect('first@example.com'),b.protect('Public manual')]);
 assert.equal(r.decision,'redact');assert.equal(s.decision,'allow');assert.equal(s.findings.length,0);assert.equal(f.records.length,2);
});
test('adapter no-output after audit failure, including already detected PII',async()=>{
 const f=fixture({audit:{tenantId:'tenant-a',actor:()=> 'a'.repeat(64),append:async()=>{throw Error('disk failure');}}});
 const r=await f.gate.textAdapter(context()).protect('a@example.com');assert.equal(r.output,null);assert.equal(r.decision,'block');
});
test('VisualPrivacyEngine accepts the enterprise TextResult adapter without changing OCR code',()=>{
 const f=fixture();const visual=new VisualPrivacyEngine({backend:{inspect:async()=>{throw Error('not used');},render:async()=>{throw Error('not used');}},textEngine:f.gate.textAdapter(context())});
 assert.ok(visual);
});
