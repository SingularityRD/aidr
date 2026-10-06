import test from 'node:test';import assert from 'node:assert/strict';
import {PrivacyEngine} from '../dist/index.js';
const caps={local:true,offsetUnit:'utf16',languages:['tr','en'],entities:['PERSON','ADDRESS'],revision:'a'.repeat(64),entitiesByLanguage:{tr:['PERSON','ADDRESS'],en:['PERSON','ADDRESS']}};
const cleanNer={capabilities:caps,async detect(){return {complete:true,entities:[]};}};
for(const mark of ['GİZLİ','ÇOK GİZLİ','HİZMETE ÖZEL','SECRET','TOP SECRET','NATO SECRET','CONFIDENTIAL'])test(`classified marking blocks: ${mark}`,async()=>{
  const r=await new PrivacyEngine().protect(`${mark}\nInternal design`);assert.equal(r.decision,'block');assert.equal(r.output,null);
});
test('review action produces no forwardable output',async()=>{
  const r=await new PrivacyEngine({actions:{EMAIL:'review'}}).protect('a@example.com');assert.equal(r.decision,'review');assert.equal(r.output,null);
});
test('block action produces no forwardable output',async()=>{
  const r=await new PrivacyEngine({actions:{EMAIL:'block'}}).protect('a@example.com');assert.equal(r.decision,'block');assert.equal(r.output,null);
});
test('literals are case-insensitive, normalized, and not regex',async()=>{
  const e=new PrivacyEngine({literals:[{value:'PROJE KARTAL',type:'INTERNAL'},{value:'(a+)+$',type:'INTERNAL'}]});
  assert.equal((await e.protect('Proje Kartal aktif')).output,'[INTERNAL] aktif');
  assert.equal((await e.protect('x (a+)+$ y')).output,'x [INTERNAL] y');
});
test('overlapping dictionary block cannot be hidden by larger email span',async()=>{
  const r=await new PrivacyEngine({literals:[{value:'example',type:'INTERNAL'}],actions:{INTERNAL:'block'}}).protect('alice@example.com');
  assert.equal(r.decision,'block');assert.equal(r.output,null);
});
test('defense requires real provider configuration',async()=>{
  const e=new PrivacyEngine({profile:'defense'});
  for(const x of ['abc','Name: Jane Doe',''])assert.deepEqual((await e.protect(x)).reasons,['NER_REQUIRED']);
  assert.equal((await e.protectJson('{}')).output,null);
});
test('defense checks each language, not only global type union',async()=>{
  const ner={...cleanNer,capabilities:{...caps,entitiesByLanguage:{tr:['PERSON','ADDRESS'],en:['PERSON']}}};
  assert.deepEqual((await new PrivacyEngine({profile:'defense',ner}).protect('text')).reasons,['NER_CAPABILITY_MISSING']);
});
test('defense secret and literal policy cannot be downgraded',async()=>{
  for(const type of ['SECRET','PRIVATE_KEY','INTERNAL','CLASSIFIED'])assert.throws(()=>new PrivacyEngine({profile:'defense',actions:{[type]:'redact'}}));
});
test('defense policy runs with fully declared test provider',async()=>{
  const e=new PrivacyEngine({profile:'defense',ner:cleanNer,literals:[{value:'Project Falcon',type:'INTERNAL'}]});
  assert.equal((await e.protect('Project Falcon')).decision,'block');assert.equal((await e.protect('Hello')).decision,'allow');
});
test('unknown entity and action configuration rejected',()=>{
  assert.throws(()=>new PrivacyEngine({actions:{WHATEVER:'redact'}}));assert.throws(()=>new PrivacyEngine({actions:{EMAIL:'allow'}}));
});
test('configuration bounds reject NaN, zero and excessive limits',()=>{
  for(const n of [NaN,0,-1,1.5,Infinity,2**40])assert.throws(()=>new PrivacyEngine({maxInputBytes:n}));
});
test('literal dictionary size limits',()=>{
  assert.throws(()=>new PrivacyEngine({literals:[{value:'',type:'PERSON'}]}));
  assert.throws(()=>new PrivacyEngine({literals:Array.from({length:1025},()=>({value:'x',type:'PERSON'}))}));
});
test('engine options copied, mutations cannot weaken decisions',async()=>{
  const actions={EMAIL:'block'},literals=[{value:'KARTAL',type:'INTERNAL'}];const e=new PrivacyEngine({actions,literals});
  actions.EMAIL='redact';literals[0].value='OTHER';
  assert.equal((await e.protect('a@example.com')).decision,'block');assert.equal((await e.protect('KARTAL')).output,'[INTERNAL]');
});
test('return values deeply freeze privacy-relevant metadata',async()=>{
  const r=await new PrivacyEngine().protect('alice@example.com');
  for(const object of [r,r.findings,r.findings[0],r.reasons,r.audit,r.audit.counts])assert.ok(Object.isFrozen(object));
});
test('max input length produces no raw error data',async()=>{
  const r=await new PrivacyEngine({maxInputBytes:4}).protect('secret@example.com');assert.equal(r.output,null);assert.deepEqual(r.reasons,['INPUT_LIMIT']);assert.ok(!JSON.stringify(r).includes('secret@example.com'));
});
test('findings cannot be silently truncated on exhaustion',async()=>{
  const r=await new PrivacyEngine({maxFindings:1}).protect('a@example.com; b@example.com');assert.equal(r.output,null);assert.deepEqual(r.reasons,['FINDING_LIMIT']);
});
test('disposed engine blocks instead of falling back',async()=>{
  const e=new PrivacyEngine();e.dispose();assert.deepEqual((await e.protect('hello')).reasons,['DISPOSED']);
});
test('dispose revokes in-flight text and JSON releases',async()=>{
  for(const input of ['hello','a@example.com']){
    let release;const ner={capabilities:caps,detect:async()=>new Promise(resolve=>{release=resolve;})};
    const e=new PrivacyEngine({ner}),pending=e.protect(input);await new Promise(resolve=>setImmediate(resolve));
    e.dispose();release({complete:true,entities:[]});const r=await pending;
    assert.equal(r.output,null);assert.deepEqual(r.reasons,['DISPOSED']);
  }
  const e=new PrivacyEngine(),pending=e.protectJson('null');e.dispose();
  assert.deepEqual((await pending).reasons,['DISPOSED']);assert.equal((await pending).output,null);
});
