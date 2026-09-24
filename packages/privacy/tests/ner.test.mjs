import test from 'node:test';import assert from 'node:assert/strict';import {resolve}from 'node:path';
import {PrivacyEngine,LocalNerProcess}from '../dist/index.js';
const caps={local:true,offsetUnit:'utf16',languages:['tr','en'],entities:['PERSON','ADDRESS'],revision:'a'.repeat(64),entitiesByLanguage:{tr:['PERSON','ADDRESS'],en:['PERSON','ADDRESS']}};
const provider=(detect,capabilities=caps)=>({capabilities,detect});
test('external NER spans are applied in UTF-16 units, not code points',async()=>{
 const text='🚀 Jane Doe left.';const ner=provider(async()=>({complete:true,entities:[{start:3,end:11,type:'PERSON',score:.98}]}));
 const r=await new PrivacyEngine({ner}).protect(text);assert.equal(r.output,'🚀 [PERSON] left.');
});
test('NER overlapping span union does not expose any tail',async()=>{
 const ner=provider(async()=>({complete:true,entities:[{start:0,end:5,type:'PERSON',score:.9},{start:3,end:9,type:'ADDRESS',score:.95}]}));
 const r=await new PrivacyEngine({ner}).protect('abcdefghi x');assert.equal(r.output,'[ADDRESS] x');
});
test('low confidence is not silently discarded in strict profile',async()=>{
 const ner=provider(async()=>({complete:true,entities:[{start:0,end:4,type:'PERSON',score:.01}]}));
 assert.equal((await new PrivacyEngine({ner}).protect('Jane')).output,'[PERSON]');
});
test('defense low confidence holds output for review',async()=>{
 const ner=provider(async()=>({complete:true,entities:[{start:0,end:4,type:'PERSON',score:.3}]}));
 const r=await new PrivacyEngine({ner,profile:'defense'}).protect('Jane');assert.equal(r.decision,'review');assert.equal(r.output,null);
});
for(const [name,result]of [
 ['incomplete',{complete:false,entities:[]}],['missing complete',{entities:[]}],['not array',{complete:true,entities:{}}],
 ['invalid start',{complete:true,entities:[{start:-1,end:3,type:'PERSON',score:.9}]}],
 ['invalid end',{complete:true,entities:[{start:0,end:999,type:'PERSON',score:.9}]}],
 ['empty interval',{complete:true,entities:[{start:1,end:1,type:'PERSON',score:.9}]}],
 ['NaN score',{complete:true,entities:[{start:0,end:3,type:'PERSON',score:NaN}]}],
 ['score out of range',{complete:true,entities:[{start:0,end:3,type:'PERSON',score:1.1}]}],
 ['unknown type',{complete:true,entities:[{start:0,end:3,type:'NOT_A_TYPE',score:.9}]}],
 ['fractional offset',{complete:true,entities:[{start:.5,end:3,type:'PERSON',score:.9}]}],
 ['null entity',{complete:true,entities:[null]}],
 ])test(`malformed model output blocks: ${name}`,async()=>{
 const r=await new PrivacyEngine({ner:provider(async()=>result)}).protect('Jane');assert.equal(r.output,null);assert.equal(r.decision,'block');
});
test('surrogate-splitting NER offsets rejected',async()=>{
 const ner=provider(async()=>({complete:true,entities:[{start:1,end:4,type:'PERSON',score:.9}]}));assert.equal((await new PrivacyEngine({ner}).protect('🚀 Jane')).output,null);
});
test('NER errors never echo input or exception messages',async()=>{
 const ner=provider(async()=>{throw new Error('secret alice@example.com');});const r=await new PrivacyEngine({ner}).protect('alice@example.com');
 assert.equal(r.output,null);assert.deepEqual(r.reasons,['NER_FAILURE']);assert.ok(!JSON.stringify(r).includes('alice'));
});
test('NER timeout fails closed and signals abort',async()=>{
 let aborted=false;const ner=provider(async(_,signal)=>new Promise(()=>signal.addEventListener('abort',()=>{aborted=true;})));
 const r=await new PrivacyEngine({ner,nerTimeoutMs:10}).protect('Jane');assert.equal(r.output,null);assert.ok(aborted);assert.deepEqual(r.reasons,['NER_TIMEOUT']);
});
test('concurrency overload rejects instead of queuing raw requests without bounds',async()=>{
 let release;const ner=provider(async()=>new Promise(r=>{release=r;}));const e=new PrivacyEngine({ner,maxConcurrent:1});
 const pending=e.protect('first');await new Promise(r=>setImmediate(r));const second=await e.protect('second');
 assert.equal(second.output,null);assert.deepEqual(second.reasons,['CONCURRENCY_LIMIT']);release({complete:true,entities:[]});assert.equal((await pending).output,'first');
});
test('decoded NER views are scanned as well as original',async()=>{
 const ner=provider(async(text)=>{const start=text.indexOf('Jane');return {complete:true,entities:start<0?[]:[{start,end:start+4,type:'PERSON',score:.9}]};});
 const r=await new PrivacyEngine({ner}).protect('\\u004aane');assert.equal(r.output,'[PERSON]');
});
test('remote or byte-offset NER declarations rejected',()=>{
 assert.throws(()=>new PrivacyEngine({ner:provider(async()=>({}),{...caps,local:false})}));assert.throws(()=>new PrivacyEngine({ner:provider(async()=>({}),{...caps,offsetUnit:'bytes'})}));
});
const open=mode=>LocalNerProcess.open({command:process.execPath,args:[resolve('tests/fixtures/mock-ner.mjs'),mode],startupTimeoutMs:1000});
test('real child process protocol round-trip (mock model, not HF inference)',async()=>{
 const ner=await open('normal');try{const r=await new PrivacyEngine({ner}).protect('🚀 Jane Doe went home');assert.equal(r.output,'🚀 [PERSON] went home');}finally{ner.close();}
});
test('child process handles successive isolated requests',async()=>{
 const ner=await open('normal');try{const e=new PrivacyEngine({ner});assert.equal((await e.protect('Jane Doe')).output,'[PERSON]');assert.equal((await e.protect('no name here')).output,'no name here');}finally{ner.close();}
});
for(const mode of ['crash','wrong-id','incomplete','malformed','flood'])test(`child IPC failure: ${mode}`,async()=>{
 const ner=await open(mode);try{const r=await new PrivacyEngine({ner,nerTimeoutMs:2000}).protect('Jane Doe');assert.equal(r.output,null);}finally{ner.close();}
});
test('aborted hung child is terminated and not reused',async()=>{
 const ner=await open('hang');try{const e=new PrivacyEngine({ner,nerTimeoutMs:20});assert.equal((await e.protect('Jane Doe')).output,null);assert.equal((await e.protect('Again')).output,null);}finally{ner.close();}
});
test('failed executable cannot create a ready provider',async()=>{await assert.rejects(LocalNerProcess.open({command:'/not/a/real/program',args:[],startupTimeoutMs:100}));});
test('relative executable rejected (no PATH-based execution)',async()=>{await assert.rejects(LocalNerProcess.open({command:'python3',args:[]}));});
test('startup handshake timeout terminates child',async()=>{await assert.rejects(LocalNerProcess.open({command:process.execPath,args:[resolve('tests/fixtures/mock-ner.mjs'),'no-ready'],startupTimeoutMs:20}));});
