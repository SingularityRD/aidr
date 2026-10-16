import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {existsSync,readFileSync} from 'node:fs';
import {NativeSession} from '../../dist/native/session.js';
import {BrowserPrivacyEngine} from '../../dist/browser/engine.js';
import {PrivacyEngine} from '../../dist/index.js';
import {VisualPrivacyEngine,LocalImageProcess} from '../../dist/visual/index.js';
import {input,backend,textEngine,words} from '../visual/helpers.mjs';

// Browser Guard asks the native host whether an uploaded image shows sensitive text (`image-scan`):
// a decision and per-type counts only, never pixels, OCR text or positions.
const make=(o={})=>new VisualPrivacyEngine({backend:backend(),textEngine:textEngine(),...o});
const noLeak=(r,...values)=>{for(const v of values)assert.ok(!JSON.stringify(r).includes(v),v);};

test('inspect blocks an image with sensitive text and reports counts only',async()=>{
  const b=backend({lines:['Ad Soyad: Ayşe Yılmaz','E-posta: ayse@example.com','TCKN 10000000146']});
  const r=await make({backend:b}).inspect(input);
  assert.equal(r.decision,'block');
  assert.deepEqual(r.reasons,['IMAGE_SENSITIVE_TEXT']);
  assert.equal(r.counts.EMAIL,1);assert.equal(r.counts.TC_KIMLIK,1);assert.equal(r.counts.PERSON,1);
  assert.equal(b.calls.render,0);
  assert.equal('output' in r,false);
  assert.equal(r.audit.verification,'not-released');
  noLeak(r,'ayse@example.com','10000000146','Yılmaz');
});

test('inspect allows an image whose OCR text is fully read and benign',async()=>{
  const r=await make({backend:backend({lines:['Quarterly roadmap','Release ready']})}).inspect(input);
  assert.equal(r.decision,'allow');assert.deepEqual(r.reasons,[]);assert.deepEqual(r.counts,{});
});

for(const [name,options,reason]of [
  ['no text is not clean',{backend:backend({lines:[]})},'IMAGE_NO_TEXT'],
  ['an undecoded barcode is not clean',{backend:backend({lines:['Release ready'],mutateScan:s=>({...s,barcodes:[{x:400,y:40,width:90,height:90}]})})},'IMAGE_BARCODE_NOT_INSPECTED'],
  ['uncertain OCR is not clean',{backend:backend({lines:['Unknown characters'],wordOptions:{confidence:10}})},'IMAGE_OCR_UNCERTAIN'],
  ['a text engine review without findings is not clean',{textEngine:{protect:async()=>({decision:'review',findings:[],output:null,reasons:['OPAQUE_ENCODING'],audit:{coverage:'rules-only'}})}},'IMAGE_TEXT_REVIEW'],
  ['a failing backend is not clean',{backend:{inspect:async()=>{throw new Error('secret=DO-NOT-LEAK');},render:async()=>{}}},'IMAGE_INTERNAL_FAILURE'],
  ['a timeout is not clean',{timeoutMs:5,backend:backend({delay:40})},'IMAGE_TIMEOUT'],
  ['an oversized image is not clean',{maxInputBytes:1},'IMAGE_INPUT_LIMIT'],
])test(`inspect: ${name}`,async()=>{
  const r=await make(options).inspect(input);
  assert.equal(r.decision,'review',JSON.stringify(r));assert.deepEqual(r.reasons,[reason]);assert.deepEqual(r.counts,{});
  noLeak(r,'DO-NOT-LEAK');
  await new Promise(resolve=>setTimeout(resolve,50));
});

test('inspect: sensitive text wins over uncertain words elsewhere',async()=>{
  const b=backend({lines:['Email: jane@example.com'],mutateScan:s=>({...s,pages:[{words:[...s.pages[0].words,...words(['blurry'],{confidence:5}).map(w=>({...w,y:200}))]}]})});
  const r=await make({backend:b}).inspect(input);
  assert.equal(r.decision,'block');assert.ok(r.counts.EMAIL>=1);
});

test('inspect: a finding under a review action is still sensitive',async()=>{
  const r=await make({textEngine:textEngine({actions:{EMAIL:'review'}})}).inspect(input);
  assert.equal(r.decision,'block');assert.equal(r.counts.EMAIL,1);
});

test('inspect: classified markings and block-action types block',async()=>{
  const r=await make({backend:backend({lines:['TOP SECRET','Release plan']})}).inspect(input);
  assert.equal(r.decision,'block');assert.deepEqual(r.reasons,['IMAGE_TEXT_BLOCK']);
});

test('inspect: block-all image policy never decodes, all-text policy blocks any text',async()=>{
  const b=backend();
  const blocked=await make({mode:'block',backend:b}).inspect(input);
  assert.equal(blocked.decision,'block');assert.deepEqual(blocked.reasons,['IMAGE_POLICY_BLOCK']);assert.equal(b.calls.inspect,0);
  const text=await make({mode:'all-text',backend:backend({lines:['Release ready']})}).inspect(input);
  assert.equal(text.decision,'block');assert.deepEqual(text.reasons,['IMAGE_TEXT_PRESENT']);
});

// --- native protocol --------------------------------------------------------------------------

const hash=b=>createHash('sha256').update(b).digest('hex'),pd='c'.repeat(64);let seq=0;
const request=(op,p={})=>({v:1,id:'o'+(++seq),op,...p});
async function commitImage(session,bytes){
  await session.handle(request('begin',{kind:'image-scan',size:bytes.length,sha256:hash(bytes),policyDigest:pd}));
  await session.handle(request('write',{offset:0,data:bytes.toString('base64')}));
  return session.handle(request('commit'));
}
const session=visual=>new NativeSession({text:new BrowserPrivacyEngine({maxInputBytes:1048576}),...(visual?{visual}:{}),policyId:'test',policyDigest:pd});

test('native image-scan returns a decision and counts, never bytes',async()=>{
  const s=session(make({backend:backend({lines:['IBAN TR33 0006 1005 1978 6457 8413 26']})}));
  assert.equal((await s.handle(request('hello'))).ocr,true);
  const r=await commitImage(s,input);
  assert.equal(r.ok,true);assert.equal(r.decision,'block');assert.equal(r.counts.IBAN,1);
  assert.equal(r.outputBytes,0);assert.equal(r.sha256,undefined);assert.equal(r.policyDigest,pd);
  assert.equal(r.coverage,'rules-only');
  noLeak(r,'TR33');
  await assert.rejects(s.handle(request('read',{offset:0})));
  s.close();
});

test('native image-scan of a clean image allows',async()=>{
  const s=session(make({backend:backend({lines:['Release ready']})}));
  const r=await commitImage(s,input);
  assert.equal(r.decision,'allow');assert.deepEqual(r.counts,{});assert.equal(r.outputBytes,0);
  s.close();
});

test('native image-scan without OCR reports not inspected, not clean',async()=>{
  const s=session();
  assert.equal((await s.handle(request('hello'))).ocr,false);
  const r=await commitImage(s,input);
  assert.equal(r.decision,'review');assert.deepEqual(r.reasons,['NATIVE_OCR_UNAVAILABLE']);assert.equal(r.outputBytes,0);
  s.close();
});

test('native image-scan keeps the 8 MiB image limit',async()=>{
  const s=session();
  await assert.rejects(s.handle(request('begin',{kind:'image-scan',size:8388609,sha256:pd,policyDigest:pd})));
  s.close();
});

// --- real OCR (optional dependency) -------------------------------------------------------------

// Real Tesseract OCR needs the vision worker configuration (vision/config.example.json) with local
// Python, Tesseract, eng+tur traineddata and a manifest. Without it this test reports an explicit skip.
const visionConfig=process.env.AIDR_VISION_CONFIG??new URL('../../vision/local.config.json',import.meta.url).pathname;
const needsOcr=existsSync(visionConfig)?{}:{skip:`real OCR needs a vision worker config at ${visionConfig} (set AIDR_VISION_CONFIG; see vision/config.example.json)`};
test('real OCR: image-scan blocks a screenshot with personal data',needsOcr,async()=>{
  // Same shape the native host reads: {backend, policy} (src/native/host.ts).
  const config=JSON.parse(readFileSync(visionConfig,'utf8'));
  const engine=new VisualPrivacyEngine({...config.policy,backend:new LocalImageProcess(config.backend),textEngine:new PrivacyEngine({maxInputBytes:262144})});
  try{
    const image=readFileSync(new URL('../../fixtures/visual/english-dark.png',import.meta.url));
    const r=await commitImage(session(engine),image);
    assert.equal(r.decision,'block',JSON.stringify(r));
    assert.ok((r.counts.EMAIL??0)+(r.counts.PHONE??0)+(r.counts.CREDIT_CARD??0)>0,JSON.stringify(r.counts));
  }finally{engine.dispose();}
});
