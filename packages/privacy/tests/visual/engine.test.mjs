import test from 'node:test';
import assert from 'node:assert/strict';
import {VisualPrivacyEngine} from '../../dist/visual/index.js';
import {input,backend,textEngine,scan,words,png} from './helpers.mjs';
const make=(o={})=>new VisualPrivacyEngine({backend:backend(),textEngine:textEngine(),release:'automatic',...o});
function denied(r,code){assert.ok(['block','review'].includes(r.decision));assert.equal(r.output,null);assert.equal(r.contentType,null);assert.equal(r.filename,null);assert.equal(r.outputSha256,null);if(code)assert.ok(r.reasons.includes(code),JSON.stringify(r.reasons));}
test('manual is default, no pixel artifact is released',async()=>{const b=backend();const r=await new VisualPrivacyEngine({backend:b,textEngine:textEngine()}).protect(input);denied(r,'IMAGE_MANUAL_REVIEW');assert.equal(b.calls.render,0);assert.equal(r.regions.length,1);});
test('actual text core selects PII and independent PNG check passes',async()=>{const r=await make().protect(input);assert.equal(r.decision,'redact');assert.ok(r.output.length);assert.equal(r.filename,'aidr-sanitized.png');assert.match(r.outputSha256,/^[a-f0-9]{64}$/);assert.deepEqual(r.regions[0].types,['EMAIL']);assert.ok(!JSON.stringify(r).includes('jane@example.com'));});
test('benign image is still re-encoded, never original bytes',async()=>{const r=await make({backend:backend({lines:['Service ready']})}).protect(input);assert.equal(r.decision,'allow');assert.ok(!r.output.equals(input));assert.equal(r.regions.length,0);});
test('all-text mode protects unclassified words too',async()=>{const r=await make({mode:'all-text',backend:backend({lines:['SecretishCustomerName WithoutLabel']})}).protect(input);assert.equal(r.decision,'redact');assert.ok(r.regions.some(r=>r.types.includes('ALL_TEXT')));});
test('block-all policy never invokes a decoder',async()=>{const b=backend();denied(await make({mode:'block',backend:b}).protect(input),'IMAGE_POLICY_BLOCK');assert.equal(b.calls.inspect,0);});
for(const [label,value,type]of [
 ['Ad Soyad','Çağrı Öztürk','PERSON'],['Full name','Jane Doe','PERSON'],['Telefon','0532 123 45 67','PHONE'],
 ['Email','jane@example.com','EMAIL'],['TCKN','10000000146','TC_KIMLIK'],['IBAN','TR33 0006 1005 1978 6457 8413 26','IBAN'],
 ['Credit card','4111 1111 1111 1111','CREDIT_CARD'],['SSN','123-45-6789','US_SSN'],['Adres','Atatürk Mahallesi 5 Ankara','ADDRESS'],
 ['Address','123 Main Street','ADDRESS'],['Password','this-is-synthetic-test','SECRET'],['Passport','X12345678','PASSPORT'],
 ['Date of birth','1990-01-01','DATE_OF_BIRTH'],['Tax ID','1234567890','TAX_ID'],['Account number','9876543210','BANK_ACCOUNT']
])test(`OCR geometry + core ${type} ${label}`,async()=>{const r=await make({backend:backend({lines:[`${label}: ${value}`]})}).protect(input);assert.equal(r.decision,'redact',JSON.stringify(r.reasons));assert.ok(r.regions.some(r=>r.types.includes(type)));});
test('geometric regrouping connects sparse label and value blocks',async()=>{const r=await make({backend:backend({lines:['Full name: Jane Doe'],wordOptions:{sparse:true}})}).protect(input);assert.equal(r.decision,'redact');assert.ok(r.regions.some(r=>r.types.includes('PERSON')));});
test('multiline label:value bridge preserves source rectangles',async()=>{const r=await make({backend:backend({lines:['Full name:','Jane Doe']})}).protect(input);assert.equal(r.decision,'redact');assert.ok(r.regions.some(r=>r.y>30&&r.types.includes('PERSON')));});
test('word-level mode masks complete OCR tokens',async()=>{const r=await make({granularity:'word'}).protect(input);assert.equal(r.decision,'redact');assert.ok(r.regions[0].x>10);});
test('overlapping lower priority block is not downgraded by geometry',async()=>{const r=await make({textEngine:textEngine({literals:[{value:'jane@example.com',type:'INTERNAL'}],actions:{INTERNAL:'block'}})}).protect(input);denied(r,'IMAGE_TEXT_BLOCK');});
test('classification marking is non-downgradable',async()=>{denied(await make({backend:backend({lines:['TOP SECRET','Email: jane@example.com']})}).protect(input),'IMAGE_TEXT_BLOCK');});
test('text core review is preserved with no bytes',async()=>{denied(await make({textEngine:textEngine({actions:{EMAIL:'review'}})}).protect(input),'IMAGE_TEXT_REVIEW');});
test('requireNer rejects rules-only',async()=>{denied(await make({requireNer:true}).protect(input),'IMAGE_NER_REQUIRED');});
test('no OCR text is not an allow',async()=>{denied(await make({backend:backend({lines:[]})}).protect(input),'IMAGE_NO_TEXT');});
test('unmasked low-confidence text goes to review',async()=>{denied(await make({backend:backend({lines:['Unknown characters'],wordOptions:{confidence:10}})}).protect(input),'IMAGE_OCR_UNCERTAIN');});
test('low-confidence PII already fully masked may proceed',async()=>{assert.equal((await make({backend:backend({wordOptions:{confidence:10}})}).protect(input)).decision,'redact');});
test('redact-line policy adds uncertain whole row',async()=>{const r=await make({uncertainText:'redact-line',backend:backend({lines:['Unknown characters'],wordOptions:{confidence:10}})}).protect(input);assert.equal(r.decision,'redact');assert.ok(r.regions.some(r=>r.types.includes('OCR_UNCERTAIN')));});
test('tiny recognized text cannot silently pass',async()=>{const r=await make({backend:backend({lines:['hello'],mutateScan:s=>({...s,pages:[{words:s.pages[0].words.map(w=>({...w,height:3}))}]})})}).protect(input);denied(r,'IMAGE_OCR_UNCERTAIN');});
for(const action of ['block','redact'])test(`barcode policy ${action}`,async()=>{const r=await make({barcodeAction:action,backend:backend({mutateScan:s=>({...s,barcodes:[{x:450,y:60,width:100,height:100}]})})}).protect(input);if(action==='block')denied(r,'IMAGE_BARCODE_BLOCKED');else{assert.equal(r.decision,'redact');assert.ok(r.regions.some(r=>r.types.includes('BARCODE')));}});
test('residual PII cancels previously rendered artifact',async()=>{const r=await make({backend:backend({mutateRender:r=>({...r,pages:[{words:words(['Email: residual@example.com'])}]})})}).protect(input);denied(r,'IMAGE_RESIDUAL_PII');assert.ok(!JSON.stringify(r).includes('residual@example.com'));});
test('residual barcode cancels artifact',async()=>{denied(await make({backend:backend({mutateRender:r=>({...r,barcodes:[{x:1,y:1,width:5,height:5}]})})}).protect(input),'IMAGE_RESIDUAL_BARCODE');});
test('renderer claiming masks without black pixels fails independent verifier',async()=>{denied(await make({backend:backend({fill:255})}).protect(input),'IMAGE_PIXEL_VERIFICATION_FAILED');});
for(const [name,patch,code]of [
 ['missing complete',s=>({...s,complete:false}),'IMAGE_PROTOCOL_INVALID'],
 ['wrong input hash',s=>({...s,inputSha256:'b'.repeat(64)}),'IMAGE_HASH_MISMATCH'],
 ['invalid pixel hash',s=>({...s,pixelSha256:'no'}),'IMAGE_HASH_MISMATCH'],
 ['zero width',s=>({...s,width:0}),'IMAGE_DIMENSION_LIMIT'],
 ['huge height',s=>({...s,height:99999}),'IMAGE_DIMENSION_LIMIT'],
 ['pixel bomb',s=>({...s,width:8192,height:8192}),'IMAGE_PIXEL_LIMIT'],
 ['gif pretends image',s=>({...s,format:'GIF'}),'IMAGE_FORMAT_UNSUPPORTED'],
 ['missing Turkish',s=>({...s,languages:['eng']}),'IMAGE_OCR_UNAVAILABLE'],
 ['missing barcode scan',s=>({...s,barcodes:undefined}),'IMAGE_PROTOCOL_INVALID'],
 ['missing OCR',s=>({...s,pages:[] }),'IMAGE_PROTOCOL_INVALID'],
 ['negative box',s=>({...s,pages:[{words:[{...s.pages[0].words[0],x:-1}]}]}),'IMAGE_GEOMETRY_INVALID'],
 ['NaN confidence',s=>({...s,pages:[{words:[{...s.pages[0].words[0],confidence:NaN}]}]}),'IMAGE_PROTOCOL_INVALID'],
 ['unpaired surrogate',s=>({...s,pages:[{words:[{...s.pages[0].words[0],text:'\ud800'}]}]}),'IMAGE_PROTOCOL_INVALID'],
 ['embedded whitespace',s=>({...s,pages:[{words:[{...s.pages[0].words[0],text:'a b'}]}]}),'IMAGE_PROTOCOL_INVALID'],
 ['empty word',s=>({...s,pages:[{words:[{...s.pages[0].words[0],text:''}]}]}),'IMAGE_PROTOCOL_INVALID'],
 ['bad line',s=>({...s,pages:[{words:[{...s.pages[0].words[0],line:-1}]}]}),'IMAGE_PROTOCOL_INVALID'],
])test(`untrusted scan contract ${name}`,async()=>{denied(await make({backend:backend({mutateScan:patch})}).protect(input),code);});
for(const [name,patch]of [['width',r=>({...r,width:639})],['complete',r=>({...r,complete:false})],['png type',r=>({...r,png:'bad'})],['missing barcode',r=>({...r,barcodes:null})]])test(`bad render contract ${name}`,async()=>denied(await make({backend:backend({mutateRender:patch})}).protect(input),'IMAGE_PROTOCOL_INVALID'));
for(const value of [undefined,null,'data:image/png;base64,aaa',{},[],42,new Uint8Array(),new Uint8Array(new SharedArrayBuffer(20))])test(`invalid image input ${String(value).slice(0,20)}`,async()=>denied(await make().protect(value),'IMAGE_INPUT_INVALID'));
test('byte limit',async()=>denied(await make({maxInputBytes:1}).protect(input),'IMAGE_INPUT_LIMIT'));
test('word count limit',async()=>denied(await make({maxWords:1}).protect(input),'IMAGE_OCR_LIMIT'));
test('text bytes limit',async()=>denied(await make({maxTextBytes:3}).protect(input),'IMAGE_OCR_LIMIT'));
test('region limit',async()=>denied(await make({maxRegions:1,backend:backend({lines:['Email: a@example.com','Phone: 0532 123 45 67']})}).protect(input),'IMAGE_REGION_LIMIT'));
test('unknown errors have static reason, not secret exception text',async()=>{const r=await make({backend:{inspect:async()=>{throw new Error('secret=DO-NOT-LEAK');},render:async()=>{}}}).protect(input);denied(r,'IMAGE_INTERNAL_FAILURE');assert.ok(!JSON.stringify(r).includes('DO-NOT-LEAK'));});
test('concurrency bound rejects rather than queues raw images',async()=>{const e=make({maxConcurrent:1,backend:backend({delay:30})});const first=e.protect(input);denied(await e.protect(input),'IMAGE_CONCURRENCY_LIMIT');assert.equal((await first).decision,'redact');});
test('timeout fails closed even if backend ignores signal; capacity stays reserved',async()=>{const e=make({timeoutMs:5,maxConcurrent:1,backend:backend({delay:30})});denied(await e.protect(input),'IMAGE_TIMEOUT');denied(await e.protect(input),'IMAGE_CONCURRENCY_LIMIT');await new Promise(r=>setTimeout(r,50));});
test('external abort is fail closed',async()=>{const c=new AbortController();const pending=make({backend:backend({delay:40})}).protect(input,c.signal);c.abort();denied(await pending,'IMAGE_ABORTED');await new Promise(r=>setTimeout(r,50));});
test('already aborted does not inspect',async()=>{const c=new AbortController();c.abort();const b=backend();denied(await make({backend:b}).protect(input,c.signal),'IMAGE_ABORTED');assert.equal(b.calls.inspect,0);});
test('dispose blocks future work',async()=>{const e=make();e.dispose();denied(await e.protect(input),'IMAGE_DISPOSED');});
test('caller mutation cannot swap original after inspection begins',async()=>{const caller=Buffer.from(input);let original;const b=backend({delay:15,mutateScan:(s,data)=>{original=Buffer.from(data);return s;}});const pending=make({backend:b}).protect(caller);caller.fill(0);assert.equal((await pending).decision,'redact');assert.ok(original.equals(input));});
for(const [key,value]of [['mode','bad'],['release','allow'],['granularity','character'],['barcodeAction','allow'],['uncertainText','ignore'],['minConfidence',NaN],['paddingPx',0],['maxPixels',1e12],['maxConcurrent',0],['requireNer','yes'],['policyId','contains spaces']])test(`reject unsafe configuration ${key}`,()=>assert.throws(()=>make({[key]:value}),/IMAGE_CONFIGURATION_INVALID/));
