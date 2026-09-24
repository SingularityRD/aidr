import test from 'node:test';import assert from 'node:assert/strict';
import {PrivacyEngine}from '../dist/index.js';
const e=new PrivacyEngine({maxScanMs:10000});
for(const key of ['name','full_name','firstName','last_name','adSoyad','adı_soyadı','email','e-posta','phone','telefon','tckn','tc_kimlik_no','iban','credit_card_number','cardNumber','address','adres','ssn','dateOfBirth','doğum_tarihi','passport','taxId','vkn','account_number','password','api_key','clientSecret','accessToken','authorization','cookie','private_key','source_code','username','plaka'])test(`schema-based masking: ${key}`,async()=>{
 const r=await e.protectJson(JSON.stringify({[key]:'not-recognizable-by-format'}));assert.equal(r.decision,'redact');assert.ok(!r.output.includes('not-recognizable-by-format'));assert.equal(JSON.parse(r.output)[key][0],'[');
});
test('nested structures, arrays and typed scalar redaction',async()=>{
 const r=await e.protectJson(JSON.stringify({people:[{name:'Jane Doe',tc:10000000146},{name:'Çağrı Öztürk'}],count:2,enabled:true,empty:null}));
 assert.deepEqual(JSON.parse(r.output),{people:[{name:'[PERSON]',tc:'[TC_KIMLIK]'},{name:'[PERSON]'}],count:2,enabled:true,empty:null});
});
test('sensitive subtrees are masked as one field, no recursive remnant',async()=>{
 const r=await e.protectJson('{"address":{"line1":"Hidden Rd","city":"Hidden city"}}');assert.equal(r.output,'{"address":"[ADDRESS]"}');
});
test('escaped keys normalize, escaped values are decoded before inspection',async()=>{
 const r=await e.protectJson('{"na\\u006de":"Jane Doe","message":"alice\\u0040example.com"}');assert.equal(r.output,'{"name":"[PERSON]","message":"[EMAIL]"}');
});
test('PII in keys blocks rather than mutating keys or leaking paths',async()=>{
 const r=await e.protectJson('{"alice@example.com":"value"}');assert.equal(r.output,null);assert.deepEqual(r.reasons,['SENSITIVE_JSON_KEY']);assert.ok(!JSON.stringify(r).includes('alice'));
});
for(const [name,s]of [
 ['duplicate','{"name":"Alice","name":"Bob"}'],['escaped duplicate','{"name":"A","na\\u006de":"B"}'],
 ['prototype','{"__proto__":{"polluted":true}}'],['constructor','{"constructor":1}'],['prototype nested','{"a":{"prototype":1}}'],
 ['invalid syntax','{not json}'],['trailing comma','[1,2,]'],['trailing bytes','{}false'],['unsafe integer','{"x":9007199254740993}'],
 ['nonfinite','{"x":1e9999}'],['NaN','NaN'],['lone escaped surrogate','"\\ud800"'],['leading zero','01'],['unclosed','{"a":'],
 ])test(`JSON fail closed: ${name}`,async()=>{const r=await e.protectJson(s);assert.equal(r.decision,'block');assert.equal(r.output,null);});
test('depth budget',async()=>{const r=await new PrivacyEngine({maxJsonDepth:2}).protectJson('[[[1]]]');assert.deepEqual(r.reasons,['JSON_DEPTH_LIMIT']);});
test('node budget',async()=>{const r=await new PrivacyEngine({maxJsonNodes:2}).protectJson('[1,2,3]');assert.deepEqual(r.reasons,['JSON_NODE_LIMIT']);});
test('total finding budget across individually safe-sized fields',async()=>{const r=await new PrivacyEngine({maxFindings:1}).protectJson('{"name":"Jane","phone":"555"}');assert.equal(r.output,null);});
test('one blocked field aborts the entire JSON release',async()=>{const r=await new PrivacyEngine({actions:{EMAIL:'block'}}).protectJson('{"message":"hello","email":"alice@example.com"}');assert.equal(r.output,null);assert.equal(r.decision,'block');});
test('primitives and exact empty JSON values are supported',async()=>{
 for(const s of ['true','false','null','0','1.25','[]','{}','"hello"'])assert.equal((await e.protectJson(s)).output,s);
});
test('numeric identifier in untyped field cannot pass through',async()=>{const r=await e.protectJson('{"x":10000000146}');assert.equal(r.output,'{"x":"[TC_KIMLIK]"}');});
test('null sensitive field remains null',async()=>{assert.equal((await e.protectJson('{"email":null}')).output,'{"email":null}');});
