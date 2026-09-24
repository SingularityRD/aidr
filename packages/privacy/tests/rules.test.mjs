import test from 'node:test';
import assert from 'node:assert/strict';
import {scanText,maskText,validIbanAnyCountry,IBAN_REGISTRY_LENGTHS,DEFAULT_MAX_CHARS} from '../dist/rules.js';
import {BrowserPrivacyEngine} from '../dist/browser/engine.js';
import {IBAN_LENGTHS} from '../dist/validators.js';
import {positives,negatives} from './fixtures/cases.mjs';

const types=r=>r.findings.map(f=>f.type);
const slice=(t,f)=>t.slice(f.start,f.end);

test('pure rules recognise every shared positive fixture',()=>{
  for(const [name,text,type,value] of positives){
    const r=scanText(text);
    assert.equal(r.incomplete,false,name);
    const hit=r.findings.find(f=>f.type===type);
    assert.ok(hit,`${name}: ${JSON.stringify(r)}`);
    assert.ok(!maskText(text,r.findings).includes(value),name);
  }
});

test('pure rules stay quiet on every shared benign fixture',()=>{
  for(const text of negatives)assert.deepEqual(scanText(text).findings,[],text);
});

test('rules agree with the browser engine protect pipeline',()=>{
  const engine=new BrowserPrivacyEngine({maxInputBytes:65536});
  const text='Ad Soyad: Ahmet Yılmaz; Telefon: 0532 123 45 67; E-posta: ahmet@example.com; IBAN: TR33 0006 1005 1978 6457 8413 26';
  const browser=engine.protect(text),rules=scanText(text);
  assert.equal(browser.decision,'redact');
  assert.equal(maskText(text,rules.findings,'label'),browser.output);
  assert.deepEqual(rules.findings.map(f=>[f.type,f.start,f.end]),browser.findings.map(f=>[f.type,f.start,f.end]));
});

test('TCKN checksum is enforced without a label and bypassed only with context',()=>{
  assert.deepEqual(types(scanText('id 10000000146 ok')),['TC_KIMLIK']);
  assert.deepEqual(scanText('id 10000000147 ok').findings,[]);
  assert.deepEqual(scanText('11111111111').findings,[]);
  assert.deepEqual(types(scanText('TC: 10000000147')),['TC_KIMLIK']);
});

test('IBAN mod-97 across the full registry, including countries outside the validated subset',()=>{
  const samples=['TR33 0006 1005 1978 6457 8413 26','DE89 3704 0044 0532 0130 00','AL47 2121 1009 0000 0002 3569 8741',
    'MU17 BOMM 0101 1010 3030 0200 000M UR','LC55 HEMM 0001 0001 0012 0012 0002 3015','BR15 0000 0000 0000 1093 2840 814P 2'];
  for(const iban of samples){
    const text=`pay to ${iban} today`,r=scanText(text);
    assert.deepEqual(types(r),['IBAN'],iban);assert.equal(slice(text,r.findings[0]),iban);
    assert.ok(validIbanAnyCountry(iban),iban);
  }
  assert.deepEqual(scanText('AL48 2121 1009 0000 0002 3569 8741').findings,[]);
  assert.deepEqual(scanText('TR33 0006 1005 1978 6457 8413 27').findings,[]);
  assert.equal(validIbanAnyCountry('ZZ47 2121 1009 0000 0002 3569 8741'),false);
  for(const [country,length] of Object.entries(IBAN_LENGTHS))assert.equal(IBAN_REGISTRY_LENGTHS[country],length,country);
});

test('secret patterns are fully consumed',()=>{
  const cases=[
    ['sk-proj-abcdefghijklmnop1234','sk-proj-abcdefghijklmnop1234'],
    ['sk-ant-api03-abcdefghijklmnopqrstu','sk-ant-api03-abcdefghijklmnopqrstu'],
    ['github_pat_11ABCDEFG0123456789abcdef','github_pat_11ABCDEFG0123456789abcdef'],
    ['glpat-abcdefghijklmnop1234','glpat-abcdefghijklmnop1234'],
    ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdEFGHijkl','eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdEFGHijkl'],
    ['şifre=Gizli123!','Gizli123!'],
    // URL userinfo overlaps the EMAIL-shaped host; the merged span keeps the SECRET type.
    ['https://user:pass@example.com/x','user:pass@example.com'],
  ];
  for(const [text,value] of cases){
    const r=scanText(`x ${text} y`),hit=r.findings.find(f=>f.type==='SECRET');
    assert.ok(hit,text);assert.equal(`x ${text} y`.slice(hit.start,hit.end),value);
  }
  const pem='-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkq\n-----END PRIVATE KEY-----';
  assert.deepEqual(types(scanText(pem)),['PRIVATE_KEY']);
});

test('TR addresses, phones and contextual person names',()=>{
  const text='Adres: Atatürk Mahallesi Cumhuriyet Caddesi No:5 Kadıköy\nMerhaba, benim adım Ayşe Demir. Tel +90 (532) 123 45 67';
  const r=scanText(text);
  assert.deepEqual(new Set(types(r)),new Set(['ADDRESS','PERSON','PHONE']));
  assert.equal(maskText(text,r.findings),'Adres: [ADDRESS]\nMerhaba, benim adım [PERSON]. Tel [PHONE]');
});

test('enabled filters before merging and rejects unknown types',()=>{
  const text='mail x@example.com phone 0532 123 45 67';
  assert.deepEqual(types(scanText(text,{enabled:['PHONE']})),['PHONE']);
  assert.deepEqual(scanText(text,{enabled:[]}).findings,[]);
  assert.throws(()=>scanText(text,{enabled:['NOPE']}),{code:'INVALID_CONFIGURATION'});
  assert.throws(()=>scanText(text,{maxChars:0}),{code:'INVALID_CONFIGURATION'});
});

test('literals use the dictionary matcher with Turkish case folding',()=>{
  const r=scanText('Proje İSTANBUL-X gizli',{literals:[{value:'istanbul-x',type:'INTERNAL'}]});
  assert.deepEqual(types(r),['INTERNAL']);
});

test('uninspectable input is incomplete, never silently clean',()=>{
  const big=scanText('a'.repeat(11),{maxChars:10});
  assert.deepEqual(big,{findings:[],incomplete:true,reasons:['INPUT_LIMIT']});
  assert.equal(DEFAULT_MAX_CHARS,1048576);
  const broken=scanText('password: "abc and 10000000146 x@example.com');
  assert.equal(broken.incomplete,true);assert.deepEqual(broken.reasons,['INCOMPLETE_SECRET']);
  // Detectors that ran before the malformed field still report (a lower bound).
  assert.ok(types(broken).includes('TC_KIMLIK'));
  const pem=scanText('-----BEGIN PRIVATE KEY-----\nabc');
  assert.equal(pem.incomplete,true);assert.deepEqual(pem.reasons,['INCOMPLETE_PRIVATE_KEY']);
});

test('control characters and lone surrogates do not abort the scan',()=>{
  const r=scanText('\x1b[31mab\ud800cd x@example.com\x1b[0m');
  assert.equal(r.incomplete,false);assert.deepEqual(types(r),['EMAIL']);
});

test('maskText unions overlaps and validates spans',()=>{
  const text='0123456789';
  assert.equal(maskText(text,[{type:'EMAIL',start:1,end:4,score:1},{type:'SECRET',start:3,end:6,score:1}],'label'),'0[SECRET]6789');
  assert.equal(maskText(text,[{type:'EMAIL',start:1,end:4,score:1}],'redact'),'0[REDACTED]456789');
  assert.throws(()=>maskText(text,[{type:'EMAIL',start:4,end:4,score:1}]),{code:'INVALID_SPAN'});
  assert.throws(()=>maskText(text,[{type:'EMAIL',start:0,end:11,score:1}]),{code:'INVALID_SPAN'});
  assert.throws(()=>maskText(text,[],'token'),{code:'INVALID_CONFIGURATION'});
});

test('results are frozen and offsets map to the original string',()=>{
  const text='🛡️👩‍💻 ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｃｏｍ 🚀',r=scanText(text);
  assert.ok(Object.isFrozen(r)&&Object.isFrozen(r.findings)&&Object.isFrozen(r.findings[0]));
  assert.equal(slice(text,r.findings[0]),'ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｃｏｍ');
});

test('50 KB mixed text scans in bounded time',()=>{
  const line='Ad Soyad: Ahmet Yılmaz; Telefon: 0532 123 45 67; x@example.com; const a = f(b, 12345);\n';
  const text=line.repeat(Math.ceil(51200/line.length)).slice(0,51200);
  scanText(text);
  const times=[];for(let i=0;i<3;i++){const t=performance.now();scanText(text);times.push(performance.now()-t);}
  assert.ok(Math.min(...times)<250,`best of 3 took ${Math.min(...times)}ms`);
});
