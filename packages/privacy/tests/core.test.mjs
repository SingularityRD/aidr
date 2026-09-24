import test from 'node:test';
import assert from 'node:assert/strict';
import {PrivacyEngine} from '../dist/index.js';
import {positives,negatives} from './fixtures/cases.mjs';
const engine=new PrivacyEngine({maxScanMs:10000});
for(const [name,text,type,value] of positives) test(`recognize and mask: ${name}`,async()=>{
  const result=await engine.protect(text);
  assert.equal(result.decision,'redact',JSON.stringify(result));
  assert.ok(result.findings.some(f=>f.type===type),JSON.stringify(result));
  assert.ok(!result.output.includes(value),JSON.stringify(result));
  assert.ok(!JSON.stringify(result.audit).includes(value));
  for(const f of result.findings){assert.ok(f.start>=0&&f.end>f.start&&f.end<=text.length);}
});
for(const [i,text] of negatives.entries())test(`benign regression ${i+1}`,async()=>{
  const result=await engine.protect(text);
  assert.equal(result.decision,'allow',JSON.stringify(result));assert.equal(result.output,text);
});
test('TR exact output and multiple entities',async()=>{
  const r=await engine.protect('Ad Soyad: Ahmet Yılmaz; Telefon: 0532 123 45 67; E-posta: ahmet@example.com');
  assert.equal(r.output,'Ad Soyad: [PERSON]; Telefon: [PHONE]; E-posta: [EMAIL]');
});
test('EN exact output and punctuation',async()=>{
  const r=await engine.protect('My name is Jane Doe. Email: jane.doe@example.com. Phone: +1 (415) 555-0123');
  assert.equal(r.output,'My name is [PERSON]. Email: [EMAIL]. Phone: [PHONE]');
});
test('redact mode uses constant-size placeholder, no last-four leakage',async()=>{
  const r=await new PrivacyEngine({mask:'redact'}).protect('4111 1111 1111 1111');
  assert.equal(r.output,'[REDACTED]');
});
test('idempotence of generated labels',async()=>{
  for(const [,text]of positives){const r=await engine.protect(text);if(r.output!==null)assert.equal((await engine.protect(r.output)).output,r.output);}
});
