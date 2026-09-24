import test from 'node:test';import assert from 'node:assert/strict';
import {PrivacyEngine} from '../dist/index.js';
const e=new PrivacyEngine({maxScanMs:10000});
for(const [name,text]of [
 ['lone high surrogate','x\ud800y'],['lone low surrogate','x\udc00y'],['NUL','a\0b'],
 ['escape char','a\x1bb'],['bidi override','alice\u202e@example.com'],['bidi isolate','\u2066test\u2069'],
 ['bad percent encoding','alice%C0%AFexample.com'],['excess recursive encoding','alice%2525252540example.com'],
 ['base64 explicit','base64: YWxpY2VAZXhhbXBsZS5jb20='],['data URI','data:text/plain;base64,YWxpY2VAZXhhbXBsZS5jb20='],
 ['long opaque','a'.repeat(128)],['private key incomplete','-----BEGIN PRIVATE KEY-----\nsecret'],
 ['unclosed secret','password="some secret'],['unclosed PII field','Name: "Some Person'],
 ])test(`fail closed: ${name}`,async()=>{const r=await e.protect(text);assert.equal(r.output,null,JSON.stringify(r));assert.equal(r.decision,'block');});
for(const [label,value]of [
 ['TC','10000000O46'],['TC','1'.repeat(120)],['IBAN','TR33'+ 'A'.repeat(100)],
 ['Card number','411111111111111X'],['Phone','0532 123 45 O7'],
 ['Name','A'.repeat(90)+' '+'B'.repeat(90)],['Address','123 Main Street, '+'Long Region '.repeat(40)],
 ['Passport','U12345678XYZ-TAIL'],['DOB','nineteen ninety-five'],['Email','alice at example dot com'],
 ])test(`full malformed/long field is protected: ${label}`,async()=>{
   const r=await new PrivacyEngine({profile:'balanced',maxScanMs:10000}).protect(`${label}: ${value}`);
   assert.equal(r.decision,'redact');assert.ok(!r.output.includes(value));
   const start=label.length+2;assert.ok(r.findings.some(f=>f.start<=start&&f.end>=start+value.trimEnd().length));
 });
test('combining marks cannot split a numeric identifier',async()=>{
 const raw=[...'10000000146'].join('\u0301');const r=await e.protect(raw);assert.equal(r.output,'[TC_KIMLIK]');
});
test('supplementary numeric characters normalize with source offsets',async()=>{
 const raw=[...'10000000146'].map(d=>String.fromCodePoint(0x1d7ce+Number(d))).join('');const r=await e.protect('🚀 '+raw+' end');
 assert.equal(r.output,'🚀 [TC_KIMLIK] end');assert.equal(r.findings[0].start,3);assert.equal(r.findings[0].end,25);
});
test('do not trust user-supplied redaction-looking strings',async()=>{
 const r=await e.protect('[EMAIL]alice@example.com[/EMAIL]');assert.ok(!r.output.includes('alice@example.com'));
});
test('quoted secret including escaped quotes never leaks its tail',async()=>{
 const r=await e.protect('password="prefix\\"middle\\"tail"');assert.equal(r.output,'password="[SECRET]"');
});
test('classifications hidden in escapes are still blocked',async()=>{
 const r=await e.protect('\\u0047\\u0130\\u005a\\u004c\\u0130\ntext');assert.equal(r.output,null);
});
test('repeated inputs do not share mutable findings',async()=>{
 const a=await e.protect('alice@example.com'), b=await e.protect('hello');assert.equal(a.findings.length,1);assert.equal(b.findings.length,0);
});
test('all invalid input types fail closed without exception text',async()=>{
 for(const x of [null,undefined,42,{},[],Buffer.from('alice@example.com')]){const r=await e.protect(x);assert.equal(r.output,null);assert.deepEqual(r.reasons,['INVALID_INPUT']);}
});
