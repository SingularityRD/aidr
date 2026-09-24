import test from 'node:test';import assert from 'node:assert/strict';
import {PrivacyEngine,AtomicTextGate}from '../dist/index.js';
const e=new PrivacyEngine({maxScanMs:10000});
test('all byte split positions preserve complete masking and UTF-8',async()=>{
 const text='🛡️ Çağrı: alice@example.com; TC: 10000000146',bytes=Buffer.from(text),expected=(await e.protect(text)).output;
 for(let i=0;i<=bytes.length;i++){const g=new AtomicTextGate(e);assert.equal(g.push(bytes.subarray(0,i)),undefined);assert.equal(g.push(bytes.subarray(i)),undefined);assert.equal((await g.finish()).output,expected);}
});
test('one-byte chunks including Turkish and emoji code points',async()=>{
 const g=new AtomicTextGate(e);for(const byte of Buffer.from('🚀 İsim: Çağrı Öztürk; alice@example.com'))g.push(Buffer.from([byte]));assert.ok(!(await g.finish()).output.includes('alice@example.com'));
});
test('buffer copying prevents post-push mutation',async()=>{
 const g=new AtomicTextGate(e),b=Buffer.from('alice@example.com');g.push(b);b.fill(65);assert.equal((await g.finish()).output,'[EMAIL]');
});
test('invalid UTF-8 is rejected, not replaced silently',async()=>{
 for(const bytes of [[0xc0,0xaf],[0xed,0xa0,0x80],[0xe2,0x82],[0xff]]){const g=new AtomicTextGate(e);g.push(Buffer.from(bytes));await assert.rejects(g.finish(),/INVALID_UTF8/);assert.equal(g.state,'aborted');}
});
test('overflow aborts and cannot be resumed',async()=>{
 const g=new AtomicTextGate(new PrivacyEngine({maxInputBytes:4}));assert.throws(()=>g.push(Buffer.from('12345')),/INPUT_LIMIT/);await assert.rejects(g.finish());assert.throws(()=>g.push(Buffer.from('x')));
});
test('finish is one-shot and push is closed after completion',async()=>{
 const g=new AtomicTextGate(e);g.push(Buffer.from('hello'));assert.equal((await g.finish()).output,'hello');await assert.rejects(g.finish());assert.throws(()=>g.push(Buffer.from('x')));
});
test('explicit abort produces no release',async()=>{const g=new AtomicTextGate(e);g.push(Buffer.from('alice@example.com'));g.abort();await assert.rejects(g.finish());});
test('message hold timeout aborts without releasing',async()=>{const g=new AtomicTextGate(e,5);g.push(Buffer.from('alice@'));await new Promise(r=>setTimeout(r,15));await assert.rejects(g.finish());});
test('empty stream is supported',async()=>{assert.equal((await new AtomicTextGate(e).finish()).output,'');});
