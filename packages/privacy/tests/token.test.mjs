import test from 'node:test';import assert from 'node:assert/strict';
import {PrivacyEngine}from '../dist/index.js';
const key=Buffer.alloc(32,7);
const make=(tenant='a',tokenKey=key,keyId='v1')=>new PrivacyEngine({mask:'token',tenantId:tenant,tokenKey,keyId});
test('tokenization requires a tenant and minimum 256-bit key',()=>{
  for(const o of [{},{tokenKey:key},{tenantId:'a',tokenKey:Buffer.alloc(31)}])assert.throws(()=>new PrivacyEngine({mask:'token',...o}));
});
test('stable same-tenant tokens without retaining a value vault',async()=>{
  const e=make();const a=await e.protect('alice@example.com'),b=await e.protect('alice@example.com');assert.equal(a.output,b.output);
  assert.match(a.output,/^\[EMAIL~v1~[A-Za-z0-9_-]{24}\]$/);assert.ok(!JSON.stringify(a).includes('alice'));assert.equal(JSON.stringify(e),'{}');
});
test('tenant separation',async()=>assert.notEqual((await make('a').protect('alice@example.com')).output,(await make('b').protect('alice@example.com')).output));
test('key separation',async()=>assert.notEqual((await make('a',Buffer.alloc(32,1)).protect('alice@example.com')).output,(await make('a',Buffer.alloc(32,2)).protect('alice@example.com')).output));
test('key rotation identifier separates tokens',async()=>assert.notEqual((await make('a',key,'v1').protect('alice@example.com')).output,(await make('a',key,'v2').protect('alice@example.com')).output));
test('tenant tuples resist delimiter ambiguity',async()=>assert.notEqual((await make('a:b',key,'c').protect('alice@example.com')).output,(await make('a',key,'b.c').protect('alice@example.com')).output));
test('key buffer copied at construction',async()=>{const k=Buffer.alloc(32,9),e=make('a',k);const before=(await e.protect('alice@example.com')).output;k.fill(0);assert.equal((await e.protect('alice@example.com')).output,before);});
test('phone formatting canonicalization',async()=>{const e=make();assert.equal((await e.protect('0532 123 45 67')).output,(await e.protect('05321234567')).output);});
test('email domain canonicalization only',async()=>{const e=make();assert.equal((await e.protect('Alice@EXAMPLE.COM')).output,(await e.protect('Alice@example.com')).output);assert.notEqual((await e.protect('Alice@example.com')).output,(await e.protect('alice@example.com')).output);});
test('generated token idempotence',async()=>{const e=make();const r=await e.protect('alice@example.com');assert.equal((await e.protect(r.output)).output,r.output);});
