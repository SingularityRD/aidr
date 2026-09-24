import test from 'node:test';import assert from 'node:assert/strict';
import {normalize,normalizeView,identity,decodeView,sourceSpan}from '../dist/normalize.js';
import {PrivacyEngine}from '../dist/index.js';
test('ASCII/Turkish fast path leaves NFKC-stable text unchanged',()=>{
 const s='Çağrı Öztürk, IĞDIR, İSTANBUL, ŞÜKRÜ, ad Soyad.\r\n';
 const view=normalize(s);assert.equal(view.text,s);
 for(let i=0;i<s.length;i++)assert.deepEqual([view.starts[i],view.ends[i]],[i,i+1]);
});
test('ASCII fast path preserves prior encoded span map',()=>{
 const v=normalizeView(decodeView(identity('%61%62%63')));assert.equal(v.text,'abc');
 assert.deepEqual(sourceSpan(v,0,1),[0,9]);assert.deepEqual(sourceSpan(v,1,3),[0,9]);
});
test('Unicode compatibility characters still follow full normalization',()=>{
 assert.equal(normalize('ａｌｉｃｅ＠example.com').text,'alice@example.com');
 assert.equal(normalize('١٢٣').text,'123');assert.equal(normalize('A\u200bB').text,'AB');
});
test('Fast-path common Turkish and English data retains complete masking',async()=>{
 const e=new PrivacyEngine();
 const r=await e.protect('İsim: Çağrı Öztürk; Email: jane@example.com');
 assert.equal(r.output,'İsim: [PERSON]; Email: [EMAIL]');
});
test('Turkish uppercase dotted-I labels are recognized without shifting offsets',async()=>{
 const e=new PrivacyEngine();
 for(const [label,value,type]of [['T.C. KİMLİK NUMARASI','not_a_valid_identifier','TC_KIMLIK'],['İSİM','Çağrı Öztürk','PERSON'],['ŞİFRE','sensitive-demo','SECRET'],['KREDİ KARTI NUMARASI','not_a_valid_card','CREDIT_CARD']]){
  const r=await e.protect(`${label}: ${value}`);assert.equal(r.output,`${label}: [${type}]`);
 }
});
