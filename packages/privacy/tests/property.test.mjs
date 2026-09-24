import test from 'node:test';import assert from 'node:assert/strict';
import {PrivacyEngine,validTckn,validLuhn,mergeFindings}from '../dist/index.js';
import {normalize,detectionViews,isBoundary}from '../dist/normalize.js';
let state=0x5eed1234;const rand=()=>{state^=state<<13;state^=state>>>17;state^=state<<5;return(state>>>0)/4294967296;};
const integer=n=>Math.floor(rand()*n);
function tckn(){const d=[1+integer(9),...Array.from({length:8},()=>integer(10))];let a=0,b=0;d.forEach((x,i)=>i%2===0?a+=x:b+=x);d.push(((7*a-b)%10+10)%10);d.push(d.reduce((s,x)=>s+x,0)%10);return d.join('');}
function card(){const s='4'+Array.from({length:14},()=>integer(10)).join('');let sum=0;for(let i=0;i<s.length;i++){const n=Number(s[i])*(i%2===0?2:1);sum+=n>9?n-9:n;}return s+String((10-sum%10)%10);}
const e=new PrivacyEngine({maxScanMs:10000});
test('property: 2000 valid TCKNs, corrupted check digits, and redaction spans',async()=>{
 for(let i=0;i<2000;i++){const x=tckn();assert.ok(validTckn(x));assert.ok(!validTckn(x.slice(0,-1)+((Number(x.at(-1))+1)%10)));const r=await e.protect(x);assert.equal(r.output,'[TC_KIMLIK]');}
});
test('property: 2000 generated Luhn cards and mutated check digits',async()=>{
 for(let i=0;i<2000;i++){const x=card();assert.ok(validLuhn(x));assert.ok(!validLuhn(x.slice(0,-1)+((Number(x.at(-1))+1)%10)));const r=await e.protect(x);assert.equal(r.output,'[CREDIT_CARD]');}
});
test('property: 1500 randomized Unicode/encoding variants preserve PII coverage',async()=>{
 const variants=[x=>x,x=>[...x].join('\u200b'),x=>[...x].map(c=>String.fromCharCode(0xff10+Number(c))).join(''),x=>[...x].map(c=>String.fromCharCode(0x0660+Number(c))).join(''),x=>[...x].join('\u0301'),x=>[...x].map(c=>'%'+c.charCodeAt(0).toString(16)).join('')];
 for(let i=0;i<1500;i++){const raw=variants[i%variants.length](tckn()),before=['🚀 ','🧑‍💻 ','Çağrı ',''][integer(4)],text=before+raw+'; done';const r=await e.protect(text);assert.equal(r.output,before+'[TC_KIMLIK]; done');for(const f of r.findings){assert.ok(isBoundary(text,f.start));assert.ok(isBoundary(text,f.end));}}
});
test('property: 3000 random interval unions preserve exactly the covered character set',()=>{
 for(let i=0;i<3000;i++){const fs=Array.from({length:1+integer(15)},()=>{const a=integer(90);return{start:a,end:a+1+integer(100-a),type:['PERSON','ADDRESS','SECRET'][integer(3)],score:.8,evidence:'pattern'};});const merged=mergeFindings(fs);for(let p=0;p<100;p++)assert.equal(fs.some(f=>f.start<=p&&p<f.end),merged.some(f=>f.start<=p&&p<f.end));for(let j=1;j<merged.length;j++)assert.ok(merged[j-1].end<=merged[j].start);}
});
test('property: 1500 arbitrary Unicode views have monotonic valid source mappings',()=>{
 const chars=['a','İ','ı','é','e\u0301','\u200b','🚀','٣','９',' ','\n','&amp;','%40'];
 for(let i=0;i<1500;i++){const text=Array.from({length:1+integer(30)},()=>chars[integer(chars.length)]).join('');for(const v of detectionViews(text)){assert.equal(v.starts.length,v.text.length);assert.equal(v.ends.length,v.text.length);for(let j=0;j<v.text.length;j++){assert.ok(v.starts[j]>=0&&v.ends[j]<=text.length&&v.starts[j]<v.ends[j]);if(j)assert.ok(v.starts[j]>=v.starts[j-1]);}}}
});
test('normalized view does not corrupt a decomposed Turkish grapheme',()=>{
 const v=normalize('I\u0307pek');assert.equal(v.text,'İpek');assert.deepEqual([v.starts[0],v.ends[0]],[0,2]);
});
