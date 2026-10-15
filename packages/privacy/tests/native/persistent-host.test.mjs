import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {createHash,createHmac,randomBytes} from 'node:crypto';
import {FrameDecoder,encodeFrame} from '../../dist/native/framing.js';
import {NativeSession} from '../../dist/native/session.js';
import {BrowserPrivacyEngine} from '../../dist/browser/engine.js';
import {deriveEdmKey,parseEdmSecret,EDM_KEY_LABEL} from '../../dist/native/edm.js';

// BG-11: Browser Guard keeps ONE host process (and its NER worker) for many scans instead of
// starting a process per scan. BG-8: exact-data keys are derived in the host from a secret that
// never appears in browser policy.
const id='hmcbdjjldiobifmolecnmalilknnapcb',pd='a'.repeat(64);
const hash=b=>createHash('sha256').update(b).digest('hex');
let seq=0;const request=(op,p={})=>({v:1,id:'p'+(++seq),op,...p});
const make=(extra={})=>new NativeSession({text:new BrowserPrivacyEngine({maxInputBytes:1048576}),policyId:'test',policyDigest:pd,...extra});
async function scan(s,text){const bytes=Buffer.from(text);await s.handle(request('begin',{kind:'text',size:bytes.length,sha256:hash(bytes),policyDigest:pd}));await s.handle(request('write',{offset:0,data:bytes.toString('base64')}));return s.handle(request('commit'));}

test('a persistent session serves many documents, including after unread output and cancel',async()=>{
  const s=make();
  const h=await s.handle(request('hello',{persistent:true}));assert.equal(h.persistent,true);
  const first=await scan(s,'Email: a@example.com');assert.equal(first.decision,'redact');
  // The client did not read the output back: the next document still starts.
  const second=await scan(s,'nothing to see');assert.equal(second.decision,'allow');
  await s.handle(request('begin',{kind:'text',size:1,sha256:hash('a'),policyDigest:pd}));
  await s.handle(request('cancel'));
  const third=await scan(s,'Mail b@example.com');assert.equal(third.decision,'redact');
  const r=await s.handle(request('read',{offset:0}));assert.equal(Buffer.from(r.data,'base64').toString(),'Mail [EMAIL]');
  assert.equal(s.documents,4);
  // A keep-alive hello is accepted while idle.
  assert.equal((await s.handle(request('hello',{persistent:true}))).persistent,true);
  s.close();
  await assert.rejects(s.handle(request('hello',{persistent:true})));
});

test('a plain hello keeps the original one-document session (older clients)',async()=>{
  const s=make();const h=await s.handle(request('hello'));assert.equal('persistent' in h,false);
  assert.equal((await scan(s,'Email: a@example.com')).decision,'redact');
  await assert.rejects(scan(s,'again'));
});

test('persistent hello must be literally true',async()=>{await assert.rejects(make().handle(request('hello',{persistent:1})));});

test('correlation ids are a rolling window, so a long session never runs out',async()=>{
  const s=make();await s.handle(request('hello',{persistent:true}));
  for(let i=0;i<600;i++)await s.handle(request('hello',{persistent:true}));
  const q=request('hello',{persistent:true});await s.handle(q);await assert.rejects(s.handle(q));
});

test('edm-keys derives one key per dataset and needs an idle session',async()=>{
  const secret=randomBytes(32),s=make({exactDataKey:d=>deriveEdmKey(secret,d).toString('base64')});
  await s.handle(request('hello',{persistent:true}));
  const r=await s.handle(request('edm-keys',{datasetIds:['crm-a','crm-b']}));
  const expect=d=>createHmac('sha256',secret).update(`${EDM_KEY_LABEL}\u0000${d}`).digest('base64');
  assert.deepEqual(r.keys,{'crm-a':expect('crm-a'),'crm-b':expect('crm-b')});
  assert.notEqual(r.keys['crm-a'],r.keys['crm-b']);
  for(const bad of [[],['x/y'],['a','a'],Array.from({length:17},(_,i)=>`d${i}`),'crm-a'])await assert.rejects(s.handle(request('edm-keys',{datasetIds:bad})));
  await s.handle(request('begin',{kind:'text',size:1,sha256:hash('a'),policyDigest:pd}));
  await assert.rejects(s.handle(request('edm-keys',{datasetIds:['crm-a']})));
  // A host without a secret answers with no keys (the extension then fails closed).
  const none=make();assert.deepEqual((await none.handle(request('edm-keys',{datasetIds:['crm-a']}))).keys,{});
});

test('the EDM secret must be base64 of at least 32 bytes',()=>{
  assert.throws(()=>parseEdmSecret(randomBytes(16).toString('base64')));
  assert.throws(()=>parseEdmSecret('not base64!'));
  assert.equal(parseEdmSecret(`${randomBytes(32).toString('base64')}\n`).length,32);
});

function startHost(config){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'aidr-persistent-')),file=path.join(dir,'config.json');
  fs.writeFileSync(file,JSON.stringify(config(dir)));
  const child=spawn(process.execPath,['dist/native/host.js','--config',file,`chrome-extension://${id}/`],{stdio:['pipe','pipe','ignore']}),decoder=new FrameDecoder();
  let pending,n=0;const fail=()=>pending?.reject(Error('HOST_DISCONNECTED'));
  child.on('exit',fail);
  child.stdout.on('data',chunk=>{for(const r of decoder.push(chunk)){if(r.id===pending?.id&&r.ok===true)pending.resolve(r);else fail();}});
  const rpc=(op,fields={})=>new Promise((resolve,reject)=>{const q={v:1,id:`h${++n}`,op,...fields},timer=setTimeout(()=>reject(Error('HOST_TIMEOUT')),10000);pending={id:q.id,resolve:r=>{clearTimeout(timer);pending=undefined;resolve(r);},reject:e=>{clearTimeout(timer);pending=undefined;reject(e);}};child.stdin.write(encodeFrame(q));});
  const stop=async()=>{const done=child.exitCode!==null?Promise.resolve():new Promise(r=>child.once('close',r));child.kill();await done;decoder.close();fs.rmSync(dir,{recursive:true,force:true});};
  return {child,rpc,stop};
}

test('the real host process serves several scans and edm-keys on one connection',async()=>{
  const secret=randomBytes(32);
  const host=startHost(dir=>{const f=path.join(dir,'edm.b64');fs.writeFileSync(f,secret.toString('base64'));return {version:1,allowedExtensionIds:[id],exactData:{secretFile:f}};});
  try{
    const hello=await host.rpc('hello',{persistent:true});assert.equal(hello.persistent,true);
    const pid=host.child.pid;
    for(const text of ['Email: a@example.com','plain text','TCKN 10000000146']){
      const bytes=Buffer.from(text);
      await host.rpc('begin',{kind:'text',size:bytes.length,sha256:hash(bytes),policyDigest:hello.policyDigest});
      await host.rpc('write',{offset:0,data:bytes.toString('base64')});
      const c=await host.rpc('commit');assert.ok(['allow','redact'].includes(c.decision));
    }
    const keys=await host.rpc('edm-keys',{datasetIds:['crm-customers']});
    assert.equal(keys.keys['crm-customers'],deriveEdmKey(secret,'crm-customers').toString('base64'));
    assert.equal(host.child.pid,pid);assert.equal(host.child.exitCode,null);
  }finally{await host.stop();}
});

test('the host refuses to start with a weak or relative EDM secret',async()=>{
  for(const exactData of [dir=>{const f=path.join(dir,'weak.b64');fs.writeFileSync(f,randomBytes(8).toString('base64'));return {secretFile:f};},()=>({secretFile:'edm.b64'}),()=>({secretFile:'/x',extra:1})]){
    const host=startHost(dir=>({version:1,allowedExtensionIds:[id],exactData:exactData(dir)}));
    try{await assert.rejects(host.rpc('hello',{persistent:true}));}finally{await host.stop();}
  }
});
