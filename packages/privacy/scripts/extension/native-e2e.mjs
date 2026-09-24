/** Real Node child stdio and production native client. Chrome port API is a shim;
 * OS Chrome native-host registration and installed-extension behavior are NOT tested. */
import fs from 'node:fs';import path from 'node:path';import os from 'node:os';import vm from 'node:vm';import{spawn}from'node:child_process';import{webcrypto,createHash}from'node:crypto';import assert from'node:assert/strict';
import{parsePolicy}from'../../dist/browser/policy.js';import{encodeFrame,FrameDecoder}from'../../dist/native/framing.js';import{verifiedPng}from'../../dist/visual/png.js';
const ROOT=process.cwd(),OUT=path.join(ROOT,'reports/browser'),ID='hmcbdjjldiobifmolecnmalilknnapcb',dir=fs.mkdtempSync(path.join(os.tmpdir(),'aidr-native-e2e-'));
const report={scope:'production browser native client + real framed Node stdio host; Chrome native port mocked; actual approved-origin check; optional one real OCR image; no installed-browser registration or learned NER',cases:[]};
const hash=b=>createHash('sha256').update(b).digest('hex'),digest=p=>hash(JSON.stringify(parsePolicy(p===undefined?undefined:JSON.stringify(p))));
const pendingProcesses=new Set();
const event=()=>{const listeners=[];return{addListener:f=>listeners.push(f),removeListener:f=>{const i=listeners.indexOf(f);if(i>=0)listeners.splice(i,1);},emit:m=>listeners.forEach(f=>f(m))};};
function client(config,{origin=`chrome-extension://${ID}/`,tamper=null}={}){
 const cfg=path.join(dir,crypto.randomUUID()+'.json');fs.writeFileSync(cfg,JSON.stringify(config),{mode:0o600});
 const stderr=[];let launches=0;
 const chrome={runtime:{connectNative(name){assert.equal(name,'com.singularity.aidr_privacy');launches++;
   const child=spawn(process.execPath,['dist/native/host.js','--config',cfg,origin],{cwd:ROOT,shell:false,stdio:['pipe','pipe','pipe']});pendingProcesses.add(child);const decoder=new FrameDecoder(),onMessage=event(),onDisconnect=event();let closed=false;
   const port={onMessage,onDisconnect,postMessage(q){if(closed)throw Error('PORT_CLOSED');child.stdin.write(encodeFrame(q));},disconnect(){if(closed)return;closed=true;child.stdin.end();child.kill('SIGTERM');}};
   child.stderr.on('data',c=>stderr.push(Buffer.from(c)));child.on('error',()=>{closed=true;onDisconnect.emit();});child.on('close',()=>{pendingProcesses.delete(child);decoder.close();closed=true;onDisconnect.emit();});
   child.stdout.on('data',chunk=>{try{for(let m of decoder.push(chunk)){if(tamper)m=tamper(m);onMessage.emit(m);}}catch{port.disconnect();onDisconnect.emit();}});child.stdin.on('error',()=>{closed=true;onDisconnect.emit();});return port;
 }}};
 const context=vm.createContext({chrome,crypto:webcrypto,TextEncoder,TextDecoder,Uint8Array,ArrayBuffer,performance,setTimeout,clearTimeout,URL,btoa,atob,console});
 new vm.Script(fs.readFileSync(path.join(OUT,'test-bundles/native-fixture.js'),'utf8')).runInContext(context);
 return {call:(kind,bytes=new Uint8Array(),pd=digest(config.browserPolicyJSON===undefined?undefined:JSON.parse(config.browserPolicyJSON)))=>context.nativeClient(kind,bytes,pd),stderr,launches:()=>launches};
}
const config={version:1,allowedExtensionIds:[ID],text:{profile:'strict'}};
async function run(name,fn){const start=performance.now(),c={name,pass:false};try{Object.assign(c,await fn());c.pass=true;}catch(e){c.error=e instanceof Error?e.message:String(e);console.error(e);}c.elapsedMs=Math.round((performance.now()-start)*100)/100;report.cases.push(c);console.log(JSON.stringify(c));save();}
function save(){report.passed=report.cases.filter(c=>c.pass).length;report.total=report.cases.length;fs.writeFileSync(path.join(OUT,'native-e2e.json'),JSON.stringify(report,null,2)+'\n');}
try{
 await run('real host hello and matching policy',async()=>{const c=client(config),r=await c.call('health');assert.equal(r.meta.local,true);assert.equal(r.meta.ocr,false);assert.equal(r.meta.policyDigest,digest());assert.equal(c.stderr.length,0);});
 for(const[kind,text,absent]of[['text','Email a@example.com','a@example.com'],['json','{"name":"Jane Doe","email":"jane@example.com"}','Jane Doe'],['csv','name,email\nJane Doe,jane@example.com','Jane Doe'],['tsv','name\temail\nJane Doe\tjane@example.com','Jane Doe']])await run(`real host ${kind} redaction via chunked client`,async()=>{const c=client(config),r=await c.call(kind,Buffer.from(text));assert.ok(r.bytes);assert.equal(r.meta.decision,'redact');assert.ok(!Buffer.from(r.bytes).toString().includes(absent));assert.equal(r.meta.coverage,'rules-only');assert.equal(c.stderr.length,0);});
 await run('large real document crosses native frame boundaries',async()=>{const c=client(config),text='Public project note. '.repeat(15000);const r=await c.call('text',Buffer.from(text));assert.equal(Buffer.from(r.bytes).toString(),text);return{sourceBytes:Buffer.byteLength(text),outputBytes:r.bytes.length};});
 await run('wrong invoking extension origin is rejected by host',async()=>{const c=client(config,{origin:'chrome-extension://'+'a'.repeat(32)+'/'});await assert.rejects(c.call('health'));assert.equal(c.stderr.length,0);});
 await run('host and browser policy mismatch blocks before raw transfer',async()=>{const c=client(config);await assert.rejects(c.call('text',Buffer.from('a@example.com'),'b'.repeat(64)),/NATIVE_POLICY_MISMATCH/);});
 await run('managed organization literal blocks in real host',async()=>{const p={literals:[{value:'PROJECT-ORION-TEST',type:'INTERNAL'}]};const c=client({...config,browserPolicyJSON:JSON.stringify(p)}),r=await c.call('text',Buffer.from('PROJECT-ORION-TEST'));assert.equal(r.bytes,null);assert.equal(r.meta.decision,'block');});
 await run('image call without OCR capability has no bytes',async()=>{const c=client(config);await assert.rejects(c.call('image',Buffer.from('secret')),/NATIVE_OCR_UNAVAILABLE/);});
 await run('tampered native output digest rejected',async()=>{const c=client(config,{tamper:m=>m.outputBytes?{...m,sha256:'0'.repeat(64)}:m});await assert.rejects(c.call('text',Buffer.from('Hello public')),/NATIVE_OUTPUT_CHANGED/);});
 await run('bad native response correlation rejected',async()=>{const c=client(config,{tamper:m=>({...m,id:'wrong-id'})});await assert.rejects(c.call('health'));});
 if(process.env.AIDR_VISION_CONFIG){
  await run('real TR screenshot OCR through production native client and host',async()=>{
   const backend=JSON.parse(fs.readFileSync(process.env.AIDR_VISION_CONFIG,'utf8'));
   const c=client({...config,visual:{backend,policy:{release:'automatic',uncertainText:'redact-line'}}});
   const input=fs.readFileSync('fixtures/visual/turkish.png'),r=await c.call('image',input);assert.ok(r.bytes);assert.equal(r.meta.contentType,'image/png');assert.equal(r.meta.verification,'pixel-and-residual-scan');assert.equal(r.meta.filename,'aidr-sanitized.png');
   const truth=JSON.parse(fs.readFileSync('fixtures/visual/turkish.truth.json','utf8'));verifiedPng(r.bytes,1200,620,truth.map(t=>t.box));
   fs.writeFileSync(path.join(OUT,'native-ocr-turkish.redacted.png'),r.bytes);assert.equal(c.stderr.length,0);
   return {decision:r.meta.decision,sourceBytes:input.length,outputBytes:r.bytes.length,verifiedSensitiveRows:truth.length,coverage:r.meta.coverage};
  });
 }else report.realOcr='not run: AIDR_VISION_CONFIG not set';
}finally{
 for(const child of pendingProcesses)child.kill('SIGKILL');fs.rmSync(dir,{recursive:true,force:true});save();
}
process.exitCode=report.passed===report.total?0:1;
