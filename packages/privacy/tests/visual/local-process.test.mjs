import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs/promises';import os from 'node:os';import path from 'node:path';
import {LocalImageProcess} from '../../dist/visual/local-process.js';
const python=process.env.AIDR_TEST_PYTHON??'/usr/bin/python3';
const base={python,tesseract:'/trusted/tesseract',tessdata:'/trusted/tessdata',manifest:'/trusted/manifest',processTimeoutMs:2000};
async function fake(source,fn,options={}){const d=await fs.mkdtemp(path.join(os.tmpdir(),'aidr-worker-test-'));try{const worker=path.join(d,'worker.py');await fs.writeFile(worker,source);return await fn(new LocalImageProcess({...base,...options,worker}));}finally{await fs.rm(d,{recursive:true,force:true});}}
// Test doubles are explicitly fake workers; these tests do not measure OCR accuracy.
const consume='import sys,json\nr=json.load(sys.stdin)\n';const input=Buffer.from('synthetic');
for(const [name,body,code]of [
 ['nonzero',"sys.exit(3)",'IMAGE_WORKER_FAILED'],
 ['invalid-json',"print('secret-content-not-json')",'IMAGE_PROTOCOL_INVALID'],
 ['invalid-utf8',"sys.stdout.buffer.write(b'\\xff')",'IMAGE_PROTOCOL_INVALID'],
 ['bad-protocol',"print(json.dumps({'protocol':2,'complete':True}))",'IMAGE_PROTOCOL_INVALID'],
 ['safe-known-error',"print(json.dumps({'protocol':1,'complete':False,'code':'IMAGE_ARTIFACT_MISMATCH'}))",'IMAGE_ARTIFACT_MISMATCH'],
 ['unsafe-error-suppressed',"print(json.dumps({'protocol':1,'complete':False,'code':'customer-secret'}))",'IMAGE_WORKER_FAILED'],
 ['stdout-limit',"print('x'*6000)",'IMAGE_WORKER_OUTPUT_LIMIT'],
 ['stderr-limit',"sys.stderr.write('x'*300000);sys.stderr.flush();print('{}')",'IMAGE_WORKER_OUTPUT_LIMIT'],
])test(`local process ${name}`,()=>fake(consume+body,async b=>{await assert.rejects(b.inspect(input,new AbortController().signal),e=>e.code===code&&!e.message.includes('customer-secret'));},{maxResponseBytes:4096}));
test('local process missing executable fails closed',async()=>{const b=new LocalImageProcess({...base,python:'/not-existing-python'});await assert.rejects(b.inspect(input,new AbortController().signal),e=>e.code==='IMAGE_WORKER_FAILED');});
test('local process stage timeout',()=>fake(consume+'import time\ntime.sleep(5)',async b=>{await assert.rejects(b.inspect(input,new AbortController().signal),e=>e.code==='IMAGE_TIMEOUT');},{processTimeoutMs:150}));
test('local process cancellation',()=>fake(consume+'import time\ntime.sleep(5)',async b=>{const c=new AbortController();setTimeout(()=>c.abort(),150);await assert.rejects(b.inspect(input,c.signal),e=>e.code==='IMAGE_ABORTED');}));
test('local process does not inherit application secrets',()=>fake(consume+"import os\nprint(json.dumps({'protocol':1,'complete':True,'leaked':'AIDR_SECRET_TEST' in os.environ}))",async b=>{process.env.AIDR_SECRET_TEST='should-not-be-visible';try{const r=await b.inspect(input,new AbortController().signal);assert.equal(r.leaked,false);}finally{delete process.env.AIDR_SECRET_TEST;}}));
test('local process default passes are 11 and 6',()=>fake(consume+"print(json.dumps({'protocol':1,'complete':True,'psms':r['psms']}))",async b=>{assert.deepEqual((await b.inspect(input,new AbortController().signal)).psms,[11,6]);}));
for(const value of ['!!!!','YQ=','AB==',''])test(`invalid render base64 ${JSON.stringify(value)}`,()=>fake(consume+`print(json.dumps({'protocol':1,'complete':True,'png':${JSON.stringify(value)}}))`,async b=>{await assert.rejects(b.render(input,{pixelSha256:'a'.repeat(64)},[],new AbortController().signal),e=>e.code==='IMAGE_PROTOCOL_INVALID');}));
test('valid canonical base64 render is decoded',()=>fake(consume+"print(json.dumps({'protocol':1,'complete':True,'png':'YWJj'}))",async b=>{assert.equal((await b.render(input,{pixelSha256:'a'.repeat(64)},[],new AbortController().signal)).png.toString(),'abc');}));
for(const [field,value]of [['python','relative'],['manifest','/bad\0path'],['dualPass','yes'],['processTimeoutMs',0],['maxResponseBytes',1]])test(`invalid local config ${field}`,()=>assert.throws(()=>new LocalImageProcess({...base,[field]:value})));
