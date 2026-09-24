/** Local synthetic microbenchmark; not a production capacity or privacy-recall measurement. */
import assert from 'node:assert/strict';import fs from 'node:fs/promises';import os from 'node:os';import path from 'node:path';import { performance } from 'node:perf_hooks';
import { SensitiveDataIndex,createFileAuditSink,AuditJournal } from '../../dist/enterprise/index.js';
import { fixture,context,key,toolFixture,request,toolContext } from '../../tests/enterprise/helpers.mjs';
const output={scope:'sequential warm synthetic microbenchmarks in this container; no neural NER, OCR, provider traffic, distributed store or production concurrency',node:process.version,platform:os.platform(),cpu:os.cpus()[0]?.model,cases:[]};
async function measure(name,fn,extra={},samples=200,warmup=30){for(let i=0;i<warmup;i++)await fn();const times=[];for(let i=0;i<samples;i++){const t=performance.now();await fn();times.push(performance.now()-t);}times.sort((a,b)=>a-b);const q=p=>Number(times[Math.min(times.length-1,Math.ceil(p*times.length)-1)].toFixed(3));output.cases.push({name,samples,warmup,...extra,medianMs:q(.5),p95Ms:q(.95),p99Ms:q(.99)});}
const index=new SensitiveDataIndex('tenant-a','synthetic-records','k',key());for(let i=0;i<1000;i++)index.enrollRecord('r'+i,{part:'PART'+i,site:'SITE'+i},'restricted');
const publicText=n=>('Public documentation for this release. '.repeat(Math.ceil(n/39))).slice(0,n);
await measure('keyed record scan',()=>assert.equal(index.scan(publicText(4096)).length,0),{inputBytes:4096,records:1000});
for(const n of [1024,4096,16384]){const f=fixture();await measure('enterprise gate with in-memory acknowledged audit',async()=>assert.equal((await f.gate.protect(publicText(n),context())).decision,'allow'),{inputBytes:n});}
const dir=await fs.mkdtemp(path.join(os.tmpdir(),'aidr-bench-'));let sink;
try{sink=await createFileAuditSink(path.join(dir,'audit'));const j=new AuditJournal('tenant-a','bench-log','k',key(),sink.write),f=fixture({audit:j});await measure('enterprise gate with local file fsync audit',async()=>assert.equal((await f.gate.protect(publicText(4096),context())).decision,'allow'),{inputBytes:4096},100,20);}finally{await sink?.close();await fs.rm(dir,{recursive:true,force:true});}
const tools=toolFixture();await measure('approved read-tool inspection',async()=>assert.equal((await tools.guard.inspect(request(),toolContext())).decision,'allow'));
output.sampledProcessRssMiB=Number((process.memoryUsage().rss/1048576).toFixed(2));output.memoryNote='One post-run Node process RSS sample; NOT peak or incremental module memory.';
await fs.writeFile('reports/enterprise/benchmark.json',JSON.stringify(output,null,2)+'\n');console.log(JSON.stringify(output,null,2));
