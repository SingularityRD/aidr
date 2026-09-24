/** One real bilingual OCR pipeline using enterprise TextResult adapter + synced audit. */
import fs from 'node:fs/promises';import os from 'node:os';import path from 'node:path';import assert from 'node:assert/strict';
import { VisualPrivacyEngine,LocalImageProcess } from '../../dist/visual/index.js';import { verifiedPng } from '../../dist/visual/png.js';
import { createFileAuditSink,AuditJournal,verifyAudit } from '../../dist/enterprise/index.js';import { fixture,context,key } from '../../tests/enterprise/helpers.mjs';
if(!process.env.AIDR_VISION_CONFIG)throw Error('AIDR_VISION_CONFIG_REQUIRED');
const dir=await fs.mkdtemp(path.join(os.tmpdir(),'aidr-enterprise-image-'));let sink;
try{
 const backend=new LocalImageProcess(JSON.parse(await fs.readFile(process.env.AIDR_VISION_CONFIG,'utf8')));sink=await createFileAuditSink(path.join(dir,'audit'));const k=key(),j=new AuditJournal('tenant-a','image-log','k',k,sink.write),f=fixture({audit:j});
 const engine=new VisualPrivacyEngine({backend,textEngine:f.gate.textAdapter(context()),release:'automatic',uncertainText:'redact-line'});
 const input=await fs.readFile('fixtures/visual/turkish.png'),start=performance.now(),r=await engine.protect(input);const elapsedMs=performance.now()-start;
 assert.equal(r.decision,'redact');assert.ok(r.output);const truth=JSON.parse(await fs.readFile('fixtures/visual/turkish.truth.json','utf8'));verifiedPng(r.output,1200,620,truth.map(x=>x.box));
 await fs.writeFile('reports/enterprise/enterprise-ocr.redacted.png',r.output);
 const records=(await fs.readFile(path.join(dir,'audit'),'utf8')).trim().split('\n').map(JSON.parse);assert.equal(verifyAudit(records,j.checkpoint(),k),true);assert.ok(!JSON.stringify(records).includes('@'));
 const report={scope:'real local OCR + enterprise context gate + original UTF16 spans + real local fsync audit + independent known-row pixel verification; synthetic TR image, no learned NER or field recall estimate',passed:true,decision:r.decision,verifiedSensitiveRows:truth.length,auditRecords:records.length,elapsedMs:Math.round(elapsedMs*100)/100,inputBytes:input.length,outputBytes:r.output.length};
 await fs.writeFile('reports/enterprise/visual-e2e.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));
}finally{await sink?.close();await fs.rm(dir,{recursive:true,force:true});}
