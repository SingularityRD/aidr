/** Real Tesseract + persistent 0.5 audit and original 0.4 gate; synthetic image/trusted context fixture.
 * This is NOT a live IdP/provider session, a field accuracy benchmark, or a new learned NER test. */
import {readFileSync,writeFileSync,mkdtempSync,chmodSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';import {join} from 'node:path';import assert from 'node:assert/strict';
import {SqliteControlStore} from '../../dist/platform/state.js';
import {PersistentAuditJournal} from '../../dist/platform/persistent-audit.js';
import {EnterprisePrivacyGate} from '../../dist/enterprise/engine.js';
import {PrivacyEngine} from '../../dist/index.js';import {VisualPrivacyEngine,LocalImageProcess} from '../../dist/visual/index.js';
import {verifiedPng} from '../../dist/visual/png.js';import{verifyAudit}from'../../dist/enterprise/audit.js';
import{registry,context,NOW}from'../../tests/enterprise/helpers.mjs';
const root=mkdtempSync(join(tmpdir(),'aidr-platform-image-'));chmodSync(root,0o700);let store;
try{const auditKey=Buffer.alloc(32,35);store=new SqliteControlStore(join(root,'control.sqlite'),new Map([['tenant-a',{active:'k1',keys:[{id:'k1',key:Buffer.alloc(32,30)}]}]]));
 const audit=new PersistentAuditJournal(store.tenant('tenant-a'),'image-log','audit1',auditKey),gate=new EnterprisePrivacyGate({registry:registry(),audit,textEngine:new PrivacyEngine({profile:'strict'}),clock:()=>NOW});
 const config=JSON.parse(readFileSync(process.env.AIDR_VISION_CONFIG??'reports/platform/vision-local-config.json'));
 const visual=new VisualPrivacyEngine({backend:new LocalImageProcess(config),textEngine:gate.textAdapter(context()),release:'automatic',uncertainText:'redact-line'});
 const input=readFileSync('fixtures/visual/turkish.png'),start=performance.now(),result=await visual.protect(input),elapsedMs=performance.now()-start;
 assert.equal(result.decision,'redact');assert(result.output);const truth=JSON.parse(readFileSync('fixtures/visual/turkish.truth.json'));verifiedPng(result.output,1200,620,truth.map(r=>r.box));
 assert(verifyAudit(audit.records(),audit.checkpoint(),auditKey));assert(!JSON.stringify(audit.records()).includes('@'));
 writeFileSync('reports/platform/platform-ocr.redacted.png',result.output);
 const report={passed:true,scope:'real local eng+tur OCR; encrypted durable SQLite audit; synthetic image; trusted test context; no live IdP/NER/provider',verifiedSensitiveRows:truth.length,auditRecords:audit.records().length,inputBytes:input.length,outputBytes:result.output.length,elapsedMs};
 writeFileSync('reports/platform/visual-e2e.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));visual.dispose();audit.dispose();
}finally{store?.close();rmSync(root,{recursive:true,force:true});}
