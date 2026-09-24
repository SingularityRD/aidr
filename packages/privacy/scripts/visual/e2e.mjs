/** Real OCR inference on a SMALL synthetic suite; NOT an independent accuracy benchmark. */
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import {performance} from 'node:perf_hooks';
import {PrivacyEngine} from '../../dist/index.js';
import {VisualPrivacyEngine,LocalImageProcess} from '../../dist/visual/index.js';
const config=JSON.parse(fs.readFileSync(process.env.AIDR_VISION_CONFIG??'vision/local.config.json','utf8'));
const folder='reports/visual';fs.mkdirSync(folder,{recursive:true});
const cases=[
 {file:'turkish.png',expected:'redact',types:['PERSON','EMAIL','PHONE','TC_KIMLIK','IBAN','ADDRESS'],truth:'turkish.truth.json'},
 {file:'english-dark.png',expected:'redact',types:['PERSON','EMAIL','PHONE','CREDIT_CARD','ADDRESS'],truth:'english-dark.truth.json'},
 {file:'turkish.jpg',expected:'redact',types:['PERSON','EMAIL','PHONE','TC_KIMLIK','IBAN','ADDRESS'],truth:'turkish.truth.json'},
 {file:'turkish-oriented.jpg',expected:'redact',types:['PERSON','EMAIL','PHONE','TC_KIMLIK','IBAN','ADDRESS'],truth:'turkish.truth.json'},
 {file:'turkish.webp',expected:'redact',types:['PERSON','EMAIL','PHONE','TC_KIMLIK','IBAN','ADDRESS'],truth:'turkish.truth.json'},
 {file:'qr.png',expected:'block',code:'IMAGE_BARCODE_BLOCKED'},
 {file:'qr.png',suffix:'redact',expected:'redact',barcodeAction:'redact',types:['BARCODE']},
 {file:'blank.png',expected:'block',code:'IMAGE_NO_TEXT'},
];
let peakNodeRss=process.memoryUsage().rss;
const sample=setInterval(()=>peakNodeRss=Math.max(peakNodeRss,process.memoryUsage().rss),25);
const report=[];
const selected=process.env.AIDR_E2E_FROM ? cases.slice(Number(process.env.AIDR_E2E_FROM), Number(process.env.AIDR_E2E_TO??cases.length)) : cases;
const reportName=process.env.AIDR_E2E_REPORT??'e2e.json';
const save=()=>fs.writeFileSync(path.join(folder,reportName),JSON.stringify({schemaVersion:1,testScope:'developer-created synthetic images; real local Tesseract eng+tur; no learned NER',cases:report,passed:report.filter(x=>x.pass).length,total:selected.length,peakNodeRssBytes:peakNodeRss},null,2)+'\n');
try{
 for(const c of selected){
  const engine=new VisualPrivacyEngine({backend:new LocalImageProcess(config),textEngine:new PrivacyEngine({maxInputBytes:262144}),release:'automatic',uncertainText:'redact-line',barcodeAction:c.barcodeAction??'block'});
  const start=performance.now();const result=await engine.protect(fs.readFileSync(path.join('fixtures/visual',c.file)));
  const record={file:c.file,variant:c.suffix??'default',expected:c.expected,decision:result.decision,reasons:result.reasons,
   regions:result.regions,outputBytes:result.output?.length??0,elapsedMs:Math.round((performance.now()-start)*1000)/1000,audit:result.audit,pass:false};
  report.push(record);
  assert.equal(result.decision,c.expected,JSON.stringify(record));
  if(c.code)assert.ok(result.reasons.includes(c.code));
  if(c.types)for(const type of c.types)assert.ok(result.regions.some(r=>r.types.includes(type)),`Missing ${type} in ${c.file}`);
  if(result.output){
   const name=c.file.replace(/\./g,'-')+(c.suffix?'-'+c.suffix:'')+'.redacted.png';
   fs.writeFileSync(path.join(folder,name),result.output);record.outputFile=name;
   if(c.truth)record.truthFile=c.truth;
  }else{assert.equal(result.outputSha256,null);assert.equal(result.filename,null);}
  record.pass=true;save();
  console.log(JSON.stringify({file:c.file,variant:record.variant,decision:result.decision,regions:result.regions.length,elapsedMs:record.elapsedMs,pass:true}));
  engine.dispose();
 }
}finally{
 clearInterval(sample);
 save();
}
