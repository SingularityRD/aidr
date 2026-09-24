/** Default: developer-generated smoke fixtures, NOT an independent accuracy benchmark.
 * External JSONL: {id?, language?:'tr'|'en', text, entities:[{start,end,type}]}
 * Spans are exact UTF-16 offsets. Raw text is never written into the evaluation report.
 */
import fs from 'node:fs';
import { PrivacyEngine, LocalNerProcess, ENTITY_TYPES } from '../dist/index.js';
import { positives, negatives } from '../tests/fixtures/cases.mjs';
const args=process.argv.slice(2);
const inputFile=args[0]&&!args[0].startsWith('--')?args.shift():undefined;
let nerConfig,profile='strict';
for(let i=0;i<args.length;i++){
 if(args[i]==='--ner-config'&&args[i+1])nerConfig=args[++i];
 else if(args[i]==='--profile'&&['balanced','strict','defense'].includes(args[i+1]))profile=args[++i];
 else throw new Error('INVALID_EVALUATION_ARGUMENTS');
}
let documents;
if (inputFile) {
  const raw = fs.readFileSync(inputFile,'utf8');
  if (Buffer.byteLength(raw)>16*1024*1024) throw new Error('EVALUATION_INPUT_LIMIT');
  documents=raw.split(/\r?\n/).filter(Boolean).map(line=>JSON.parse(line));
} else {
  documents=[...positives.map(([_name,text,type,value],i)=>({id:`positive-${i}`,language:'unspecified',text,
    entities:[{start:text.indexOf(value),end:text.indexOf(value)+value.length,type}]})),
    ...negatives.map((text,i)=>({id:`negative-${i}`,language:'unspecified',text,entities:[]}))];
}
const provider=nerConfig?await LocalNerProcess.open(JSON.parse(fs.readFileSync(nerConfig,'utf8'))):undefined;
// Configuration is administrator-controlled and may start a local executable. Never accept it from end users.
const engine=new PrivacyEngine({profile,...(provider?{ner:provider}:{}),nerTimeoutMs:60000});
try {
const stat=()=>({documents:0,goldEntities:0,predictedEntities:0,exactTruePositive:0,
  goldPiiCharacters:0,maskedPiiCharacters:0,blockedDocuments:0,reviewDocuments:0,
  positiveDocuments:0,forwardedPositiveDocuments:0,leakedPositiveDocuments:0,
  negativeDocuments:0,falsePositiveNegativeDocuments:0});
const overall=stat(),byLanguage={},byType={};
const add=(target,value)=>{for(const k of Object.keys(value))target[k]+=value[k];};
for(const doc of documents) {
  if(!doc||typeof doc.text!=='string'||!Array.isArray(doc.entities))throw new Error('INVALID_EVALUATION_DOCUMENT');
  for(const e of doc.entities)if(!Number.isInteger(e.start)||!Number.isInteger(e.end)||e.start<0||e.end>doc.text.length||e.end<=e.start||!ENTITY_TYPES.includes(e.type))throw new Error('INVALID_EVALUATION_SPAN');
  const result=await engine.protect(doc.text), s=stat();s.documents=1;
  const goldSet=new Set(doc.entities.map(e=>`${e.start}:${e.end}:${e.type}`));
  const goldChars=new Set(),masked=new Set();
  for(const e of doc.entities)for(let i=e.start;i<e.end;i++)goldChars.add(i);
  for(const e of result.findings)for(let i=e.start;i<e.end;i++)masked.add(i);
  s.goldEntities=doc.entities.length;s.predictedEntities=result.findings.length;
  s.exactTruePositive=result.findings.filter(e=>goldSet.has(`${e.start}:${e.end}:${e.type}`)).length;
  s.goldPiiCharacters=goldChars.size;s.maskedPiiCharacters=[...goldChars].filter(i=>masked.has(i)).length;
  if(result.decision==='block')s.blockedDocuments=1;
  if(result.decision==='review')s.reviewDocuments=1;
  if(doc.entities.length) {
    s.positiveDocuments=1;
    if(result.output!==null){s.forwardedPositiveDocuments=1;if(s.maskedPiiCharacters<s.goldPiiCharacters)s.leakedPositiveDocuments=1;}
  } else {s.negativeDocuments=1;if(result.decision!=='allow')s.falsePositiveNegativeDocuments=1;}
  add(overall,s);
  const language=['tr','en'].includes(doc.language)?doc.language:'unspecified';
  byLanguage[language]??=stat();add(byLanguage[language],s);
  for(const type of new Set([...doc.entities.map(e=>e.type),...result.findings.map(e=>e.type)])){
    const t=byType[type]??={gold:0,predicted:0,exactTruePositive:0};
    t.gold+=doc.entities.filter(e=>e.type===type).length;
    t.predicted+=result.findings.filter(e=>e.type===type).length;
    t.exactTruePositive+=result.findings.filter(e=>e.type===type&&goldSet.has(`${e.start}:${e.end}:${e.type}`)).length;
  }
}
const ratio=(a,b)=>b?+(a/b).toFixed(6):null;
function metrics(s){const precision=ratio(s.exactTruePositive,s.predictedEntities),recall=ratio(s.exactTruePositive,s.goldEntities);
 return {...s,exactPrecision:precision,exactRecall:recall,exactF1:precision!==null&&recall!==null&&precision+recall?+(2*precision*recall/(precision+recall)).toFixed(6):null,
  piiCharacterCoverage:ratio(s.maskedPiiCharacters,s.goldPiiCharacters),
  forwardedPositiveLeakRate:ratio(s.leakedPositiveDocuments,s.forwardedPositiveDocuments),
  negativeDocumentFalsePositiveRate:ratio(s.falsePositiveNegativeDocuments,s.negativeDocuments)};}
const report={schemaVersion:1,generatedAt:new Date().toISOString(),coverage:provider?'rules-and-ner':'rules-only',profile,
 modelRevision:provider?.capabilities.revision??null,
 dataset:inputFile?'user-supplied-external-jsonl':'developer-generated-regression-fixtures',
 independentHeldOutBenchmark:false,
 caveats:['Default fixtures are known during development and cannot establish real-world accuracy.',
 'Gold spans are minimal sensitive values; conservative over-masking reduces exact-span precision/recall.',
 'Policy-blocked documents are not counted as correct detection or forwarded leaks; block counts are reported separately.',
 provider?'A local provider was invoked; this does not establish the validity of its capability declarations.':'NER model inference is NOT evaluated here.',
 'External fixture provenance/independence is not automatically verified.'],
 overall:metrics(overall),byLanguage:Object.fromEntries(Object.entries(byLanguage).map(([k,v])=>[k,metrics(v)])),byType};
fs.mkdirSync('reports',{recursive:true});fs.writeFileSync('reports/evaluation.json',JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify(report,null,2));

} finally {engine.dispose();provider?.close();}
