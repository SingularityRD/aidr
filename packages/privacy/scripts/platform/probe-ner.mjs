/** Synthetic real-worker readiness/inference probe. This never qualifies model quality. */
import {readFileSync,writeFileSync} from 'node:fs';
import {LocalNerProcess,PrivacyEngine} from '../../dist/index.js';
import {parseJsonStrict} from '../../dist/json.js';
const [providerFile,reportFile,...extra]=process.argv.slice(2);
if(!providerFile||!reportFile||extra.length){console.error('Usage: node scripts/platform/probe-ner.mjs local-provider.json probe-report.json');process.exit(2);}
let provider,engine;
try{
 provider=await LocalNerProcess.open(parseJsonStrict(readFileSync(providerFile,'utf8'),8,1000));
 engine=new PrivacyEngine({profile:'defense',ner:provider,maxConcurrent:1,nerTimeoutMs:60000});
 const cases=[
  {id:'tr-person-address',language:'tr',text:'Ahmet Yılmaz, Atatürk Mahallesi 12. Sokak No: 5 Ankara adresinde yaşıyor.',expected:[{type:'PERSON',start:0,end:12},{type:'ADDRESS',start:14,end:54}]},
  {id:'en-person-address',language:'en',text:'My name is Rajesh Kumar and I live at 42 MG Road, Bangalore.',expected:[{type:'PERSON',start:11,end:23},{type:'ADDRESS',start:38,end:59}]},
  {id:'en-utf16',language:'en',text:'😀 My name is Rajesh Kumar.',expected:[{type:'PERSON',start:14,end:26}]},
 ];
 const results=[];
 for(const sample of cases){
  const detected=await provider.detect(sample.text,AbortSignal.timeout(60000)),modelTypes=[...new Set(detected.entities.map(f=>f.type))].sort();
  const start=performance.now(),result=await engine.protect(sample.text),types=[...new Set(result.findings.map(f=>f.type))].sort();
  const covered=(gold,spans)=>{let cursor=gold.start;for(const span of spans.filter(f=>f.end>gold.start&&f.start<gold.end).sort((a,b)=>a.start-b.start)){if(span.start>cursor)break;cursor=Math.max(cursor,span.end);}return cursor>=gold.end;};
  const expectedTypes=sample.expected.map(f=>f.type);
  results.push({id:sample.id,language:sample.language,decision:result.decision,reasons:result.reasons,types,expected:sample.expected,
   modelTypes,modelSpans:detected.entities,modelExpectedTypesPresent:expectedTypes.every(type=>modelTypes.includes(type)),expectedTypesPresent:expectedTypes.every(type=>types.includes(type)),
   modelExactSpans:sample.expected.every(g=>detected.entities.some(f=>f.type===g.type&&f.start===g.start&&f.end===g.end)),
   modelTypedCoverage:sample.expected.every(g=>covered(g,detected.entities.filter(f=>f.type===g.type))),runtimeMaskCoverage:sample.expected.every(g=>covered(g,result.findings)),
   utf16OffsetsValid:result.findings.every(f=>Number.isSafeInteger(f.start)&&Number.isSafeInteger(f.end)&&f.start>=0&&f.end<=sample.text.length&&f.start<f.end),elapsedMs:Math.round(performance.now()-start)});
 }
 const report={schemaVersion:1,ready:true,modelRevision:provider.capabilities.revision,capabilities:provider.capabilities,scope:'three synthetic real-inference smoke cases; not independent accuracy evidence',qualified:false,results};
 writeFileSync(reportFile,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
 console.log(JSON.stringify({ready:true,qualified:false,results}));
 if(results.some(result=>!result.expectedTypesPresent||!result.runtimeMaskCoverage||!result.utf16OffsetsValid))process.exitCode=3;
}catch{console.error('NER_PROBE_FAILED');process.exitCode=2;}finally{engine?.dispose();provider?.close();}
