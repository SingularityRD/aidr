/** Administrator-controlled offline learned-NER corpus evaluation. Output contains aggregates only.
 * Corpus provenance and holdout independence remain operator declarations, not authenticated facts.
 */
import {readFileSync,writeFileSync,lstatSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {PrivacyEngine,LocalNerProcess} from '../../dist/index.js';
import {parseJsonStrict} from '../../dist/json.js';
import {validateSplit,scoreDataset,qualification} from '../../dist/platform/evaluation.js';

function read(path,limit=16777216){
 const stat=lstatSync(path);if(!stat.isFile()||stat.isSymbolicLink()||stat.size>limit)throw Error('CORPUS_INPUT');
 return new TextDecoder('utf-8',{fatal:true}).decode(readFileSync(path));
}
function samples(path){
 const lines=read(path).trim().split('\n');if(!lines.length||lines.length>10000)throw Error('CORPUS_LIMIT');
 return lines.map(line=>parseJsonStrict(line,12,50000));
}
export async function qualifyNer({goldFile,trainFile,nerConfigFile,policyFile,reportFile}){
 const gold=samples(goldFile),train=trainFile?samples(trainFile):[];validateSplit(train,gold);
 const policy=parseJsonStrict(read(policyFile,65536),8,1000),keys=['requiredTypes','minGold','minRecallLower','minPrecisionLower','maxCleanFalseAlarmRate'];
 if(!policy||Object.keys(policy).length!==keys.length||keys.some(key=>!Object.hasOwn(policy,key))||!Array.isArray(policy.requiredTypes)||!['PERSON','ADDRESS'].every(type=>policy.requiredTypes.includes(type)))throw Error('EVAL_QUALIFICATION_CONFIG');
 // Validate the declared acceptance configuration before starting a local executable.
 qualification(scoreDataset([],new Map()),policy.requiredTypes,policy.minGold,policy.minRecallLower,policy.minPrecisionLower,policy.maxCleanFalseAlarmRate);
 const provider=await LocalNerProcess.open(parseJsonStrict(read(nerConfigFile,65536),8,1000));let engine;
 try{
  engine=new PrivacyEngine({profile:'defense',ner:provider,maxConcurrent:1,nerTimeoutMs:60000});
  const predictions=new Map(),modelPredictions=new Map();
  const runtimeCoverage={tr:{goldSpans:0,maskedGoldSpans:0,positiveDocuments:0,forwardedPositiveDocuments:0,forwardedIncompleteGoldDocuments:0,deniedPositiveDocuments:0},en:{goldSpans:0,maskedGoldSpans:0,positiveDocuments:0,forwardedPositiveDocuments:0,forwardedIncompleteGoldDocuments:0,deniedPositiveDocuments:0}};
  for(const sample of gold){
   const detected=await provider.detect(sample.text,AbortSignal.timeout(60000));
   modelPredictions.set(sample.id,{spans:detected.entities.map(({start,end,type})=>({start,end,type})),decision:detected.entities.length?'redact':'allow'});
   const result=await engine.protect(sample.text);predictions.set(sample.id,{spans:result.findings.map(({start,end,type})=>({start,end,type})),decision:result.decision});
   // Any-type mask coverage measures masking ranges; it does not turn a wrong type into a true positive.
   const coverage=runtimeCoverage[sample.language];let masked=0;
   for(const span of sample.spans){let cursor=span.start;for(const finding of result.findings.filter(f=>f.end>span.start&&f.start<span.end).sort((a,b)=>a.start-b.start)){if(finding.start>cursor)break;cursor=Math.max(cursor,finding.end);}if(cursor>=span.end)masked++;}
   coverage.goldSpans+=sample.spans.length;coverage.maskedGoldSpans+=masked;
   if(sample.spans.length){coverage.positiveDocuments++;if(['allow','redact'].includes(result.decision)&&result.output!==null){coverage.forwardedPositiveDocuments++;if(masked<sample.spans.length)coverage.forwardedIncompleteGoldDocuments++;}else coverage.deniedPositiveDocuments++;}
  }
  const report=scoreDataset(gold,predictions),modelReport=scoreDataset(gold,modelPredictions);
  const qualify=value=>qualification(value,policy.requiredTypes,policy.minGold,policy.minRecallLower,policy.minPrecisionLower,policy.maxCleanFalseAlarmRate);
  const runtimeAcceptance=qualify(report),modelAcceptance=qualify(modelReport),reasons=[...runtimeAcceptance.reasons,...modelAcceptance.reasons.map(reason=>'MODEL_'+reason)];
  const acceptance={qualified:!reasons.length,reasons};
  const result={schemaVersion:1,mode:'offline-rules-and-learned-ner',profile:'defense',modelRevision:provider.capabilities.revision,capabilities:provider.capabilities,
   corpusSha256:createHash('sha256').update(readFileSync(goldFile)).digest('hex'),provenance:'operator-declared; not authenticated',trainingSplitCheck:trainFile?'provided-training-corpus':'not-provided; publisher training overlap not verified',policy,report,modelReport,runtimeCoverage,runtimeCoverageScope:'union of all reported masking intervals regardless of type; forwarded counts mean allow/redact with non-null output, no network send is performed; denied documents are counted separately, not as perfect recognition',modelDecisionScope:'span presence only; runtime block/review measured separately',runtimeAcceptance,modelAcceptance,acceptance};
  writeFileSync(reportFile,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
  return result;
 }finally{engine?.dispose();provider.close();}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const [goldFile,nerConfigFile,policyFile,reportFile,trainFile,...extra]=process.argv.slice(2);
 if(!goldFile||!nerConfigFile||!policyFile||!reportFile||extra.length){console.error('Usage: node scripts/platform/qualify-ner.mjs gold.jsonl local-provider.json acceptance-policy.json aggregate-report.json [train.jsonl]');process.exit(2);}
 try{const result=await qualifyNer({goldFile,nerConfigFile,policyFile,reportFile,trainFile});console.log(JSON.stringify({samples:result.report.samples,modelRevision:result.modelRevision,qualified:result.acceptance.qualified,reasons:result.acceptance.reasons}));if(!result.acceptance.qualified)process.exitCode=3;}
 catch{console.error('NER_QUALIFICATION_FAILED');process.exitCode=2;}
}
