import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,readFileSync,existsSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {qualifyNer} from '../../scripts/platform/qualify-ner.mjs';

function fixture(){
 const root=mkdtempSync(join(tmpdir(),'aidr-qualify-')),goldFile=join(root,'gold.jsonl'),nerConfigFile=join(root,'provider.json'),policyFile=join(root,'policy.json'),reportFile=join(root,'report.json');
 const gold={id:'synthetic1',documentId:'document1',language:'en',origin:'synthetic',text:'Jane Doe arrives tomorrow.',spans:[{start:0,end:8,type:'PERSON'}]};
 writeFileSync(goldFile,JSON.stringify(gold)+'\n');
 writeFileSync(nerConfigFile,JSON.stringify({command:process.execPath,args:[fileURLToPath(new URL('../fixtures/mock-ner.mjs',import.meta.url))]}));
 writeFileSync(policyFile,readFileSync(new URL('../../ner/qualification-policy.example.json',import.meta.url)));
 return {root,gold,goldFile,nerConfigFile,policyFile,reportFile};
}
test('learned corpus runner uses defense provider, keeps synthetic evidence unqualified and reports no raw corpus',async()=>{
 const f=fixture();try{
  const result=await qualifyNer(f),encoded=readFileSync(f.reportFile,'utf8');
  assert.equal(result.profile,'defense');assert.equal(result.mode,'offline-rules-and-learned-ner');
  assert.equal(result.report.buckets['en:PERSON'].tp,1);assert.equal(result.acceptance.qualified,false);
  assert.equal(result.modelReport.buckets['en:PERSON'].tp,1);assert.equal(result.modelAcceptance.qualified,false);
  assert.equal(result.runtimeCoverage.en.goldSpans,1);assert.equal(result.runtimeCoverage.en.maskedGoldSpans,1);
  assert.equal(result.runtimeCoverage.en.positiveDocuments,1);assert.equal(result.runtimeCoverage.en.forwardedIncompleteGoldDocuments,0);
  assert(result.acceptance.reasons.includes('INDEPENDENT_CORPORATE_CORPUS_REQUIRED'));
  assert.equal(result.modelRevision,'a'.repeat(64));assert(!encoded.includes('Jane Doe'));assert(!encoded.includes('document1'));
  await assert.rejects(qualifyNer(f),/EEXIST/);
 }finally{rmSync(f.root,{recursive:true,force:true});}
});
test('learned corpus runner rejects train/test leakage before opening provider',async()=>{
 const f=fixture();try{
  const trainFile=join(f.root,'train.jsonl');writeFileSync(trainFile,JSON.stringify({...f.gold,id:'training1'})+'\n');
  await assert.rejects(qualifyNer({...f,trainFile}),/LEAKAGE/);assert.equal(existsSync(f.reportFile),false);
 }finally{rmSync(f.root,{recursive:true,force:true});}
});
test('learned corpus runner cannot remove required name/address acceptance gates',async()=>{
 const f=fixture();try{
  const policy=JSON.parse(readFileSync(f.policyFile));policy.requiredTypes=['PERSON'];writeFileSync(f.policyFile,JSON.stringify(policy));
  await assert.rejects(qualifyNer(f),/EVAL_QUALIFICATION_CONFIG/);assert.equal(existsSync(f.reportFile),false);
 }finally{rmSync(f.root,{recursive:true,force:true});}
});
