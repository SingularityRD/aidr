import test from 'node:test';
import assert from 'node:assert/strict';
import {scoreDataset,qualification} from '../../dist/platform/evaluation.js';

// Generated fixtures exercise the gate; they are not independent model evidence.
function corpus(cleanCounts={tr:100,en:100},cleanDecision=()=> 'allow'){
 const samples=[],predictions=new Map();
 for(const language of ['tr','en']){
  for(const type of ['PERSON','ADDRESS'])for(let i=0;i<100;i++){
   const id=`${language}-${type}-${i}`,spans=[{start:0,end:5,type}];
   samples.push({id,documentId:id,language,origin:'independent-corporate',text:`value ${id}`,spans});
   predictions.set(id,{spans,decision:'redact'});
  }
  for(let i=0;i<cleanCounts[language];i++){
   const id=`${language}-clean-${i}`;
   samples.push({id,documentId:id,language,origin:'independent-corporate',text:`public ${id}`,spans:[]});
   predictions.set(id,{spans:[],decision:cleanDecision(language,i)});
  }
 }
 return scoreDataset(samples,predictions);
}
const requiredTypes=['PERSON','ADDRESS'];

test('qualification: exact detections cannot hide 100% clean blocking or absent EN negatives',()=>{
 const report=corpus({tr:100,en:0},()=> 'block'),result=qualification(report,requiredTypes);
 assert.equal(report.cleanFalseAlarm,100);
 assert.equal(report.buckets['en:ADDRESS'].precision,1);
 assert.equal(result.qualified,false);
 assert(result.reasons.includes('CLEAN_FALSE_ALARM_RATE'));
 assert(result.reasons.includes('CLEAN_NEGATIVES_REQUIRED_en'));
});

test('qualification: requires the negative evidence floor independently in each language',()=>{
 for(const cleanCounts of [{tr:100,en:0},{tr:0,en:100},{tr:100,en:99},{tr:99,en:100}]){
  const result=qualification(corpus(cleanCounts),requiredTypes);
  assert.equal(result.qualified,false);
  for(const language of ['tr','en'])if(cleanCounts[language]<100)assert(result.reasons.includes(`CLEAN_NEGATIVES_REQUIRED_${language}`));
 }
 assert.equal(qualification(corpus(),requiredTypes).qualified,true);
});

test('qualification: block, review and redact count as clean disruption',()=>{
 for(const decision of ['block','review','redact']){
  const report=corpus(undefined,()=>decision),result=qualification(report,requiredTypes);
  assert.equal(report.cleanFalseAlarm,200);
  assert.equal(result.qualified,false);
  assert(result.reasons.includes('CLEAN_FALSE_ALARM_RATE_tr'));
  assert(result.reasons.includes('CLEAN_FALSE_ALARM_RATE_en'));
 }
});

test('qualification: configured clean false alarm boundary applies per language without dilution',()=>{
 const boundary=corpus(undefined,(_language,i)=>i<5?'review':'allow');
 assert.equal(qualification(boundary,requiredTypes).qualified,true);
 assert.equal(qualification(boundary,requiredTypes,100,.95,.90,.04).qualified,false);
 const over=corpus({tr:100,en:1000},(language,i)=>language==='tr'&&i<6?'block':'allow');
 assert(over.cleanFalseAlarm/over.cleanSamples<.05);
 assert.equal(over.cleanByLanguage.tr.samples,100);
 assert.equal(over.cleanByLanguage.tr.falseAlarm,6);
 assert.deepEqual(qualification(over,requiredTypes).reasons,['CLEAN_FALSE_ALARM_RATE_tr']);
});

test('qualification: invalid false alarm configuration and old reports cannot pass',()=>{
 const report=corpus();
 for(const maximum of [-.01,1,Infinity,NaN,'0.05'])assert.throws(()=>qualification(report,requiredTypes,100,.95,.90,maximum),/EVAL_QUALIFICATION_CONFIG/);
 assert.equal(qualification(report,requiredTypes,100,.95,.90,0).qualified,true);
 const {cleanByLanguage,...oldReport}=report;
 assert.equal(qualification(oldReport,requiredTypes).qualified,false);
});
