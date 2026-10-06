import { hash, deny, frozen } from '../enterprise/util.js';
export interface Span {start:number;end:number;type:string;}
export interface GoldSample {id:string;documentId:string;language:'tr'|'en';origin:'synthetic'|'independent-corporate';text:string;spans:readonly Span[];}
export interface Prediction {spans:readonly Span[];decision:'allow'|'redact'|'review'|'block';}
function validate(sample:GoldSample):void{
 if(!sample.id||!sample.documentId||!['tr','en'].includes(sample.language)||!['synthetic','independent-corporate'].includes(sample.origin)||sample.text.length>1048576||sample.spans.length>10000)deny('EVAL_SAMPLE');
 for(const s of sample.spans)if(!Number.isSafeInteger(s.start)||!Number.isSafeInteger(s.end)||s.start<0||s.end<=s.start||s.end>sample.text.length||!/^[A-Z_]{1,40}$/.test(s.type))deny('EVAL_SPAN');
 const keys=sample.spans.map(s=>`${s.type}:${s.start}:${s.end}`);if(new Set(keys).size!==keys.length)deny('EVAL_DUPLICATE_SPAN');
}
export function validateSplit(train:readonly GoldSample[],test:readonly GoldSample[]):void{
 const ids=new Set<string>(),docs=new Set(train.map(s=>s.documentId)),texts=new Set(train.map(s=>hash(s.text.normalize('NFKC').replace(/\s+/gu,' ').trim())));
 for(const s of [...train,...test]){validate(s);if(ids.has(s.id))deny('EVAL_DUPLICATE_ID');ids.add(s.id);}
 for(const s of test)if(docs.has(s.documentId)||texts.has(hash(s.text.normalize('NFKC').replace(/\s+/gu,' ').trim())))deny('EVAL_TRAIN_TEST_LEAKAGE');
}
export function wilson(success:number,total:number):{lower:number;upper:number}|null{
 if(!Number.isSafeInteger(success)||!Number.isSafeInteger(total)||success<0||total<success)deny('EVAL_COUNT');if(!total)return null;const z=1.959963984540054,p=success/total,den=1+z*z/total,center=(p+z*z/(2*total))/den,delta=z*Math.sqrt(p*(1-p)/total+z*z/(4*total*total))/den;return {lower:Math.max(0,center-delta),upper:Math.min(1,center+delta)};
}
export function scoreDataset(samples:readonly GoldSample[],predictions:ReadonlyMap<string,Prediction>){
 const buckets=new Map<string,{tp:number;fp:number;fn:number;covered:number;gold:number}>(),cleanByLanguage={tr:{samples:0,falseAlarm:0},en:{samples:0,falseAlarm:0}};let abstained=0,blocked=0,cleanFalseAlarm=0;const ids=new Set();
 for(const s of samples){validate(s);if(ids.has(s.id))deny('EVAL_DUPLICATE_ID');ids.add(s.id);const p=predictions.get(s.id);if(!p||!['allow','redact','review','block'].includes(p.decision))deny('EVAL_PREDICTION');validate({...s,spans:p.spans});if(p.decision==='review')abstained++;if(p.decision==='block')blocked++;if(!s.spans.length){const clean=cleanByLanguage[s.language];clean.samples++;if(p.decision!=='allow'){clean.falseAlarm++;cleanFalseAlarm++;}}
  const types=new Set([...s.spans,...p.spans].map(x=>x.type));for(const type of types){const key=s.language+':'+type,b=buckets.get(key)??{tp:0,fp:0,fn:0,covered:0,gold:0};const g=s.spans.filter(x=>x.type===type),q=p.spans.filter(x=>x.type===type);const exact=new Set(q.map(x=>x.start+':'+x.end));const tp=g.filter(x=>exact.has(x.start+':'+x.end)).length;b.tp+=tp;b.fn+=g.length-tp;b.fp+=q.length-tp;b.gold+=g.length;
   for(const gold of g){let cursor=gold.start;for(const x of q.filter(x=>x.end>gold.start&&x.start<gold.end).sort((a,b)=>a.start-b.start)){if(x.start>cursor)break;cursor=Math.max(cursor,x.end);}if(cursor>=gold.end)b.covered++;}buckets.set(key,b);
  }
 }
 if(predictions.size!==samples.length)deny('EVAL_EXTRA_PREDICTION');
 return frozen({samples:samples.length,corpusDigest:hash(samples),cleanSamples:samples.filter(s=>!s.spans.length).length,cleanByLanguage,synthetic:samples.filter(s=>s.origin==='synthetic').length,independent:samples.filter(s=>s.origin==='independent-corporate').length,abstained,blocked,cleanFalseAlarm,buckets:Object.fromEntries([...buckets].map(([k,b])=>[k,{...b,precision:b.tp+b.fp?b.tp/(b.tp+b.fp):null,recall:b.gold?b.tp/b.gold:null,precisionInterval:wilson(b.tp,b.tp+b.fp),recallInterval:wilson(b.tp,b.gold),coverageRecall:b.gold?b.covered/b.gold:null}]))});
}
/** Approval requires separate language/type coverage; absent corporate evidence cannot pass. */
export function qualification(report:ReturnType<typeof scoreDataset>,requiredTypes:readonly string[],minGold=100,minRecallLower=.95,minPrecisionLower=.90,maxCleanFalseAlarmRate=.05):{qualified:boolean;reasons:string[]}{
 if(!Number.isSafeInteger(minGold)||minGold<1||![minRecallLower,minPrecisionLower].every(x=>Number.isFinite(x)&&x>0&&x<=1)||!Number.isFinite(maxCleanFalseAlarmRate)||maxCleanFalseAlarmRate<0||maxCleanFalseAlarmRate>=1||!requiredTypes.length||requiredTypes.some(t=>!/^[A-Z_]{1,40}$/.test(t)))deny('EVAL_QUALIFICATION_CONFIG');
 const reasons:string[]=[];if(!report.independent||report.synthetic)reasons.push('INDEPENDENT_CORPORATE_CORPUS_REQUIRED');
 if(report.cleanSamples<minGold)reasons.push('CLEAN_NEGATIVES_REQUIRED');
 if(report.cleanSamples&&report.cleanFalseAlarm/report.cleanSamples>maxCleanFalseAlarmRate)reasons.push('CLEAN_FALSE_ALARM_RATE');
 // Defaults are an engineering acceptance example, not a regulation or certification.
 for(const language of ['tr','en'] as const){const clean=report.cleanByLanguage?.[language];if(!clean||clean.samples<minGold)reasons.push('CLEAN_NEGATIVES_REQUIRED_'+language);else if(clean.falseAlarm/clean.samples>maxCleanFalseAlarmRate)reasons.push('CLEAN_FALSE_ALARM_RATE_'+language);
 for(const type of requiredTypes){const b=report.buckets[language+':'+type];if(!b||b.gold<minGold)reasons.push('INSUFFICIENT_'+language+'_'+type);else {
  if(!b.recallInterval||b.recallInterval.lower<minRecallLower)reasons.push('RECALL_'+language+'_'+type);
  if(!b.precisionInterval||b.precisionInterval.lower<minPrecisionLower)reasons.push('PRECISION_'+language+'_'+type);
 }}}
 return {qualified:!reasons.length,reasons};
}
export function distributionDrift(baseline:readonly number[],current:readonly number[],minSamples=100):{ready:boolean;jsDivergence:number|null}{
 if(baseline.length!==current.length||baseline.length<2||baseline.length>1000||[...baseline,...current].some(x=>!Number.isSafeInteger(x)||x<0))deny('DRIFT_INPUT');const a=baseline.reduce((x,y)=>x+y,0),b=current.reduce((x,y)=>x+y,0);if(a<minSamples||b<minSamples)return {ready:false,jsDivergence:null};let js=0;for(let i=0;i<baseline.length;i++){const p=baseline[i]!/a,q=current[i]!/b,m=(p+q)/2;if(p)js+=p*Math.log2(p/m)/2;if(q)js+=q*Math.log2(q/m)/2;}return {ready:true,jsDivergence:js};
}
