/** Operator-supplied, authorized JSONL corpus. No network; output contains aggregates, not raw text.
 * Independent-corporate is an operator-declared provenance field, NOT authenticated ownership. */
import {readFileSync,writeFileSync,lstatSync} from 'node:fs';
import {PrivacyEngine} from '../../dist/index.js';
import {parseJsonStrict} from '../../dist/json.js';
import {validateSplit,scoreDataset,qualification} from '../../dist/platform/evaluation.js';
const args=process.argv.slice(2);if(args.length!==2){console.error('Usage: node scripts/platform/evaluate-corpus.mjs approved-gold.jsonl aggregate-report.json');process.exit(2);}
try{
 const stat=lstatSync(args[0]);if(!stat.isFile()||stat.isSymbolicLink()||stat.size>16777216)throw Error('CORPUS_INPUT');
 const lines=new TextDecoder('utf8',{fatal:true}).decode(readFileSync(args[0])).trim().split('\n');if(!lines.length||lines.length>10000)throw Error('CORPUS_LIMIT');
 const samples=lines.map(line=>parseJsonStrict(line,12,50000));validateSplit([],samples);
 const engine=new PrivacyEngine({profile:'strict'}),predictions=new Map();
 for(const s of samples){const r=await engine.protect(s.text);predictions.set(s.id,{spans:r.findings.map(f=>({start:f.start,end:f.end,type:f.type})),decision:r.decision});}
 const report=scoreDataset(samples,predictions),acceptance=qualification(report,['PERSON','EMAIL','PHONE','TC_KIMLIK','IBAN','CREDIT_CARD','ADDRESS']);
 writeFileSync(args[1],JSON.stringify({mode:'rules-only; approved NER must be separately evaluated',report,acceptance},null,2)+'\n',{flag:'wx',mode:0o600});
 console.log(JSON.stringify({samples:report.samples,qualified:acceptance.qualified}));if(!acceptance.qualified)process.exitCode=3;
}catch{console.error('CORPUS_EVALUATION_FAILED');process.exitCode=2;}
