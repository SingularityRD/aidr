import { inspectSignals } from '../enterprise/signals.js';
import { assertWellFormed, detectionViews, sourceSpan } from '../normalize.js';
import { detectRules, hasOpaqueEncoding, keyType } from '../detectors.js';
import { LiteralMatcher } from '../dictionary.js';
import { mergeFindings } from '../spans.js';
import { fail, PrivacyError, requireInt } from '../errors.js';
import { parseJsonStrict } from '../json.js';
import { ENGINE_VERSION } from '../version.js';
import { ENTITY_TYPES, type Action, type EntityType, type Finding, type LiteralRule, type TextResult, type JsonResult, type JsonValue } from '../types.js';
export interface BrowserOptions {
  readonly injectionAction?:'off'|'review'|'block';
  readonly sourceCodeAction?:'off'|'review'|'block';
  readonly literals?: readonly LiteralRule[];
  readonly actions?: Readonly<Partial<Record<EntityType,Action>>>;
  readonly maxInputBytes?:number;
  readonly maxFindings?:number;
  readonly maxScanMs?:number;
  readonly policyId?:string;
  readonly mask?:'label'|'redact';
}
/** Same rule/normalization/validator sources as the Node engine; deliberately NO NER or token mode.
 * Safe for bundling into isolated extension contexts. Scores are not accuracy guarantees. */
export class BrowserPrivacyEngine {
  readonly maxInputBytes:number;
  #injection:'off'|'review'|'block';#sourceCode:'off'|'review'|'block';
  #maxFindings:number;#maxScanMs:number;#policyId:string;#mask:'label'|'redact';
  #matcher:LiteralMatcher;#hasLiterals:boolean;#actions:Partial<Record<EntityType,Action>>;
  constructor(o:BrowserOptions={}) {
    this.#injection=o.injectionAction===undefined?'off':o.injectionAction;this.#sourceCode=o.sourceCodeAction===undefined?'off':o.sourceCodeAction;
    if(!['off','review','block'].includes(this.#injection)||!['off','review','block'].includes(this.#sourceCode))fail('INVALID_CONFIGURATION');
    this.maxInputBytes=requireInt(o.maxInputBytes??65536,1,1048576);
    this.#maxFindings=requireInt(o.maxFindings??2048,1,10000);
    this.#maxScanMs=requireInt(o.maxScanMs??1000,1,30000);
    this.#policyId=o.policyId??'aidr-browser-v1';this.#mask=o.mask??'label';
    if(!/^[A-Za-z0-9_.-]{1,64}$/.test(this.#policyId)||!['label','redact'].includes(this.#mask))fail('INVALID_CONFIGURATION');
    this.#actions={...o.actions};
    for(const [type,action]of Object.entries(this.#actions))if(!ENTITY_TYPES.includes(type as EntityType)||!['redact','review','block'].includes(action))fail('INVALID_CONFIGURATION');
    if(this.#actions.CLASSIFIED&&this.#actions.CLASSIFIED!=='block')fail('UNSAFE_POLICY');
    const literals=o.literals??[];
    for(const r of literals)if(!r||typeof r.value!=='string'||!ENTITY_TYPES.includes(r.type))fail('INVALID_CONFIGURATION');
    this.#matcher=new LiteralMatcher(literals);this.#hasLiterals=literals.length>0;
  }
  #action(type:EntityType):Action{return type==='CLASSIFIED'?'block':this.#actions[type]??'redact';}
  #replacement(type:EntityType):string{return this.#mask==='redact'?'[REDACTED]':`[${type}]`;}
  #audit(start:number,bytes:number,findings:readonly Finding[]) {
    const counts:Partial<Record<EntityType,number>>=Object.create(null) as Partial<Record<EntityType,number>>;
    for(const f of findings)counts[f.type]=(counts[f.type]??0)+1;
    return Object.freeze({engineVersion:ENGINE_VERSION,policyId:this.#policyId,profile:'strict' as const,
      coverage:'rules-only' as const,inputBytes:bytes,counts:Object.freeze(counts),elapsedMs:Math.round((performance.now()-start)*1000)/1000});
  }
  protect(text:string):TextResult {
    const start=performance.now();let bytes=0;
    const result=(decision:TextResult['decision'],output:string|null,findings:Finding[],reasons:string[]):TextResult=>Object.freeze({decision,output,
      findings:Object.freeze(findings.map(f=>Object.freeze({...f}))),reasons:Object.freeze(reasons),audit:this.#audit(start,bytes,findings)});
    try {
      if(typeof text!=='string')fail('INVALID_INPUT');
      // Character bound avoids allocating an unbounded UTF-8 byte array first.
      if(text.length>this.maxInputBytes)fail('INPUT_LIMIT');
      bytes=new TextEncoder().encode(text).length;if(bytes>this.maxInputBytes)fail('INPUT_LIMIT');assertWellFormed(text);
      if(/[\u202a-\u202e\u2066-\u2069]/u.test(text))fail('BIDI_CONTROL');
      const found:Finding[]=[],seen=new Set<string>();
      const push=(f:Finding)=>{const k=`${f.start}:${f.end}:${f.type}`;if(seen.has(k))return;seen.add(k);if(found.length>=this.#maxFindings)fail('FINDING_LIMIT');found.push(f);};
      const check=()=>{if(performance.now()-start>this.#maxScanMs)fail('SCAN_BUDGET');};
      const views=detectionViews(text);check();
      for(const view of views){
        detectRules(view.text,(a,b,type,score,evidence)=>{const [start,end]=sourceSpan(view,a,b);push({start,end,type,score,evidence});});
        if(this.#hasLiterals)this.#matcher.scan(view.text,(a,b,type)=>{const [start,end]=sourceSpan(view,a,b);push({start,end,type,score:1,evidence:'dictionary'});});
        check();
      }
      if(views.some(v=>hasOpaqueEncoding(v.text)))fail('OPAQUE_ENCODING');
      const merged=mergeFindings(found);
      if(found.some(f=>this.#action(f.type)==='block'))return result('block',null,merged,['POLICY_BLOCK']);
      const signals=(this.#injection!=='off'||this.#sourceCode!=='off')?inspectSignals(text):[];
      const policySignals=signals.filter(s=>s==='SOURCE_CODE_HINT'?this.#sourceCode!=='off':this.#injection!=='off');
      if(policySignals.some(s=>(s==='SOURCE_CODE_HINT'?this.#sourceCode:this.#injection)==='block'))return result('block',null,merged,policySignals);
      if(policySignals.length)return result('review',null,merged,policySignals);
      if(found.some(f=>this.#action(f.type)==='review'))return result('review',null,merged,['REVIEW_REQUIRED']);
      if(!merged.length)return result('allow',text,[],[]);
      const chunks:string[]=[];let pos=0;
      for(const f of merged){chunks.push(text.slice(pos,f.start),this.#replacement(f.type));pos=f.end;}chunks.push(text.slice(pos));
      return result('redact',chunks.join(''),merged,[]);
    }catch(e){return result('block',null,[],[e instanceof PrivacyError&&/^[A-Z_]{1,64}$/.test(e.code)?e.code:'BROWSER_SCAN_FAILURE']);}
  }
  protectJson(input:string):JsonResult {
    const start=performance.now();let bytes=0;const all:Finding[]=[];const reasons=new Set<string>();
    let decision:TextResult['decision']='allow';
    const observe=(r:TextResult)=>{all.push(...r.findings);for(const x of r.reasons)reasons.add(x);
      if(r.decision==='block')decision='block';else if(r.decision==='review'&&decision!=='block')decision='review';else if(r.decision==='redact'&&decision==='allow')decision='redact';
      if(all.length>this.#maxFindings)fail('JSON_FINDING_LIMIT');};
    const walk=(v:JsonValue,forced?:EntityType):JsonValue=>{
      if(performance.now()-start>this.#maxScanMs)fail('JSON_BUDGET');
      if(forced&&v!==null) {
        const raw=typeof v==='string'?v:JSON.stringify(v);observe(this.protect(raw));
        if(raw.length)all.push({start:0,end:raw.length,type:forced,score:1,evidence:'schema'});
        if(all.length>this.#maxFindings)fail('JSON_FINDING_LIMIT');
        const a=this.#action(forced);if(a==='block'){decision='block';reasons.add('POLICY_BLOCK');}
        else if(a==='review'&&decision!=='block'){decision='review';reasons.add('REVIEW_REQUIRED');}else if(decision==='allow')decision='redact';
        return this.#replacement(forced);
      }
      if(typeof v==='string'||typeof v==='number'){const r=this.protect(String(v));observe(r);return typeof v==='number'&&r.decision==='allow'?v:r.output;}
      if(Array.isArray(v))return v.map(x=>walk(x));
      if(v&&typeof v==='object'){const out:Record<string,JsonValue>=Object.create(null) as Record<string,JsonValue>;
        for(const [k,val]of Object.entries(v)){if(this.protect(k).decision!=='allow')fail('SENSITIVE_JSON_KEY');out[k]=walk(val,keyType(k));}return out;}
      return v;
    };
    try{
      if(typeof input!=='string')fail('INVALID_INPUT');if(input.length>this.maxInputBytes)fail('INPUT_LIMIT');
      bytes=new TextEncoder().encode(input).length;if(bytes>this.maxInputBytes)fail('INPUT_LIMIT');assertWellFormed(input);
      const output=JSON.stringify(walk(parseJsonStrict(input,32,4096)));
      const d=decision as TextResult['decision'];return Object.freeze({decision:d,output:d==='block'||d==='review'?null:output,reasons:Object.freeze([...reasons]),audit:this.#audit(start,bytes,all)});
    }catch(e){return Object.freeze({decision:'block',output:null,reasons:Object.freeze([e instanceof PrivacyError?e.code:'BROWSER_SCAN_FAILURE']),audit:this.#audit(start,bytes,all)});}
  }
}
