import { createHmac } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { PrivacyError, fail, requireInt } from './errors.js';
import { assertWellFormed, detectionViews, normalize, isBoundary, sourceSpan } from './normalize.js';
import { LiteralMatcher } from './dictionary.js';
import { detectRules, hasOpaqueEncoding, keyType } from './detectors.js';
import { parseJsonStrict } from './json.js';
import { ENTITY_TYPES, type Action, type AuditSummary, type EngineOptions, type EntityType,
  type Finding, type JsonResult, type JsonValue, type MaskMode, type NerProvider,
  type Profile, type TextResult } from './types.js';
const VERSION='0.5.0-rc.1';
const KNOWN_ERRORS=new Set(['INPUT_LIMIT','FINDING_LIMIT','SCAN_BUDGET','INVALID_UNICODE','UNSUPPORTED_CONTROL',
  'INVALID_ENCODING','ENCODING_DEPTH','INVALID_SPAN','INCOMPLETE_PRIVATE_KEY','OPAQUE_ENCODING',
  'BIDI_CONTROL','NER_REQUIRED','NER_CAPABILITY_MISSING','NER_FAILURE','NER_TIMEOUT','NER_INCOMPLETE',
  'NER_INVALID_OUTPUT','CONCURRENCY_LIMIT','INVALID_INPUT','INVALID_JSON','DUPLICATE_JSON_KEY',
  'UNSAFE_JSON_KEY','UNSAFE_JSON_NUMBER','JSON_DEPTH_LIMIT','JSON_NODE_LIMIT','SENSITIVE_JSON_KEY',
  'JSON_BUDGET','JSON_FINDING_LIMIT','DISPOSED','NORMALIZATION_LIMIT','INCOMPLETE_SECRET','INCOMPLETE_FIELD']);
export { mergeFindings } from './spans.js';
import { mergeFindings } from './spans.js';
interface Config {
  profile:Profile; mask:MaskMode; tenantId:string; keyId:string; policyId:string;
  maxInputBytes:number;maxFindings:number;maxScanMs:number;nerTimeoutMs:number;
  maxConcurrent:number;maxJsonDepth:number;maxJsonNodes:number;
}
function staticCode(error:unknown):string {
  return error instanceof PrivacyError&&KNOWN_ERRORS.has(error.code)?error.code:'INTERNAL_FAILURE';
}
function canonical(value:string,type:EntityType):string {
  let s=normalize(value).text;
  if(['TC_KIMLIK','CREDIT_CARD','US_SSN','PHONE'].includes(type))s=s.replace(/[ ()\t.-]/g,'');
  if(type==='IBAN')s=s.replace(/[ \t-]/g,'').toUpperCase();
  if(type==='EMAIL'){const i=s.lastIndexOf('@');if(i>=0)s=s.slice(0,i+1)+s.slice(i+1).toLowerCase();}
  return s;
}
export class PrivacyEngine {
  #config:Config;
  #matcher:LiteralMatcher;
  #hasLiterals:boolean;
  #actions:Readonly<Partial<Record<EntityType,Action>>>;
  #ner:NerProvider|undefined;
  #key:Buffer|undefined;
  #active=0;
  #disposed=false;
  constructor(options:EngineOptions={}) {
    const profile=options.profile??'strict',mask=options.mask??'label';
    if(!['balanced','strict','defense'].includes(profile)||!['label','redact','token'].includes(mask))fail('INVALID_CONFIGURATION');
    const policyId=options.policyId??'aidr-default-v1',keyId=options.keyId??'v1',tenantId=options.tenantId??'';
    if(!/^[A-Za-z0-9_.-]{1,64}$/.test(policyId)||!/^[A-Za-z0-9_.-]{1,32}$/.test(keyId))fail('INVALID_CONFIGURATION');
    if(mask==='token' && (typeof tenantId!=='string'||!tenantId||tenantId.length>128||!options.tokenKey||options.tokenKey.length<32||options.tokenKey.length>128))fail('TOKEN_KEY_REQUIRED');
    this.#config={profile,mask,tenantId,keyId,policyId,
      maxInputBytes:requireInt(options.maxInputBytes??65536,1,1048576),
      maxFindings:requireInt(options.maxFindings??2048,1,10000),
      maxScanMs:requireInt(options.maxScanMs??1000,1,30000),
      nerTimeoutMs:requireInt(options.nerTimeoutMs??5000,1,120000),
      maxConcurrent:requireInt(options.maxConcurrent??4,1,64),
      maxJsonDepth:requireInt(options.maxJsonDepth??32,1,128),
      maxJsonNodes:requireInt(options.maxJsonNodes??4096,1,50000)};
    this.#actions=Object.freeze({...options.actions});
    for(const [type,action]of Object.entries(this.#actions))if(!ENTITY_TYPES.includes(type as EntityType)||!['redact','review','block'].includes(action))fail('INVALID_CONFIGURATION');
    // Classification markings are non-downgradable. In defense, secrets and internal matches also block.
    if(this.#actions.CLASSIFIED&&this.#actions.CLASSIFIED!=='block')fail('UNSAFE_POLICY');
    if(profile==='defense')for(const t of ['SECRET','PRIVATE_KEY','INTERNAL'] as const)if(this.#actions[t]&&this.#actions[t]!=='block')fail('UNSAFE_POLICY');
    const rules=options.literals??[];
    for(const r of rules)if(typeof r.value!=='string'||!ENTITY_TYPES.includes(r.type))fail('INVALID_CONFIGURATION');
    this.#matcher=new LiteralMatcher(rules);this.#hasLiterals=rules.length>0;
    if(options.tokenKey)this.#key=Buffer.from(options.tokenKey);
    this.#ner=options.ner;
    if(this.#ner) {
      const c=this.#ner.capabilities;
      if(!c||c.local!==true||c.offsetUnit!=='utf16'||!Array.isArray(c.languages)||!Array.isArray(c.entities)
        ||!c.languages.length||!c.entities.length||c.languages.some(l=>!['tr','en'].includes(l))
        ||c.entities.some(t=>!ENTITY_TYPES.includes(t))||!/^[A-Za-z0-9._:-]{1,128}$/.test(c.revision))fail('INVALID_NER_CONFIGURATION');
    }
  }
  get maxInputBytes():number{return this.#config.maxInputBytes;}
  /** Erases the copied HMAC key. JS strings / GC memory are not guaranteed zeroizable. */
  dispose():void{this.#key?.fill(0);this.#key=undefined;this.#disposed=true;}
  #action(type:EntityType):Action {
    if(type==='CLASSIFIED')return 'block';
    if(this.#config.profile==='defense'&&['SECRET','PRIVATE_KEY','INTERNAL'].includes(type))return 'block';
    return this.#actions[type]??'redact';
  }
  #audit(start:number,bytes:number,findings:readonly Finding[]):AuditSummary {
    const counts:Partial<Record<EntityType,number>>=Object.create(null) as Partial<Record<EntityType,number>>;
    for(const f of findings)counts[f.type]=(counts[f.type]??0)+1;
    return Object.freeze({engineVersion:VERSION,policyId:this.#config.policyId,profile:this.#config.profile,
      coverage:this.#ner?'rules-and-ner':'rules-only',inputBytes:bytes,counts:Object.freeze(counts),
      elapsedMs:Math.round((performance.now()-start)*1000)/1000});
  }
  #result(start:number,bytes:number,decision:TextResult['decision'],output:string|null,findings:readonly Finding[],reasons:string[]):TextResult {
    return Object.freeze({decision,output,findings:Object.freeze(findings.map(f=>Object.freeze({...f}))),
      reasons:Object.freeze(reasons),audit:this.#audit(start,bytes,findings)});
  }
  #replacement(value:string,type:EntityType):string {
    const c=this.#config;if(c.mask==='label')return `[${type}]`;if(c.mask==='redact')return '[REDACTED]';
    if(!this.#key||this.#disposed)fail('DISPOSED');
    // HMAC, not a plain hash; domain separation and a length-safe tuple bind tenant, type and key version.
    const token=createHmac('sha256',this.#key).update(JSON.stringify(['aidr-pii-v1',c.tenantId,c.keyId,type,canonical(value,type)])).digest('base64url').slice(0,24);
    return `[${type}~${c.keyId}~${token}]`;
  }
  #checkText(text:string):number {
    if(typeof text!=='string')fail('INVALID_INPUT');
    const bytes=Buffer.byteLength(text,'utf8');if(bytes>this.#config.maxInputBytes)fail('INPUT_LIMIT');
    assertWellFormed(text);if(this.#disposed)fail('DISPOSED');return bytes;
  }
  #checkCapabilities():void {
    if(this.#config.profile==='defense') {
      if(!this.#ner)fail('NER_REQUIRED');
      const caps=this.#ner.capabilities;
      if(!(['tr','en'] as const).every(l=>caps.languages.includes(l) && ['PERSON','ADDRESS'].every(t=>caps.entitiesByLanguage?.[l]?.includes(t as EntityType))))fail('NER_CAPABILITY_MISSING');
    }
  }
  async #find(text:string):Promise<Finding[]> {
    const start=performance.now(),c=this.#config;const found:Finding[]=[];const seen=new Set<string>();
    const check=()=>{if(performance.now()-start>c.maxScanMs)fail('SCAN_BUDGET');};
    const push=(f:Finding)=>{
      const key=`${f.start}:${f.end}:${f.type}`;if(seen.has(key))return;seen.add(key);
      if(found.length>=c.maxFindings)fail('FINDING_LIMIT');found.push(f);
    };
    if(c.profile!=='balanced'&&/[\u202a-\u202e\u2066-\u2069]/u.test(text))fail('BIDI_CONTROL');
    const views=detectionViews(text);check();
    for(const view of views) {
      detectRules(view.text,(start,end,type,score,evidence)=>{const [a,b]=sourceSpan(view,start,end);push({start:a,end:b,type,score,evidence});});
      if(this.#hasLiterals)this.#matcher.scan(view.text,(start,end,type)=>{const [a,b]=sourceSpan(view,start,end);push({start:a,end:b,type,score:1,evidence:'dictionary'});});
      check();
    }
    if(c.profile!=='balanced'&&views.some(v=>hasOpaqueEncoding(v.text)))fail('OPAQUE_ENCODING');
    this.#checkCapabilities();
    if(this.#ner) {
      // Scan each distinct decoded view, not only the raw text. Never permit silent model truncation.
      const deadline=performance.now()+c.nerTimeoutMs;
      for(const view of views) {
        const controller=new AbortController();let timer:ReturnType<typeof setTimeout>|undefined;
        try {
          const remaining=deadline-performance.now();if(remaining<=0)fail('NER_TIMEOUT');
          const timeout=new Promise<never>((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new PrivacyError('NER_TIMEOUT'));},remaining);});
          const task=Promise.resolve().then(()=>this.#ner!.detect(view.text,controller.signal)).catch(()=>fail('NER_FAILURE'));
          const result=await Promise.race([task,timeout]);
          if(!result||result.complete!==true)fail('NER_INCOMPLETE');
          if(!Array.isArray(result.entities)||result.entities.length>c.maxFindings)fail('NER_INVALID_OUTPUT');
          for(const e of result.entities) {
            if(!e||!ENTITY_TYPES.includes(e.type)||!Number.isFinite(e.score)||e.score<0||e.score>1
              ||!Number.isSafeInteger(e.start)||!Number.isSafeInteger(e.end)||e.start<0||e.end<=e.start||e.end>view.text.length
              ||!isBoundary(view.text,e.start)||!isBoundary(view.text,e.end))fail('NER_INVALID_OUTPUT');
            const [a,b]=sourceSpan(view,e.start,e.end);push({start:a,end:b,type:e.type,score:e.score,evidence:'ner'});
          }
        } finally {if(timer)clearTimeout(timer);controller.abort();}
      }
    }
    return found;
  }
  async protect(text:string):Promise<TextResult> {
    const start=performance.now();let bytes=0,entered=false;
    try {
      bytes=this.#checkText(text);
      if(this.#active>=this.#config.maxConcurrent)fail('CONCURRENCY_LIMIT');this.#active++;entered=true;
      const findings=await this.#find(text),merged=mergeFindings(findings);
      // Evaluate ALL findings before overlap resolution so lower-priority block rules cannot disappear.
      if(findings.some(f=>this.#action(f.type)==='block'))return this.#result(start,bytes,'block',null,merged,['POLICY_BLOCK']);
      if(findings.some(f=>this.#action(f.type)==='review')||this.#config.profile==='defense'&&findings.some(f=>f.evidence==='ner'&&f.score<.7))
        return this.#result(start,bytes,'review',null,merged,['REVIEW_REQUIRED']);
      if(!merged.length)return this.#result(start,bytes,'allow',text,[],[]);
      const chunks:string[]=[];let pos=0;
      for(const f of merged){chunks.push(text.slice(pos,f.start),this.#replacement(text.slice(f.start,f.end),f.type));pos=f.end;}
      chunks.push(text.slice(pos));return this.#result(start,bytes,'redact',chunks.join(''),merged,[]);
    } catch(error) {return this.#result(start,bytes,'block',null,[],[staticCode(error)]);}
    finally{if(entered)this.#active--;}
  }
  /** Strict JSON text input. Output is serialized JSON; sensitive scalars may change to marker strings. */
  async protectJson(input:string):Promise<JsonResult> {
    const start=performance.now();let bytes=0;const all:Finding[]=[];const reasons=new Set<string>();let decision:TextResult['decision']='allow';
    const check=()=>{if(performance.now()-start>this.#config.maxScanMs+this.#config.nerTimeoutMs)fail('JSON_BUDGET');};
    const observe=(r:TextResult)=>{
      for(const f of r.findings){all.push(f);if(all.length>this.#config.maxFindings)fail('JSON_FINDING_LIMIT');}
      for(const code of r.reasons)reasons.add(code);
      if(r.decision==='block')decision='block';else if(r.decision==='review'&&decision!=='block')decision='review';else if(r.decision==='redact'&&decision==='allow')decision='redact';
    };
    const walk=async(v:JsonValue,forced?:EntityType):Promise<JsonValue>=>{
      check();
      if(forced&&v!==null) {
        const raw=typeof v==='string'?v:JSON.stringify(v);
        // Still scan marked fields: classified/private-key policy outranks ordinary field redaction.
        const r=await this.protect(raw);observe(r);
        const f:Finding={start:0,end:raw.length,type:forced,score:1,evidence:'schema'};
        if(raw.length)all.push(f);if(all.length>this.#config.maxFindings)fail('JSON_FINDING_LIMIT');
        const action=this.#action(forced);
        if(action==='block'){decision='block';reasons.add('POLICY_BLOCK');}
        else if(action==='review'&&decision!=='block'){decision='review';reasons.add('REVIEW_REQUIRED');}
        else if(decision==='allow')decision='redact';
        return this.#replacement(raw,forced);
      }
      if(typeof v==='string'||typeof v==='number') {
        const r=await this.protect(String(v));observe(r);if(r.output===null)return null;
        return typeof v==='number'&&r.decision==='allow'?v:r.output;
      }
      if(Array.isArray(v)){const result:JsonValue[]=[];for(const item of v)result.push(await walk(item));return result;}
      if(v&&typeof v==='object') {
        const result:Record<string,JsonValue>=Object.create(null) as Record<string,JsonValue>;
        for(const [key,val]of Object.entries(v)) {
          const k=await this.protect(key);if(k.decision!=='allow')fail('SENSITIVE_JSON_KEY');
          result[key]=await walk(val,keyType(key));
        }
        return result;
      }
      return v;
    };
    try {
      bytes=this.#checkText(input);this.#checkCapabilities();const parsed=parseJsonStrict(input,this.#config.maxJsonDepth,this.#config.maxJsonNodes);
      const safe=await walk(parsed);check();
      // TypeScript cannot track mutation through async closures; derive the terminal state here.
      const terminal=decision as TextResult['decision'];
      return Object.freeze({decision:terminal,output:terminal==='block'||terminal==='review'?null:JSON.stringify(safe),
        reasons:Object.freeze([...reasons]),audit:this.#audit(start,bytes,all)});
    } catch(error) {return Object.freeze({decision:'block',output:null,reasons:Object.freeze([staticCode(error)]),audit:this.#audit(start,bytes,all)});}
  }
}
