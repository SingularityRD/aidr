import { randomUUID } from 'node:crypto';
import { PrivacyEngine } from '../engine.js';
import type { TextResult } from '../types.js';
import { AuditJournal, type AuditRecord } from './audit.js';
import { PolicyRegistry, validateContext } from './policy.js';
import { SensitiveDataIndex } from './data-index.js';
import { ProvenanceLedger } from './provenance.js';
import { ActivityBudget } from './budget.js';
import { inspectSignals } from './signals.js';
import { CLASSIFICATIONS, maximumClassification, type Classification, type ControlDecision, type TrustedContext } from './types.js';
import { ControlError, frozen, hash, textBound, deny, oneOf } from './util.js';
export interface EnterpriseResult {
  readonly decision:ControlDecision;readonly output:string|null;readonly reasons:readonly string[];
  readonly classification:Classification;readonly matchedRecords:number;readonly policyRevision:number|null;
  /** Decision evidence, not proof that the provider received the message. */
  readonly audit:AuditRecord|null;
}
export interface EnterpriseOptions {
  readonly registry:PolicyRegistry;readonly audit:Pick<AuditJournal,'tenantId'|'actor'|'append'>;readonly textEngine?:Pick<PrivacyEngine,'protect'>;
  readonly indexes?:readonly Pick<SensitiveDataIndex,'tenantId'|'scan'>[];readonly provenance?:ProvenanceLedger;readonly budget?:Pick<ActivityBudget,'consume'>;
  readonly clock?:()=>number;
}
/** Server/native control plane. Context and registration APIs must never be exposed directly to
 * the browser/model; authenticate and resolve them through AIDR before calling. */
export class EnterprisePrivacyGate {
  #active=0;#options:EnterpriseOptions;#text:Pick<PrivacyEngine,'protect'>;
  constructor(options:EnterpriseOptions){this.#options={...options,indexes:Object.freeze([...(options.indexes??[])])};
    this.#text=options.textEngine??new PrivacyEngine({profile:'strict',actions:{SECRET:'block',PRIVATE_KEY:'block',INTERNAL:'block'}});}
  async protect(text:string,context:TrustedContext):Promise<EnterpriseResult> {return this.#run(text,context);}
  /** Trusted repository metadata only. A stored label cannot be downgraded by text matching. */
  async protectSource(text:string,context:TrustedContext,classification:Classification):Promise<EnterpriseResult> {
    return this.#run(text,context,undefined,undefined,oneOf(classification,CLASSIFICATIONS));
  }
  /** Trusted egress only, after atomic consumption of an exact action/session approval.
   * Repeats every control; only semantic review may release already sanitized text. */
  async protectReviewed(text:string,context:TrustedContext,expectedRevision:number):Promise<EnterpriseResult> {return this.#run(text,context,undefined,expectedRevision);}
  /** Bridge for VisualPrivacyEngine/OCR and other existing TextResult consumers. The exact
   * original UTF-16 PII spans are preserved; enterprise denial never has an output. */
  async protectText(text:string,context:TrustedContext):Promise<TextResult> {
    const details:{base?:TextResult}={},start=performance.now();const r=await this.#run(text,context,details);
    const base=details.base;return frozen({decision:r.decision,output:r.output,findings:base?.findings??[],
      reasons:r.reasons,audit:base?.audit??{engineVersion:'0.5.0-rc.1',policyId:'enterprise',profile:'strict',coverage:'rules-only',inputBytes:typeof text==='string'?Math.min(Buffer.byteLength(text),1048576):0,counts:{},elapsedMs:performance.now()-start}});
  }
  /** One trusted request context, snapshotted at binding. Never resolve identity from OCR text. */
  textAdapter(context:TrustedContext):{protect:(text:string)=>Promise<TextResult>} {
    const c=validateContext(context);return Object.freeze({protect:(text:string)=>this.protectText(text,c)});
  }
  async #run(text:string,context:TrustedContext,details?:{base?:TextResult},reviewedRevision?:number,classification:Classification='public'):Promise<EnterpriseResult> {
    if(this.#active>=8)return frozen({decision:'block',output:null,reasons:['CONTROL_BUSY'],classification:'public',matchedRecords:0,policyRevision:null,audit:null});
    this.#active++;try{return await this.#protect(text,context,details,reviewedRevision,classification);}finally{this.#active--;}
  }
  async #protect(text:string,context:TrustedContext,details?:{base?:TextResult},reviewedRevision?:number,classification:Classification='public'):Promise<EnterpriseResult> {
    const o=this.#options,clock=o.clock??Date.now;let policyRevision:number|null=null,matchedRecords=0,tainted=false;
    let c:TrustedContext|undefined,epoch='',destinationId='unknown',counts:Record<string,number>={},inputBytes=0;
    let decision:ControlDecision='block',output:string|null=null;const reasons=new Set<string>();
    const out=(audit:AuditRecord|null):EnterpriseResult=>frozen({decision,output:decision==='allow'||decision==='redact'?output:null,reasons:[...reasons],classification,matchedRecords,policyRevision,audit});
    try{
      const p=o.registry.active(clock());policyRevision=p.revision;epoch=hash(p);c=validateContext(context);
      if(reviewedRevision!==undefined&&(!Number.isSafeInteger(reviewedRevision)||reviewedRevision<1||reviewedRevision!==p.revision))deny('REVIEW_POLICY_CHANGED');
      if(c.tenantId!==p.tenantId||o.audit.tenantId!==p.tenantId)deny('TENANT_MISMATCH');
      textBound(text,p.maxInputBytes);inputBytes=Buffer.byteLength(text);
      if(o.budget&&!o.budget.consume(c.tenantId,c.subjectId,inputBytes,clock()))deny('ACTIVITY_BUDGET');
      const dest=p.destinations.find(d=>d.origin===c!.destination);
      if(!dest){decision=p.unknownDestination;reasons.add('DESTINATION_UNAPPROVED');}
      else{
        destinationId=dest.id;
        if(!dest.accounts.includes(c.account)||dest.requireVerifiedAccount&&!c.accountVerified)deny('ACCOUNT_UNVERIFIED');
        if(dest.requireManagedDevice&&c.device!=='managed')deny('DEVICE_UNMANAGED');
        if(dest.groups.length&&!dest.groups.some(g=>c!.groups.includes(g)))deny('GROUP_FORBIDDEN');
        if(dest.requireProvenance&&!c.assetIds.length)deny('PROVENANCE_REQUIRED');
        if(c.assetIds.length&&!o.provenance)deny('PROVENANCE_REQUIRED');
        if(o.provenance){if(o.provenance.tenantId!==c.tenantId)deny('TENANT_MISMATCH');const provenance=o.provenance.resolve(text,c.assetIds,clock());classification=maximumClassification(classification,provenance.classification);tainted=provenance.tainted;}
        for(const index of o.indexes??[]){if(index.tenantId!==c.tenantId)deny('TENANT_MISMATCH');const matches=index.scan(text);matchedRecords+=matches.length;classification=maximumClassification(classification,...matches.map(x=>x.classification));}
        if(CLASSIFICATIONS.indexOf(classification)>CLASSIFICATIONS.indexOf(dest.maxClassification))deny('CLASSIFICATION_DENIED');
        const signals=inspectSignals(text),injection=signals.filter(s=>!['ACTIVE_CONTENT','SOURCE_CODE_HINT'].includes(s));
        const base:TextResult=await this.#text.protect(text);if(details)details.base=base;counts={...base.audit.counts};
        if(base.decision==='block'){decision='block';for(const x of base.reasons)reasons.add(x);}
        else if(signals.includes('ACTIVE_CONTENT')&&p.blockActiveContent){decision='block';reasons.add('ACTIVE_CONTENT');}
        else if(base.decision==='redact'&&p.piiAction==='block'){decision='block';reasons.add('PII_BLOCK');}
        else if(tainted||injection.length){
          if(!tainted&&reviewedRevision===p.revision&&p.injectionAction==='review'&&['allow','redact'].includes(base.decision)&&base.output!==null){decision=base.decision;output=base.output;reasons.add('SEMANTIC_REVIEW_APPROVED');}
          else decision=p.injectionAction;
          if(base.decision==='review')for(const code of base.reasons)reasons.add(code);
          if(tainted)reasons.add('PROVENANCE_TAINTED');for(const code of injection)reasons.add(code);
        }
        else if(base.decision==='review'){decision='review';for(const x of base.reasons)reasons.add(x);}
        else{decision=base.decision;output=base.output;if(output===null)deny('SCANNER_INVALID');}
      }
      // Check both expiry and body/revision after asynchronous scanning.
      if(hash(o.registry.active(clock()))!==epoch)deny('POLICY_CHANGED');
    }catch(e){decision='block';output=null;reasons.add(e instanceof ControlError?e.code:'CONTROL_FAILURE');}
    if(!c||policyRevision===null||c.tenantId!==o.audit.tenantId)return out(null);
    let record:AuditRecord;
    try{record=await o.audit.append({eventId:randomUUID(),at:clock(),actorRef:o.audit.actor(c.subjectId),destinationId,
      policyRevision,decision,classification,reasons:[...reasons],counts,inputBytes});}
    catch{decision='block';output=null;reasons.add('AUDIT_UNAVAILABLE');return out(null);}
    // A policy update during the durable write must not release previously cleared bytes.
    try{if(hash(o.registry.active(clock()))!==epoch)deny('POLICY_CHANGED');}catch{decision='block';output=null;reasons.add('POLICY_CHANGED');}
    return out(record);
  }
}
