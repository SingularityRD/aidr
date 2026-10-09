import type { TLSSocket } from 'node:tls';
import { hash, id, deny, textBound } from '../enterprise/util.js';
import { ContextResolver, type RequestCredentials, type AuthenticatedContext } from './identity.js';
import { DurableDispatchLedger, DurableBudget } from './durable.js';
import type { TenantState } from './state.js';
import { bytesDigest } from './state.js';
import type { EnterprisePrivacyGate } from '../enterprise/engine.js';
import type { VisualPrivacyEngine } from '../visual/engine.js';
import type { ByteTransport, ProviderKind, NetworkReply } from './network.js';
import { parseJsonStrict } from '../json.js';
import { providerRequest } from './network.js';
import type { ReviewWorkflow } from './review.js';
export interface EgressDestination {readonly id:string;readonly origin:string;readonly model:string;readonly kind:ProviderKind;readonly transport:ByteTransport;}
export interface EgressReceipt {readonly requestId:string;readonly decision:'sent'|'blocked'|'review'|'unknown';readonly reason:string;readonly outputBytes:number;readonly response:NetworkReply|null;readonly reviewCaseId?:string;}
export interface EgressOptions {
 readonly state:TenantState;readonly identity:ContextResolver;readonly destinations:readonly EgressDestination[];
 readonly gate:(context:AuthenticatedContext)=>Pick<EnterprisePrivacyGate,'protect'>&Partial<Pick<EnterprisePrivacyGate,'protectReviewed'>>;
 readonly visual?:(context:AuthenticatedContext)=>Pick<VisualPrivacyEngine,'protect'>;
 readonly policyEpoch:()=>string;readonly clock?:()=>number;readonly budget?:DurableBudget;readonly reviews?:ReviewWorkflow;
}
/** Owns the final transport; applications receive a receipt, not a reusable 'safe' bearer token.
 * Do not expose provider credentials or an alternate outbound client to untrusted applications.
 * An OS/network boundary is still required to prevent processes bypassing this service. */
export class EnforcedEgress {
 #o:EgressOptions;#dest:Map<string,EgressDestination>;#ledger:DurableDispatchLedger;#active=0;
 constructor(o:EgressOptions){this.#o={...o};this.#dest=new Map();for(const d of o.destinations){id(d.id);if(this.#dest.has(d.id)||new URL(d.origin).origin!==d.origin||!d.origin.startsWith('https://'))deny('EGRESS_CONFIG');this.#dest.set(d.id,{...d});}this.#ledger=new DurableDispatchLedger(o.state);}
 async sendOnTls(credentials:RequestCredentials,request:Parameters<EnforcedEgress['send']>[1],socket:TLSSocket):Promise<EgressReceipt>{return this.send(this.#o.identity.bindTlsCredentials(credentials,socket),request);}
 async send(credentials:RequestCredentials,request:{requestId:string;destinationId:string;text:string;images?:readonly Uint8Array[];reviewCaseId?:string}):Promise<EgressReceipt>{
   if(this.#active>=8)return {requestId:'unavailable',decision:'blocked',reason:'EGRESS_BUSY',outputBytes:0,response:null};this.#active++;
   let requestId='unavailable',reserved=false,dispatched=false;const clock=this.#o.clock??Date.now;
   const result=(decision:EgressReceipt['decision'],reason:string,outputBytes=0,response:NetworkReply|null=null):EgressReceipt=>({requestId,decision,reason,outputBytes,response});
   try{
     requestId=id(request.requestId);const reviewCaseId=request.reviewCaseId===undefined?undefined:id(request.reviewCaseId),dest=this.#dest.get(id(request.destinationId));if(!dest)deny('EGRESS_DESTINATION');
     const text=textBound(request.text,1048576),inputs=request.images??[];if(!Array.isArray(inputs)||inputs.length>8)deny('EGRESS_IMAGES');let bytes=Buffer.byteLength(text);const images=inputs.map(i=>{if(!(i instanceof Uint8Array))deny('EGRESS_IMAGE_INVALID');bytes+=i.byteLength;if(i.byteLength>8388608||bytes>16777216)deny('EGRESS_LIMIT');return Buffer.from(i);});
     const context=this.#o.identity.resolve(credentials,dest.origin,'api');if(context.principal.tenantId!==this.#o.state.tenantId)deny('TENANT_MISMATCH');const epoch=this.#o.policyEpoch();
     if(this.#o.budget&&!this.#o.budget.consume(context.principal.tenantId,context.principal.subjectId,bytes,clock()))deny('EGRESS_QUOTA');
     const action=hash({text,images:images.map(bytesDigest),destination:dest.id,model:dest.model,epoch,tenant:context.principal.tenantId,subject:context.principal.subjectId,session:context.principal.sessionId});
     this.#ledger.reserve(requestId,action,context.principal.subjectId,context.principal.sessionId,clock());reserved=true;
     const gate=this.#o.gate(context);let clean=await gate.protect(text,context.context);
     const reviewable=clean.decision==='review'&&clean.policyRevision!==null&&clean.reasons.length>0&&clean.reasons.every(r=>['INSTRUCTION_OVERRIDE','PROMPT_EXTRACTION','ROLE_DELIMITER','ROLE_SPOOF'].includes(r));
     if(reviewCaseId){
       if(!reviewable||!this.#o.reviews||!gate.protectReviewed)deny('REVIEW_NOT_OVERRIDABLE');this.#o.identity.assertContext(context);if(this.#o.policyEpoch()!==epoch)deny('POLICY_CHANGED');
       if(!this.#o.reviews.consumeApproved(context.principal,reviewCaseId,action,clean.policyRevision!))deny('REVIEW_APPROVAL_REQUIRED');
       clean=await gate.protectReviewed(text,context.context,clean.policyRevision!);
     }else if(reviewable&&this.#o.reviews&&gate.protectReviewed){
       this.#o.identity.assertContext(context);if(this.#o.policyEpoch()!==epoch)deny('POLICY_CHANGED');const c=this.#o.reviews.open(context.principal,{actionDigest:action,policyRevision:clean.policyRevision!,reason:'SEMANTIC_REVIEW',destination:dest.id,explanation:'Review the exact session-bound operation flagged by: '+clean.reasons.join(', ')+'. Privacy controls are repeated after approval.'});
       this.#ledger.transition(requestId,'reserved','failed',clock());reserved=false;return {...result('review','TEXT_POLICY'),reviewCaseId:c.id};
     }
     if(clean.output===null||!['allow','redact'].includes(clean.decision)){this.#ledger.transition(requestId,'reserved','failed',clock());reserved=false;return result(clean.decision==='review'?'review':'blocked','TEXT_POLICY');}
     const safeImages:{mime:'image/png';bytes:Uint8Array}[]=[];
     for(const image of images){if(!this.#o.visual)deny('IMAGE_SCANNER_REQUIRED');const r=await this.#o.visual(context).protect(image);if(r.output===null||!['allow','redact'].includes(r.decision))deny('IMAGE_POLICY');safeImages.push({mime:'image/png',bytes:Buffer.from(r.output)});}
     const payload=providerRequest(dest.kind,dest.model,{text:clean.output,images:safeImages});
     // No provider request, first-upload or tool effect has occurred before this line.
     this.#o.identity.assertContext(context);if(this.#o.policyEpoch()!==epoch)deny('POLICY_CHANGED');
     this.#ledger.transition(requestId,'reserved','dispatched',clock());dispatched=true;
     const response=await dest.transport.send(payload.body,undefined,()=>{this.#o.identity.assertContext(context);if(this.#o.policyEpoch()!==epoch)deny('POLICY_CHANGED');});
     this.#ledger.transition(requestId,'dispatched','completed',clock());dispatched=false;reserved=false;
     // Parse only supported text output. Tool calls, inline media and unknown reply shapes do not pass.
     try {
       this.#o.identity.assertContext(context);if(this.#o.policyEpoch()!==epoch)deny('POLICY_CHANGED');
       const text=providerResponseText(dest.kind,response.body),reply=await gate.protect(text,context.context);
       this.#o.identity.assertContext(context);if(this.#o.policyEpoch()!==epoch||reply.output===null||!['allow','redact'].includes(reply.decision))deny('RESPONSE_POLICY');
       return result('sent','POLICY_PASSED',payload.body.length,{status:200,contentType:'application/json',body:Buffer.from(JSON.stringify({outputText:reply.output}))});
     } catch {return result('sent','RESPONSE_WITHHELD',payload.body.length,null);}
   }catch(e){
     if(dispatched){try{this.#ledger.transition(requestId,'dispatched','unknown',clock());}catch{/* no raw fallback on journal failure */}return result('unknown','DISPATCH_OUTCOME_UNKNOWN');}
     if(reserved){try{this.#ledger.transition(requestId,'reserved','failed',clock());}catch{/* remain reserved, deny retry */}}
     const code=e instanceof Error&&/^[A-Z][A-Z0-9_]{1,63}$/.test(e.message)?e.message:'EGRESS_FAILURE';return result('blocked',code);
   }finally{this.#active--;}
 }
}

function providerResponseText(kind:ProviderKind,bytes:Buffer):string {
 const data=parseJsonStrict(new TextDecoder('utf8',{fatal:true}).decode(bytes),24,50000) as Record<string,unknown>;const texts:string[]=[];
 if(kind==='openai-responses'){
  if(!Array.isArray(data.output)||data.output.length>100)deny('PROVIDER_REPLY');
  for(const raw of data.output){const item=raw as Record<string,unknown>;if(item.type!=='message'||item.role!=='assistant'||!Array.isArray(item.content))deny('PROVIDER_REPLY');for(const v of item.content){const p=v as Record<string,unknown>;if(p.type!=='output_text'||typeof p.text!=='string')deny('PROVIDER_REPLY');texts.push(p.text);}}
 }else{
  if(!Array.isArray(data.candidates)||data.candidates.length!==1)deny('PROVIDER_REPLY');const candidate=data.candidates[0] as {content?:{parts?:unknown[]}};
  if(!Array.isArray(candidate.content?.parts))deny('PROVIDER_REPLY');for(const raw of candidate.content.parts){const p=raw as Record<string,unknown>;if(typeof p.text!=='string'||Object.keys(p).some(k=>!['text','thought','thoughtSignature'].includes(k)))deny('PROVIDER_REPLY');if(p.thought!==true)texts.push(p.text);}
 }
 if(!texts.length)deny('PROVIDER_REPLY');return texts.join('\n');
}
