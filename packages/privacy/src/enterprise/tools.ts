import { PrivacyEngine } from '../engine.js';
import { ApprovalLedger, type ApprovalBinding } from './approvals.js';
import { inspectSignals } from './signals.js';
import { ActivityBudget } from './budget.js';
import { canonical, frozen, object, id, integer, oneOf, list, hash, mac, secret, deny, textBound, urlAllowed, httpsOrigin, ControlError } from './util.js';
import { parseJsonStrict } from '../json.js';
/** Deliberately restricted schema, NOT full JSON Schema. Unknown schema keywords fail closed. */
export type ToolSchema=
 |{readonly type:'string';readonly maxLength:number;readonly enum?:readonly string[];readonly format?:'https-url'|'opaque-id'}
 |{readonly type:'number';readonly minimum:number;readonly maximum:number}
 |{readonly type:'boolean'}
 |{readonly type:'array';readonly items:ToolSchema;readonly maxItems:number}
 |{readonly type:'object';readonly properties:Readonly<Record<string,ToolSchema>>;readonly required:readonly string[];readonly additionalProperties:false};
function schema(s:ToolSchema,depth=0):void {
  if(depth>8)deny('TOOL_SCHEMA_LIMIT');const v=object(s,['type','maxLength','enum','format','minimum','maximum','items','maxItems','properties','required','additionalProperties']);
  const keys:Record<string,string[]>={string:['type','maxLength','enum','format'],number:['type','minimum','maximum'],boolean:['type'],array:['type','items','maxItems'],object:['type','properties','required','additionalProperties']};
  if(typeof v.type!=='string'||!keys[v.type]||Object.keys(v).some(k=>!keys[v.type as string]!.includes(k)))deny('TOOL_SCHEMA_INVALID');
  switch(s.type){
    case 'string':integer(s.maxLength,1,65536);if(s.enum!==undefined){const a=list(s.enum,256);if(!a.length||a.some(x=>typeof x!=='string'||x.length>s.maxLength)||new Set(a).size!==a.length)deny('TOOL_SCHEMA_INVALID');}if(s.format!==undefined)oneOf(s.format,['https-url','opaque-id']);break;
    case 'number':if(!Number.isFinite(s.minimum)||!Number.isFinite(s.maximum)||s.minimum>s.maximum)deny('TOOL_SCHEMA_INVALID');break;
    case 'boolean':break;
    case 'array':integer(s.maxItems,0,1000);schema(s.items,depth+1);break;
    case 'object':{
      if(s.additionalProperties!==false||!s.properties||typeof s.properties!=='object'||Array.isArray(s.properties)||Object.keys(s.properties).length>64)deny('TOOL_SCHEMA_INVALID');
      const required=list(s.required,64);if(new Set(required).size!==required.length)deny('TOOL_SCHEMA_INVALID');
      for(const k of required){id(k);if(!Object.hasOwn(s.properties,k as string))deny('TOOL_SCHEMA_INVALID');}
      for(const [k,v]of Object.entries(s.properties)){id(k);schema(v,depth+1);}break;
    }
  }
}
function validate(s:ToolSchema,v:unknown,origins:readonly string[],depth=0):void {
  if(depth>8)deny('TOOL_ARGUMENT_LIMIT');
  switch(s.type){
    case 'string':if(typeof v!=='string'||v.length>s.maxLength||s.enum&&!s.enum.includes(v))deny('TOOL_ARGUMENT_INVALID');if(s.format==='https-url'&&!urlAllowed(v,origins))deny('TOOL_DESTINATION_DENIED');if(s.format==='opaque-id')id(v);break;
    case 'number':if(typeof v!=='number'||!Number.isFinite(v)||v<s.minimum||v>s.maximum)deny('TOOL_ARGUMENT_INVALID');break;
    case 'boolean':if(typeof v!=='boolean')deny('TOOL_ARGUMENT_INVALID');break;
    case 'array':for(const item of list(v,s.maxItems))validate(s.items,item,origins,depth+1);break;
    case 'object':{const o=object(v,Object.keys(s.properties));for(const k of s.required)if(!Object.hasOwn(o,k))deny('TOOL_ARGUMENT_INVALID');for(const [k,value]of Object.entries(o))validate(s.properties[k]!,value,origins,depth+1);break;}
  }
}
export interface ToolRule {readonly serverId:string;readonly name:string;readonly definitionHash:string;readonly effect:'read'|'write'|'delete'|'execute';readonly requiredScopes:readonly string[];readonly allowedOrigins:readonly string[];readonly requireApproval:boolean;readonly arguments:ToolSchema;}
export interface ToolContext {readonly tenantId:string;readonly subjectId:string;readonly sessionId:string;readonly scopes:readonly string[];}
export interface ToolRequest {readonly serverId:string;readonly name:string;readonly definition:unknown;readonly argumentsJSON:string;}
export interface ToolResult {readonly decision:'allow'|'review'|'block';readonly arguments:unknown|null;readonly reasons:readonly string[];readonly approval:ApprovalBinding|null;}
export interface ToolGuardOptions {readonly tenantId:string;readonly policyRevision:number;readonly key:Uint8Array;readonly rules:readonly ToolRule[];readonly approvals:Pick<ApprovalLedger,'consume'|'revokeAll'>;readonly budget?:Pick<ActivityBudget,'consume'>;readonly textEngine?:Pick<PrivacyEngine,'protectJson'>;readonly clock?:()=>number;}
/** Pins full reviewed MCP tool definition (including description/annotations). It is an SDK
 * execution guard, not an MCP transport/proxy or authentication implementation. */
export class ToolCallGuard {
  #rules:Map<string,ToolRule>;#key:Buffer;#o:ToolGuardOptions;#text:Pick<PrivacyEngine,'protectJson'>;#epoch=0;#disposed=false;
  constructor(options:ToolGuardOptions){id(options.tenantId);integer(options.policyRevision,1);this.#key=secret(options.key);this.#o={...options};this.#rules=this.#compile(options.rules);
    this.#text=options.textEngine??new PrivacyEngine({profile:'strict',actions:{SECRET:'block',PRIVATE_KEY:'block',INTERNAL:'block'}});}
  #compile(input:readonly ToolRule[]):Map<string,ToolRule>{
    const rules=new Map<string,ToolRule>();for(const raw of list(frozen(input),256)){
      const r=object(raw,['serverId','name','definitionHash','effect','requiredScopes','allowedOrigins','requireApproval','arguments']) as unknown as ToolRule;
      id(r.serverId);id(r.name);if(!/^[a-f0-9]{64}$/.test(r.definitionHash))deny('TOOL_RULE_INVALID');oneOf(r.effect,['read','write','delete','execute']);
      for(const s of list(r.requiredScopes,128))id(s);for(const origin of list(r.allowedOrigins,128))if(httpsOrigin(origin)!==origin)deny('TOOL_RULE_INVALID');
      if(typeof r.requireApproval!=='boolean')deny('TOOL_RULE_INVALID');schema(r.arguments);const key=canonical([r.serverId,r.name]);if(rules.has(key))deny('TOOL_DUPLICATE');rules.set(key,r);
    }return rules;
  }
  updateRules(revision:number,rules:readonly ToolRule[]):void {
    if(this.#disposed)deny('TOOL_DISPOSED');integer(revision,this.#o.policyRevision+1);const compiled=this.#compile(rules);
    this.#o={...this.#o,policyRevision:revision};this.#rules=compiled;this.#epoch++;this.#o.approvals.revokeAll();
  }
  async inspect(request:ToolRequest,context:ToolContext,approvalToken?:string):Promise<ToolResult> {
    const result=(decision:ToolResult['decision'],args:unknown|null,reasons:string[],approval:ApprovalBinding|null=null):ToolResult=>frozen({decision,arguments:args,reasons,approval});
    try{
      if(this.#disposed)deny('TOOL_DISPOSED');const epoch=this.#epoch,clock=this.#o.clock??Date.now;
      const c=object(frozen(context),['tenantId','subjectId','sessionId','scopes']) as unknown as ToolContext;id(c.tenantId);id(c.subjectId);id(c.sessionId);for(const s of list(c.scopes,128))id(s);
      if(c.tenantId!==this.#o.tenantId)deny('TENANT_MISMATCH');
      const q=object(frozen(request),['serverId','name','definition','argumentsJSON']) as unknown as ToolRequest;id(q.serverId);id(q.name);
      const r=this.#rules.get(canonical([q.serverId,q.name]));if(!r)deny('TOOL_UNAPPROVED');
      if(hash(q.definition)!==r.definitionHash)deny('TOOL_DEFINITION_DRIFT');
      if(r.requiredScopes.some(scope=>!c.scopes.includes(scope)))deny('TOOL_SCOPE_DENIED');
      textBound(q.argumentsJSON);const args=parseJsonStrict(q.argumentsJSON,16,10000);validate(r.arguments,args,r.allowedOrigins);
      const signals=inspectSignals(q.argumentsJSON);if(signals.some(s=>s!=='SOURCE_CODE_HINT'))deny('TOOL_CONTENT_UNSAFE');
      // Never silently redact execution arguments: redaction could change the action's semantics.
      const pii=await this.#text.protectJson(q.argumentsJSON);if(pii.decision!=='allow')deny('TOOL_SENSITIVE_ARGUMENT');
      if(this.#disposed||epoch!==this.#epoch)deny('TOOL_POLICY_CHANGED');
      const binding:ApprovalBinding={tenantId:c.tenantId,subjectId:c.subjectId,sessionId:c.sessionId,policyRevision:this.#o.policyRevision,
        actionDigest:mac(this.#key,'aidr-tool-action-v1',c,r,hash(q.definition),args)};
      const mustApprove=r.requireApproval||r.effect!=='read';
      if(mustApprove&&approvalToken===undefined)return result('review',null,['TOOL_APPROVAL_REQUIRED'],binding);
      if(mustApprove&&!this.#o.approvals.consume(approvalToken!,binding,clock()))deny('TOOL_APPROVAL_INVALID');
      if(this.#o.budget&&!this.#o.budget.consume(c.tenantId,c.subjectId,Buffer.byteLength(q.argumentsJSON),clock()))deny('TOOL_BUDGET');
      return result('allow',args,[]);
    }catch(e){return result('block',null,[e instanceof ControlError?e.code:'TOOL_CONTROL_FAILURE']);}
  }
  /** Execute only through this wrapper at the final trusted tool boundary. Never reuse inspect()
   * output as an authorization token. On executor failure, a consumed approval stays consumed. */
  async execute<T>(request:ToolRequest,context:ToolContext,executor:(args:unknown)=>Promise<T>,approvalToken?:string):Promise<T> {
    const epoch=this.#epoch;const r=await this.inspect(request,context,approvalToken);if(epoch!==this.#epoch)deny('TOOL_POLICY_CHANGED');if(r.decision!=='allow'||r.arguments===null)deny('TOOL_EXECUTION_DENIED');
    if(this.#disposed)deny('TOOL_DISPOSED');const output=await executor(r.arguments);
    if(this.#disposed)deny('TOOL_DISPOSED');if(epoch!==this.#epoch)deny('TOOL_POLICY_CHANGED');return output;
  }
  /** Narrow MCP output boundary: any redaction/review/block withholds the entire result.
   * A grant to execute an action never grants permission to release its returned content. */
  async protectOutput(output:unknown):Promise<unknown> {
    if(this.#disposed)deny('TOOL_DISPOSED');const epoch=this.#epoch,json=canonical(frozen(output));
    if(inspectSignals(json).some(s=>s!=='SOURCE_CODE_HINT'))deny('TOOL_OUTPUT_UNSAFE');
    const result=await this.#text.protectJson(json);
    if(this.#disposed)deny('TOOL_DISPOSED');if(epoch!==this.#epoch)deny('TOOL_POLICY_CHANGED');
    if(result.decision!=='allow'||typeof result.output!=='string')deny('TOOL_SENSITIVE_OUTPUT');
    return frozen(parseJsonStrict(result.output,16,20000));
  }
  dispose():void{this.#disposed=true;this.#key.fill(0);this.#rules.clear();this.#epoch++;}
}
export function toolDefinitionHash(definition:unknown):string {return hash(definition);}
