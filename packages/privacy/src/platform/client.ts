/** Application's only model-send capability. Provider keys remain on the gateway. */
import { request } from 'node:https';
import { randomUUID } from 'node:crypto';
import { createSecureContext } from 'node:tls';
import { parseJsonStrict } from '../json.js';
import { canonical, deny, hash,id, object } from '../enterprise/util.js';
import type { RequestCredentials } from './identity.js';
import type {SourceDocument} from './dspm.js';
export interface TextGatewayClientOptions {
  origin:string;destinationId:string;tls:{ca:Buffer;cert:Buffer;key:Buffer};
  /** Use the existing core OS-vault store in host configuration; never browser localStorage. */
  credentials:()=>RequestCredentials|Promise<RequestCredentials>;
}
export interface TextDispatchReceipt {requestId:string;decision:'sent'|'blocked'|'review'|'unknown';reason:string;outputBytes:number;outputText:string|null;reviewCaseId?:string;}
export class TextGatewayClient {
  #o:TextGatewayClientOptions;#origin:URL;
  constructor(options:TextGatewayClientOptions){
    const u=new URL(options.origin);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||u.pathname!=='/'||options.origin!==u.origin)deny('CLIENT_CONFIG');
    id(options.destinationId);for(const k of ['ca','cert','key']as const)if(!Buffer.isBuffer(options.tls[k])||!options.tls[k].length)deny('CLIENT_CONFIG');
    createSecureContext({...options.tls,minVersion:'TLSv1.2'});this.#o={...options,tls:{...options.tls}};this.#origin=u;
  }
  async session(action:'begin'|'complete'|'refresh'|'revoke',body:unknown={}):Promise<Record<string,unknown>>{
    if(!['begin','complete','refresh','revoke'].includes(action))deny('CLIENT_ACTION');
    return this.#post('/v1/session/'+action,(action==='refresh'||action==='revoke')?await this.#o.credentials():body);
  }
  async protect(text:string,options:{binding?:Record<string,unknown>;signal?:AbortSignal}={}):Promise<{decision:string;output:string|null;policyRevision:number|null;bindingDigest:string|null}>{
    if(typeof text!=='string'||Buffer.byteLength(text)>450000)deny('CLIENT_TEXT_LIMIT');
    const data=await this.#post('/v1/protect',{destinationId:this.#o.destinationId,text,...(options.binding?{binding:options.binding}:{})},await this.#o.credentials(),options.signal);
    if(data.output!==null&&typeof data.output!=='string'||!['allow','redact','review','block'].includes(data.decision as string))deny('CLIENT_RESPONSE');
    if(data.decision!=='allow'&&data.decision!=='redact')return {decision:data.decision as string,output:null,policyRevision:null,bindingDigest:null};
    if(data.bindingDigest!==hash(options.binding??null)||!Number.isSafeInteger(data.policyRevision)||(data.policyRevision as number)<1)deny('CLIENT_RESPONSE');
    return {decision:data.decision as string,output:data.output as string|null,policyRevision:data.policyRevision as number,bindingDigest:data.bindingDigest as string};
  }
  async synchronizeSource(sourceId:string,generation:number,documents:readonly SourceDocument[]){
    return this.#post('/v1/admin/data-source',{sourceId:id(sourceId),generation,documents,complete:true},await this.#o.credentials(),undefined,12582912);
  }
  async readSource(sourceId:string,documentId:string){return this.#post('/v1/source/read',{sourceId:id(sourceId),documentId:id(documentId)},await this.#o.credentials());}
  async protectDocument(input:Uint8Array,kind:string,signal?:AbortSignal){
    if(!(input instanceof Uint8Array)||!input.length||input.length>8388608||!/^[a-z]{1,8}$/.test(kind))deny('CLIENT_DOCUMENT_LIMIT');
    return this.#post('/v1/document/protect',{kind,data:Buffer.from(input).toString('base64')},await this.#o.credentials(),signal,12582912);
  }
  async sendDocument(input:Uint8Array,kind:string,options:{requestId?:string;reviewCaseId?:string;signal?:AbortSignal}={}):Promise<TextDispatchReceipt>{
    const result=await this.protectDocument(input,kind,options.signal);
    if(!['allow','redact'].includes(result.decision as string)||typeof result.output!=='string'||result.mime!=='text/plain')deny('CLIENT_DOCUMENT_DENIED');
    return this.send(result.output,options);
  }
  async silenceAudio(input:Uint8Array,signal?:AbortSignal){
    if(!(input instanceof Uint8Array)||!input.length||input.length>1048576)deny('CLIENT_AUDIO_LIMIT');
    return this.#post('/v1/audio/protect',{data:Buffer.from(input).toString('base64')},await this.#o.credentials(),signal,2097152);
  }
  async send(text:string,options:{requestId?:string;reviewCaseId?:string;signal?:AbortSignal}={}):Promise<TextDispatchReceipt>{
    if(typeof text!=='string'||Buffer.byteLength(text)>500000)deny('CLIENT_TEXT_LIMIT');const requestId=id(options.requestId??randomUUID());
    const credentials=await this.#o.credentials();const data=await this.#post('/v1/egress',{requestId,destinationId:this.#o.destinationId,text,...(options.reviewCaseId?{reviewCaseId:id(options.reviewCaseId)}:{})},credentials,options.signal);
    object(data,['requestId','decision','reason','outputBytes','reviewCaseId','output']);
    if(data.requestId!==requestId||!['sent','blocked','review','unknown'].includes(data.decision as string)||typeof data.reason!=='string'||!Number.isSafeInteger(data.outputBytes)||(data.outputBytes as number)<0)deny('CLIENT_RESPONSE');
    let outputText:string|null=null;
    if(data.output!==null){if(data.decision!=='sent'||typeof data.output!=='string')deny('CLIENT_RESPONSE');const output=object(parseJsonStrict(data.output,4,16),['outputText']);if(typeof output.outputText!=='string')deny('CLIENT_RESPONSE');outputText=output.outputText;}
    return {requestId,decision:data.decision as TextDispatchReceipt['decision'],reason:data.reason,outputBytes:data.outputBytes as number,outputText,...(data.reviewCaseId===undefined?{}:{reviewCaseId:id(data.reviewCaseId)})};
  }
  async #post(path:string,body:unknown,credentials?:RequestCredentials,signal?:AbortSignal,maxBytes=524288):Promise<Record<string,unknown>>{
    const bytes=Buffer.from(canonical(body,maxBytes));signal?.throwIfAborted();
    if(credentials)for(const name of ['userToken','deviceToken','providerToken']as const)if(typeof credentials[name]!=='string'||!credentials[name]||credentials[name].length>24000||/[\r\n]/.test(credentials[name]))deny('CLIENT_CREDENTIALS');
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>req.destroy(new Error('CLIENT_OUTCOME_UNKNOWN')),60000);
      const req=request(new URL(path,this.#origin),{...this.#o.tls,method:'POST',rejectUnauthorized:true,minVersion:'TLSv1.2',agent:false,signal,maxHeaderSize:16384,
        headers:{'content-type':'application/json','content-length':String(bytes.length),...(credentials?{authorization:'Bearer '+credentials.userToken,'x-aidr-device':credentials.deviceToken,'x-aidr-provider':credentials.providerToken}:{})}},res=>{
        let size=0;const chunks:Buffer[]=[];if(![200,403,409,502,503].includes(res.statusCode??0)||(res.headers['content-type']??'').split(';')[0]?.trim()!=='application/json'||res.headers['content-encoding']){res.resume();req.destroy(new Error('CLIENT_RESPONSE'));return;}
        res.on('data',p=>{const b=Buffer.from(p);size+=b.length;if(size>2097152)req.destroy(new Error('CLIENT_RESPONSE_LIMIT'));else chunks.push(b);});res.on('error',()=>reject(new Error('CLIENT_OUTCOME_UNKNOWN')));
        res.on('end',()=>{try{const data=parseJsonStrict(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)),16,4096);if(!data||typeof data!=='object'||Array.isArray(data))deny('CLIENT_RESPONSE');resolve(data as Record<string,unknown>);}catch{reject(new Error('CLIENT_RESPONSE'));}});
      });req.once('close',()=>clearTimeout(timer));req.once('error',()=>reject(new Error('CLIENT_OUTCOME_UNKNOWN')));req.end(bytes);
    });
  }
}
