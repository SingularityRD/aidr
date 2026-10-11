import type {IncomingMessage,ServerResponse} from 'node:http';
import type {TLSSocket} from 'node:tls';
import {fileURLToPath} from 'node:url';
import {parseJsonStrict} from '../json.js';
import {ControlError,deny,id,integer,object} from '../enterprise/util.js';
import {DocumentCdr} from './documents.js';
import type {SourceDocument} from './dspm.js';
import type {createPlatformRuntime} from './runtime.js';
import {AudioPrivacy} from './modalities.js';
/** Out-of-scope or over-limit refusals whose stable code is returned with the 403 so an operator can tell an
 * unsupported input/size from an authorization failure. Identity, ACL and policy codes stay undisclosed. */
const SCOPE_REFUSALS=new Set(['DATA_POLICY_NOT_CONFIGURED','DOCUMENT_PARSER_NOT_CONFIGURED','ASR_NOT_CONFIGURED','DATA_LIMIT','DOCUMENT_INPUT',
 'AUDIO_LIMIT','AUDIO_FORMAT','AUDIO_CHUNK','AUDIO_DUPLICATE','AUDIO_PCM16_REQUIRED','DSPM_INCOMPLETE','DSPM_LIMIT','DSPM_POLICY_CAPACITY',
 'INDEX_CAPACITY','INDEX_CONTENT_LIMIT','INDEX_DOCUMENT_TOO_SHORT','INDEX_FIELD_TOO_SHORT','INDEX_SCAN_LIMIT','CONTENT_LIMIT']);
export function createDataHandler(runtime:Awaited<ReturnType<typeof createPlatformRuntime>>,destination:{origin:string},documents?:{python:string;workerSha256:string},audioMode?:'silence-all'){
 let active=0;const paths=['/v1/admin/data-source','/v1/source/read','/v1/document/protect','/v1/audio/protect'];
 return async(req:IncomingMessage,res:ServerResponse):Promise<boolean>=>{
  if(!paths.includes(req.url??''))return false;res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
  const reply=(status:number,v:unknown)=>{res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(v));};
  if(active>=2){reply(503,{decision:'block',output:null});return true;}active++;
  try{
   if(req.method!=='POST'||req.headers.origin||req.headers['content-type']!=='application/json'||req.headers['content-encoding'])deny('DATA_REQUEST');
   for(const key of ['authorization','x-aidr-device','x-aidr-provider'])if(typeof req.headers[key]!=='string'||(req.headers[key]as string).length>24000)deny('DATA_CREDENTIALS');
   if(!req.headers.authorization!.startsWith('Bearer '))deny('DATA_CREDENTIALS');
   const credentials=runtime.identity.bindTlsCredentials({userToken:req.headers.authorization!.slice(7),deviceToken:req.headers['x-aidr-device']as string,providerToken:req.headers['x-aidr-provider']as string},req.socket as TLSSocket);
   const context=runtime.identity.resolve(credentials,destination.origin),epoch=runtime.policyEpoch();
   if((req.url==='/v1/admin/data-source'||req.url==='/v1/source/read')&&!runtime.dataPolicy)deny('DATA_POLICY_NOT_CONFIGURED');
   if(req.url==='/v1/admin/data-source')runtime.identity.assertPrincipal(context.principal,'security-admin');
   if(req.url==='/v1/document/protect'&&!documents)deny('DOCUMENT_PARSER_NOT_CONFIGURED');
   if(req.url==='/v1/audio/protect'&&audioMode!=='silence-all')deny('ASR_NOT_CONFIGURED');
   let bytes=0;const chunks:Buffer[]=[];for await(const p of req){const b=Buffer.from(p);bytes+=b.length;if(bytes>(req.url==='/v1/source/read'?4096:12582912))deny('DATA_LIMIT');chunks.push(b);}
   const body=parseJsonStrict(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)),12,20000);runtime.identity.assertContext(context);
   if(req.url==='/v1/admin/data-source'){
    const v=object(body,['sourceId','generation','documents','complete']);id(v.sourceId);integer(v.generation,1);if(v.complete!==true||!Array.isArray(v.documents))deny('DSPM_INCOMPLETE');
    for(const d of v.documents)object(d,['id','text','groups','classification']);
    runtime.sources.replace(context.principal,v.sourceId as string,v.generation as number,v.documents as SourceDocument[],true);
    // Rebuild immediately: unsupported index sizes/content stay denied rather than declared usable.
    runtime.dataPolicy!.scan('');reply(200,{synchronized:true});
   }else if(req.url==='/v1/source/read'){
    const v=object(body,['sourceId','documentId']);const source=runtime.sources.read(context.principal,id(v.sourceId),id(v.documentId));
    const result=await runtime.gate.protectSource(source.text,{...context.context,channel:'retrieval'},source.classification);runtime.identity.assertContext(context);if(runtime.policyEpoch()!==epoch)deny('POLICY_CHANGED');
    reply(200,{decision:result.decision,output:result.output,classification:source.classification});
   }else if(req.url==='/v1/audio/protect'){
    const v=object(body,['data']);if(typeof v.data!=='string'||v.data.length>1398104||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(v.data))deny('AUDIO_LIMIT');
    const input=Buffer.from(v.data,'base64');if(!input.length||input.length>1048576||input.toString('base64')!==v.data)deny('AUDIO_LIMIT');
    const result=await new AudioPrivacy({mode:'silence-all'}).protect(input);runtime.identity.assertContext(context);if(runtime.policyEpoch()!==epoch)deny('POLICY_CHANGED');
    reply(200,{decision:result.decision,output:result.output?.toString('base64')??null,mime:'audio/wav',reason:result.reason});
   }else{
    const v=object(body,['kind','data']);if(typeof v.kind!=='string'||typeof v.data!=='string'||v.data.length>11184812||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(v.data))deny('DOCUMENT_INPUT');
    const input=Buffer.from(v.data,'base64');if(!input.length||input.toString('base64')!==v.data)deny('DOCUMENT_INPUT');
    const cdr=new DocumentCdr({python:documents!.python,worker:fileURLToPath(new URL('../../parsers/worker.py',import.meta.url)),workerSha256:documents!.workerSha256,protector:runtime.gate.textAdapter(context.context)});
    const result=await cdr.protect(input,v.kind);runtime.identity.assertContext(context);if(runtime.policyEpoch()!==epoch)deny('POLICY_CHANGED');
    reply(200,{decision:result.decision,output:result.output?.toString('utf8')??null,mime:result.mime,filename:result.filename,reason:result.reason});
   }
  }catch(e){const reason=e instanceof ControlError&&SCOPE_REFUSALS.has(e.code)?e.code:undefined;if(!res.headersSent)reply(403,{decision:'block',output:null,...(reason?{reason}:{})});else res.destroy();}finally{active--;}
  return true;
 };
}
