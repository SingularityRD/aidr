import type {IncomingMessage,ServerResponse} from 'node:http';
import type {TLSSocket} from 'node:tls';
import {parseJsonStrict} from '../json.js';
import {deny,hash,id,object} from '../enterprise/util.js';
import type {createPlatformRuntime} from './runtime.js';
/** Local scanner endpoint only: never invokes a provider and never releases raw input on denial. */
export function createProtectHandler(runtime:Awaited<ReturnType<typeof createPlatformRuntime>>,destination:{id:string;origin:string}){
 let active=0;
 return async(req:IncomingMessage,res:ServerResponse):Promise<boolean>=>{
  if(req.url!=='/v1/protect')return false;res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
  const reply=(status:number,v:unknown)=>{res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(v));};
  if(active>=8){reply(503,{decision:'block',output:null});return true;}active++;
  try{
   if(req.method!=='POST'||req.headers.origin||req.headers['content-type']!=='application/json'||req.headers['content-encoding'])deny('PROTECT_REQUEST');
   for(const key of ['authorization','x-aidr-device','x-aidr-provider'])if(typeof req.headers[key]!=='string'||(req.headers[key]as string).length>24000)deny('PROTECT_CREDENTIALS');
   if(!req.headers.authorization!.startsWith('Bearer '))deny('PROTECT_CREDENTIALS');let bytes=0;const chunks:Buffer[]=[];
   for await(const p of req){const b=Buffer.from(p);bytes+=b.length;if(bytes>524288)deny('PROTECT_LIMIT');chunks.push(b);}
   const v=object(parseJsonStrict(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)),16,4096),['destinationId','text','binding']);
   if(id(v.destinationId)!==destination.id||typeof v.text!=='string')deny('PROTECT_DESTINATION');
   const credentials=runtime.identity.bindTlsCredentials({userToken:req.headers.authorization!.slice(7),deviceToken:req.headers['x-aidr-device']as string,providerToken:req.headers['x-aidr-provider']as string},req.socket as TLSSocket);
   const context=runtime.identity.resolve(credentials,destination.origin),epoch=runtime.policyEpoch();
   if(v.binding!==undefined&&(!v.binding||typeof v.binding!=='object'||Array.isArray(v.binding)||(v.binding as Record<string,unknown>).tenantId!==context.principal.tenantId))deny('PROTECT_BINDING');
   const bindingDigest=hash(v.binding??null),result=await runtime.gate.protect(v.text,context.context);
   runtime.identity.assertContext(context);if(runtime.policyEpoch()!==epoch)deny('POLICY_CHANGED');
   reply(200,{decision:result.decision,output:result.output,reasons:result.reasons,policyRevision:result.policyRevision,bindingDigest});
  }catch{if(!res.headersSent)reply(403,{decision:'block',output:null});else res.destroy();}finally{active--;}
  return true;
 };
}
