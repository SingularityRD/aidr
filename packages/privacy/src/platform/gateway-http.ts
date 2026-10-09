import type { TLSSocket } from 'node:tls';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { parseJsonStrict } from '../json.js';
import { deny, object, id } from '../enterprise/util.js';
import type { EnforcedEgress } from './egress.js';
/** Intended behind a mutually authenticated ingress/reverse proxy or direct TLS server.
 * No web-origin/CORS access and no request-controlled upstream URLs, API keys or tenant IDs. */
export function createEgressHandler(gateway:EnforcedEgress,options:{requireTLS?:boolean;maxBodyBytes?:number;allowImages?:boolean}={}){
 return async(req:IncomingMessage,res:ServerResponse):Promise<void>=>{
  res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');const respond=(code:number,body:unknown)=>{res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(body));};
  try{
   if(options.requireTLS!==false&&!(req.socket as {encrypted?:boolean}).encrypted)deny('TLS_REQUIRED');
   if(req.method!=='POST'||req.url!=='/v1/egress'||req.headers.origin||req.headers['content-encoding']||req.headers['content-type']!=='application/json')deny('REQUEST_DENIED');
   for(const key of ['authorization','x-aidr-device','x-aidr-provider'])if(typeof req.headers[key]!=='string'||(req.headers[key] as string).length>24000)deny('CREDENTIALS_REQUIRED');
   if(!req.headers.authorization!.startsWith('Bearer '))deny('CREDENTIALS_REQUIRED');
   let n=0;const chunks:Buffer[]=[];for await(const p of req){const b=Buffer.from(p);n+=b.length;if(n>(options.maxBodyBytes??12582912))deny('REQUEST_LIMIT');chunks.push(b);}
   const v=object(parseJsonStrict(new TextDecoder('utf8',{fatal:true}).decode(Buffer.concat(chunks)),12,1000),['requestId','destinationId','text','images','reviewCaseId']);id(v.requestId);id(v.destinationId);if(v.reviewCaseId!==undefined)id(v.reviewCaseId);if(typeof v.text!=='string')deny('REQUEST_SCHEMA');
   if(options.allowImages===false&&v.images!==undefined)deny('REQUEST_IMAGES');
   if(v.images!==undefined&&(!Array.isArray(v.images)||v.images.length>8))deny('REQUEST_IMAGES');const images=((v.images as unknown[])??[]).map(x=>{if(typeof x!=='string'||x.length>11184816||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(x))deny('REQUEST_IMAGE');const b=Buffer.from(x,'base64');if(!b.length||b.toString('base64')!==x)deny('REQUEST_IMAGE');return b;});
   const credentials={userToken:req.headers.authorization!.slice(7),deviceToken:req.headers['x-aidr-device'] as string,providerToken:req.headers['x-aidr-provider'] as string},request={requestId:v.requestId as string,destinationId:v.destinationId as string,text:v.text,images,...(v.reviewCaseId===undefined?{}:{reviewCaseId:v.reviewCaseId as string})};
   const result=options.requireTLS===false?await gateway.send(credentials,request):await gateway.sendOnTls(credentials,request,req.socket as TLSSocket);
   // Do not forward arbitrary provider HTTP headers/cookies or raw provider JSON.
   respond(result.decision==='sent'?200:result.decision==='review'?409:result.decision==='unknown'?502:403,{requestId:result.requestId,decision:result.decision,reason:result.reason,outputBytes:result.outputBytes,...(result.reviewCaseId?{reviewCaseId:result.reviewCaseId}:{}),output:result.response?result.response.body.toString('utf8'):null});
  }catch{if(!res.headersSent)respond(403,{decision:'blocked',reason:'REQUEST_DENIED',output:null});else res.destroy();}
 };
}
