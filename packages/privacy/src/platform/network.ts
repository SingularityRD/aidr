import { request as httpsRequest } from 'node:https';
import { lookup as dnsLookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import type { LookupFunction } from 'node:net';
import { integer, deny } from '../enterprise/util.js';
const excluded=new BlockList();for(const [ip,prefix]of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.0.2.0',24],['192.168.0.0',16],['192.88.99.0',24],['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',4],['240.0.0.0',4]] as const)excluded.addSubnet(ip,prefix,'ipv4');
for(const [ip,prefix]of [['2001::',32],['2001:db8::',32],['2002::',16],['3fff::',20]] as const)excluded.addSubnet(ip,prefix,'ipv6');
/** Conservative global-address allowlist. IPv4-mapped, link-local, ULA and translation forms fail. */
export function isPublicAddress(ip:string):boolean{const family=isIP(ip);if(family===4)return !excluded.check(ip,'ipv4');if(family===6)return /^[23][0-9a-f]{0,3}:/i.test(ip)&&!excluded.check(ip,'ipv6');return false;}
export interface NetworkReply {readonly status:number;readonly body:Buffer;readonly contentType:string;}
/** Trusted transports must invoke beforeDispatch after asynchronous setup, before sending bytes. */
export interface ByteTransport {send(body:Uint8Array,signal?:AbortSignal,beforeDispatch?:()=>void):Promise<NetworkReply>;}
export interface PinnedHttpsOptions {
 readonly url:string;readonly headers?:Readonly<Record<string,string>>;readonly maxRequestBytes?:number;readonly maxResponseBytes?:number;readonly timeoutMs?:number;
 /** DNS resolver is server infrastructure, never supplied from an incoming request. */
 readonly resolve?:(hostname:string)=>Promise<readonly {address:string;family:number}[]>;
}
/** Fixed destination, fresh validated DNS, pinned lookup, no redirects, no proxy env, no streaming.
 * HTTP errors/timeouts never transparently retry a sensitive POST. */
export class PinnedHttpsTransport implements ByteTransport {
 #o:PinnedHttpsOptions;#url:URL;#headers:Readonly<Record<string,string>>;
 constructor(o:PinnedHttpsOptions){const u=new URL(o.url);if(u.protocol!=='https:'||u.username||u.password||u.hash||u.port&&u.port!=='443'||isIP(u.hostname)||!u.hostname.includes('.')||u.hostname.endsWith('.')||u.hostname.includes('xn--'))deny('NETWORK_DESTINATION');
   const headers={...(o.headers??{} )};for(const [k,v]of Object.entries(headers)){if(!['authorization','content-type','x-goog-api-key','openai-organization','openai-project','accept'].includes(k.toLowerCase())||typeof v!=='string'||v.length>8192||/[\r\n\0]/.test(v))deny('NETWORK_HEADERS');}
   this.#url=u;this.#headers=Object.freeze(headers);this.#o={...o};integer(o.maxRequestBytes??8388608,1,33554432);integer(o.maxResponseBytes??2097152,1,8388608);integer(o.timeoutMs??30000,1,120000);
 }
 async send(input:Uint8Array,signal?:AbortSignal,beforeDispatch?:()=>void):Promise<NetworkReply>{
   if(!(input instanceof Uint8Array)||input.byteLength>(this.#o.maxRequestBytes??8388608))deny('NETWORK_REQUEST_LIMIT');const body=Buffer.from(input);if(signal?.aborted)deny('NETWORK_ABORTED');
   const started=Date.now();let dnsTimer:ReturnType<typeof setTimeout>|undefined;const records=await Promise.race([(this.#o.resolve??(host=>dnsLookup(host,{all:true,verbatim:true})))(this.#url.hostname),new Promise<never>((_,reject)=>{dnsTimer=setTimeout(()=>reject(new Error('NETWORK_DNS_TIMEOUT')),this.#o.timeoutMs??30000);})]).finally(()=>clearTimeout(dnsTimer));if(signal?.aborted)deny('NETWORK_ABORTED');
   if(!records.length||records.length>64||records.some(r=>!isPublicAddress(r.address)||![4,6].includes(r.family)||isIP(r.address)!==r.family))deny('NETWORK_ADDRESS_DENIED');
   const selected=records[0]!;
   beforeDispatch?.();
   const lookup:LookupFunction=((host:string,opts:unknown,cb:Function)=>{if(host!==this.#url.hostname){cb(new Error('NETWORK_HOST_CHANGED'));return;}if((opts as {all?:boolean}).all)cb(null,[selected]);else cb(null,selected.address,selected.family);}) as LookupFunction;
   return new Promise((resolve,reject)=>{
     let settled=false;const fail=()=>{if(!settled){settled=true;reject(new Error('NETWORK_FAILED'));}};
     const req=httpsRequest(this.#url,{method:'POST',headers:{...this.#headers,'Content-Length':String(body.length)},agent:false,lookup,servername:this.#url.hostname,rejectUnauthorized:true,minVersion:'TLSv1.2',...(signal?{signal}:{})},res=>{
       const status=res.statusCode??0;if(status<200||status>=300||res.headers['content-encoding']&&res.headers['content-encoding']!=='identity'){res.destroy();req.destroy();fail();return;}
       const chunks:Buffer[]=[];let n=0;res.on('data',(b:Buffer)=>{n+=b.length;if(n>(this.#o.maxResponseBytes??2097152)){res.destroy();req.destroy();fail();return;}chunks.push(b);});
       res.on('end',()=>{if(!settled){settled=true;resolve({status,body:Buffer.concat(chunks),contentType:String(res.headers['content-type']??'')});}});res.on('error',fail);res.on('aborted',fail);
     });
     const timer=setTimeout(()=>{req.destroy();fail();},Math.max(1,(this.#o.timeoutMs??30000)-(Date.now()-started)));req.on('close',()=>clearTimeout(timer));req.on('error',fail);
     if(beforeDispatch)req.once('socket',socket=>socket.once('secureConnect',()=>{try{beforeDispatch();req.end(body);}catch{req.destroy();fail();}}));else req.end(body);
   });
 }
}
export type ProviderKind='openai-responses'|'gemini-generate-content';
export interface SafeMessage {readonly text:string;readonly images:readonly {readonly mime:'image/png';readonly bytes:Uint8Array}[];}
export function providerRequest(kind:ProviderKind,model:string,message:SafeMessage):{path:string;body:Buffer}{
 if(!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(model)||message.images.length>8)deny('PROVIDER_CONFIGURATION');
 if(kind==='openai-responses')return {path:'/v1/responses',body:Buffer.from(JSON.stringify({model,store:false,stream:false,input:[{role:'user',content:[{type:'input_text',text:message.text},...message.images.map(i=>({type:'input_image',image_url:'data:image/png;base64,'+Buffer.from(i.bytes).toString('base64')}))]}]}))};
 if(kind==='gemini-generate-content')return {path:'/v1beta/models/'+encodeURIComponent(model)+':generateContent',body:Buffer.from(JSON.stringify({contents:[{role:'user',parts:[{text:message.text},...message.images.map(i=>({inlineData:{mimeType:i.mime,data:Buffer.from(i.bytes).toString('base64')}}))]}]}))};
 return deny('PROVIDER_UNSUPPORTED');
}
/** Constructs the ONLY approved upstream URL from server-side provider kind and model. */
export function providerTransport(kind:ProviderKind,model:string,apiKey:string):{origin:string;transport:PinnedHttpsTransport}{
 const path=providerRequest(kind,model,{text:'',images:[]}).path;
 const origin=kind==='openai-responses'?'https://api.openai.com':'https://generativelanguage.googleapis.com';
 return {origin,transport:new PinnedHttpsTransport({url:origin+path,headers:kind==='openai-responses'?{'Content-Type':'application/json',Authorization:'Bearer '+apiKey}:{'Content-Type':'application/json','x-goog-api-key':apiKey}})};
}
