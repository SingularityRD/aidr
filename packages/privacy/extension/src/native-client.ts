import { CHUNK_BYTES, toBase64, fromBase64, sha256 } from '../../src/browser/transport.js';
export interface NativeResult {meta:Record<string,any>;bytes:Uint8Array|null;}
/** No localhost HTTP endpoint, no CORS bypass, no long-lived secret in page JavaScript. */
export async function nativeCall(kind:'image'|'text'|'json'|'csv'|'tsv'|'health',bytes:Uint8Array,policyDigest:string):Promise<NativeResult> {
  const port=chrome.runtime.connectNative('com.singularity.aidr_privacy');let pending:{id:string;resolve:(m:any)=>void;reject:()=>void;timer:ReturnType<typeof setTimeout>}|undefined,closed=false;
  const stop=()=>{closed=true;if(pending){clearTimeout(pending.timer);pending.reject();pending=undefined;}};
  port.onDisconnect.addListener(()=>{void chrome.runtime.lastError;stop();});
  port.onMessage.addListener((m:any)=>{
    if(!pending||!m||m.v!==1||m.id!==pending.id||m.ok!==true){stop();try{port.disconnect();}catch{}return;}
    const p=pending;pending=undefined;clearTimeout(p.timer);p.resolve(m);
  });
  const rpc=(op:string,payload:Record<string,unknown>={}):Promise<any>=>new Promise((resolve,reject)=>{
    if(closed||pending){reject(new Error('NATIVE_UNAVAILABLE'));return;}
    const id=crypto.randomUUID();const timer=setTimeout(()=>{stop();try{port.disconnect();}catch{}},125000);
    pending={id,resolve,reject:()=>reject(new Error('NATIVE_UNAVAILABLE')),timer};
    try{port.postMessage({v:1,id,op,...payload});}catch{stop();}
  });
  try{
    const hello=await rpc('hello');if(hello.local!==true||hello.protocol!==1||hello.policyDigest!==policyDigest)throw new Error('NATIVE_POLICY_MISMATCH');
    if(kind==='health')return {meta:hello,bytes:null};
    if(kind==='image'&&hello.ocr!==true)throw new Error('NATIVE_OCR_UNAVAILABLE');
    await rpc('begin',{kind,size:bytes.length,sha256:await sha256(bytes),policyDigest});
    for(let offset=0;offset<bytes.length;offset+=CHUNK_BYTES){const chunk=bytes.subarray(offset,offset+CHUNK_BYTES);const a=await rpc('write',{offset,data:toBase64(chunk)});if(a.received!==offset+chunk.length)throw new Error('NATIVE_PROTOCOL_INVALID');}
    const meta=await rpc('commit');
    if(!['allow','redact','review','block'].includes(meta.decision))throw new Error('NATIVE_PROTOCOL_INVALID');
    if(meta.decision==='block'||meta.decision==='review'){if(meta.outputBytes!==0)throw new Error('NATIVE_PROTOCOL_INVALID');return {meta,bytes:null};}
    if(meta.policyDigest!==policyDigest||!Number.isSafeInteger(meta.outputBytes)||meta.outputBytes<0||meta.outputBytes>16777216||typeof meta.sha256!=='string'||!/^[a-f0-9]{64}$/.test(meta.sha256))throw new Error('NATIVE_PROTOCOL_INVALID');
    const output=new Uint8Array(meta.outputBytes);let offset=0;
    while(offset<output.length){const m=await rpc('read',{offset});const part=fromBase64(m.data,CHUNK_BYTES);
      if(m.offset!==offset||!part.length||offset+part.length>output.length)throw new Error('NATIVE_PROTOCOL_INVALID');
      output.set(part,offset);offset+=part.length;if(m.done!==(offset===output.length))throw new Error('NATIVE_PROTOCOL_INVALID');}
    if(await sha256(output)!==meta.sha256)throw new Error('NATIVE_OUTPUT_CHANGED');
    return {meta,bytes:output};
  }finally{stop();try{port.disconnect();}catch{}}
}
