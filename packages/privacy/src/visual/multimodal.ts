import type { TextResult } from '../types.js';
import type { VisualResult } from './types.js';
import { imageFail, integer } from './errors.js';
export interface GuardedMessage {
  readonly decision:'allow'|'redact'|'review'|'block';
  readonly output:{readonly text:string;readonly images:readonly {readonly bytes:Buffer;readonly contentType:'image/png';readonly filename:'aidr-sanitized.png'}[]}|null;
  readonly reasons:readonly string[];
}
/** All-or-nothing message egress. Snapshot every attachment before any asynchronous scan.
 * No remote URLs, filesystem paths, client OCR, custom MIME or raw names are forwarded.
 * Call the upstream AI/tool API ONLY after output !== null. */
export async function protectMultimodal(
  text:string,
  images:readonly Uint8Array[],
  textEngine:{protect(text:string):Promise<TextResult>},
  visualEngine:{protect(input:Uint8Array,signal?:AbortSignal):Promise<VisualResult>},
  options:{signal?:AbortSignal;maxImages?:number;maxTotalBytes?:number}={},
):Promise<GuardedMessage>{
  const snapshots:Buffer[]=[],outputs:{bytes:Buffer;contentType:'image/png';filename:'aidr-sanitized.png'}[]=[];
  let success=false;
  const deny=(reason:string,decision:'review'|'block'='block'):GuardedMessage=>Object.freeze({decision,output:null,reasons:Object.freeze([reason])});
  try{
    const maxImages=integer(options.maxImages??4,1,16,'IMAGE_CONFIGURATION_INVALID');
    const maxBytes=integer(options.maxTotalBytes??16*1024*1024,1,64*1024*1024,'IMAGE_CONFIGURATION_INVALID');
    if(typeof text!=='string'||!Array.isArray(images)||images.length>maxImages||options.signal?.aborted)return deny('MESSAGE_INPUT_REJECTED');
    let total=Buffer.byteLength(text);if(total>maxBytes)return deny('MESSAGE_INPUT_REJECTED');
    for(const image of images){
      if(!(image instanceof Uint8Array)||image.buffer instanceof SharedArrayBuffer)return deny('MESSAGE_INPUT_REJECTED');
      total+=image.byteLength;if(total>maxBytes)return deny('MESSAGE_INPUT_REJECTED');snapshots.push(Buffer.from(image));
    }
    const t=await textEngine.protect(text);
    if(options.signal?.aborted)return deny('MESSAGE_ABORTED');
    if(!t||!['allow','redact'].includes(t.decision)||typeof t.output!=='string')return deny('MESSAGE_TEXT_REJECTED',t?.decision==='review'?'review':'block');
    let changed=t.decision==='redact';
    for(const image of snapshots){
      const r=await visualEngine.protect(image,options.signal);
      if(options.signal?.aborted){r?.output?.fill(0);return deny('MESSAGE_ABORTED');}
      if(!r||!['allow','redact'].includes(r.decision)||!Buffer.isBuffer(r.output)||r.contentType!=='image/png'||r.filename!=='aidr-sanitized.png')return deny('MESSAGE_ATTACHMENT_REJECTED',r?.decision==='review'?'review':'block');
      outputs.push({bytes:r.output,contentType:'image/png',filename:'aidr-sanitized.png'});changed ||= r.decision==='redact';
    }
    if(options.signal?.aborted)return deny('MESSAGE_ABORTED');
    success=true;
    return Object.freeze({decision:changed?'redact':'allow',output:Object.freeze({text:t.output,images:Object.freeze(outputs.map(x=>Object.freeze(x)))}),reasons:Object.freeze([])});
  }catch{return deny('MESSAGE_PROCESSING_FAILED');}
  finally{for(const s of snapshots)s.fill(0);if(!success)for(const o of outputs)o.bytes.fill(0);}
}
