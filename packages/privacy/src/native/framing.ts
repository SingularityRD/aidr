import { parseJsonStrict } from '../json.js';
export const MAX_FRAME_BYTES=524288;
/** Chrome Native Messaging framing; deployed x86/ARM hosts are little endian. */
export function encodeFrame(value:unknown):Buffer {
  const body=Buffer.from(JSON.stringify(value),'utf8');if(!body.length||body.length>MAX_FRAME_BYTES)throw new Error('NATIVE_FRAME_LIMIT');
  const out=Buffer.alloc(body.length+4);out.writeUInt32LE(body.length,0);body.copy(out,4);return out;
}
export class FrameDecoder {
  #buffer=Buffer.alloc(0);#dead=false;
  push(chunk:Uint8Array):Record<string,unknown>[] {
    if(this.#dead||chunk.length>2*MAX_FRAME_BYTES||this.#buffer.length+chunk.length>2*MAX_FRAME_BYTES+4)throw new Error('NATIVE_FRAME_LIMIT');
    this.#buffer=Buffer.concat([this.#buffer,chunk]);const results:Record<string,unknown>[]=[];
    try{
      while(this.#buffer.length>=4){const n=this.#buffer.readUInt32LE(0);if(!n||n>MAX_FRAME_BYTES)throw new Error('NATIVE_FRAME_LIMIT');if(this.#buffer.length<n+4)break;
        const text=new TextDecoder('utf-8',{fatal:true}).decode(this.#buffer.subarray(4,n+4));
        const v=parseJsonStrict(text,12,5000);if(!v||typeof v!=='object'||Array.isArray(v))throw new Error('NATIVE_FRAME_INVALID');
        results.push(v as Record<string,unknown>);this.#buffer=this.#buffer.subarray(n+4);if(results.length>32)throw new Error('NATIVE_FRAME_LIMIT');
      }return results;
    }catch(e){this.close();throw e;}
  }
  finish():void{if(this.#buffer.length)throw new Error('NATIVE_FRAME_TRUNCATED');}
  close():void{this.#buffer.fill(0);this.#buffer=Buffer.alloc(0);this.#dead=true;}
}
