import { PrivacyEngine } from './engine.js';
import { fail, requireInt } from './errors.js';
import type { TextResult } from './types.js';
/** Atomic message gate: push never emits bytes. Only finish() may produce forwardable output. */
export class AtomicTextGate {
  #parts:Buffer[]=[];#bytes=0;#state:'open'|'finishing'|'closed'|'aborted'='open';
  #timer:ReturnType<typeof setTimeout>;
  constructor(readonly engine:PrivacyEngine,maxHoldMs=30000) {
    requireInt(maxHoldMs,1,300000);this.#timer=setTimeout(()=>this.abort(),maxHoldMs);this.#timer.unref();
  }
  get state():string{return this.#state;}
  push(chunk:Uint8Array):void {
    if(this.#state!=='open')fail('GATE_CLOSED');
    if(!(chunk instanceof Uint8Array)){this.abort();fail('INVALID_CHUNK');}
    this.#bytes+=chunk.byteLength;if(this.#bytes>this.engine.maxInputBytes){this.abort();fail('INPUT_LIMIT');}
    this.#parts.push(Buffer.from(chunk)); // Copy: caller mutation cannot alter already accepted bytes.
  }
  abort():void {this.#state='aborted';clearTimeout(this.#timer);this.#clear();}
  #clear():void{for(const p of this.#parts)p.fill(0);this.#parts=[];this.#bytes=0;}
  async finish():Promise<TextResult> {
    if(this.#state!=='open')fail('GATE_CLOSED');this.#state='finishing';
    let text:string;const buffer=Buffer.concat(this.#parts);
    try{text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(buffer);}catch{this.abort();fail('INVALID_UTF8');}
    finally{buffer.fill(0);this.#clear();}
    try {
      const result=await this.engine.protect(text);
      if((this.#state as string)==='aborted')fail('GATE_CLOSED');
      this.#state='closed';return result;
    } finally{clearTimeout(this.#timer);if(this.#state==='finishing')this.#state='aborted';}
  }
}
