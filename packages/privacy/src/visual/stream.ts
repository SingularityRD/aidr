import { imageFail, integer } from './errors.js';
import type { VisualResult } from './types.js';
/** An upload/clipboard stream is atomic: push() emits NOTHING. Only finish() may return
 * a new sanitized artifact. Aborts and buffer limits are terminal, never passthrough. */
export class AtomicImageGate {
  #parts:Buffer[]=[];#bytes=0;#state:'open'|'finishing'|'closed'|'aborted'='open';
  #controller=new AbortController();
  #timer:ReturnType<typeof setTimeout>;
  #max:number;
  constructor(readonly engine:{protect(bytes:Uint8Array,signal?:AbortSignal):Promise<VisualResult>},maxBytes=8*1024*1024,maxHoldMs=30000){
    this.#max=integer(maxBytes,1,8*1024*1024,'IMAGE_CONFIGURATION_INVALID');
    integer(maxHoldMs,1,120000,'IMAGE_CONFIGURATION_INVALID');
    this.#timer=setTimeout(()=>this.abort(),maxHoldMs);this.#timer.unref();
  }
  get state():string{return this.#state;}
  push(chunk:Uint8Array):void {
    if(this.#state!=='open')imageFail('IMAGE_ABORTED');
    if(!(chunk instanceof Uint8Array)||chunk.buffer instanceof SharedArrayBuffer){this.abort();imageFail('IMAGE_INPUT_INVALID');}
    if(this.#bytes+chunk.byteLength>this.#max){this.abort();imageFail('IMAGE_INPUT_LIMIT');}
    this.#bytes+=chunk.byteLength;this.#parts.push(Buffer.from(chunk));
  }
  #clear():void{for(const p of this.#parts)p.fill(0);this.#parts=[];this.#bytes=0;}
  abort():void{if(this.#state==='closed')return;this.#state='aborted';this.#controller.abort();clearTimeout(this.#timer);this.#clear();}
  async finish():Promise<VisualResult>{
    if(this.#state!=='open')imageFail('IMAGE_ABORTED');this.#state='finishing';
    const bytes=Buffer.concat(this.#parts);this.#clear();
    try{
      const result=await this.engine.protect(bytes,this.#controller.signal);
      if(this.#controller.signal.aborted){result.output?.fill(0);imageFail('IMAGE_ABORTED');}
      this.#state='closed';return result;
    }finally{bytes.fill(0);clearTimeout(this.#timer);if(this.#state==='finishing')this.#state='aborted';}
  }
}
