export const CHUNK_BYTES=196608;
export function toBase64(bytes:Uint8Array):string {
  let s='';for(let i=0;i<bytes.length;i+=8192)s+=String.fromCharCode(...bytes.subarray(i,i+8192));return btoa(s);
}
export function fromBase64(s:unknown,maxBytes:number):Uint8Array {
  if(typeof s!=='string'||s.length>Math.ceil(maxBytes/3)*4||s.length%4!==0||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))throw new Error('TRANSPORT_INVALID');
  const raw=atob(s);if(raw.length>maxBytes)throw new Error('TRANSPORT_LIMIT');const out=Uint8Array.from(raw,c=>c.charCodeAt(0));
  if(toBase64(out)!==s)throw new Error('TRANSPORT_NONCANONICAL');return out;
}
export async function sha256(bytes:Uint8Array):Promise<string>{const copy=new Uint8Array(bytes);return [...new Uint8Array(await crypto.subtle.digest('SHA-256',copy.buffer))].map(x=>x.toString(16).padStart(2,'0')).join('');}
export interface Binding {readonly tabId:number;readonly origin:string;readonly documentToken:string;readonly epoch:string;}
interface Ticket<T>{value:T;binding:Binding;expires:number;bytes:number;}
/** Sanitized values only; one use, document/origin/policy-bound, bounded and never persisted. */
export class TicketVault<T> {
  #items=new Map<string,Ticket<T>>();#clock:()=>number;#ttl:number;
  constructor(clock=()=>Date.now(),ttl=120000){this.#clock=clock;this.#ttl=ttl;}
  prune():void{for(const [k,t]of this.#items)if(t.expires<=this.#clock())this.#items.delete(k);}
  issue(value:T,binding:Binding,bytes:number):string {
    this.prune();if(!Number.isSafeInteger(bytes)||bytes<0||bytes>16777216||this.#items.size>=8||[...this.#items.values()].reduce((n,t)=>n+t.bytes,0)+bytes>33554432)throw new Error('TICKET_LIMIT');
    const id=crypto.randomUUID();this.#items.set(id,{value,binding:{...binding},bytes,expires:this.#clock()+this.#ttl});return id;
  }
  consume(id:unknown,binding:Binding):T {
    this.prune();if(typeof id!=='string')throw new Error('TICKET_INVALID');const t=this.#items.get(id);this.#items.delete(id);
    if(!t||(['tabId','origin','documentToken','epoch'] as const).some(k=>t.binding[k]!==binding[k]))throw new Error('TICKET_INVALID');return t.value;
  }
  clear():void{this.#items.clear();}
  get size():number{this.prune();return this.#items.size;}
}
