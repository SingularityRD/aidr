import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import { parseJsonStrict } from '../json.js';
/** Static errors only; never interpolate caller-controlled text into errors. */
export class ControlError extends Error { constructor(readonly code:string){super(code);this.name='ControlError';} }
export function deny(code='CONTROL_INVALID'):never { throw new ControlError(code); }
export function id(x:unknown):string {if(typeof x!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$/.test(x))deny();return x;}
export function integer(x:unknown,min=0,max=Number.MAX_SAFE_INTEGER):number {if(!Number.isSafeInteger(x)||(x as number)<min||(x as number)>max)deny();return x as number;}
export function object(x:unknown,keys:readonly string[]):Record<string,unknown> {
  if(!x||typeof x!=='object'||Array.isArray(x)||Object.keys(x).some(k=>!keys.includes(k)))deny();return x as Record<string,unknown>;
}
export function oneOf<T extends string>(x:unknown,values:readonly T[]):T {if(typeof x!=='string'||!values.includes(x as T))deny();return x as T;}
export function list(x:unknown,max=256):unknown[] {if(!Array.isArray(x)||x.length>max)deny();return x;}
export function bool(x:unknown):boolean {if(typeof x!=='boolean')deny();return x;}
/** A versioned JS JSON canonicalization, NOT a claim of RFC 8785 conformance.
 * Rejects accessors, hidden properties, sparse arrays, exotic prototypes and non-finite numbers. */
export function canonical(value:unknown,maxBytes=1048576):string {
  let nodes=0,units=0;const seen=new Set<object>();
  const charge=(s:string)=>{units+=s.length;if(units>maxBytes)deny('CONTROL_LIMIT');return s;};
  const walk=(v:unknown,depth:number):string=>{
    if(++nodes>50000||depth>32)deny('CONTROL_LIMIT');
    if(v===null)return 'null';if(typeof v==='boolean')return v?'true':'false';
    if(typeof v==='string'){if(v.length>maxBytes||/[\ud800-\udfff]/u.test(v))deny('CONTROL_INVALID');return charge(JSON.stringify(v));}
    if(typeof v==='number'){if(!Number.isFinite(v)||Math.abs(v)>Number.MAX_SAFE_INTEGER)deny();return charge(JSON.stringify(v));}
    if(typeof v!=='object'||!v)deny();
    if(seen.has(v)||Object.getOwnPropertySymbols(v).length)deny();seen.add(v);
    let out:string;
    if(Array.isArray(v)){
      if(v.length>20000||Object.keys(v).length!==v.length||Object.getOwnPropertyNames(v).length!==v.length+1)deny();
      const items:string[]=[];for(let i=0;i<v.length;i++){const d=Object.getOwnPropertyDescriptor(v,String(i));if(!d||!('value'in d)||!d.enumerable)deny();items.push(walk(d.value,depth+1));}out='['+items.join(',')+']';
    }else{
      const proto=Object.getPrototypeOf(v);if(proto!==null&&proto!==Object.prototype)deny();
      const keys=Object.getOwnPropertyNames(v).sort(),items:string[]=[];
      for(const key of keys){if(['__proto__','constructor','prototype'].includes(key))deny();const d=Object.getOwnPropertyDescriptor(v,key)!;
        if(!('value'in d)||!d.enumerable)deny();items.push(charge(JSON.stringify(key))+':'+walk(d.value,depth+1));}
      out='{'+items.join(',')+'}';
    }
    seen.delete(v);if(out.length>maxBytes)deny('CONTROL_LIMIT');return out;
  };
  const result=walk(value,0);if(Buffer.byteLength(result)>maxBytes)deny('CONTROL_LIMIT');return result;
}
export function frozen<T>(value:T):T {
  const v=parseJsonStrict(canonical(value),32,50000) as T;
  const freeze=(x:unknown):void=>{if(x&&typeof x==='object'){for(const v of Object.values(x))freeze(v);Object.freeze(x);}};freeze(v);return v;
}
export function secret(x:Uint8Array):Buffer {if(!(x instanceof Uint8Array)||x.byteLength<32||x.byteLength>128)deny('KEY_REQUIRED');return Buffer.from(x);}
export function hash(v:unknown):string{return createHash('sha256').update(canonical(v)).digest('hex');}
export function mac(key:Uint8Array,domain:string,...parts:unknown[]):string{return createHmac('sha256',key).update(canonical([domain,...parts])).digest('hex');}
export function equalHex(a:unknown,b:string):boolean {return typeof a==='string'&&/^[0-9a-f]{64}$/.test(a)&&b.length===64&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));}
/** Exact HTTPS origin configuration. No suffix matching, credentials, IDNA ambiguity or IP literals.
 * This is NOT a DNS rebinding defense: transport must pin/validate resolved addresses and redirects. */
export function httpsOrigin(raw:unknown):string {
  if(typeof raw!=='string'||raw.length>2048||/[\s\\\u0000-\u001f\u007f]/u.test(raw))deny('DESTINATION_INVALID');
  let u:URL;try{u=new URL(raw);}catch{deny('DESTINATION_INVALID');}
  if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||u.pathname!=='/'||u.port||!u.hostname.includes('.')
    ||isIP(u.hostname)||u.hostname.includes(':')||u.hostname.endsWith('.')||u.hostname.split('.').some(p=>p.startsWith('xn--'))
    ||/\.(?:localhost|local|internal|invalid)$/i.test(u.hostname))deny('DESTINATION_INVALID');
  return u.origin;
}
export function urlAllowed(raw:unknown,origins:readonly string[]):boolean {
  try{
    if(typeof raw!=='string'||raw.length>4096||/[\s\\\u0000-\u001f\u007f]/u.test(raw))return false;
    const u=new URL(raw);if(u.username||u.password||u.hash)return false;
    return origins.includes(httpsOrigin(u.origin));
  }catch{return false;}
}
export function textBound(text:unknown,maxBytes=65536):string {
  if(typeof text!=='string'||text.length>maxBytes||/[\ud800-\udfff]/u.test(text)||Buffer.byteLength(text)>maxBytes)deny('CONTENT_LIMIT');return text;
}
