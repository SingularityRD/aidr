import { fail } from './errors.js';
import { assertWellFormed } from './normalize.js';
import type { JsonValue } from './types.js';
/** Strict bounded parser: rejects duplicate keys, prototype keys, unsafe numbers and trailing bytes. */
export function parseJsonStrict(input:string,maxDepth=32,maxNodes=4096):JsonValue {
  let p=0,nodes=0;
  function ws():void {while(/[ \t\r\n]/.test(input[p]??'\x00'))p++;}
  function string():string {
    const start=p++;let escaped=false;
    for(;p<input.length;p++) {
      const c=input[p]!;
      if(!escaped&&c==='"') {
        let value:string;try{value=JSON.parse(input.slice(start,++p)) as string;}catch{fail('INVALID_JSON');}
        assertWellFormed(value);return value;
      }
      if(!escaped&&c==='\\')escaped=true;else escaped=false;
    }
    return fail('INVALID_JSON');
  }
  function value(depth:number):JsonValue {
    if(depth>maxDepth)fail('JSON_DEPTH_LIMIT');if(++nodes>maxNodes)fail('JSON_NODE_LIMIT');ws();
    const c=input[p];
    if(c==='"')return string();
    if(c==='{') {
      p++;ws();const result:Record<string,JsonValue>=Object.create(null) as Record<string,JsonValue>;const keys=new Set<string>();
      if(input[p]==='}'){p++;return result;}
      while(p<input.length) {
        ws();if(input[p]!=='"')fail('INVALID_JSON');const key=string();
        if(keys.has(key))fail('DUPLICATE_JSON_KEY');keys.add(key);
        if(['__proto__','prototype','constructor'].includes(key))fail('UNSAFE_JSON_KEY');
        ws();if(input[p++]!==':')fail('INVALID_JSON');result[key]=value(depth+1);ws();
        if(input[p]==='}'){p++;return result;}if(input[p++]!==',')fail('INVALID_JSON');
      }
      return fail('INVALID_JSON');
    }
    if(c==='[') {
      p++;ws();const out:JsonValue[]=[];if(input[p]===']'){p++;return out;}
      while(p<input.length) {out.push(value(depth+1));ws();if(input[p]===']'){p++;return out;}if(input[p++]!==',')fail('INVALID_JSON');}
      return fail('INVALID_JSON');
    }
    for(const [literal,v]of [['true',true],['false',false],['null',null]] as const)if(input.startsWith(literal,p)){p+=literal.length;return v;}
    const m=/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(input.slice(p));
    if(m){p+=m[0].length;const num=Number(m[0]);if(!Number.isFinite(num)||(Number.isInteger(num)&&!Number.isSafeInteger(num)))fail('UNSAFE_JSON_NUMBER');return num;}
    return fail('INVALID_JSON');
  }
  const result=value(0);ws();if(p!==input.length)fail('INVALID_JSON');return result;
}
