import { bytesDigest } from './state.js';
import { deny } from '../enterprise/util.js';
import { parseJsonStrict } from '../json.js';
export interface Classification {label:string;probability:number;probabilities:Readonly<Record<string,number>>;decision:'review'|'no-additional-signal';modelDigest:string;}
/** Small actually-trained baseline; NEVER authorizes release and is NOT a NER model. */
interface LinearModel {format:string;classes:string[];vocabulary:Record<string,number>;weights:number[][];bias:number[];trainingOrigin:string;}
export class LinearRiskClassifier {
 #m:LinearModel;readonly digest:string;
 constructor(bytes:Uint8Array,expectedSha256:string){if(bytes.length>8388608||(this.digest=bytesDigest(bytes))!==expectedSha256)deny('MODEL_PIN');const m=parseJsonStrict(new TextDecoder('utf8',{fatal:true}).decode(bytes),8,200000) as unknown as LinearModel;
  if(m.format!=='aidr-char-linear-v1'||m.classes.length!==3||new Set(m.classes).size!==3||m.classes.some(c=>!['benign','sensitive','injection'].includes(c))||m.weights.length!==3||m.bias.length!==3)deny('MODEL_SCHEMA');
  const n=Object.keys(m.vocabulary).length;if(n<1||n>12000||new Set(Object.values(m.vocabulary)).size!==n||Object.values(m.vocabulary).some(i=>!Number.isInteger(i)||i<0||i>=n)||m.weights.some(row=>row.length!==n||row.some(x=>!Number.isFinite(x)))||m.bias.some(x=>!Number.isFinite(x)))deny('MODEL_SCHEMA');this.#m=m;
 }
 classify(text:string):Classification {if(typeof text!=='string'||text.length>65536)deny('CLASSIFIER_LIMIT');const normalized=text.normalize('NFKC').toLowerCase().replace(/ı/g,'i').replace(/i\u0307/g,'i'),chars=Array.from(normalized),indices=new Set<number>();
  for(let n=3;n<=5;n++)for(let i=0;i+n<=chars.length;i++){const j=this.#m.vocabulary[chars.slice(i,i+n).join('')];if(j!==undefined)indices.add(j);}
  const logits=this.#m.bias.map((b,c)=>{for(const j of indices)b+=this.#m.weights[c]![j]!;return b;}),max=Math.max(...logits),e=logits.map(x=>Math.exp(x-max)),sum=e.reduce((a,b)=>a+b,0),p=e.map(x=>x/sum),best=p.indexOf(Math.max(...p)),probabilities=Object.fromEntries(this.#m.classes.map((c,i)=>[c,p[i]!]));
  const label=this.#m.classes[best]!;return {label,probability:p[best]!,probabilities,decision:indices.size<8||p[best]!<.75||label!=='benign'?'review':'no-additional-signal',modelDigest:this.digest};
 }
}
