import { detectionViews } from '../normalize.js';
import { id, integer, secret, mac, frozen, textBound, oneOf, deny } from './util.js';
import { CLASSIFICATIONS, type Classification } from './types.js';
function tokens(text:string):string[]{
  const normalized=text.normalize('NFKC').toLowerCase().replace(/[\u200b-\u200f\u2060\ufeff]/gu,'').replace(/[ı]/gu,'i').replace(/i\u0307/gu,'i');
  const t=normalized.match(/[\p{L}\p{N}]+/gu)??[];if(t.length>8192||t.some(x=>x.length>512))deny('INDEX_CONTENT_LIMIT');return t;
}
export interface DataMatch {readonly datasetId:string;readonly reference:string;readonly kind:'exact-record'|'document-fragment';readonly classification:Classification;readonly matched:number;}
interface RecordEntry {reference:string;classification:Classification;minimumFields:number;fields:readonly string[];}
interface FragmentEntry {reference:string;classification:Classification;hashes:ReadonlySet<string>;minMatches:number;minCoverage:number;}
/** Tenant-keyed hashes only retained after enrollment. Not encryption/anonymization, private-set
 * intersection, fuzzy OCR matching, or a replacement for million-row EDM infrastructure. */
export class SensitiveDataIndex {
  readonly tenantId:string;readonly datasetId:string;readonly keyId:string;
  #key:Buffer;#records:RecordEntry[]=[];#fragments:FragmentEntry[]=[];#lengths=new Set<number>();#references=new Set<string>();#disposed=false;#fingerprints=0;
  constructor(tenantId:string,datasetId:string,keyId:string,key:Uint8Array,readonly maxFingerprints=100000){integer(maxFingerprints,1,250000);this.tenantId=id(tenantId);this.datasetId=id(datasetId);this.keyId=id(keyId);this.#key=secret(key);}
  #h(value:unknown):string{return mac(this.#key,'aidr-data-index-v1',this.tenantId,this.datasetId,this.keyId,value);}
  #ready():void{if(this.#disposed)deny('INDEX_DISPOSED');if(this.#records.length+this.#fragments.length>=10000)deny('INDEX_CAPACITY');}
  enrollRecord(recordId:string,fields:Readonly<Record<string,string>>,classification:Classification='confidential',minimumFields=2):void {
    this.#ready();id(recordId);oneOf(classification,CLASSIFICATIONS);const input=frozen(fields),entries=Object.entries(input);integer(entries.length,1,32);integer(minimumFields,1,entries.length);
    const hashes:string[]=[],lengths:number[]=[];for(const [name,value]of entries){id(name);const t=tokens(textBound(value,4096));integer(t.length,1,16);if(t.join('').length<3)deny('INDEX_FIELD_TOO_SHORT');hashes.push(this.#h(t));lengths.push(t.length);}
    if(new Set(hashes).size!==hashes.length)deny('INDEX_DUPLICATE_FIELD');
    if(this.#fingerprints+hashes.length>this.maxFingerprints)deny('INDEX_CAPACITY');const reference=this.#h(['record',recordId]);if(this.#references.has(reference))deny('INDEX_DUPLICATE_RECORD');
    this.#fingerprints+=hashes.length;this.#records.push({reference,classification,minimumFields,fields:Object.freeze(hashes)});this.#references.add(reference);for(const n of lengths)this.#lengths.add(n);
  }
  enrollDocument(documentId:string,text:string,classification:Classification='confidential',minMatches=4,minCoverage=.2):void {
    this.#ready();id(documentId);oneOf(classification,CLASSIFICATIONS);integer(minMatches,2,8192);
    if(!Number.isFinite(minCoverage)||minCoverage<=0||minCoverage>1)deny();const ts=tokens(textBound(text));
    const hashes=new Set<string>();for(let i=0;i+5<=ts.length;i++)hashes.add(this.#h(ts.slice(i,i+5)));
    if(hashes.size<minMatches)deny('INDEX_DOCUMENT_TOO_SHORT');if(this.#fingerprints+hashes.size>this.maxFingerprints)deny('INDEX_CAPACITY');const reference=this.#h(['document',documentId]);if(this.#references.has(reference))deny('INDEX_DUPLICATE_RECORD');
    this.#fingerprints+=hashes.size;this.#fragments.push({reference,classification,hashes,minMatches,minCoverage});this.#references.add(reference);this.#lengths.add(5);
  }
  scan(text:string):readonly DataMatch[] {
    if(this.#disposed)deny('INDEX_DISPOSED');textBound(text);const candidates=new Set<string>();let operations=0;
    for(const view of detectionViews(text)){const ts=tokens(view.text);for(const len of this.#lengths)for(let i=0;i+len<=ts.length;i++){if(++operations>65536)deny('INDEX_SCAN_LIMIT');candidates.add(this.#h(ts.slice(i,i+len)));}}
    const matches:DataMatch[]=[];
    for(const r of this.#records){const matched=r.fields.filter(h=>candidates.has(h)).length;if(matched>=r.minimumFields)matches.push({datasetId:this.datasetId,reference:r.reference,kind:'exact-record',classification:r.classification,matched});}
    for(const d of this.#fragments){let matched=0;for(const h of d.hashes)if(candidates.has(h))matched++;
      if(matched>=d.minMatches&&matched/d.hashes.size>=d.minCoverage)matches.push({datasetId:this.datasetId,reference:d.reference,kind:'document-fragment',classification:d.classification,matched});}
    return frozen(matches);
  }
  /** Export excludes source strings AND key; treat hashes as sensitive and protect at rest. */
  snapshot():unknown {if(this.#disposed)deny('INDEX_DISPOSED');return frozen({format:'aidr-data-index-v1',tenantId:this.tenantId,datasetId:this.datasetId,keyId:this.keyId,
    records:this.#records,fragments:this.#fragments.map(f=>({...f,hashes:[...f.hashes]}))});}
  dispose():void{this.#key.fill(0);this.#records=[];this.#fragments=[];this.#lengths.clear();this.#references.clear();this.#fingerprints=0;this.#disposed=true;}
}
