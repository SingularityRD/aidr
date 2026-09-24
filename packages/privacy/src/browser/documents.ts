import { assertWellFormed } from '../normalize.js';
import type { TextResult, JsonResult, EntityType } from '../types.js';
export type DocumentKind='text'|'json'|'csv'|'tsv';
export interface DocumentScanner {
  protect(text:string):TextResult|Promise<TextResult>;
  protectJson(text:string):JsonResult|Promise<JsonResult>;
}
export interface DocumentResult {
  readonly decision:TextResult['decision'];readonly output:string|null;
  readonly filename:'aidr-sanitized.txt'|'aidr-sanitized.json'|'aidr-sanitized.csv'|'aidr-sanitized.tsv'|null;
  readonly contentType:string|null;readonly reasons:readonly string[];
  readonly counts:Readonly<Partial<Record<EntityType,number>>>;
}
/** Strict RFC4180-style parser: rectangular table, bounded cells, no ambiguous malformed quotes. */
export function parseDelimited(text:string,delimiter:','|'\t',maxCells=10000):string[][] {
  if(delimiter!==','&&delimiter!=='\t')throw new Error('DOCUMENT_INVALID');
  if(text.length>1048576)throw new Error('DOCUMENT_LIMIT');assertWellFormed(text);
  const rows:string[][]=[];let row:string[]=[],cell='',quoted=false,closed=false,count=0;
  const push=()=>{if(++count>maxCells||cell.length>65536)throw new Error('DOCUMENT_LIMIT');row.push(cell);cell='';closed=false;};
  const endRow=()=>{push();rows.push(row);row=[];if(rows.length>2000)throw new Error('DOCUMENT_LIMIT');};
  for(let i=0;i<text.length;i++){
    const c=text[i]!;
    if(quoted){if(c==='"'){if(text[i+1]==='"'){cell+='"';i++;}else{quoted=false;closed=true;}}else cell+=c;continue;}
    if(c===delimiter){push();continue;}
    if(c==='\r'||c==='\n'){if(c==='\r'&&text[i+1]==='\n')i++;endRow();continue;}
    if(closed)throw new Error('DOCUMENT_INVALID');
    if(c==='"'){if(cell.length)throw new Error('DOCUMENT_INVALID');quoted=true;}else cell+=c;
    if(cell.length>65536)throw new Error('DOCUMENT_LIMIT');
  }
  if(quoted)throw new Error('DOCUMENT_INVALID');
  if(cell.length||row.length||closed||!rows.length)endRow();
  const width=rows[0]?.length??0;if(!width||width>128||rows.some(r=>r.length!==width))throw new Error('DOCUMENT_INVALID');
  return rows;
}
export function serializeDelimited(rows:readonly (readonly string[])[],delimiter:','|'\t'):string {
  const quote=(v:string)=>'"'+v.replace(/"/g,'""')+'"';return rows.map(row=>row.map(quote).join(delimiter)).join('\r\n')+'\r\n';
}
/** Structured sanitization preserves column boundaries and uses header semantics via protectJson.
 * Formula-leading CSV/TSV cells are blocked, not sent through to spreadsheet execution. */
export async function protectDocument(input:string,kind:DocumentKind,scanner:DocumentScanner,maxBytes=1048576):Promise<DocumentResult> {
  const counts:Partial<Record<EntityType,number>>=Object.create(null) as Partial<Record<EntityType,number>>;
  const denied=(code:string):DocumentResult=>({decision:'block',output:null,filename:null,contentType:null,reasons:[code],counts});
  const add=(r:TextResult|JsonResult)=>{for(const [k,n]of Object.entries(r.audit.counts))counts[k as EntityType]=(counts[k as EntityType]??0)+(n??0);};
  try{
    if(!['text','json','csv','tsv'].includes(kind)||typeof input!=='string')return denied('DOCUMENT_INVALID');
    if(input.length>maxBytes||new TextEncoder().encode(input).length>maxBytes)return denied('DOCUMENT_LIMIT');
    assertWellFormed(input);if(input.includes('\0'))return denied('DOCUMENT_BINARY');
    if(input.charCodeAt(0)===0xfeff)input=input.slice(1);
    let output:string,decision:TextResult['decision']='allow';
    if(kind==='text'||kind==='json'){
      const r=kind==='json'?await scanner.protectJson(input):await scanner.protect(input);add(r);
      if(r.output===null)return {decision:r.decision,output:null,filename:null,contentType:null,reasons:r.reasons,counts};
      output=r.output;decision=r.decision;
    }else{
      const delimiter=kind==='csv'?',':'\t',rows=parseDelimited(input,delimiter),headers=rows[0]!;
      if(new Set(headers.map(h=>h.trim().toLocaleLowerCase('tr'))).size!==headers.length||headers.some(h=>!h.trim()))return denied('DOCUMENT_HEADER_INVALID');
      for(const row of rows)for(const cell of row)if(/^[\s\u200b-\u200f\ufeff]*[=+\-@]/u.test(cell))return denied('DOCUMENT_FORMULA');
      // Scan headers too; do not let PII in column names survive or create prototype-pollution keys.
      for(const h of headers){const r=await scanner.protect(h);if(r.decision!=='allow'||['__proto__','constructor','prototype'].includes(h))return denied('DOCUMENT_HEADER_INVALID');}
      const result:string[][]=[headers];let cells=0;
      for(const row of rows.slice(1)){
        const record:Record<string,string>=Object.create(null) as Record<string,string>;for(let c=0;c<headers.length;c++)record[headers[c]!]=row[c]!;
        const r=await scanner.protectJson(JSON.stringify(record));add(r);
        if(r.output===null)return {decision:r.decision,output:null,filename:null,contentType:null,reasons:r.reasons,counts};
        if(r.decision==='redact')decision='redact';
        const parsed=JSON.parse(r.output) as Record<string,unknown>;const safe=headers.map(h=>{const v=parsed[h];if(typeof v!=='string')throw new Error();return v;});
        cells+=safe.length;if(cells>10000)throw new Error();result.push(safe);
      }
      output=serializeDelimited(result,delimiter);
    }
    if(new TextEncoder().encode(output).length>2*maxBytes)return denied('DOCUMENT_OUTPUT_LIMIT');
    const metadata={text:['aidr-sanitized.txt','text/plain;charset=utf-8'],json:['aidr-sanitized.json','application/json'],csv:['aidr-sanitized.csv','text/csv;charset=utf-8'],tsv:['aidr-sanitized.tsv','text/tab-separated-values;charset=utf-8']} as const;
    return {decision,output,filename:metadata[kind][0],contentType:metadata[kind][1],reasons:[],counts};
  }catch{return denied('DOCUMENT_INVALID');}
}
