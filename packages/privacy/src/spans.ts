import type { EntityType, Finding } from './types.js';
const PRIORITY:Partial<Record<EntityType,number>>={CLASSIFIED:100,PRIVATE_KEY:95,SECRET:90,INTERNAL:85,
  IBAN:80,CREDIT_CARD:75,TC_KIMLIK:70,US_SSN:65,ADDRESS:60,EMAIL:55,PERSON:50};
/** Union overlapping intervals rather than discarding a lower-priority interval's exposed tail. */
export function mergeFindings(findings:readonly Finding[]):Finding[] {
  const sorted=[...findings].sort((a,b)=>a.start-b.start||b.end-a.end); const out:Finding[]=[];
  for(const f of sorted) {
    const last=out.at(-1);
    if(!last||f.start>=last.end) {out.push({...f});continue;}
    const winner=(PRIORITY[f.type]??10)>(PRIORITY[last.type]??10)?f:last;
    out[out.length-1]={...winner,start:last.start,end:Math.max(last.end,f.end),score:Math.max(last.score,f.score)};
  }
  return out;
}
