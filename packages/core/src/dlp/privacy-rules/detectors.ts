// GENERATED from packages/privacy/src/detectors.ts by scripts/sync-privacy-rules.mjs — do not edit
// Regenerate: pnpm sync:privacy-rules (verify: pnpm verify:privacy-rules)
import { isIP } from './ip.js';
import { validTckn, validIban, validLuhn, validSsn, IBAN_LENGTHS } from './validators.js';
import { fail } from './errors.js';
import type { EntityType, Evidence } from './types.js';
export type Emit=(start:number,end:number,type:EntityType,score:number,evidence:Evidence)=>void;
function run(text:string, re:RegExp, type:EntityType, emit:Emit, score=.85, evidence:Evidence='pattern', group=0):void {
  for(const m of text.matchAll(re)) {
    const v=m[group]; if(!v)continue;
    const offset=group===0?0:m[0].lastIndexOf(v);
    emit(m.index+offset,m.index+offset+v.length,type,score,evidence);
  }
}
/** Field labels (TR/EN) of the labelled-field detector, as regex sources (İ/ı folded to i when compiled). */
const FIELD_LABELS:readonly (readonly [string,EntityType])[]=[
  ['(?:full[ \\t]+name|first[ \\t]+name|last[ \\t]+name|name|ad[ıi]?[ \\t]+soyad[ıi]?|isim|adı)','PERSON'],
  ['(?:e-?posta|e-?mail(?:[ \\t]+address)?)','EMAIL'],
  ['(?:phone|telephone|mobile|telefon|tel|gsm|cep[ \\t]+telefonu)(?:[ \\t]*(?:number|no))?','PHONE'],
  ['(?:T\\.?C\\.?(?:[ \\t]*(?:kimlik)(?:[ \\t]*(?:no(?:su)?|numarası))?)?|TCKN|Turkish[ \\t]+ID)','TC_KIMLIK'],
  ['IBAN','IBAN'],
  ['(?:credit[ \\t]*card(?:[ \\t]*(?:number|no))?|card[ \\t]*(?:number|no)|kredi[ \\t]*kartı(?:[ \\t]*(?:numarası|no))?|kart[ \\t]*no)','CREDIT_CARD'],
  ['(?:SSN|social[ \\t]+security(?:[ \\t]+number)?)','US_SSN'],
  ['(?:date[ \\t]*of[ \\t]*birth|birth[ \\t]*date|dob|doğum[ \\t]*tarihi)','DATE_OF_BIRTH'],
  ['(?:passport|pasaport)(?:[ \\t]*(?:number|numarası|no))?','PASSPORT'],
  ['(?:tax[ \\t]*(?:id|number)|vergi[ \\t]*(?:no(?:su)?|numarası)|vkn)','TAX_ID'],
  ['(?:bank[ \\t]*account(?:[ \\t]*(?:number|no))?|account[ \\t]*(?:number|no)|hesap[ \\t]*(?:no(?:su)?|numarası))','BANK_ACCOUNT'],
  ['(?:national[ \\t]*id|identity[ \\t]*number|kimlik[ \\t]*(?:no(?:su)?|numarası))','NATIONAL_ID'],
  ['(?:(?:home|postal)[ \\t]+address|address|adres|ikametg[aâ]h)','ADDRESS'],
];
/** Labels of the `key=value` credential detector, used only to find where a SECRET value's label starts. */
const SECRET_LABEL='(?:api[_ -]?key|client[_ -]?secret|access[_ -]?token|refresh[_ -]?token|password|passwd|pwd|secret|şifre|sifre|bearer|basic)';
/** JS /i is not Turkish-locale-aware; labels are matched against a length-preserving view with İ/ı folded to i. */
const foldLabel=(text:string):string=>text.replace(/[İı]/g,'i');
/** Protect complete explicitly labeled fields, including malformed identifiers/check digits.
 * Stop at another recognized field or a structural delimiter, not at a regex length cap.
 */
function detectFields(text:string,emit:Emit):void {
  const labelText=foldLabel(text);
  const fields:{at:number;start:number;type:EntityType}[]=[];
  for(const [label,type]of FIELD_LABELS) {
    const re=new RegExp('(?<![\\p{L}\\p{N}])'+foldLabel(label)+'[ \\t]*[:=#][ \\t]*','giu');
    for(const m of labelText.matchAll(re))fields.push({at:m.index,start:m.index+m[0].length,type});
  }
  fields.sort((a,b)=>a.at-b.at||a.start-b.start);
  for(let i=0;i<fields.length;i++) {
    const f=fields[i]!;let start=f.start,end=start;const quote=text[start];
    if(quote==='"'||quote==="'") {
      start++;end=start;let escaped=false;
      for(;end<text.length;end++) {const c=text[end]!;if(!escaped&&c===quote)break;if(!escaped&&c==='\\')escaped=true;else escaped=false;}
      if(end===text.length)fail('INCOMPLETE_FIELD');
    } else {
      let j=i+1;while(j<fields.length&&fields[j]!.at<start)j++;
      const next=fields[j]?.at??text.length;
      end=start;while(end<next&&!/[\r\n;|]/.test(text[end]!))end++;
      while(end>start&&/[ \t.,!?]/.test(text[end-1]!))end--;
    }
    if(end>start)emit(start,end,f.type,.9,'context');
  }
}
type Span={start:number;end:number;type:EntityType;score:number;evidence:Evidence};
/** Context spans that may run past their value: labelled fields, contextual names/addresses, labelled ids. */
const NARROWABLE:ReadonlySet<EntityType>=new Set(FIELD_LABELS.map(([,type])=>type));
/** Punctuation/whitespace between a field value and the next value or its label. */
const SEPARATOR=/[\s,;:=#.!?\/|(<\[\-–—"']/u;
/** Longest separator run still read as "right after" a contextual name (`Ayşe Yılmaz, (`). */
const MAX_NAME_GAP=4;
let labelPatterns:ReadonlyMap<EntityType,RegExp>|undefined;
/** Per type: a label of that type ending the string (`, TCKN`, `e-posta`, `T.C. Kimlik No`, `"password"`). */
function labelPattern(type:EntityType):RegExp|undefined {
  if(!labelPatterns) {
    const sources=new Map<EntityType,string[]>([['SECRET',[SECRET_LABEL]]]);
    for(const [label,t]of FIELD_LABELS)sources.set(t,[...(sources.get(t)??[]),foldLabel(label)]);
    labelPatterns=new Map([...sources].map(([t,alts])=>[t,new RegExp('(?<![\\p{L}\\p{N}])(?:'+alts.join('|')+')["\']?$','iu')]));
  }
  return labelPatterns.get(type);
}
function trimSeparators(text:string,from:number,end:number):number {
  while(end>from&&SEPARATOR.test(text[end-1]!))end--;
  return end;
}
/** Start of a `type` label that ends (after separators) at `end`, no earlier than `from`; -1 when there is none. */
function labelStart(labelText:string,from:number,end:number,type:EntityType):number {
  const re=labelPattern(type); if(!re)return -1;
  const at=trimSeparators(labelText,from,end), window=Math.max(from,at-48);
  const m=re.exec(labelText.slice(window,at)); if(!m)return -1;
  const start=window+m.index;
  // A window that starts inside a word must not turn that word's tail into a label.
  return start===window&&start>0&&/[\p{L}\p{N}]/u.test(labelText[start-1]!)?-1:start;
}
function firstStartingAfter(values:readonly Span[],pos:number):number {
  let lo=0,hi=values.length;
  while(lo<hi){const mid=(lo+hi)>>1;if(values[mid]!.start<=pos)lo=mid+1;else hi=mid;}
  return lo;
}
/**
 * A context span (labelled field, contextual name, `Adres:` line) runs to its delimiter, so it can swallow
 * the next value on the line: `Ad Soyad: Ayşe Yılmaz, TCKN 10000000146` read as one PERSON field that
 * `mergeFindings` then relabels by priority as a TC_KIMLIK. The value ends before the next validated value
 * of another type (checksum/pattern evidence, or a label-anchored SECRET) and that value's own label:
 * - PERSON: at any such value inside the name or right after it (a name holds no identifier);
 * - other fields and ADDRESS: only at a value introduced by its own label (`Tel 0532…`, `IBAN TR…`), because
 *   identifiers and addresses may contain digit runs that happen to validate as another type.
 * Nothing that was covered is exposed: the rest of the old span, from the value on, becomes a context span
 * of the value's type (the field that label opens, as `IBAN: …` would), and is narrowed in turn. It also
 * keeps the value covered when a caller filters the checksum/pattern finding itself out.
 * SECRET spans are never split or narrowed.
 */
function narrowFields(text:string,spans:readonly Span[],enabled:(type:EntityType)=>boolean):Span[] {
  const values=spans.filter(s=>(s.evidence==='checksum'||s.evidence==='pattern'||(s.type==='SECRET'&&s.evidence==='context'))&&enabled(s.type));
  if(!values.length||!spans.some(s=>s.evidence==='context'&&NARROWABLE.has(s.type)))return [...spans];
  values.sort((a,b)=>a.start-b.start);
  const labelText=foldLabel(text), out:Span[]=[], work=[...spans];
  for(let s=work.pop();s;s=work.pop()) {
    if(s.evidence!=='context'||!NARROWABLE.has(s.type)){out.push(s);continue;}
    const person=s.type==='PERSON', limit=person?s.end+MAX_NAME_GAP:s.end-1;
    let end=s.end,tail:Span|undefined;
    for(let i=firstStartingAfter(values,s.start);i<values.length&&values[i]!.start<=limit;i++) {
      const v=values[i]!;
      if(v.type===s.type||(v.start>=s.end&&trimSeparators(text,s.end,v.start)>s.end))continue;
      const before=Math.min(v.start,s.end), label=labelStart(labelText,s.start,before,v.type);
      if(label<0&&!person)continue;
      end=trimSeparators(text,s.start,label<0?before:label);
      if(v.start<s.end)tail={start:v.start,end:s.end,type:v.type,score:s.score,evidence:'context'};
      break;
    }
    if(end>s.start)out.push(end===s.end?s:{...s,end});
    if(tail)work.push(tail);
  }
  return out;
}
/** Every TR/EN rule over `text`. Spans are buffered so labelled fields can be narrowed; a detector that
 * aborts (PrivacyError) still hands over everything found before it. `enabled` names the types the caller
 * reports: a value of a type it drops does not end a field, so the field keeps covering it.
 */
export function detectRules(text:string,emit:Emit,enabled:(type:EntityType)=>boolean=()=>true):void {
  const spans:Span[]=[];
  try{collectRules(text,(start,end,type,score,evidence)=>{spans.push({start,end,type,score,evidence});});}
  finally{for(const s of narrowFields(text,spans,enabled))emit(s.start,s.end,s.type,s.score,s.evidence);}
}
function collectRules(text:string,emit:Emit):void {
  detectFields(text,emit);
  // Unicode local parts and IDNs. This is a privacy recognizer, not an RFC mailbox validator.
  run(text,/(?<![\p{L}\p{N}_.%+'-])[\p{L}\p{N}\p{M}_.%+'-]{1,64}@[\p{L}\p{N}](?:[\p{L}\p{N}.-]{0,251}[\p{L}\p{N}])?\.[\p{L}]{2,24}(?![\p{L}\p{N}-])/gu,'EMAIL',emit,.99);
  // Explicit [at]/[dot] forms are handled by the offset-preserving decoding pass.
  for(const m of text.matchAll(/(?<![\p{L}\p{N}])[1-9](?:[ -]?[0-9]){10}(?![0-9])/gu)) {
    if(validTckn(m[0]))emit(m.index,m.index+m[0].length,'TC_KIMLIK',.99,'checksum');
  }
  // Read exactly the registered country length, never greedily eat the following word.
  for(const m of text.matchAll(/(?<![\p{L}\p{N}])[A-Za-z]{2}[ -]?[0-9]{2}/gu)) {
    const expected=IBAN_LENGTHS[m[0].slice(0,2).toUpperCase()]; if(!expected)continue;
    let i=m.index, count=0, spaces=0;
    for(;i<text.length&&count<expected;i++) {
      const c=text[i]!;
      if(/[A-Za-z0-9]/.test(c)){count++;spaces=0;}
      else if(/[ \t-]/.test(c)&&spaces++<3)continue;
      else break;
    }
    if(count===expected && !/[A-Za-z0-9]/.test(text[i]??'') && validIban(text.slice(m.index,i))) emit(m.index,i,'IBAN',.99,'checksum');
  }
  for(const m of text.matchAll(/(?<![\p{L}\p{N}])(?:[0-9][ -]?){12,18}[0-9](?![0-9])/gu)) {
    if(validLuhn(m[0]))emit(m.index,m.index+m[0].length,'CREDIT_CARD',.97,'checksum');
  }
  for(const m of text.matchAll(/(?<![0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}(?![0-9])/g)) {
    if(validSsn(m[0]))emit(m.index,m.index+m[0].length,'US_SSN',.97,'pattern');
  }
  // TR mobile and landline, including parentheses and international variants.
  run(text,/(?<![\p{L}\p{N}])(?:\+90[ .-]?|0090[ .-]?|0)[(]?[2-5][0-9]{2}[)]?[ .-]?[0-9]{3}[ .-]?[0-9]{2}[ .-]?[0-9]{2}(?:[ \t]{0,3}(?:ext\.?|x|dahili)[ \t]{0,3}[0-9]{1,6})?(?![0-9])/giu,'PHONE',emit,.97);
  // International format is plausibility-based, not a full national-numbering-plan validator.
  run(text,/(?<![\p{L}\p{N}])\+[1-9][0-9]{0,2}[ .-]?(?:\([0-9]{1,4}\)[ .-]?)?[0-9](?:[ .-]?[0-9]){5,11}(?:[ \t]{0,3}(?:ext\.?|x)[ \t]{0,3}[0-9]{1,6})?(?![0-9])/giu,'PHONE',emit,.9);
  run(text,/(?<![0-9])\([2-9][0-9]{2}\)[ .-]?[2-9][0-9]{2}[ .-]?[0-9]{4}(?:[ \t]{0,3}(?:ext\.?|x)[ \t]{0,3}[0-9]{1,6})?(?![0-9])/giu,'PHONE',emit,.9);
  run(text,/(?<![0-9])[2-9][0-9]{2}[-.][2-9][0-9]{2}[-.][0-9]{4}(?![0-9])/g,'PHONE',emit,.88);
  // A failed checksum is NOT a safe-data exemption when context says the value is sensitive.
  run(text,/(?:\bT\.?C\.?\s*(?:kimlik\s*(?:no(?:su)?|numarası)?|no(?:su)?)?|\bTCKN|\bTurkish\s+ID)\s*[:=#]\s*([0-9][0-9 -]{4,30}[0-9])/giu,'TC_KIMLIK',emit,.9,'context',1);
  run(text,/(?:\bSSN|social security(?: number)?)\s*[:=#]\s*([0-9][0-9 -]{4,20}[0-9])/giu,'US_SSN',emit,.9,'context',1);
  run(text,/(?:\bIBAN)\s*[:=#]\s*([A-Za-z]{2}[0-9][A-Za-z0-9 -]{10,38})/giu,'IBAN',emit,.85,'context',1);
  run(text,/(?:credit\s*card(?:\s*(?:number|no))?|card\s*(?:number|no)|kredi\s*kartı(?:\s*(?:numarası|no))?|kart\s*no)\s*[:=#]\s*([0-9][0-9 -]{10,26}[0-9])/giu,'CREDIT_CARD',emit,.88,'context',1);
  run(text,/(?:phone|telephone|mobile|telefon|tel|gsm|cep(?:\s*telefonu)?)[ \t]*(?:number|no)?[ \t]*[:=][ \t]*(\+?[0-9(][0-9 ().-]{4,27}[0-9](?:[ \t]{0,3}(?:ext\.?|x|dahili)[ \t]{0,3}[0-9]{1,6})?)/giu,'PHONE',emit,.87,'context',1);
  run(text,/(?:date\s*of\s*birth|birth\s*date|dob|doğum\s*tarihi)[ \t]*[:=][ \t]*([0-9][\p{L}0-9 /.,-]{3,29})/giu,'DATE_OF_BIRTH',emit,.9,'context',1);
  const ids:[RegExp,EntityType][]=[
    [/(?:passport(?:\s*(?:number|no))?|pasaport(?:\s*(?:numarası|no))?)[ \t]*[:=#][ \t]*([A-Z0-9][A-Z0-9 -]{3,24})/giu,'PASSPORT'],
    [/(?:tax\s*(?:id|number)|vergi\s*(?:no(?:su)?|numarası)|vkn)[ \t]*[:=#][ \t]*([A-Z0-9][A-Z0-9 -]{3,24})/giu,'TAX_ID'],
    [/(?:bank\s*account(?:\s*(?:number|no))?|account\s*(?:number|no)|hesap\s*(?:no(?:su)?|numarası))[ \t]*[:=#][ \t]*([A-Z0-9][A-Z0-9 -]{3,34})/giu,'BANK_ACCOUNT'],
    [/(?:national\s*id|identity\s*number|kimlik\s*(?:no(?:su)?|numarası))[ \t]*[:=#][ \t]*([A-Z0-9][A-Z0-9 -]{3,24})/giu,'NATIONAL_ID'],
  ];
  for(const [re,type]of ids)run(text,re,type,emit,.85,'context',1);
  // Explicitly contextual name heuristics. Never advertise these as general NER.
  const name='([\\p{L}][\\p{L}\\p{M}’\'’-]{0,39}(?:[ \\t]+[\\p{Lu}][\\p{L}\\p{M}’\'’-]{0,39}){0,4})';
  run(text,new RegExp('(?:ad[ıi]?\\s*soyad[ıi]?|full\\s*name|first\\s*name|last\\s*name|name|isim|adı)[ \\t]*[:=][ \\t]*'+name,'gu'),'PERSON',emit,.8,'context',1);
  run(text,new RegExp('(?:Ad Soyad|Adı Soyadı|Name|Full Name)[ \\t]*[:=][ \\t]*'+name,'gu'),'PERSON',emit,.8,'context',1);
  run(text,new RegExp('(?:[Mm]y name is|[Aa]dım|[Mm]erhaba,? ben|[Mm]erhaba,? benim adım)[ \\t]+'+name,'gu'),'PERSON',emit,.8,'context',1);
  run(text,new RegExp('(?:[Dd]r\\.|[Mm]r\\.|[Mm]rs\\.|[Mm]s\\.|[Ss]ayın)[ \\t]+'+name,'gu'),'PERSON',emit,.78,'context',1);
  // Address labels consume the remainder of their field/line; contextual and intentionally conservative.
  run(text,/(?:\baddress|\bpostal address|\bhome address|\badres|\bikametg[aâ]h)[ \t]*[:=][ \t]*([^\r\n;"<>]{4,240})/giu,'ADDRESS',emit,.87,'context',1);
  run(text,/(?<![\p{L}\p{N}])[0-9]{1,6}[ \t]+(?:[\p{L}0-9.'-]{1,30}[ \t]+){1,5}(?:Street|St\.?|Road|Rd\.?|Avenue|Ave\.?|Lane|Ln\.?|Drive|Dr\.?|Boulevard|Blvd\.?)(?:[ ,]+[^\r\n;"<>]{1,100})?/gu,'ADDRESS',emit,.8,'context');
  run(text,/(?<![\p{L}\p{N}])(?:[\p{L}0-9.'-]{1,30}[ \t]+){1,4}(?:Mahallesi|Mah\.|Caddesi|Cad\.|Sokak|Sok\.|Sk\.)(?:[^\r\n;"<>]{0,150})/gu,'ADDRESS',emit,.8,'context');
  // Local infrastructure identifiers may be confidential even when not directly personal.
  for(const m of text.matchAll(/(?<![\w:])[0-9a-fA-F:.]{3,64}(?![\w:])/g)) {
    const v=m[0].replace(/[.,]+$/g,''); if(isIP(v))emit(m.index,m.index+v.length,'IP_ADDRESS',.95,'pattern');
  }
  run(text,/(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}(?![0-9a-fA-F])/g,'MAC_ADDRESS',emit,.95);
  // Consume complete credential tokens, not only a prefix or last-four mask.
  run(text,/(?<![A-Za-z0-9_])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9_])/g,'SECRET',emit,.99);
  run(text,/(?<![A-Za-z0-9_])(?:gh[pousr]_|github_pat_|glpat-|sk-(?:proj-|ant-api[0-9]{2}-)?)[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])/g,'SECRET',emit,.98);
  run(text,/\b(?:Bearer|Basic)[ \t]+([A-Za-z0-9_+/.=~-]{8,})/gi,'SECRET',emit,.98,'context',1);
  // Same boundary class on both sides: starting after `-` too let `eyJ-eyJ-…` rescan the rest of
  // the run from every `eyJ`, which is quadratic in the input length.
  run(text,/(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?![A-Za-z0-9_-])/g,'SECRET',emit,.97);
  for(const m of text.replace(/[İı]/g,'i').matchAll(/(?:api[_ -]?key|client[_ -]?secret|access[_ -]?token|refresh[_ -]?token|password|passwd|pwd|secret|şifre|sifre)["']?[ \t]*[:=][ \t]*/giu)) {
    let start=m.index+m[0].length, end=start;
    const quote=text[start];
    if(quote==='"'||quote==="'") {
      start++;end=start;let escaped=false;
      for(;end<text.length;end++) {
        const c=text[end]!;
        if(!escaped&&c===quote)break;
        if(!escaped&&c==='\\')escaped=true;else escaped=false;
      }
      if(end===text.length)fail('INCOMPLETE_SECRET');
    } else {
      while(end<text.length&&!/[\s,;"'<>]/u.test(text[end]!))end++;
    }
    if(end>start)emit(start,end,'SECRET',.98,'context');
  }
  run(text,/[A-Za-z][A-Za-z0-9+.-]{1,20}:\/\/([^\s/?#]+@)/g,'SECRET',emit,.98,'context',1);
  for(const m of text.matchAll(/-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g)) {
    const tail=/-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g;
    tail.lastIndex=m.index+m[0].length;const end=tail.exec(text);
    if(!end)fail('INCOMPLETE_PRIVATE_KEY');emit(m.index,end.index+end[0].length,'PRIVATE_KEY',1,'pattern');
  }
  run(text,/(?:^|\n)[ \t]*(?:TOP SECRET|NATO SECRET|NATO CONFIDENTIAL|SECRET|CONFIDENTIAL|ÇOK GİZLİ|GİZLİ|HİZMETE ÖZEL)(?=$|[ \t\r\n:/-])/gu,'CLASSIFIED',emit,1);
}
export function hasOpaqueEncoding(text:string):boolean {
  // Deliberately conservative. We do NOT claim arbitrary binary/base64 is safe after a regex scan.
  return /(?:data:[^\s,;]{0,80};base64,|\bbase64\s*[:=]|\bhex\s*[:=])/i.test(text)
    || /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{48,}={0,2}(?![A-Za-z0-9+/=_-])/u.test(text);
}
const SENSITIVE_KEYS:Readonly<Record<string,EntityType>>=Object.freeze({
  name:'PERSON',fullname:'PERSON',firstname:'PERSON',lastname:'PERSON',adsoyad:'PERSON',adisoyadi:'PERSON',ad:'PERSON',soyad:'PERSON',isim:'PERSON',
  email:'EMAIL',emailaddress:'EMAIL',eposta:'EMAIL',phone:'PHONE',telephone:'PHONE',telefon:'PHONE',gsm:'PHONE',mobile:'PHONE',
  tckn:'TC_KIMLIK',tckimlik:'TC_KIMLIK',tckimlikno:'TC_KIMLIK',tc:'TC_KIMLIK',iban:'IBAN',
  creditcard:'CREDIT_CARD',creditcardnumber:'CREDIT_CARD',cardnumber:'CREDIT_CARD',kartno:'CREDIT_CARD',
  address:'ADDRESS',homeaddress:'ADDRESS',postaladdress:'ADDRESS',adres:'ADDRESS',streetaddress:'ADDRESS',
  ssn:'US_SSN',socialsecuritynumber:'US_SSN',dob:'DATE_OF_BIRTH',dateofbirth:'DATE_OF_BIRTH',dogumtarihi:'DATE_OF_BIRTH',
  passport:'PASSPORT',passportnumber:'PASSPORT',pasaport:'PASSPORT',nationalid:'NATIONAL_ID',
  taxid:'TAX_ID',vkn:'TAX_ID',vergino:'TAX_ID',accountnumber:'BANK_ACCOUNT',hesapno:'BANK_ACCOUNT',
  password:'SECRET',passwd:'SECRET',pwd:'SECRET',secret:'SECRET',clientsecret:'SECRET',apikey:'SECRET',
  accesstoken:'SECRET',refreshtoken:'SECRET',authorization:'SECRET',cookie:'SECRET',setcookie:'SECRET',sifre:'SECRET',
  privatekey:'PRIVATE_KEY',sourcecode:'INTERNAL',internalcode:'INTERNAL',username:'USERNAME',
  healthid:'HEALTH_ID',licenseplate:'LICENSE_PLATE',plaka:'LICENSE_PLATE',
});
export function keyType(key:string):EntityType|undefined {
  const k=key.normalize('NFKD').replace(/\p{M}/gu,'').replace(/[ıİ]/g,'i').toLowerCase().replace(/[^a-z0-9]/g,'');
  return SENSITIVE_KEYS[k];
}
