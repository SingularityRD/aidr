import { fail } from './errors.js';
export interface TextView { text: string; starts: number[]; ends: number[]; }
const segmenter = new Intl.Segmenter('und', { granularity: 'grapheme' });
const digits = [0x0660,0x06f0,0x07c0,0x0966,0x09e6,0x0a66,0x0ae6,0x0b66,0x0be6,
  0x0c66,0x0ce6,0x0d66,0x0de6,0x0e50,0x0ed0,0x0f20,0x1040,0x1090,0x17e0,
  0x1810,0x1946,0x19d0,0x1a80,0x1a90,0x1b50,0x1bb0,0x1c40,0x1c50,0xa620,
  0xa8d0,0xa900,0xa9d0,0xa9f0,0xaa50,0xabf0,0xff10,0x104a0,0x11066,
  0x110f0,0x11136,0x111d0,0x112f0,0x11450,0x114d0,0x11650,0x116c0,
  0x11730,0x118e0,0x11950,0x11c50,0x11d50,0x11da0,0x16a60,0x16ac0,
  0x16b50,0x1d7ce,0x1d7d8,0x1d7e2,0x1d7ec,0x1d7f6,0x1e140,0x1e2f0,0x1e950];
function fold(c: string): string {
  const n = c.codePointAt(0)!;
  for (const d of digits) if (n >= d && n <= d + 9) return String(n - d);
  if (/[\p{Cf}\u034f\ufe00-\ufe0f\u{e0100}-\u{e01ef}]/u.test(c)) return '';
  if (/[\u2010-\u2015\u2212]/u.test(c)) return '-';
  if (/[\u2018\u2019]/u.test(c)) return "'";
  return c;
}
export function identity(text: string): TextView {
  const starts=new Array<number>(text.length), ends=new Array<number>(text.length);
  for(let i=0;i<text.length;i++){starts[i]=i;ends[i]=i+1;}
  return {text,starts,ends};
}
function append(out: TextView, s: string, start: number, end: number): void {
  if(out.text.length+s.length>1048576) fail('NORMALIZATION_LIMIT');
  out.text += s;
  for (let j=0;j<s.length;j++) { out.starts.push(start); out.ends.push(end); }
}
export function normalizeView(input: TextView): TextView {
  // These characters are NFKC-stable and need no folding. Keep prior decoding offsets.
  // Non-ASCII obfuscation, combining marks, emoji and all other scripts still use grapheme mapping.
  if(/^[\x00-\x7fÇĞİÖŞÜçğıöşü]*$/u.test(input.text))return input;
  const out: TextView = {text:'',starts:[],ends:[]};
  for (const {segment,index} of segmenter.segment(input.text)) {
    const normalized = segment.normalize('NFKC');
    let s = [...normalized].map(fold).join('');
    if(/^\p{Nd}/u.test(normalized)) s=s.replace(/\p{M}/gu,'');
    if (s) append(out,s,input.starts[index]!,input.ends[index+segment.length-1]!);
  }
  return out;
}
export function normalize(text: string): TextView { return normalizeView(identity(text)); }
/** Decode only explicit, bounded encodings, keeping spans in the original source. */
export function decodeView(input: TextView): TextView {
  const pattern = /(?:%[0-9a-fA-F]{2})+|\\u\{[0-9a-fA-F]{1,6}\}|\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|&(?:#x[0-9a-fA-F]{1,6}|#[0-9]{1,7}|commat|period|colon|sol|amp|nbsp|Tab|NewLine);|[\[(]\s{0,2}(?:at|dot)\s{0,2}[\])]/g;
  if(!pattern.test(input.text))return input;
  pattern.lastIndex=0;
  const out: TextView = {text:'',starts:[],ends:[]}; let pos=0;
  for (const match of input.text.matchAll(pattern)) {
    const at=match.index, raw=match[0];
    out.text+=input.text.slice(pos,at); for(let k=pos;k<at;k++){out.starts.push(input.starts[k]!);out.ends.push(input.ends[k]!);}
    let decoded=raw;
    try {
      if (raw[0]==='%') decoded=decodeURIComponent(raw);
      else if (raw.startsWith('\\')) {
        const hex=raw.startsWith('\\u{')?raw.slice(3,-1):raw.slice(2);
        const cp=parseInt(hex,16); if (cp>0x10ffff) fail('INVALID_ENCODING');
        decoded=String.fromCodePoint(cp);
      } else if (raw.startsWith('&#')) {
        const cp=raw[2]==='x'?parseInt(raw.slice(3,-1),16):Number(raw.slice(2,-1));
        if(cp>0x10ffff || cp===0) fail('INVALID_ENCODING'); decoded=String.fromCodePoint(cp);
      } else if (raw[0]==='&') {
        decoded=({commat:'@',period:'.',colon:':',sol:'/',amp:'&',nbsp:' ',Tab:'\t',NewLine:'\n'} as Record<string,string>)[raw.slice(1,-1)]!;
      } else decoded=raw.includes('at')?'@':'.';
    } catch { fail('INVALID_ENCODING'); }
    append(out,decoded,input.starts[at]!,input.ends[at+raw.length-1]!); pos=at+raw.length;
  }
  out.text+=input.text.slice(pos); for(let k=pos;k<input.text.length;k++){out.starts.push(input.starts[k]!);out.ends.push(input.ends[k]!);}
  return out;
}
export function detectionViews(text: string): TextView[] {
  const base=normalize(text); const views=[base]; let last=base;
  for(let i=0;i<3;i++) {
    const next=normalizeView(decodeView(last));
    if(next.text===last.text) return views;
    views.push(next); last=next;
  }
  if(normalizeView(decodeView(last)).text!==last.text) fail('ENCODING_DEPTH');
  return views;
}
export function sourceSpan(view: TextView, start: number, end: number): [number,number] {
  if(!Number.isInteger(start)||!Number.isInteger(end)||start<0||end<=start||end>view.text.length) fail('INVALID_SPAN');
  return [view.starts[start]!,view.ends[end-1]!];
}
/** Avoid slicing an emoji/supplementary code point in half. */
export function isBoundary(text:string, p:number):boolean {
  return !(p>0 && p<text.length && /[\ud800-\udbff]/.test(text[p-1]!) && /[\udc00-\udfff]/.test(text[p]!));
}
export function assertWellFormed(text:string):void {
  for(let i=0;i<text.length;i++) {
    const x=text.charCodeAt(i);
    if(x>=0xd800 && x<=0xdbff) { const y=text.charCodeAt(++i); if(!(y>=0xdc00 && y<=0xdfff)) fail('INVALID_UNICODE'); }
    else if(x>=0xdc00 && x<=0xdfff) fail('INVALID_UNICODE');
  }
  if(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(text)) fail('UNSUPPORTED_CONTROL');
}
