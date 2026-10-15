// GENERATED from packages/privacy/src/validators.ts by scripts/sync-privacy-rules.mjs — do not edit
// Regenerate: pnpm sync:privacy-rules (verify: pnpm verify:privacy-rules)
/** These checks verify syntax/check digits, never account existence or ownership. */
export function validTckn(value: string): boolean {
  const s=value.replace(/[ \t-]/g,'');
  if(!/^[1-9][0-9]{10}$/.test(s) || /^(.)\1+$/.test(s)) return false;
  const d=[...s].map(Number);
  const odd=d[0]!+d[2]!+d[4]!+d[6]!+d[8]!, even=d[1]!+d[3]!+d[5]!+d[7]!;
  return ((odd*7-even)%10+10)%10===d[9] && d.slice(0,10).reduce((a,b)=>a+b,0)%10===d[10];
}
export function validLuhn(value: string): boolean {
  const s=value.replace(/[ \t-]/g,'');
  if(!/^[0-9]{13,19}$/.test(s)||/^(.)\1+$/.test(s)) return false;
  let sum=0, twice=false;
  for(let i=s.length-1;i>=0;i--) { let d=Number(s[i]); if(twice){d*=2;if(d>9)d-=9;} sum+=d;twice=!twice; }
  return sum%10===0;
}
/** Explicit supported-country subset; unknown countries are NOT declared validated. */
export const IBAN_LENGTHS: Readonly<Record<string,number>>=Object.freeze({
  TR:26,GB:22,DE:22,FR:27,NL:18,ES:24,IT:27,BE:16,CH:21,AT:20,IE:22,
  PT:25,PL:28,SE:24,NO:15,DK:18,FI:18,GR:27,CZ:24,HU:28,RO:24,BG:22,
  HR:21,CY:28,EE:20,LT:20,LU:20,LV:21,MT:31,SI:19,SK:24,IS:26,LI:21,
  AE:23,SA:24,QA:29,KW:30,BH:22,JO:30,AZ:28,GE:22,RS:22,XK:20,UA:29,
});
export function validIban(value:string):boolean {
  const s=value.replace(/[ \t-]/g,'').toUpperCase();
  if(!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(s)||IBAN_LENGTHS[s.slice(0,2)]!==s.length) return false;
  if(s.startsWith('TR') && !/^TR[0-9]{24}$/.test(s)) return false;
  if(s.startsWith('DE') && !/^DE[0-9]{20}$/.test(s)) return false;
  let remainder=0;
  for(const c of s.slice(4)+s.slice(0,4)) {
    const n=c>='A'&&c<='Z'?String(c.charCodeAt(0)-55):c;
    for(const d of n) remainder=(remainder*10+Number(d))%97;
  }
  return remainder===1;
}
export function validSsn(value:string):boolean {
  if(!/^(?:[0-9]{9}|[0-9]{3}([ -])[0-9]{2}\1[0-9]{4})$/.test(value)) return false;
  const s=value.replace(/[ -]/g,'');
  const area=Number(s.slice(0,3));
  return area>0 && area!==666 && area<900 && Number(s.slice(3,5))>0 && Number(s.slice(5))>0;
}
/** Turkish tax number (VKN, 10 digits) check digit. */
export function validVkn(value:string):boolean {
  if(!/^[0-9]{10}$/.test(value)||/^(.)\1+$/.test(value)) return false;
  let sum=0;
  for(let i=0;i<9;i++) {
    const t=(Number(value[i])+9-i)%10;
    sum+=t===9?9:(t*2**(9-i))%9;
  }
  return (10-sum%10)%10===Number(value[9]);
}
