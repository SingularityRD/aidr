/** Portable literal-only IP validator. No DNS, URL parsing, octal or shorthand IPv4. */
export function isIP(input:string):0|4|6 {
  if(typeof input!=='string'||input.length>100)return 0;
  const v4=(s:string):boolean=>s.split('.').length===4&&s.split('.').every(p=>/^(?:0|[1-9][0-9]{0,2})$/.test(p)&&Number(p)<=255);
  if(v4(input))return 4;
  let s=input;
  const percent=s.indexOf('%');
  if(percent>=0){if(!/^[0-9A-Za-z_.~-]+$/.test(s.slice(percent+1)))return 0;s=s.slice(0,percent);}
  if(!s.includes(':')||/[^0-9a-fA-F:.]/.test(s))return 0;
  if(s.includes('.')) {
    const at=s.lastIndexOf(':');if(at<0||!v4(s.slice(at+1)))return 0;
    s=s.slice(0,at)+':0:0';
  }
  const halves=s.split('::');if(halves.length>2)return 0;
  const valid=(p:string)=>p===''||p.split(':').every(x=>/^[0-9a-fA-F]{1,4}$/.test(x));
  if(!halves.every(valid))return 0;
  const count=halves.reduce((n,p)=>n+(p?p.split(':').length:0),0);
  return (halves.length===2?count<8:count===8)?6:0;
}
