import {createHash} from 'node:crypto';
import {deflateSync} from 'node:zlib';
import {crc32} from '../../dist/visual/png.js';
import {PrivacyEngine} from '../../dist/index.js';
export const input=Buffer.from('synthetic-unit-fixture-not-an-image');
export function chunk(type,data){const h=Buffer.alloc(8),t=Buffer.alloc(4);h.writeUInt32BE(data.length);h.write(type,4);t.writeUInt32BE(crc32(Buffer.concat([h.subarray(4),data])));return Buffer.concat([h,data,t]);}
export function png(width=640,height=300,fill=0,filter=0){
 const ih=Buffer.alloc(13);ih.writeUInt32BE(width,0);ih.writeUInt32BE(height,4);ih[8]=8;ih[9]=2;
 const stride=width*3,raw=Buffer.alloc((stride+1)*height);
 for(let y=0;y<height;y++){raw[y*(stride+1)]=filter;for(let x=0;x<stride;x++){
  const a=x>=3?fill:0,b=y?fill:0,c=y&&x>=3?fill:0;
  const p=a+b-c,pa=Math.abs(p-a),pb=Math.abs(p-b),pc=Math.abs(p-c);
  const v=filter===0?0:filter===1?a:filter===2?b:filter===3?Math.floor((a+b)/2):pa<=pb&&pa<=pc?a:pb<=pc?b:c;
  raw[y*(stride+1)+x+1]=(fill-v)&255;
 }}
 return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),chunk('IHDR',ih),chunk('IDAT',deflateSync(raw)),chunk('IEND',Buffer.alloc(0))]);
}
export function words(lines=['Email: jane@example.com'],{confidence=95,sparse=false}={}){
 let lineId=0;return lines.flatMap((line,row)=>{let x=10;const result=line.split(' ').filter(Boolean).map(text=>{const word={text,confidence,line:sparse?lineId++:row,x,y:10+row*32,width:Math.max(7,text.length*7),height:18};x+=word.width+7;return word;});return result;});
}
export function scan(data=input,lines,options){return {protocol:1,complete:true,inputSha256:createHash('sha256').update(data).digest('hex'),pixelSha256:'a'.repeat(64),width:640,height:300,format:'PNG',languages:['eng','tur'],pages:[{words:words(lines,options)}],barcodes:[]};}
export function backend({lines,wordOptions,mutateScan,mutateRender,delay=0,fill=0}={}){
 const calls={inspect:0,render:0};
 return {calls,
  async inspect(data,signal){calls.inspect++;if(delay)await new Promise(r=>setTimeout(r,delay));const s=scan(data,lines,wordOptions);return mutateScan?mutateScan(s,data,signal):s;},
  async render(data,s,regions,signal){calls.render++;const r={protocol:1,complete:true,width:s.width,height:s.height,png:png(s.width,s.height,fill),pages:[{words:[]}],barcodes:[]};return mutateRender?mutateRender(r,data,s,regions,signal):r;}
 };
}
export function textEngine(options={}){return new PrivacyEngine({maxScanMs:10000,...options});}
