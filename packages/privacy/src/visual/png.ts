import { deflateSync, inflateSync } from 'node:zlib';
import { imageFail } from './errors.js';
import { checkBox } from './geometry.js';
import type { Box } from './types.js';
const SIGNATURE = Buffer.from([137,80,78,71,13,10,26,10]);
const CRC_TABLE = Uint32Array.from({length:256}, (_,i) => { let c=i; for(let k=0;k<8;k++) c=(c&1)?0xedb88320^(c>>>1):c>>>1; return c>>>0; });
export function crc32(data: Uint8Array): number { let c=0xffffffff; for(const n of data)c=CRC_TABLE[(c^n)&255]!^(c>>>8); return (c^0xffffffff)>>>0; }
function chunk(type: string, data: Buffer): Buffer {
  const head=Buffer.alloc(8);head.writeUInt32BE(data.length);head.write(type,4,'ascii');const tail=Buffer.alloc(4);
  tail.writeUInt32BE(crc32(Buffer.concat([head.subarray(4),data])));return Buffer.concat([head,data,tail]);
}
function paeth(a:number,b:number,c:number):number {const p=a+b-c,pa=Math.abs(p-a),pb=Math.abs(p-b),pc=Math.abs(p-c);return pa<=pb&&pa<=pc?a:pb<=pc?b:c;}
/** Independent pixel verification in Node, then reconstruction strips ALL metadata and
 * compressed-stream trailers. Only RGB8 non-interlaced PNG output is accepted. */
export function verifiedPng(input: Uint8Array, width: number, height: number, masks: readonly Box[], maxBytes = 64 * 1024 * 1024): Buffer {
  try {
    const png=Buffer.from(input);
    if(png.length>maxBytes||png.length<57||!png.subarray(0,8).equals(SIGNATURE))imageFail('IMAGE_UNVERIFIED_OUTPUT');
    let at=8,stage=0;const parts:Buffer[]=[];
    while(at<png.length){
      if(at+12>png.length)imageFail('IMAGE_UNVERIFIED_OUTPUT');
      const len=png.readUInt32BE(at),end=at+12+len;if(end>png.length)imageFail('IMAGE_UNVERIFIED_OUTPUT');
      const type=png.toString('ascii',at+4,at+8),data=png.subarray(at+8,at+8+len);
      if(png.readUInt32BE(at+8+len)!==crc32(png.subarray(at+4,at+8+len)))imageFail('IMAGE_UNVERIFIED_OUTPUT');
      if(type==='IHDR'&&stage===0){
        if(len!==13||data.readUInt32BE(0)!==width||data.readUInt32BE(4)!==height||data[8]!==8||data[9]!==2||data[10]!==0||data[11]!==0||data[12]!==0)imageFail('IMAGE_UNVERIFIED_OUTPUT');
        stage=1;
      } else if(type==='IDAT'&&(stage===1||stage===2)){parts.push(data);stage=2;}
      else if(type==='IEND'&&stage===2&&len===0&&end===png.length){stage=3;}
      else imageFail('IMAGE_UNVERIFIED_OUTPUT');
      at=end;
    }
    if(stage!==3)imageFail('IMAGE_UNVERIFIED_OUTPUT');
    const stride=width*3,expected=(stride+1)*height;
    const raw=inflateSync(Buffer.concat(parts),{maxOutputLength:expected});
    if(raw.length!==expected)imageFail('IMAGE_UNVERIFIED_OUTPUT');
    const pixels=Buffer.allocUnsafe(stride*height);
    for(let y=0;y<height;y++){
      const filter=raw[y*(stride+1)]!;if(filter>4)imageFail('IMAGE_UNVERIFIED_OUTPUT');
      for(let x=0;x<stride;x++){
        const a=x>=3?pixels[y*stride+x-3]!:0,b=y?pixels[(y-1)*stride+x]!:0,c=y&&x>=3?pixels[(y-1)*stride+x-3]!:0;
        const v=filter===0?0:filter===1?a:filter===2?b:filter===3?Math.floor((a+b)/2):paeth(a,b,c);
        pixels[y*stride+x]=(raw[y*(stride+1)+1+x]!+v)&255;
      }
    }
    for(const m of masks){checkBox(m,width,height);for(let y=m.y;y<m.y+m.height;y++)for(let x=m.x*3;x<(m.x+m.width)*3;x++)if(pixels[y*stride+x]!==0)imageFail('IMAGE_PIXEL_VERIFICATION_FAILED');}
    // Own encoder: one fresh IHDR, IDAT and IEND. No EXIF, XMP, comments, alpha or text layer.
    const clean=Buffer.allocUnsafe(expected);
    for(let y=0;y<height;y++){clean[y*(stride+1)]=0;pixels.copy(clean,y*(stride+1)+1,y*stride,(y+1)*stride);}
    const ihdr=Buffer.alloc(13);ihdr.writeUInt32BE(width,0);ihdr.writeUInt32BE(height,4);ihdr[8]=8;ihdr[9]=2;
    const out=Buffer.concat([SIGNATURE,chunk('IHDR',ihdr),chunk('IDAT',deflateSync(clean,{level:6})),chunk('IEND',Buffer.alloc(0))]);
    pixels.fill(0);raw.fill(0);clean.fill(0);
    if(out.length>maxBytes)imageFail('IMAGE_UNVERIFIED_OUTPUT');return out;
  }catch(error){
    if(error instanceof Error&&error.message==='IMAGE_PIXEL_VERIFICATION_FAILED')imageFail('IMAGE_PIXEL_VERIFICATION_FAILED');
    imageFail('IMAGE_UNVERIFIED_OUTPUT');
  }
}
