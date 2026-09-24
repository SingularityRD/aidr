import { constants } from 'node:fs';
import { open, link, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
/** CLI-only I/O. Parent directories must be private/trusted. Never follows input symlinks. */
export async function readBoundedFile(path:string,maxBytes:number):Promise<Buffer> {
  if(!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>8*1024*1024)throw new Error('FILE_LIMIT');
  const handle=await open(path,constants.O_RDONLY|(constants.O_NOFOLLOW??0)|(constants.O_NONBLOCK??0));
  const buffer=Buffer.alloc(maxBytes+1);let length=0;
  try {
    const stat=await handle.stat();if(!stat.isFile()||stat.size>maxBytes)throw new Error('FILE_INPUT');
    while(length<buffer.length){const {bytesRead}=await handle.read(buffer,length,buffer.length-length,null);if(!bytesRead)break;length+=bytesRead;}
    if(!length||length>maxBytes)throw new Error('FILE_INPUT');
    return Buffer.from(buffer.subarray(0,length));
  }finally{buffer.fill(0);await handle.close();}
}
/** Publishes a complete sanitized artifact without overwriting an existing path.
 * Hard-link publication is atomic on a local filesystem. Unsupported filesystems fail closed. */
export async function publishExclusive(path:string,data:Uint8Array):Promise<void> {
  const temp=join(dirname(path),`.aidr-${randomBytes(16).toString('hex')}.tmp`);
  const handle=await open(temp,'wx',0o600);let closed=false;
  try {await handle.writeFile(data);await handle.sync();await handle.close();closed=true;await link(temp,path);}
  finally{if(!closed)await handle.close();await unlink(temp).catch(()=>{});}
}
