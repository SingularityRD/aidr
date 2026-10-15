import { createHmac } from 'node:crypto';
import { readBoundedFile } from '../visual/file-io.js';

/**
 * Exact-data-match (EDM) key derivation for Browser Guard datasets (`keySource: "native-host"`).
 *
 * The organisation's EDM secret stays in the native host's configuration (`exactData.secretFile`),
 * never in browser policy, so it is not shown by chrome://policy, the policy registry keys or
 * policies.json. Each dataset is fingerprinted with its own key:
 *
 *   key(datasetId) = HMAC-SHA256(secret, UTF-8("aidr-edm-v2" || 0x00 || datasetId))
 *
 * packages/browser-guard/scripts/fingerprint-dataset.mjs derives the same key when it builds a
 * dataset; the extension asks the host for the keys of the datasets in its policy (`edm-keys`).
 * A leaked dataset key exposes only that dataset, and the secret itself never enters the browser.
 */
export const EDM_KEY_LABEL='aidr-edm-v2';
const EDM_MIN_SECRET_BYTES=32,EDM_MAX_SECRET_BYTES=1024;
const MAX_SECRET_FILE_BYTES=4096;

export function deriveEdmKey(secret:Uint8Array,datasetId:string):Buffer {
  return createHmac('sha256',secret).update(`${EDM_KEY_LABEL}\u0000${datasetId}`,'utf8').digest();
}

/** Decodes a base64 secret (surrounding whitespace allowed); throws unless it holds at least 32 bytes. */
export function parseEdmSecret(text:string):Buffer {
  const trimmed=text.trim();
  if(!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)||trimmed.length%4!==0)throw new Error('EDM_SECRET_INVALID');
  const secret=Buffer.from(trimmed,'base64');
  if(secret.length<EDM_MIN_SECRET_BYTES||secret.length>EDM_MAX_SECRET_BYTES){secret.fill(0);throw new Error('EDM_SECRET_INVALID');}
  return secret;
}

/** Reads the secret file named by the host configuration (base64 text, at most 4 KiB). */
export async function readEdmSecret(file:string):Promise<Buffer> {
  const bytes=await readBoundedFile(file,MAX_SECRET_FILE_BYTES);
  try{return parseEdmSecret(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}finally{bytes.fill(0);}
}
