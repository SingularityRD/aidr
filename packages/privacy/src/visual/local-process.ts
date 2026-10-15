import { spawn } from 'node:child_process';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { imageFail, integer, VISUAL_CODES, VisualError } from './errors.js';
import type { Box, ImageBackend, ImageScan, RenderScan } from './types.js';
export interface LocalImageOptions {
  readonly python: string;
  /**
   * OCR engine run by the worker. `tesseract` (default): Tesseract with eng+tur traineddata.
   * `windows`: the Windows built-in OCR (Windows.Media.Ocr) through vision/windows_ocr.ps1 and
   * Windows PowerShell 5.1; no OCR model is downloaded (the OS recognizer languages are used).
   */
  readonly ocrEngine?: 'tesseract' | 'windows';
  /** Tesseract executable and tessdata directory (required for `tesseract`). */
  readonly tesseract?: string;
  readonly tessdata?: string;
  /** Windows PowerShell 5.1 executable (required for `windows`). */
  readonly powershell?: string;
  /** Absolute path to the Windows OCR helper; defaults to the bundled vision/windows_ocr.ps1. */
  readonly windowsOcrScript?: string;
  readonly manifest: string;
  /** Absolute path to bundled worker or an explicitly trusted replacement. */
  readonly worker?: string;
  readonly dualPass?: boolean;
  readonly processTimeoutMs?: number;
  readonly maxResponseBytes?: number;
}
type ResolvedOptions = Required<Pick<LocalImageOptions,'python'|'manifest'|'worker'|'dualPass'|'processTimeoutMs'|'maxResponseBytes'|'ocrEngine'>> & {readonly engineArgs:readonly string[]};
/** Process-per-stage local backend. No network API and no inherited API keys.
 * Linux process groups ensure cancellation kills OCR descendants as well as Python.
 * This is not a sandbox: deploy with OS network denial, syscall policy and cgroups. */
export class LocalImageProcess implements ImageBackend {
  #options: ResolvedOptions;
  constructor(options: LocalImageOptions) {
    const worker=options.worker??fileURLToPath(new URL('../../vision/worker.py',import.meta.url));
    // dist/visual -> package/vision needs two parent steps, not one.
    const ocrEngine=options.ocrEngine??'tesseract';
    if(ocrEngine!=='tesseract'&&ocrEngine!=='windows')imageFail('IMAGE_CONFIGURATION_INVALID');
    const script=options.windowsOcrScript??fileURLToPath(new URL('../../vision/windows_ocr.ps1',import.meta.url));
    const engineArgs=ocrEngine==='windows'
      ?['--ocr-engine','windows','--powershell',options.powershell as string,'--windows-ocr-script',script]
      :['--tesseract',options.tesseract as string,'--tessdata',options.tessdata as string];
    for(const value of [options.python,options.manifest,worker,engineArgs[engineArgs.length-1],engineArgs[engineArgs.length-3]])
      if(typeof value!=='string'||!isAbsolute(value)||value.includes('\0'))imageFail('IMAGE_CONFIGURATION_INVALID');
    if(options.dualPass!==undefined&&typeof options.dualPass!=='boolean')imageFail('IMAGE_CONFIGURATION_INVALID');
    this.#options={python:options.python,manifest:options.manifest,worker,ocrEngine,engineArgs,
      // Windows OCR runs one pass per recognizer language; the psm passes are Tesseract's.
      dualPass:ocrEngine==='windows'?false:options.dualPass??true,
      processTimeoutMs:integer(options.processTimeoutMs??30000,1,120000,'IMAGE_CONFIGURATION_INVALID'),
      maxResponseBytes:integer(options.maxResponseBytes??64*1024*1024,1024,128*1024*1024,'IMAGE_CONFIGURATION_INVALID')};
  }
  async #call(payload: Record<string,unknown>, signal: AbortSignal): Promise<Record<string,unknown>> {
    if(signal.aborted)imageFail('IMAGE_ABORTED');
    const o=this.#options;
    return new Promise((resolve,reject)=>{
      let done=false,bytes=0;const chunks:Buffer[]=[];
      const env:Record<string,string>={PYTHONUNBUFFERED:'1',PYTHONDONTWRITEBYTECODE:'1',PYTHONNOUSERSITE:'1',OMP_THREAD_LIMIT:'1',OMP_NUM_THREADS:'1',LC_ALL:'C.UTF-8'};
      for(const key of ['PATH','SYSTEMROOT','WINDIR'])if(process.env[key])env[key]=process.env[key]!;
      const child=spawn(o.python,['-I',o.worker,...o.engineArgs,'--manifest',o.manifest],
        {env,shell:false,windowsHide:true,detached:process.platform!=='win32',stdio:['pipe','pipe','pipe']});
      const kill=()=>{
        if(process.platform!=='win32'&&child.pid){try{process.kill(-child.pid,'SIGKILL');}catch{child.kill('SIGKILL');}}
        else child.kill('SIGKILL');
      };
      const finish=(code?:string,value?:Record<string,unknown>)=>{
        if(done)return;done=true;clearTimeout(timer);signal.removeEventListener('abort',abort);
        kill();child.stdin.destroy();child.stdout.destroy();child.stderr.destroy();
        if(code){for(const c of chunks)c.fill(0);reject(new VisualError(code));}else resolve(value!);
      };
      const abort=()=>finish('IMAGE_ABORTED');
      const timer=setTimeout(()=>finish('IMAGE_TIMEOUT'),o.processTimeoutMs);
      signal.addEventListener('abort',abort,{once:true});
      if(signal.aborted){abort();return;}
      child.on('error',()=>finish('IMAGE_WORKER_FAILED'));
      child.stdin.on('error',()=>finish('IMAGE_WORKER_FAILED'));
      child.stdout.on('error',()=>finish('IMAGE_WORKER_FAILED'));
      let stderrBytes=0;
      child.stderr.on('data',(chunk:Buffer)=>{stderrBytes+=chunk.length;if(stderrBytes>262144)finish('IMAGE_WORKER_OUTPUT_LIMIT');});
      child.stdout.on('data',(chunk:Buffer)=>{bytes+=chunk.length;if(bytes>o.maxResponseBytes){finish('IMAGE_WORKER_OUTPUT_LIMIT');return;}chunks.push(chunk);});
      child.on('close',code=>{
        if(done)return;
        if(code!==0){finish('IMAGE_WORKER_FAILED');return;}
        try{
          const text=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks));
          const value=JSON.parse(text) as Record<string,unknown>;
          if(!value||value.protocol!==1)throw new Error();
          if(value.complete!==true){finish(typeof value.code==='string'&&VISUAL_CODES.has(value.code)?value.code:'IMAGE_WORKER_FAILED');return;}
          finish(undefined,value);
        }catch{finish('IMAGE_PROTOCOL_INVALID');}
      });
      child.stdin.end(JSON.stringify({protocol:1,psms:o.dualPass?[11,6]:[11],...payload}));
    });
  }
  async inspect(input: Uint8Array, signal: AbortSignal): Promise<ImageScan> {
    if(input.length>8*1024*1024)imageFail('IMAGE_INPUT_LIMIT');
    return await this.#call({task:'inspect',image:Buffer.from(input).toString('base64')},signal) as unknown as ImageScan;
  }
  async render(input: Uint8Array, scan: ImageScan, regions: readonly Box[], signal: AbortSignal): Promise<RenderScan> {
    if(input.length>8*1024*1024||regions.length>4096)imageFail('IMAGE_INPUT_LIMIT');
    const response=await this.#call({task:'render',image:Buffer.from(input).toString('base64'),pixelSha256:scan.pixelSha256,regions},signal);
    if(typeof response.png!=='string'||response.png.length>86*1024*1024||!response.png.length||response.png.length%4!==0||!/^[A-Za-z0-9+/]*={0,2}$/.test(response.png))imageFail('IMAGE_PROTOCOL_INVALID');
    const png=Buffer.from(response.png,'base64');
    if(png.toString('base64')!==response.png)imageFail('IMAGE_PROTOCOL_INVALID');
    return {...response,png} as unknown as RenderScan;
  }
}
