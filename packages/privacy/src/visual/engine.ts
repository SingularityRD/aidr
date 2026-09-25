import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { ENTITY_TYPES, type EntityType, type TextResult } from '../types.js';
import { imageFail, imageCode, integer, VisualError } from './errors.js';
import { documents, spanBoxes, padded, enclosing, rowGroups, contains, validateScan, validatePages, checkBox } from './geometry.js';
import { verifiedPng } from './png.js';
import type { VisualOptions, VisualResult, VisualAudit, VisualRegion, VisualInspection, OcrPage, Box } from './types.js';

type Stats = { inputBytes:number; width:number; height:number; wordCount:number; barcodeCount:number; textCoverage:VisualAudit['textCoverage'] };
const VISUAL_VERSION='0.2.0-rc.1';
/** Screenshot PII redaction. OCR is fallible; default manual release is deliberate.
 * The only releaseable artifact is output, a rebuilt opaque PNG after independent pixel checks.
 * No faces/handwriting/steganography guarantees and no hidden automatic bypass.
 */
export class VisualPrivacyEngine {
  #o: Required<VisualOptions>;
  #active=0;
  #disposed=false;
  #controllers=new Set<AbortController>();
  constructor(options: VisualOptions) {
    if(!options||typeof options.backend?.inspect!=='function'||typeof options.backend?.render!=='function'||typeof options.textEngine?.protect!=='function')imageFail('IMAGE_CONFIGURATION_INVALID');
    const o:Required<VisualOptions>={backend:options.backend,textEngine:options.textEngine,
      release:options.release??'manual',mode:options.mode??'pii',granularity:options.granularity??'line',
      barcodeAction:options.barcodeAction??'block',uncertainText:options.uncertainText??'review',
      minConfidence:options.minConfidence??50,minWordHeight:options.minWordHeight??7,paddingPx:options.paddingPx??6,
      maxInputBytes:options.maxInputBytes??8*1024*1024,maxPixels:options.maxPixels??12_000_000,maxDimension:options.maxDimension??8192,
      maxWords:options.maxWords??10000,maxTextBytes:options.maxTextBytes??65536,maxRegions:options.maxRegions??4096,
      timeoutMs:options.timeoutMs??45000,maxConcurrent:options.maxConcurrent??2,policyId:options.policyId??'aidr-visual-v1',requireNer:options.requireNer??false};
    if(!['manual','automatic'].includes(o.release)||!['pii','all-text','block'].includes(o.mode)||!['line','word'].includes(o.granularity)||!['block','redact'].includes(o.barcodeAction)||!['review','redact-line'].includes(o.uncertainText)||typeof o.requireNer!=='boolean'||!/^[A-Za-z0-9_.-]{1,64}$/.test(o.policyId))imageFail('IMAGE_CONFIGURATION_INVALID');
    for(const [n,min,max]of [[o.minConfidence,0,100],[o.minWordHeight,1,256],[o.paddingPx,1,128],[o.maxInputBytes,1,8*1024*1024],[o.maxPixels,1,12_000_000],[o.maxDimension,1,8192],[o.maxWords,1,10000],[o.maxTextBytes,1,262144],[o.maxRegions,1,4096],[o.timeoutMs,1,120000],[o.maxConcurrent,1,16]] as const)integer(n,min,max,'IMAGE_CONFIGURATION_INVALID');
    this.#o=Object.freeze(o);
  }
  dispose():void {this.#disposed=true;for(const c of this.#controllers)c.abort();}
  #result(start:number,inputBytes:number,stats:Stats,decision:VisualResult['decision'],output:Buffer|null,regions:readonly VisualRegion[],reasons:readonly string[]):VisualResult {
    return Object.freeze({decision,output,contentType:output?'image/png':null,filename:output?'aidr-sanitized.png':null,
      outputSha256:output?createHash('sha256').update(output).digest('hex'):null,
      regions:Object.freeze(regions.map(r=>Object.freeze({...r,types:Object.freeze([...r.types])}))),
      reasons:Object.freeze([...reasons]),audit:Object.freeze({version:VISUAL_VERSION,policyId:this.#o.policyId,
        ...stats,inputBytes,regionCount:regions.length,elapsedMs:Math.round((performance.now()-start)*1000)/1000,
        verification:output?'pixel-and-residual-scan':'not-released'})});
  }
  #check(signal:AbortSignal):void {if(signal.aborted)imageFail('IMAGE_ABORTED');if(this.#disposed)imageFail('IMAGE_DISPOSED');}
  async #text(text:string,stats:Stats,signal:AbortSignal,residual=false):Promise<TextResult> {
    this.#check(signal);
    const result=await this.#o.textEngine.protect(text);
    this.#check(signal);
    if(!result||!['allow','redact','review','block'].includes(result.decision)||!Array.isArray(result.findings)||!result.audit||!['rules-only','rules-and-ner'].includes(result.audit.coverage))imageFail('IMAGE_PROTOCOL_INVALID');
    stats.textCoverage=result.audit.coverage;
    if(this.#o.requireNer&&result.audit.coverage!=='rules-and-ner')imageFail('IMAGE_NER_REQUIRED');
    if(residual&&(result.decision!=='allow'||result.findings.length))imageFail('IMAGE_RESIDUAL_PII');
    if(result.decision==='block')imageFail('IMAGE_TEXT_BLOCK');
    if(result.decision==='review')imageFail('IMAGE_TEXT_REVIEW');
    if(typeof result.output!=='string'||(result.decision==='allow'&&result.findings.length)||(result.decision==='redact'&&!result.findings.length))imageFail('IMAGE_PROTOCOL_INVALID');
    for(const finding of result.findings) {
      if(!finding||!ENTITY_TYPES.includes(finding.type))imageFail('IMAGE_PROTOCOL_INVALID');
      integer(finding.start,0,Math.max(0,text.length-1),'IMAGE_GEOMETRY_INVALID');integer(finding.end,finding.start+1,text.length,'IMAGE_GEOMETRY_INVALID');
    }
    return result;
  }
  async #collect(pages:readonly OcrPage[],stats:Stats,signal:AbortSignal,add:(box:Box,type:VisualRegion['types'][number])=>void):Promise<void> {
    for(const page of pages) {
      for(const doc of documents(page)) {
        const result=await this.#text(doc.text,stats,signal);
        for(const finding of result.findings)for(const box of spanBoxes(doc,finding.start,finding.end,this.#o.granularity))add(box,finding.type);
      }
      if(this.#o.mode==='all-text')for(const row of rowGroups(page.words))add(enclosing(row),'ALL_TEXT');
    }
  }
  async #run(data:Buffer,signal:AbortSignal,stats:Stats):Promise<{decision:VisualResult['decision'];output:Buffer|null;regions:VisualRegion[];reasons:string[]}> {
    const o=this.#o;this.#check(signal);
    const hash=createHash('sha256').update(data).digest('hex');
    const scan=await o.backend.inspect(data,signal);this.#check(signal);
    stats.wordCount=validateScan(scan,hash,o);stats.width=scan.width;stats.height=scan.height;stats.barcodeCount=scan.barcodes.length;
    if(scan.barcodes.length&&o.barcodeAction==='block')imageFail('IMAGE_BARCODE_BLOCKED');
    if(!stats.wordCount)imageFail('IMAGE_NO_TEXT');
    const map=new Map<string,{box:Box;types:Set<VisualRegion['types'][number]>}>();
    const add=(box:Box,type:VisualRegion['types'][number])=>{
      const b=padded(box,scan.width,scan.height,o.paddingPx),key=`${b.x}:${b.y}:${b.width}:${b.height}`;
      let region=map.get(key);if(!region){if(map.size>=o.maxRegions)imageFail('IMAGE_REGION_LIMIT');region={box:b,types:new Set()};map.set(key,region);}region.types.add(type);
    };
    await this.#collect(scan.pages,stats,signal,add);
    for(const box of scan.barcodes)add(box,'BARCODE');
    let uncertain=false;
    for(const page of scan.pages)for(const row of rowGroups(page.words)) {
      for(const word of row)if(word.confidence<o.minConfidence||word.height<o.minWordHeight) {
        if([...map.values()].some(r=>contains(r.box,word)))continue;
        if(o.uncertainText==='review')uncertain=true;else add(enclosing(row),'OCR_UNCERTAIN');
      }
    }
    const regions=[...map.values()].map(r=>({...r.box,types:[...r.types].sort()}));
    if(uncertain)return {decision:'review',output:null,regions,reasons:['IMAGE_OCR_UNCERTAIN']};
    if(o.release==='manual')return {decision:'review',output:null,regions,reasons:['IMAGE_MANUAL_REVIEW']};
    this.#check(signal);
    const rendered=await o.backend.render(data,scan,regions,signal);this.#check(signal);
    if(!rendered||rendered.protocol!==1||rendered.complete!==true||rendered.width!==scan.width||rendered.height!==scan.height||!(rendered.png instanceof Uint8Array)||!Array.isArray(rendered.barcodes)||rendered.barcodes.length>256)imageFail('IMAGE_PROTOCOL_INVALID');
    validatePages(rendered.pages,scan.width,scan.height,o);
    for(const box of rendered.barcodes)checkBox(box,scan.width,scan.height);
    if(rendered.barcodes.length)imageFail('IMAGE_RESIDUAL_BARCODE');
    for(const page of rendered.pages)for(const doc of documents(page))await this.#text(doc.text,stats,signal,true);
    const png=verifiedPng(rendered.png,scan.width,scan.height,regions);
    this.#check(signal);
    return {decision:regions.length?'redact':'allow',output:png,regions,reasons:[]};
  }
  /** Admission, input snapshot, abort, dispose and timeout handling shared by `protect` and `inspect`. */
  async #bounded<T>(input:Uint8Array,signal:AbortSignal|undefined,stats:Stats,work:(data:Buffer,signal:AbortSignal)=>Promise<T>):Promise<T> {
    if(this.#disposed)imageFail('IMAGE_DISPOSED');
    if(signal?.aborted)imageFail('IMAGE_ABORTED');
    if(this.#o.mode==='block')imageFail('IMAGE_POLICY_BLOCK');
    if(!(input instanceof Uint8Array)||input.buffer instanceof SharedArrayBuffer||input.byteLength===0)imageFail('IMAGE_INPUT_INVALID');
    stats.inputBytes=input.byteLength;if(input.byteLength>this.#o.maxInputBytes)imageFail('IMAGE_INPUT_LIMIT');
    if(this.#active>=this.#o.maxConcurrent)imageFail('IMAGE_CONCURRENCY_LIMIT');
    // Snapshot BEFORE first await: callers cannot swap pixels after the scan.
    const data=Buffer.from(input),controller=new AbortController();this.#active++;this.#controllers.add(controller);
    let timer:ReturnType<typeof setTimeout>|undefined;
    let rejectStop:((error:VisualError)=>void)|undefined;
    const stop=new Promise<never>((_,reject)=>{rejectStop=reject;});
    const innerAbort=()=>rejectStop!(new VisualError(this.#disposed?'IMAGE_DISPOSED':'IMAGE_ABORTED'));
    controller.signal.addEventListener('abort',innerAbort,{once:true});
    const abort=()=>{rejectStop!(new VisualError('IMAGE_ABORTED'));controller.abort();};
    signal?.addEventListener('abort',abort,{once:true});
    const task=work(data,controller.signal);
    // Keep capacity reserved until an ignoring/hung backend actually settles.
    void task.finally(()=>{data.fill(0);this.#active--;this.#controllers.delete(controller);}).catch(()=>{});
    timer=setTimeout(()=>{rejectStop!(new VisualError('IMAGE_TIMEOUT'));controller.abort();},this.#o.timeoutMs);
    try {
      const value=await Promise.race([task,stop]);
      if(signal?.aborted||this.#disposed){(value as {output?:Buffer|null}).output?.fill(0);imageFail(signal?.aborted?'IMAGE_ABORTED':'IMAGE_DISPOSED');}
      return value;
    }finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);controller.signal.removeEventListener('abort',innerAbort);}
  }
  async protect(input:Uint8Array,signal?:AbortSignal):Promise<VisualResult> {
    const start=performance.now();
    const stats:Stats={inputBytes:0,width:0,height:0,wordCount:0,barcodeCount:0,textCoverage:'unknown'};
    try{
      const value=await this.#bounded(input,signal,stats,(data,inner)=>this.#run(data,inner,stats));
      return this.#result(start,stats.inputBytes,stats,value.decision,value.output,value.regions,value.reasons);
    }catch(error){
      const code=imageCode(error),review=['IMAGE_TEXT_REVIEW','IMAGE_OCR_UNCERTAIN'].includes(code);
      return this.#result(start,stats.inputBytes,stats,review?'review':'block',null,[],[code]);
    }
  }
  /** OCR plus the text engine, decision only: `inspect` never renders or releases image bytes. */
  async #inspect(data:Buffer,signal:AbortSignal,stats:Stats,counts:Partial<Record<EntityType,number>>):Promise<{decision:VisualInspection['decision'];reasons:string[]}> {
    const o=this.#o;
    const hash=createHash('sha256').update(data).digest('hex');
    const scan=await o.backend.inspect(data,signal);this.#check(signal);
    stats.wordCount=validateScan(scan,hash,o);stats.width=scan.width;stats.height=scan.height;stats.barcodeCount=scan.barcodes.length;
    const covered:Box[]=[];let review:string|undefined,blocked=false;
    for(const page of scan.pages)for(const doc of documents(page)) {
      this.#check(signal);
      const result=await o.textEngine.protect(doc.text);this.#check(signal);
      if(!result||!['allow','redact','review','block'].includes(result.decision)||!Array.isArray(result.findings)||!result.audit||!['rules-only','rules-and-ner'].includes(result.audit.coverage))imageFail('IMAGE_PROTOCOL_INVALID');
      stats.textCoverage=result.audit.coverage;
      if(o.requireNer&&result.audit.coverage!=='rules-and-ner')imageFail('IMAGE_NER_REQUIRED');
      for(const finding of result.findings) {
        if(!finding||!ENTITY_TYPES.includes(finding.type))imageFail('IMAGE_PROTOCOL_INVALID');
        integer(finding.start,0,Math.max(0,doc.text.length-1),'IMAGE_GEOMETRY_INVALID');integer(finding.end,finding.start+1,doc.text.length,'IMAGE_GEOMETRY_INVALID');
        const type=finding.type as EntityType;counts[type]=(counts[type]??0)+1;
        covered.push(...spanBoxes(doc,finding.start,finding.end,'word'));
      }
      if(result.decision==='block')blocked=true;
      else if(result.decision==='review')review??='IMAGE_TEXT_REVIEW';
    }
    if(Object.keys(counts).length||blocked)return {decision:'block',reasons:[blocked?'IMAGE_TEXT_BLOCK':'IMAGE_SENSITIVE_TEXT']};
    if(o.mode==='all-text'&&stats.wordCount)return {decision:'block',reasons:['IMAGE_TEXT_PRESENT']};
    if(review)return {decision:'review',reasons:[review]};
    // Barcode payloads never cross the process boundary, so their content is not inspected.
    if(scan.barcodes.length)return {decision:'review',reasons:['IMAGE_BARCODE_NOT_INSPECTED']};
    if(!stats.wordCount)return {decision:'review',reasons:['IMAGE_NO_TEXT']};
    for(const page of scan.pages)for(const word of page.words)
      if((word.confidence<o.minConfidence||word.height<o.minWordHeight)&&!covered.some(box=>contains(box,word)))return {decision:'review',reasons:['IMAGE_OCR_UNCERTAIN']};
    return {decision:'allow',reasons:[]};
  }
  /**
   * Whether an image shows sensitive text, without producing a redacted copy (the caller blocks or
   * keeps the original; masking pixels is not attempted). `allow`: OCR text was fully inspected and
   * nothing sensitive was found. `block`: sensitive text (per-type `counts`), or a policy that blocks
   * images / all text. `review`: the image could not be fully inspected (no text found, uncertain OCR,
   * undecoded barcodes, limits, timeouts, backend failures) and must never be treated as clean.
   */
  async inspect(input:Uint8Array,signal?:AbortSignal):Promise<VisualInspection> {
    const start=performance.now(),counts:Partial<Record<EntityType,number>>={};
    const stats:Stats={inputBytes:0,width:0,height:0,wordCount:0,barcodeCount:0,textCoverage:'unknown'};
    let decision:VisualInspection['decision'],reasons:string[];
    try{({decision,reasons}=await this.#bounded(input,signal,stats,(data,inner)=>this.#inspect(data,inner,stats,counts)));}
    catch(error){const code=imageCode(error);decision=code==='IMAGE_POLICY_BLOCK'?'block':'review';reasons=[code];for(const key of Object.keys(counts))delete counts[key as EntityType];}
    const {inputBytes,...rest}=stats;
    return Object.freeze({decision,counts:Object.freeze({...counts}),reasons:Object.freeze([...reasons]),
      audit:Object.freeze({version:VISUAL_VERSION,policyId:this.#o.policyId,inputBytes,...rest,regionCount:0,
        elapsedMs:Math.round((performance.now()-start)*1000)/1000,verification:'not-released' as const})});
  }
}
