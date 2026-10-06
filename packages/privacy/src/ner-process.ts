import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { isAbsolute } from 'node:path';
import { fail, requireInt } from './errors.js';
import { ENTITY_TYPES, type NerCapabilities, type NerProvider, type NerResponse, type EntityType, type Language } from './types.js';
export interface LocalNerOptions {
  /** Absolute path to an approved Python/Node executable. Never a shell command. */
  command:string;
  args:readonly string[];
  cwd?:string;
  startupTimeoutMs?:number;
  maxResponseBytes?:number;
}
/** One persistent local process, one in-flight request, bounded IPC, no listening socket. */
export class LocalNerProcess implements NerProvider {
  #child:ChildProcessWithoutNullStreams;
  #buffer=Buffer.alloc(0);
  #max:number;
  #next=0;
  #closed=false;
  #caps:NerCapabilities|undefined;
  #pending:{id:number;resolve:(r:NerResponse)=>void;reject:()=>void;cleanup:()=>void}|undefined;
  #ready:Promise<void>;
  #readyResolve!:()=>void;
  #readyReject!:()=>void;
  get capabilities():NerCapabilities{if(!this.#caps)fail('NER_NOT_READY');return this.#caps;}
  private constructor(options:LocalNerOptions) {
    if(!isAbsolute(options.command)||!Array.isArray(options.args)||options.args.some(a=>typeof a!=='string'))fail('INVALID_NER_CONFIGURATION');
    this.#max=requireInt(options.maxResponseBytes??1048576,1024,4194304);
    this.#ready=new Promise((resolve,reject)=>{this.#readyResolve=resolve;this.#readyReject=()=>reject(new Error('NER_STARTUP_FAILURE'));});
    // No inherited API keys, telemetry configuration or Hugging Face tokens.
    const env:Record<string,string>={HF_HUB_OFFLINE:'1',TRANSFORMERS_OFFLINE:'1',HF_HUB_DISABLE_TELEMETRY:'1',
      DO_NOT_TRACK:'1',PYTHONUNBUFFERED:'1',TOKENIZERS_PARALLELISM:'false'};
    for(const k of ['PATH','SYSTEMROOT','WINDIR','HOME','TMPDIR','TEMP','TMP'])if(process.env[k])env[k]=process.env[k]!;
    this.#child=spawn(options.command,[...options.args],{...(options.cwd?{cwd:options.cwd}:{}),env,shell:false,windowsHide:true,stdio:['pipe','pipe','pipe']});
    this.#child.stderr.on('data',()=>{}); // Drain, never log third-party messages that could contain input.
    this.#child.stdout.on('data',(chunk:Buffer)=>this.#onData(chunk));
    this.#child.on('error',()=>this.close());this.#child.on('exit',()=>this.close());
    this.#child.stdin.on('error',()=>this.close());this.#child.stdout.on('error',()=>this.close());
  }
  static async open(options:LocalNerOptions,signal?:AbortSignal):Promise<LocalNerProcess> {
    signal?.throwIfAborted();
    const timeout=requireInt(options.startupTimeoutMs??30000,1,300000),provider=new LocalNerProcess(options);
    const abort=()=>provider.close();signal?.addEventListener('abort',abort,{once:true});
    const timer=setTimeout(()=>provider.close(),timeout);
    try{await provider.#ready;signal?.throwIfAborted();return provider;}finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);}
  }
  #onData(chunk:Buffer):void {
    if(this.#closed)return;
    if(this.#buffer.length+chunk.length>this.#max){this.close();return;}
    this.#buffer=Buffer.concat([this.#buffer,chunk]);
    let at:number;
    while((at=this.#buffer.indexOf(10))>=0) {
      const line=this.#buffer.subarray(0,at);this.#buffer=this.#buffer.subarray(at+1);
      try {
        const data=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(line)) as Record<string,unknown>;
        if(!this.#caps) {
          if(data.ready!==true||!data.capabilities||typeof data.capabilities!=='object')throw new Error();
          const c=data.capabilities as NerCapabilities;
          if(c.local!==true||c.offsetUnit!=='utf16'||!Array.isArray(c.languages)||!Array.isArray(c.entities)
            ||!c.languages.length||!c.entities.length||c.languages.some(l=>!['tr','en'].includes(l))
            ||c.entities.some(t=>!ENTITY_TYPES.includes(t))||typeof c.revision!=='string'||!/^[a-f0-9]{64}$/.test(c.revision))throw new Error();
          const byLanguage:Partial<Record<Language,readonly EntityType[]>>={};
          if(c.entitiesByLanguage)for(const [lang,types]of Object.entries(c.entitiesByLanguage)) {
            if(!['tr','en'].includes(lang)||!Array.isArray(types)||types.some(t=>!ENTITY_TYPES.includes(t)))throw new Error();
            byLanguage[lang as Language]=Object.freeze([...types]);
          }
          this.#caps=Object.freeze({local:true,offsetUnit:'utf16',languages:Object.freeze([...c.languages]),
            entities:Object.freeze([...c.entities]),revision:c.revision,entitiesByLanguage:Object.freeze(byLanguage)});
          this.#readyResolve();
        } else {
          const p=this.#pending;if(!p||data.id!==p.id)throw new Error();
          if(data.complete!==true||!Array.isArray(data.entities))throw new Error();
          this.#pending=undefined;p.cleanup();p.resolve({complete:true,entities:data.entities as NerResponse['entities']});
        }
      }catch{this.close();return;}
    }
  }
  async detect(text:string,signal:AbortSignal):Promise<NerResponse> {
    if(this.#closed||!this.#caps||this.#pending||signal.aborted)fail('NER_UNAVAILABLE');
    if(Buffer.byteLength(text)>1048576)fail('INPUT_LIMIT');
    return new Promise((resolve,reject)=>{
      const id=++this.#next;
      const onAbort=()=>this.close();
      this.#pending={id,resolve,reject:()=>reject(new Error('NER_FAILURE')),cleanup:()=>signal.removeEventListener('abort',onAbort)};
      signal.addEventListener('abort',onAbort,{once:true});
      this.#child.stdin.write(JSON.stringify({id,text})+'\n',error=>{if(error)this.close();});
    });
  }
  close():void {
    if(this.#closed)return;this.#closed=true;this.#readyReject();
    if(this.#pending){const p=this.#pending;this.#pending=undefined;p.cleanup();p.reject();}
    this.#buffer.fill(0);this.#buffer=Buffer.alloc(0);
    this.#child.stdin.destroy();this.#child.stdout.destroy();this.#child.stderr.destroy();
    this.#child.kill('SIGKILL');
  }
}
