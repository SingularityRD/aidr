import { KeyObject, sign, verify } from 'node:crypto';
import { canonical, frozen, object, list, oneOf, bool, id, integer, httpsOrigin, hash, deny } from './util.js';
import { ACCOUNTS, CLASSIFICATIONS, type EnterprisePolicy, type TrustedContext } from './types.js';
const POLICY_KEYS=['schemaVersion','tenantId','policyId','revision','notBefore','expiresAt','destinations','unknownDestination','piiAction','injectionAction','blockActiveContent','maxInputBytes'];
export function validatePolicy(input:unknown):EnterprisePolicy {
  const p=object(frozen(input),POLICY_KEYS);if(p.schemaVersion!==1)deny('POLICY_INVALID');
  id(p.tenantId);id(p.policyId);integer(p.revision,1);integer(p.notBefore);integer(p.expiresAt);
  if((p.expiresAt as number)<=(p.notBefore as number)||(p.expiresAt as number)-(p.notBefore as number)>366*86400000)deny('POLICY_INVALID');
  integer(p.maxInputBytes,256,1048576);oneOf(p.unknownDestination,['block','review']);oneOf(p.piiAction,['redact','block']);
  oneOf(p.injectionAction,['review','block']);bool(p.blockActiveContent);
  const destinations=list(p.destinations,128),ids=new Set<string>(),origins=new Set<string>();
  for(const item of destinations){const d=object(item,['id','origin','accounts','requireVerifiedAccount','requireManagedDevice','requireProvenance','maxClassification','groups']);
    const name=id(d.id),origin=httpsOrigin(d.origin);if(ids.has(name)||origins.has(origin)||d.origin!==origin)deny('POLICY_INVALID');ids.add(name);origins.add(origin);
    const a=list(d.accounts,3);if(!a.length||new Set(a).size!==a.length)deny('POLICY_INVALID');for(const x of a)oneOf(x,ACCOUNTS);
    bool(d.requireVerifiedAccount);bool(d.requireManagedDevice);bool(d.requireProvenance);oneOf(d.maxClassification,CLASSIFICATIONS);
    const groups=list(d.groups,128);for(const g of groups)id(g);if(new Set(groups).size!==groups.length)deny('POLICY_INVALID');
  }
  return p as unknown as EnterprisePolicy;
}
export interface SignedPolicy {readonly format:'aidr-policy-v1';readonly keyId:string;readonly payload:EnterprisePolicy;readonly signature:string;}
export interface PolicyCheckpoint {readonly tenantId:string;readonly revision:number;readonly digest:string;}
function message(keyId:string,payload:EnterprisePolicy):Buffer{return Buffer.from(canonical({format:'aidr-policy-v1',keyId,payload}));}
export function signPolicy(input:EnterprisePolicy,keyId:string,key:KeyObject):SignedPolicy {
  id(keyId);const payload=validatePolicy(input);if(key.type!=='private'||key.asymmetricKeyType!=='ed25519')deny('POLICY_KEY_INVALID');
  return frozen({format:'aidr-policy-v1',keyId,payload,signature:sign(null,message(keyId,payload),key).toString('base64url')});
}
/** One registry per tenant. Persist checkpoint in trusted transactional storage BEFORE rollout.
 * In-memory anti-rollback does not protect against an administrator restoring old disk state. */
export class PolicyRegistry {
  #tenant:string;#keys:Map<string,KeyObject>;#checkpoint:PolicyCheckpoint;#active:EnterprisePolicy|undefined;#quarantined=true;#lastNow=0;#rollout=false;
  constructor(tenantId:string,keys:ReadonlyMap<string,KeyObject>,checkpoint?:PolicyCheckpoint){
    this.#tenant=id(tenantId);this.#keys=new Map(keys);if(!this.#keys.size||this.#keys.size>32)deny('POLICY_KEY_INVALID');
    for(const [name,key]of this.#keys){id(name);if(key.type!=='public'||key.asymmetricKeyType!=='ed25519')deny('POLICY_KEY_INVALID');}
    if(checkpoint){id(checkpoint.tenantId);integer(checkpoint.revision,1);if(checkpoint.tenantId!==tenantId||!/^[a-f0-9]{64}$/.test(checkpoint.digest))deny('POLICY_CHECKPOINT_INVALID');}
    this.#checkpoint=frozen(checkpoint??{tenantId,revision:0,digest:'0'.repeat(64)});
  }
  #time(now:number):void {integer(now);if(now<this.#lastNow){this.#quarantined=true;deny('CLOCK_ROLLBACK');}this.#lastNow=now;}
  install(input:unknown,now=Date.now()):PolicyCheckpoint {
    if(this.#rollout)deny('POLICY_BUSY');
    this.#quarantined=true;
    try{
      this.#time(now);const e=object(frozen(input),['format','keyId','payload','signature']);
      if(e.format!=='aidr-policy-v1')deny('POLICY_SIGNATURE_INVALID');const key=this.#keys.get(id(e.keyId));
      if(!key||typeof e.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(e.signature))deny('POLICY_SIGNATURE_INVALID');
      const p=validatePolicy(e.payload),sig=Buffer.from(e.signature,'base64url');
      if(sig.toString('base64url')!==e.signature||!verify(null,message(e.keyId as string,p),key,sig))deny('POLICY_SIGNATURE_INVALID');
      if(p.tenantId!==this.#tenant)deny('POLICY_TENANT_MISMATCH');
      if(now<p.notBefore||now>=p.expiresAt)deny('POLICY_EXPIRED');const digest=hash(p);
      if(p.revision<this.#checkpoint.revision||p.revision===this.#checkpoint.revision&&digest!==this.#checkpoint.digest)deny('POLICY_ROLLBACK');
      this.#checkpoint=frozen({tenantId:this.#tenant,revision:p.revision,digest});this.#active=p;this.#quarantined=false;return this.checkpoint();
    }catch(e){this.#active=undefined;throw e;}
  }
  /** Durable rollout: no decisions may use the new policy until the trusted checkpoint writer
   * acknowledges. Writer uncertainty, timeout or expiry keeps the registry quarantined. */
  async installDurable(input:unknown,writeCheckpoint:(checkpoint:PolicyCheckpoint)=>Promise<void>,clock:()=>number=Date.now,timeoutMs=10000):Promise<PolicyCheckpoint> {
    if(this.#rollout)deny('POLICY_BUSY');integer(timeoutMs,1,120000);
    if(typeof writeCheckpoint!=='function'||typeof clock!=='function')deny('POLICY_WRITER_REQUIRED');
    this.#rollout=true;this.#quarantined=true;this.#active=undefined;let timer:ReturnType<typeof setTimeout>|undefined;
    try{
      const now=clock();this.#time(now);
      const staged=new PolicyRegistry(this.#tenant,this.#keys,this.#checkpoint.revision?this.#checkpoint:undefined);
      const checkpoint=staged.install(input,now),policy=staged.active(now);
      // Advance high-water even on uncertain persistence; do not allow an in-process downgrade.
      this.#checkpoint=checkpoint;
      await Promise.race([Promise.resolve().then(()=>writeCheckpoint(checkpoint)),new Promise<never>((_,reject)=>{timer=setTimeout(()=>reject(new Error('POLICY_WRITE_TIMEOUT')),timeoutMs);})]);
      this.#time(clock());staged.active(this.#lastNow);this.#active=policy;this.#quarantined=false;
      return this.checkpoint();
    }catch{this.#quarantined=true;this.#active=undefined;return deny('POLICY_ROLLOUT_FAILED');}
    finally{if(timer)clearTimeout(timer);this.#rollout=false;}
  }
  active(now=Date.now()):EnterprisePolicy {
    this.#time(now);if(this.#quarantined||!this.#active)deny('POLICY_QUARANTINED');
    if(now<this.#active.notBefore||now>=this.#active.expiresAt)deny('POLICY_EXPIRED');return this.#active;
  }
  checkpoint():PolicyCheckpoint{return frozen(this.#checkpoint);}
}
export function validateContext(input:TrustedContext):TrustedContext {
  const c=object(frozen(input),['tenantId','subjectId','sessionId','groups','scopes','device','account','accountVerified','destination','channel','assetIds']);
  id(c.tenantId);id(c.subjectId);id(c.sessionId);for(const k of ['groups','scopes','assetIds']){const a=list(c[k],128);for(const v of a)id(v);if(new Set(a).size!==a.length)deny('CONTEXT_INVALID');}
  oneOf(c.device,['managed','unmanaged','unknown']);oneOf(c.account,ACCOUNTS);bool(c.accountVerified);
  oneOf(c.channel,['browser','api','retrieval','tool','output']);return frozen({...c,destination:httpsOrigin(c.destination)}) as unknown as TrustedContext;
}
