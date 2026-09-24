import { TLSSocket } from 'node:tls';
/** Pinned JWT validation and authenticated context assembly. Provider-account and device
 * claims are separate, short-lived attestations issued by YOUR trusted account/MDM brokers.
 * An IdP login alone is deliberately insufficient to prove a provider account is enterprise. */
import { KeyObject, createHash, sign, verify } from 'node:crypto';
import { parseJsonStrict } from '../json.js';
import { frozen, id, integer, object, list, canonical, deny, oneOf, httpsOrigin } from '../enterprise/util.js';
import type { TrustedContext } from '../enterprise/types.js';
import type { TenantState } from './state.js';
export interface JwtTrust {
  readonly issuer:string;readonly audience:string;readonly keys:ReadonlyMap<string,KeyObject>;
  readonly purpose?:string;readonly idTokenProfile?:boolean;readonly maxLifetimeSeconds?:number;readonly clockSkewSeconds?:number;
}
export interface VerifiedClaims {readonly iss:string;readonly aud:string|readonly string[];readonly sub:string;readonly exp:number;readonly iat:number;readonly nbf?:number;readonly jti:string;readonly [name:string]:unknown;}
function base64(raw:string,limit:number):Buffer {if(!raw||raw.length>limit||!/^[A-Za-z0-9_-]+$/.test(raw))deny('AUTH_TOKEN_INVALID');const b=Buffer.from(raw,'base64url');if(b.toString('base64url')!==raw)deny('AUTH_TOKEN_INVALID');return b;}
function parsed(raw:string,limit:number):Record<string,unknown>{const b=base64(raw,limit),text=new TextDecoder('utf-8',{fatal:true}).decode(b);const v=parseJsonStrict(text,12,2048);if(!v||typeof v!=='object'||Array.isArray(v))deny('AUTH_TOKEN_INVALID');return v as Record<string,unknown>;}
export class PinnedJwtVerifier {
  #keys:Map<string,KeyObject>;readonly issuer:string;readonly audience:string;#o:JwtTrust;
  constructor(o:JwtTrust){if(!o.issuer.startsWith('https://')||!o.audience||o.audience.length>512)deny('AUTH_TRUST_INVALID');this.issuer=o.issuer;this.audience=o.audience;this.#keys=new Map(o.keys);this.#o={...o};
    if(!this.#keys.size||this.#keys.size>32)deny('AUTH_TRUST_INVALID');for(const [kid,key]of this.#keys){id(kid);if(key.type!=='public'||!['rsa','ed25519'].includes(key.asymmetricKeyType??''))deny('AUTH_KEY_INVALID');if(key.asymmetricKeyType==='rsa'&&(key.asymmetricKeyDetails?.modulusLength??0)<2048)deny('AUTH_KEY_INVALID');}
    integer(o.maxLifetimeSeconds??600,1,86400);integer(o.clockSkewSeconds??15,0,60);
  }
  verify(token:string,now=Date.now(),nonce?:string):VerifiedClaims{
    try{if(typeof token!=='string'||token.length>24000)deny('AUTH_TOKEN_INVALID');integer(now);const parts=token.split('.');if(parts.length!==3)deny('AUTH_TOKEN_INVALID');
      const header=object(parsed(parts[0]!,4096),['alg','typ','kid']);if(header.typ!==undefined&&header.typ!=='JWT'&&header.typ!=='at+jwt')deny('AUTH_TOKEN_TYPE');
      const key=this.#keys.get(id(header.kid));if(!key)deny('AUTH_KEY_UNKNOWN');const alg=oneOf(header.alg,['EdDSA','RS256']);if((alg==='EdDSA')!==(key.asymmetricKeyType==='ed25519'))deny('AUTH_ALGORITHM');
      const signature=base64(parts[2]!,2048);if(!verify(alg==='EdDSA'?null:'RSA-SHA256',Buffer.from(parts[0]+'.'+parts[1]),key,signature))deny('AUTH_SIGNATURE');
      const c=parsed(parts[1]!,18000),seconds=Math.floor(now/1000),skew=this.#o.clockSkewSeconds??15;
      if(c.iss!==this.issuer)deny('AUTH_ISSUER');const audiences=Array.isArray(c.aud)?c.aud:[c.aud];
      // Single audience by default; no untrusted co-audiences. OIDC azp must agree when present.
      if(audiences.length!==1||audiences[0]!==this.audience||c.azp!==undefined&&c.azp!==this.audience)deny('AUTH_AUDIENCE');
      integer(c.exp);integer(c.iat);if(c.nbf!==undefined)integer(c.nbf);
      if((c.exp as number)<=(c.iat as number)||(c.exp as number)-(c.iat as number)>(this.#o.maxLifetimeSeconds??600)||(c.iat as number)>seconds+skew||seconds>=(c.exp as number)||c.nbf!==undefined&&(c.nbf as number)>seconds+skew)deny('AUTH_EXPIRED');
      if(this.#o.purpose!==undefined&&c.token_use!==this.#o.purpose)deny('AUTH_PURPOSE');if(nonce!==undefined&&c.nonce!==nonce)deny('AUTH_NONCE');
      if(this.#o.idTokenProfile){if(typeof c.sub!=='string'||c.sub.length<1||c.sub.length>255||/[\x00-\x1f\x7f]/.test(c.sub))deny('AUTH_SUBJECT');if(c.jti===undefined)c.jti=createHash('sha256').update(token).digest('hex');else id(c.jti);}else{id(c.sub);id(c.jti);}return frozen(c) as VerifiedClaims;
    }catch(e){if(e instanceof Error&&/^(AUTH_|CONTROL_)/.test(e.message))throw e;return deny('AUTH_TOKEN_INVALID');}
  }
}
/** Issuer-side helper used in tests/integrations, never exposed as a signing HTTP endpoint. */
export function issueJwt(claims:Record<string,unknown>,kid:string,key:KeyObject):string {
  id(kid);if(key.type!=='private'||!['rsa','ed25519'].includes(key.asymmetricKeyType??''))deny('AUTH_KEY_INVALID');const alg=key.asymmetricKeyType==='ed25519'?'EdDSA':'RS256';
  const head=Buffer.from(canonical({alg,kid,typ:'JWT'})).toString('base64url'),body=Buffer.from(canonical(claims,18000)).toString('base64url'),message=head+'.'+body;
  return message+'.'+sign(alg==='EdDSA'?null:'RSA-SHA256',Buffer.from(message),key).toString('base64url');
}
export interface SessionRecord {readonly subjectId:string;readonly sessionId:string;readonly version:number;readonly deviceId:string;readonly active:boolean;readonly expiresAt:number;}
export function provisionSession(state:TenantState,record:SessionRecord,now=Date.now()):void {
  id(record.subjectId);id(record.sessionId);id(record.deviceId);integer(record.version,1);integer(record.expiresAt,now+1);if(typeof record.active!=='boolean')deny('SESSION_INVALID');
  state.transaction(tx=>{const old=tx.get<SessionRecord>('sessions',record.sessionId);if(old&&record.version<=old.value.version)deny('SESSION_VERSION_ROLLBACK');tx.put('sessions',record.sessionId,record,old?.version??null,record.expiresAt);tx.event('SESSION_PROVISIONED','system',record.sessionId,now);});
}
export function revokeSession(state:TenantState,sid:string,now=Date.now()):void {id(sid);state.transaction(tx=>{const old=tx.get<SessionRecord>('sessions',sid);if(!old)deny('SESSION_UNKNOWN');tx.put('sessions',sid,{...old.value,version:old.value.version+1,active:false},old.version,old.expiresAt);tx.event('SESSION_REVOKED','system',sid,now);});}
export interface RequestCredentials {readonly userToken:string;readonly deviceToken:string;readonly providerToken:string;}
export interface AuthenticatedPrincipal {readonly tenantId:string;readonly subjectId:string;readonly sessionId:string;readonly sessionVersion:number;readonly groups:readonly string[];readonly roles:readonly string[];readonly expiresAt:number;}
export interface AuthenticatedContext {readonly principal:AuthenticatedPrincipal;readonly context:TrustedContext;readonly expiresAt:number;}
export interface IdentityOptions {
  readonly tenantId:string;readonly state:TenantState;readonly user:PinnedJwtVerifier;readonly device:PinnedJwtVerifier;readonly provider:PinnedJwtVerifier;
  /** Trusted server configuration maps signed IdP groups to local roles. Request body roles are ignored. */
  readonly requireTransportBinding?:boolean;readonly roleGroups:Readonly<Record<string,readonly string[]>>;readonly allowedScopes:readonly string[];readonly clock?:()=>number;
}
export class ContextResolver {
  #o:IdentityOptions;#principals=new WeakSet<object>();#contexts=new WeakSet<object>();#principalTokens=new WeakMap<object,string>();#contextTokens=new WeakMap<object,readonly string[]>();#transportBindings=new WeakMap<object,string>();
  constructor(o:IdentityOptions){id(o.tenantId);if(o.state.tenantId!==o.tenantId)deny('TENANT_MISMATCH');for(const [role,groups]of Object.entries(o.roleGroups)){id(role);for(const g of groups)id(g);}for(const s of o.allowedScopes)id(s);this.#o={...o,roleGroups:frozen(o.roleGroups),allowedScopes:frozen(o.allowedScopes)};}
  /** Mint binding only from a real, mutually authenticated TLS socket. Incoming JSON cannot mint it. */
  bindTlsCredentials(credentials:RequestCredentials,socket:TLSSocket):RequestCredentials {
    if(!(socket instanceof TLSSocket)||!socket.authorized||socket.destroyed)deny('AUTH_MTLS_REQUIRED');const cert=socket.getPeerCertificate();if(!cert.raw)deny('AUTH_MTLS_REQUIRED');
    const copy=Object.freeze({...credentials});this.#transportBindings.set(copy,createHash('sha256').update(cert.raw).digest('base64url'));return copy;
  }
  #session(c:VerifiedClaims,now:number):SessionRecord {
    if(c.tenant_id!==this.#o.tenantId)deny('AUTH_TENANT');id(c.sid);integer(c.session_version,1);
    const row=this.#o.state.get<SessionRecord>('sessions',c.sid as string);
    if(!row||!row.value.active||row.value.subjectId!==c.sub||row.value.version!==c.session_version||now>=row.value.expiresAt)deny('AUTH_SESSION_REVOKED');
    if(this.#o.state.get('revoked-jti',c.jti))deny('AUTH_TOKEN_REVOKED');return row.value;
  }
  authenticate(userToken:string):AuthenticatedPrincipal {
    const now=(this.#o.clock??Date.now)(),c=this.#o.user.verify(userToken,now),session=this.#session(c,now),groups=list(c.groups??[],128).map(id);
    if(new Set(groups).size!==groups.length)deny('AUTH_GROUPS');const roles=Object.entries(this.#o.roleGroups).filter(([,allowed])=>groups.some(g=>allowed.includes(g))).map(([role])=>role);
    const p=frozen({tenantId:this.#o.tenantId,subjectId:c.sub,sessionId:session.sessionId,sessionVersion:session.version,groups,roles,expiresAt:Math.min(c.exp*1000,session.expiresAt)});this.#principals.add(p);this.#principalTokens.set(p,c.jti);return p;
  }
  assertPrincipal(p:AuthenticatedPrincipal,role?:string):void{
    const now=(this.#o.clock??Date.now)();if(!p||!this.#principals.has(p)||p.tenantId!==this.#o.tenantId||now>=p.expiresAt||role&&!p.roles.includes(role))deny('AUTH_PRINCIPAL_REQUIRED');
    const jti=this.#principalTokens.get(p);if(!jti||this.#o.state.get('revoked-jti',jti))deny('AUTH_TOKEN_REVOKED');const row=this.#o.state.get<SessionRecord>('sessions',p.sessionId);if(!row||!row.value.active||row.value.subjectId!==p.subjectId||row.value.version!==p.sessionVersion||now>=row.value.expiresAt)deny('AUTH_SESSION_REVOKED');
  }
  resolve(credentials:RequestCredentials,destination:string,channel:TrustedContext['channel']='api',assetIds:readonly string[]=[]):AuthenticatedContext {
    const now=(this.#o.clock??Date.now)(),p=this.authenticate(credentials.userToken),d=this.#o.device.verify(credentials.deviceToken,now),provider=this.#o.provider.verify(credentials.providerToken,now);
    const session=this.#o.state.get<SessionRecord>('sessions',p.sessionId)!.value,origin=httpsOrigin(destination);
    for(const c of [d,provider]){if(c.tenant_id!==p.tenantId||c.sub!==p.subjectId||c.sid!==p.sessionId||c.session_version!==session.version||c.device_id!==session.deviceId)deny('AUTH_BINDING');if(this.#o.state.get('revoked-jti',c.jti))deny('AUTH_TOKEN_REVOKED');}
    if(d.managed!==true||d.compliant!==true)deny('AUTH_DEVICE_UNMANAGED');
    if(this.#o.requireTransportBinding!==false){const fingerprint=this.#transportBindings.get(credentials),cnf=d.cnf as Record<string,unknown>|undefined;if(!fingerprint||!cnf||cnf['x5t#S256']!==fingerprint)deny('AUTH_DEVICE_CHANNEL_BINDING');}
    if(provider.destination!==origin||provider.account!=='enterprise'||provider.verified!==true||provider.logged_in!==true)deny('AUTH_PROVIDER_ACCOUNT');
    for(const asset of assetIds)id(asset);if(assetIds.length>128)deny('AUTH_ASSETS');
    const signedScopes=list(provider.scopes??[],128).map(id),scopes=signedScopes.filter(s=>this.#o.allowedScopes.includes(s));
    const context:TrustedContext=frozen({tenantId:p.tenantId,subjectId:p.subjectId,sessionId:p.sessionId,groups:p.groups,scopes,device:'managed',account:'enterprise',accountVerified:true,destination:origin,channel,assetIds});
    const result=frozen({principal:p,context,expiresAt:Math.min(p.expiresAt,d.exp*1000,provider.exp*1000)});
    // frozen() copies values, so register the actual nested principal returned to callers.
    this.#principals.add(result.principal);this.#principalTokens.set(result.principal,this.#principalTokens.get(p)!);this.#contexts.add(result);this.#contextTokens.set(result,[d.jti,provider.jti]);return result;
  }
  assertContext(c:AuthenticatedContext):void{if(!c||!this.#contexts.has(c)||(this.#o.clock??Date.now)()>=c.expiresAt)deny('AUTH_CONTEXT_REQUIRED');this.assertPrincipal(c.principal);for(const jti of this.#contextTokens.get(c)??[])if(this.#o.state.get('revoked-jti',jti))deny('AUTH_TOKEN_REVOKED');}
}
export function tokenFingerprint(token:string):string{return createHash('sha256').update(token).digest('hex');}
