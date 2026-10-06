/** Fixed-endpoint OIDC and institution MDM/account broker integration.
 * The broker must obtain real MDM/provider evidence; this client never mints those claims. */
import { request } from 'node:https';
import { TLSSocket, createSecureContext } from 'node:tls';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createPublicKey, createHash, randomBytes, X509Certificate, type KeyObject, type JsonWebKey } from 'node:crypto';
import { parseJsonStrict } from '../json.js';
import { canonical, deny, frozen, hash, id, integer, list, object } from '../enterprise/util.js';
import { PinnedJwtVerifier, revokeSession, type JwtTrust, type SessionRecord, type RequestCredentials, type VerifiedClaims } from './identity.js';
import type { createPlatformRuntime } from './runtime.js';

type Runtime = Awaited<ReturnType<typeof createPlatformRuntime>>;
export interface HttpsIdentityTls {readonly ca:Buffer;readonly cert?:Buffer;readonly key?:Buffer;}
export interface BrokerConfig {
  oidc:{issuer:string;clientId:string;clientSecret:string;redirectUri:string;tls:HttpsIdentityTls;scope?:string;maxTokenLifetimeSeconds?:number};
  broker:{issuer:string;audience:string;tls:HttpsIdentityTls & {cert:Buffer;key:Buffer};destination:string};
}
function endpoint(raw:string):URL {
  if(typeof raw!=='string'||raw.length>2048||/[\s\\\u0000-\u001f\u007f]/u.test(raw))deny('BROKER_CONFIG');
  const u=new URL(raw);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)deny('BROKER_CONFIG');return u;
}
function sameOrigin(raw:unknown,issuer:URL):URL {if(typeof raw!=='string')deny('BROKER_DISCOVERY');const u=endpoint(raw);if(u.origin!==issuer.origin)deny('BROKER_ENDPOINT');return u;}
/** Explicit administrator-pinned CA and hostname verification, no proxy, redirects or caller URL. */
async function jsonHttps(url:URL,tls:HttpsIdentityTls,method:'GET'|'POST',body?:Buffer,headers:Record<string,string>={},signal?:AbortSignal):Promise<Record<string,unknown>> {
  if(!Buffer.isBuffer(tls.ca)||!tls.ca.length||Boolean(tls.cert)!==Boolean(tls.key))deny('BROKER_TLS_CONFIG');
  createSecureContext({...tls,minVersion:'TLSv1.2'});signal?.throwIfAborted();
  return new Promise((resolve,reject)=>{
    const timeout=setTimeout(()=>req.destroy(new Error('BROKER_TIMEOUT')),15000);
    const req=request(url,{...tls,method,rejectUnauthorized:true,minVersion:'TLSv1.2',agent:false,signal,
      maxHeaderSize:16384,headers:{accept:'application/json',...headers,...(body?{'content-length':String(body.length)}:{})}},res=>{
      let size=0;const chunks:Buffer[]=[];
      if(res.statusCode!==200||(res.headers['content-type']??'').split(';')[0]?.trim()!=='application/json'||res.headers['content-encoding']){res.resume();req.destroy(new Error('BROKER_RESPONSE'));return;}
      res.on('data',p=>{const b=Buffer.from(p);size+=b.length;if(size>262144)req.destroy(new Error('BROKER_LIMIT'));else chunks.push(b);});
      res.on('error',reject);res.on('end',()=>{try {const data=parseJsonStrict(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)),16,4096);if(!data||typeof data!=='object'||Array.isArray(data))deny('BROKER_RESPONSE');resolve(data as Record<string,unknown>);}catch{reject(new Error('BROKER_RESPONSE'));}});
    });
    req.once('close',()=>clearTimeout(timeout));req.once('error',()=>reject(new Error('BROKER_UNAVAILABLE')));req.end(body);
  });
}
export async function discoverJwtTrust(issuerRaw:string,audience:string,tls:HttpsIdentityTls,signal?:AbortSignal):Promise<{trust:JwtTrust;metadata:Record<string,unknown>}> {
  const issuer=endpoint(issuerRaw);if(issuerRaw.endsWith('/'))deny('BROKER_ISSUER');
  const discovery=new URL(issuerRaw+'/.well-known/openid-configuration');
  const metadata=await jsonHttps(discovery,tls,'GET',undefined,{},signal);if(metadata.issuer!==issuerRaw)deny('BROKER_ISSUER');
  const jwks=await jsonHttps(sameOrigin(metadata.jwks_uri,issuer),tls,'GET',undefined,{},signal);
  if(!Array.isArray(jwks.keys)||!jwks.keys.length||jwks.keys.length>32)deny('BROKER_KEYS');const keys=new Map<string,KeyObject>();
  for(const raw of jwks.keys){
    if(!raw||typeof raw!=='object'||Array.isArray(raw))deny('BROKER_KEYS');const j=raw as Record<string,unknown>,kid=id(j.kid);
    if(keys.has(kid)||['d','p','q','dp','dq','qi','oth','k','x5u','jku'].some(k=>j[k]!==undefined)||j.use!==undefined&&j.use!=='sig'||j.key_ops!==undefined&&(!Array.isArray(j.key_ops)||j.key_ops.length!==1||j.key_ops[0]!=='verify'))deny('BROKER_KEYS');
    if(!((j.kty==='RSA'&&(j.alg===undefined||j.alg==='RS256'))||(j.kty==='OKP'&&j.crv==='Ed25519'&&(j.alg===undefined||j.alg==='EdDSA'))))continue;
    try{keys.set(kid,createPublicKey({key:j as JsonWebKey,format:'jwk'}));}catch{deny('BROKER_KEYS');}
  }
  const trust:JwtTrust={issuer:issuerRaw,audience,keys};new PinnedJwtVerifier(trust);return {trust,metadata};
}
interface Pending {nonce:string;verifier:string;certificate:string;expiresAt:number;kind:'broker-login';}
export class ConfiguredSessionBroker {
  readonly trust:JwtTrust;readonly oidcTrust:JwtTrust;#config:BrokerConfig;#authorization:URL;#token:URL;#closed=false;#active=0;#runtime:Runtime|undefined;
  private constructor(config:BrokerConfig,trust:JwtTrust,oidcTrust:JwtTrust,metadata:Record<string,unknown>){
    this.#config=config;this.trust=trust;this.oidcTrust=oidcTrust;const issuer=endpoint(config.oidc.issuer);
    this.#authorization=sameOrigin(metadata.authorization_endpoint,issuer);this.#token=sameOrigin(metadata.token_endpoint,issuer);endpoint(config.oidc.redirectUri);
    if(typeof config.oidc.clientId!=='string'||!config.oidc.clientId||config.oidc.clientId.length>512||typeof config.oidc.clientSecret!=='string'||!config.oidc.clientSecret||config.oidc.clientSecret.length>8192)deny('BROKER_CLIENT_CONFIG');
    if(config.oidc.scope!==undefined&&(!config.oidc.scope.split(' ').includes('openid')||config.oidc.scope.length>512))deny('BROKER_CLIENT_CONFIG');
    if(!Buffer.isBuffer(config.broker.tls.cert)||!Buffer.isBuffer(config.broker.tls.key))deny('BROKER_CLIENT_CONFIG');
    createSecureContext({...config.broker.tls,minVersion:'TLSv1.2'});
    const destination=endpoint(config.broker.destination);if(destination.origin!==config.broker.destination)deny('BROKER_DESTINATION');
  }
  static async open(config:BrokerConfig,signal?:AbortSignal):Promise<ConfiguredSessionBroker>{
    const [oidc,broker]=await Promise.all([discoverJwtTrust(config.oidc.issuer,config.oidc.clientId,config.oidc.tls,signal),discoverJwtTrust(config.broker.issuer,config.broker.audience,config.broker.tls,signal)]);
    const oidcTrust={...oidc.trust,idTokenProfile:true,maxLifetimeSeconds:integer(config.oidc.maxTokenLifetimeSeconds??600,1,86400)};
    return new ConfiguredSessionBroker(config,broker.trust,oidcTrust,oidc.metadata);
  }
  async #call(route:string,body:unknown,signal?:AbortSignal){
    if(this.#closed)deny('BROKER_CLOSED');const base=endpoint(this.#config.broker.issuer),url=new URL(base.href.replace(/\/$/,'')+route);
    const result=await jsonHttps(url,this.#config.broker.tls,'POST',Buffer.from(canonical(body,65536)),{'content-type':'application/json'},signal);if(this.#closed)deny('BROKER_CLOSED');return result;
  }
  #accept(raw:Record<string,unknown>,certificate:string,expected?:{claims?:VerifiedClaims;session?:SessionRecord}):RequestCredentials {
    const runtime=this.#runtime;if(!runtime||this.#closed)deny('BROKER_NOT_READY');object(raw,['userToken','deviceToken','providerToken']);
    for(const k of ['userToken','deviceToken','providerToken'])if(typeof raw[k]!=='string')deny('BROKER_GRANT');
    const credentials=raw as unknown as RequestCredentials,now=Date.now(),verify=(purpose:string,t:string)=>new PinnedJwtVerifier({...this.trust,purpose}).verify(t,now);
    const u=verify('user',credentials.userToken),d=verify('device',credentials.deviceToken),p=verify('provider',credentials.providerToken);
    id(u.sid);integer(u.session_version,1);id(d.device_id);
    for(const c of [u,d,p])if(c.tenant_id!==runtime.state.tenantId||c.sub!==u.sub||c.sid!==u.sid||c.session_version!==u.session_version)deny('BROKER_BINDING');
    if(d.device_id!==p.device_id||d.managed!==true||d.compliant!==true||(d.cnf as Record<string,unknown>|undefined)?.['x5t#S256']!==certificate)deny('BROKER_DEVICE');
    if(p.destination!==this.#config.broker.destination||p.account!=='enterprise'||p.verified!==true||p.logged_in!==true)deny('BROKER_PROVIDER');
    for(const scope of list(p.scopes??[],128))id(scope);
    if(expected?.claims&&(u.oidc_iss!==expected.claims.iss||u.oidc_sub!==expected.claims.sub))deny('BROKER_SUBJECT');
    if(expected?.session&&(u.sub!==expected.session.subjectId||u.sid!==expected.session.sessionId||d.device_id!==expected.session.deviceId))deny('BROKER_SESSION');
    const expiresAt=Math.min(u.exp,d.exp,p.exp)*1000;
    runtime.state.transaction(tx=>{const old=tx.get<SessionRecord>('sessions',u.sid as string);
      for(const c of [u,d,p])if(tx.get('revoked-jti',c.jti))deny('AUTH_TOKEN_REVOKED');
      if(old&&(!old.value.active||now>=old.value.expiresAt||old.value.subjectId!==u.sub||old.value.deviceId!==d.device_id)||u.session_version!==(old?old.value.version+1:1))deny('BROKER_SESSION_VERSION');
      tx.put('sessions',u.sid as string,{subjectId:u.sub,sessionId:u.sid,version:u.session_version,deviceId:d.device_id,active:true,expiresAt},old?.version??null,expiresAt);
      // The existing identity validator reads this uncommitted row; invalid groups/expiry
      // roll back the new session instead of poisoning its durable next version.
      runtime.identity.authenticate(credentials.userToken);tx.event('BROKER_SESSION_PROVISIONED',u.sub,u.sid as string,now);
    });
    return frozen(credentials);
  }
  async initialize(runtime:Runtime,signal:AbortSignal){
    if(this.#runtime||this.#closed)deny('BROKER_ALREADY_INITIALIZED');this.#runtime=runtime;
    const certificate=createHash('sha256').update(new X509Certificate(this.#config.broker.tls.cert).raw).digest('base64url');
    const grant=this.#accept(await this.#call('/v1/sessions/bootstrap',{destination:this.#config.broker.destination,certificateThumbprint:certificate},signal),certificate);
    return {principal:runtime.identity.authenticate(grant.userToken),handle:this.handle.bind(this),close:()=>{this.#closed=true;}};
  }
  /** These routes require the actual enrolled client mTLS channel; body cannot supply device identity. */
  async handle(req:IncomingMessage,res:ServerResponse):Promise<boolean>{
    if(!req.url?.startsWith('/v1/session/'))return false;
    res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
    const respond=(status:number,v:unknown)=>{res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(v));};
    if(this.#active>=8){respond(503,{error:'SESSION_BUSY'});return true;}this.#active++;
    try{
      if(this.#closed||!this.#runtime||req.method!=='POST'||req.headers.origin||req.headers['content-type']!=='application/json'||req.headers['content-encoding'])deny('BROKER_REQUEST');
      const socket=req.socket;if(!(socket instanceof TLSSocket)||!socket.authorized||socket.destroyed)deny('AUTH_MTLS_REQUIRED');const cert=socket.getPeerCertificate();if(!cert.raw)deny('AUTH_MTLS_REQUIRED');
      const certificate=createHash('sha256').update(cert.raw).digest('base64url');let bytes=0;const chunks:Buffer[]=[];
      for await(const p of req){const b=Buffer.from(p);bytes+=b.length;if(bytes>80000)deny('BROKER_LIMIT');chunks.push(b);}
      const body=parseJsonStrict(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)),8,256),runtime=this.#runtime,now=Date.now();
      if(req.url==='/v1/session/begin'){
        object(body,[]);const state=randomBytes(32).toString('base64url'),nonce=randomBytes(32).toString('base64url'),verifier=randomBytes(32).toString('base64url');
        runtime.state.transaction(tx=>{tx.purgeExpiredTransient('oidc-pending',now);if(tx.count('oidc-pending',true)>=1000)deny('OIDC_BUSY');tx.put('oidc-pending',hash(state),{kind:'broker-login',nonce,verifier,certificate,expiresAt:now+300000},null,now+300000);});
        const url=new URL(this.#authorization);for(const [k,v]of Object.entries({response_type:'code',client_id:this.#config.oidc.clientId,redirect_uri:this.#config.oidc.redirectUri,scope:this.#config.oidc.scope??'openid profile',state,nonce,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'}))url.searchParams.set(k,v);
        respond(200,{location:url.href,state});
      }else if(req.url==='/v1/session/complete'){
        const v=object(body,['state','code']);if(typeof v.state!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(v.state)||typeof v.code!=='string'||!v.code||v.code.length>4096)deny('OIDC_CODE');
        const pending=runtime.state.transaction(tx=>{const row=tx.get<Pending>('oidc-pending',hash(v.state));if(!row||row.value.kind!=='broker-login'||row.value.certificate!==certificate||now>=row.value.expiresAt)deny('OIDC_STATE');tx.remove('oidc-pending',hash(v.state),row.version);return row.value;});
        const config=this.#config.oidc,form=new URLSearchParams({grant_type:'authorization_code',code:v.code,redirect_uri:config.redirectUri,code_verifier:pending.verifier});
        const formValue=(v:string)=>new URLSearchParams({v}).toString().slice(2),basic=Buffer.from(formValue(config.clientId)+':'+formValue(config.clientSecret)).toString('base64');
        const token=await jsonHttps(this.#token,config.tls,'POST',Buffer.from(form.toString()),{'content-type':'application/x-www-form-urlencoded',authorization:'Basic '+basic});
        if(typeof token.id_token!=='string')deny('OIDC_TOKEN');const claims=new PinnedJwtVerifier(this.oidcTrust).verify(token.id_token,Date.now(),pending.nonce);
        const grant=this.#accept(await this.#call('/v1/sessions',{idToken:token.id_token,certificateThumbprint:certificate,destination:this.#config.broker.destination}),certificate,{claims});
        respond(200,grant);
      }else if(req.url==='/v1/session/refresh'||req.url==='/v1/session/revoke'){
        const v=object(body,['userToken','deviceToken','providerToken']);for(const k of ['userToken','deviceToken','providerToken'])if(typeof v[k]!=='string')deny('BROKER_GRANT');
        const credentials=runtime.identity.bindTlsCredentials(v as unknown as RequestCredentials,socket),context=runtime.identity.resolve(credentials,this.#config.broker.destination),session=runtime.state.get<SessionRecord>('sessions',context.principal.sessionId)!.value;
        if(req.url.endsWith('/refresh')){
          try{const raw=await this.#call('/v1/sessions/refresh',{...credentials,certificateThumbprint:certificate,destination:this.#config.broker.destination});runtime.identity.assertContext(context);respond(200,this.#accept(raw,certificate,{session}));}
          catch(error){
            // A failed compliance/account refresh cannot retain the old lease. Do not revoke
            // a concurrent successful refresh which already advanced this session version.
            runtime.state.transaction(tx=>{const old=tx.get<SessionRecord>('sessions',session.sessionId);if(old?.value.active&&old.value.version===session.version){tx.put('sessions',session.sessionId,{...old.value,version:old.value.version+1,active:false},old.version,old.expiresAt);tx.event('BROKER_REFRESH_DENIED',session.subjectId,session.sessionId,Date.now());}});throw error;
          }
        }else {revokeSession(runtime.state,session.sessionId);const result=await this.#call('/v1/sessions/revoke',{...credentials});if(result.revoked!==true)deny('BROKER_REVOKE_NOT_ACKNOWLEDGED');respond(200,{revoked:true});}
      }else deny('BROKER_ROUTE');
    }catch{if(!res.headersSent)respond(403,{error:'SESSION_DENIED'});else res.destroy();}finally{this.#active--;}
    return true;
  }
}
