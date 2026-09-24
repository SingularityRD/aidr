import { randomBytes,createHash } from 'node:crypto';
import { frozen, hash, textBound, deny, integer } from '../enterprise/util.js';
import type { TenantState } from './state.js';
import { PinnedJwtVerifier, type VerifiedClaims, type AuthenticatedPrincipal, type ContextResolver } from './identity.js';
function token():string{return randomBytes(32).toString('base64url');}
function opaque(t:unknown):string{if(typeof t!=='string'||!/^[a-zA-Z0-9_-]{43}$/.test(t))deny('OIDC_STATE');return t;}
export interface OidcOptions {
  readonly state:TenantState;readonly identity:ContextResolver;readonly idTokenVerifier:PinnedJwtVerifier;
  readonly clientId:string;readonly authorizationEndpoint:string;readonly tokenEndpoint:string;readonly redirectUri:string;
  readonly scope?:string;readonly clock?:()=>number;
  /** Trusted fixed-endpoint HTTPS transport. No request-controlled endpoint/redirect. */
  readonly exchange:(endpoint:string,body:URLSearchParams)=>Promise<{id_token:string}>;
  /** Authoritative mapping from verified IdP claims to a local short-lived user JWT/session.
   * Must provision/revoke through your trusted IdP/MDM broker, not trust page JSON. */
  readonly establishLocalSession:(claims:VerifiedClaims)=>Promise<string>;
}
interface PendingLogin {state:string;nonce:string;verifier:string;browser:string;expiresAt:number;}
interface PortalSession {userToken:string;csrf:string;expiresAt:number;}
/** Authorization code + PKCE + state + nonce + server-only opaque session cookies.
 * No browser localStorage bearer token and no remote JWKS URL from token headers. */
export class OidcSessionManager {
  #o:OidcOptions;
  constructor(o:OidcOptions){for(const raw of [o.authorizationEndpoint,o.tokenEndpoint,o.redirectUri]){const u=new URL(raw);if(u.protocol!=='https:'||u.username||u.password||u.hash)deny('OIDC_CONFIG');}if(o.state.tenantId==='')deny('OIDC_CONFIG');textBound(o.clientId,512);this.#o={...o};}
  begin():{location:string;browserCookie:string}{const now=(this.#o.clock??Date.now)(),state=token(),nonce=token(),verifier=token(),browser=token(),challenge=createHash('sha256').update(verifier).digest('base64url');
    this.#o.state.transaction(tx=>tx.put('oidc-pending',hash(state),{state,nonce,verifier,browser:hash(browser),expiresAt:now+300000},null,now+300000));
    const u=new URL(this.#o.authorizationEndpoint);u.searchParams.set('response_type','code');u.searchParams.set('client_id',this.#o.clientId);u.searchParams.set('redirect_uri',this.#o.redirectUri);u.searchParams.set('scope',this.#o.scope??'openid profile');u.searchParams.set('state',state);u.searchParams.set('nonce',nonce);u.searchParams.set('code_challenge',challenge);u.searchParams.set('code_challenge_method','S256');return {location:u.toString(),browserCookie:browser};
  }
  async callback(state:string,code:string,browserCookie:string):Promise<{sessionCookie:string;csrf:string;expiresAt:number}> {
    opaque(state);opaque(browserCookie);textBound(code,4096);if(!code)deny('OIDC_CODE');const now=(this.#o.clock??Date.now)();
    const p=this.#o.state.transaction(tx=>{const key=hash(state),r=tx.get<PendingLogin>('oidc-pending',key);if(!r||now>=r.value.expiresAt||r.value.browser!==hash(browserCookie))deny('OIDC_STATE');tx.remove('oidc-pending',key,r.version);return r.value;});
    const data=await this.#o.exchange(this.#o.tokenEndpoint,new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:this.#o.redirectUri,client_id:this.#o.clientId,code_verifier:p.verifier}));
    const claims=this.#o.idTokenVerifier.verify(data.id_token,(this.#o.clock??Date.now)(),p.nonce),userToken=await this.#o.establishLocalSession(claims),principal=this.#o.identity.authenticate(userToken);
    const sessionCookie=token(),csrf=token(),expiresAt=Math.min(principal.expiresAt,claims.exp*1000,now+3600000);
    this.#o.state.transaction(tx=>{tx.put('portal-sessions',hash(sessionCookie),{userToken,csrf,expiresAt},null,expiresAt);tx.event('PORTAL_LOGIN',principal.subjectId,principal.sessionId,(this.#o.clock??Date.now)());});return {sessionCookie,csrf,expiresAt};
  }
  authenticate(cookie:string):{principal:AuthenticatedPrincipal;csrf:string}{opaque(cookie);const now=(this.#o.clock??Date.now)(),r=this.#o.state.get<PortalSession>('portal-sessions',hash(cookie));if(!r||now>=r.value.expiresAt)deny('PORTAL_SESSION');const principal=this.#o.identity.authenticate(r.value.userToken);return {principal,csrf:r.value.csrf};}
  logout(cookie:string):void {opaque(cookie);this.#o.state.transaction(tx=>{const r=tx.get<PortalSession>('portal-sessions',hash(cookie));if(r)tx.remove('portal-sessions',hash(cookie),r.version);});}
}
