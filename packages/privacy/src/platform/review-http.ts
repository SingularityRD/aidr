import type { IncomingMessage, ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseJsonStrict } from '../json.js';
import { object, integer, deny } from '../enterprise/util.js';
import type { OidcSessionManager } from './oidc.js';
import type { ReviewWorkflow } from './review.js';
const SESSION='__Host-aidr-session',LOGIN='__Host-aidr-login';
function cookie(req:IncomingMessage,name:string):string {const matches=(req.headers.cookie??'').split(';').map(s=>s.trim()).filter(s=>s.startsWith(name+'='));if(matches.length!==1)deny('PORTAL_COOKIE');return matches[0]!.slice(name.length+1);}
async function json(req:IncomingMessage):Promise<Record<string,unknown>>{const ct=req.headers['content-type'];if(ct!=='application/json'||req.headers['content-encoding'])deny('PORTAL_CONTENT_TYPE');let n=0;const parts:Buffer[]=[];for await(const part of req){const b=Buffer.from(part);n+=b.length;if(n>8192)deny('PORTAL_LIMIT');parts.push(b);}const raw=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts));const p=parseJsonStrict(raw,8,128);if(!p||typeof p!=='object'||Array.isArray(p))deny('PORTAL_JSON');return p as Record<string,unknown>;}
function sessionCookie(name:string,value:string,maxAge:number):string{return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;}
export function createReviewHandler(o:{sessions:OidcSessionManager;workflow:ReviewWorkflow;origin:string;assetsDirectory:string;requireTLS?:boolean}):(req:IncomingMessage,res:ServerResponse)=>Promise<void>{
  const origin=new URL(o.origin).origin;if(!origin.startsWith('https://'))deny('PORTAL_ORIGIN');
  return async(req,res)=>{
    res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Cross-Origin-Opener-Policy','same-origin');
    res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    res.setHeader('Strict-Transport-Security','max-age=31536000');const send=(code:number,body:unknown)=>{res.writeHead(code,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(body));};
    try{
      if(o.requireTLS!==false&&!(req.socket as {encrypted?:boolean}).encrypted)deny('PORTAL_TLS_REQUIRED');
      const u=new URL(req.url??'/',origin);if(u.origin!==origin)deny('PORTAL_URL');if(req.method==='GET'&&u.pathname==='/login'){const login=o.sessions.begin();res.setHeader('Set-Cookie',sessionCookie(LOGIN,login.browserCookie,300));res.writeHead(302,{Location:login.location});res.end();return;}
      if(req.method==='GET'&&u.pathname==='/oidc/callback'){
        if(u.searchParams.getAll('state').length!==1||u.searchParams.getAll('code').length!==1)deny('OIDC_STATE');
        const r=await o.sessions.callback(u.searchParams.get('state')!,u.searchParams.get('code')!,cookie(req,LOGIN));res.setHeader('Set-Cookie',[sessionCookie(SESSION,r.sessionCookie,3600),sessionCookie(LOGIN,'',0)]);res.writeHead(303,{Location:'/'});res.end();return;
      }
      if(req.method==='GET'&&['/','/app.js','/style.css'].includes(u.pathname)){
        const name=u.pathname==='/'?'index.html':u.pathname.slice(1),bytes=await readFile(resolve(o.assetsDirectory,name));res.writeHead(200,{'Content-Type':name.endsWith('.html')?'text/html; charset=utf-8':name.endsWith('.js')?'text/javascript; charset=utf-8':'text/css; charset=utf-8'});res.end(bytes);return;
      }
      const session=o.sessions.authenticate(cookie(req,SESSION));
      if(req.method==='GET'&&u.pathname==='/api/session'){send(200,{subjectId:session.principal.subjectId,roles:session.principal.roles,csrf:session.csrf});return;}
      if(req.method==='GET'&&u.pathname==='/api/reviews'){const after=u.searchParams.get('after')??'';send(200,{items:o.workflow.list(session.principal,50,after)});return;}
      const m=/^\/api\/reviews\/([A-Za-z0-9-]{36})(?:\/(decision|appeal|history))?$/.exec(u.pathname);
      if(req.method==='GET'&&m){send(200,m[2]==='history'?{items:o.workflow.history(session.principal,m[1]!)}:o.workflow.get(session.principal,m[1]!));return;}
      if(req.method!=='POST'||req.headers.origin!==origin||req.headers['x-aidr-csrf']!==session.csrf)deny('PORTAL_CSRF');
      if(u.pathname==='/logout'){o.sessions.logout(cookie(req,SESSION));res.setHeader('Set-Cookie',sessionCookie(SESSION,'',0));send(200,{ok:true});return;}
      if(m?.[2]==='decision'){
        const b=object(await json(req),['decision','reason','sequence','ttlMs']);if(typeof b.reason!=='string'||!['approved','denied'].includes(b.decision as string))deny('REVIEW_INPUT');
        send(200,o.workflow.decide(session.principal,m[1]!,b.decision as 'approved'|'denied',b.reason,integer(b.sequence,1),b.ttlMs===undefined?300000:integer(b.ttlMs,1000,3600000)));return;
      }
      if(m?.[2]==='appeal'){const b=object(await json(req),['reason']);if(typeof b.reason!=='string')deny('REVIEW_INPUT');send(200,o.workflow.appeal(session.principal,m[1]!,b.reason));return;}
      send(404,{error:'NOT_FOUND'});
    }catch{if(!res.headersSent)send(403,{error:'REQUEST_DENIED'});else res.destroy();}
  };
}
