import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomBytes,X509Certificate,sign} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {existsSync,mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer,request} from 'node:https';
import {createServer as reservePort} from 'node:net';
import {createMcpGateway} from '@singularityrd/aidr-mcp-gateway';
import {createPlatformRuntime,listenPlatform,createProtectHandler,TextGatewayClient,mcpPrivacyGuards,startPrivateMcpService,issueJwt,provisionSession} from '../../dist/platform/index.js';
import {signPolicy} from '../../dist/enterprise/policy.js';
import {canonical} from '../../dist/enterprise/util.js';
import {policy} from '../enterprise/helpers.mjs';
import {privateDirectory} from '../platform/helpers.mjs';

function certificate(root,name){
 const git=join(process.env.ProgramFiles??'C:\\Program Files','Git','usr','bin','openssl.exe'),openssl=process.env.AIDR_OPENSSL??(process.platform==='win32'&&existsSync(git)?git:'openssl');
 const cert=join(root,name+'.pem'),key=join(root,name+'.key');
 execFileSync(openssl,['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN='+name,'-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore',windowsHide:true});
 return {cert:readFileSync(cert),key:readFileSync(key)};
}
async function port(){const s=reservePort();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}

// Explicit optional-profile target: missing installed/signed packages FAIL, never skip.
test('installed public gateway and private scanner protect actual HTTP/mTLS flow and complete metadata',async t=>{
 const root=mkdtempSync(join(tmpdir(),'aidr-installed-mcp-'));privateDirectory(root);let runtime,privacy,upstream,gateway;
 const clientEnv='AIDR_MCP_INTEGRATION_CLIENT',upstreamEnv='AIDR_MCP_INTEGRATION_UPSTREAM',oldClient=process.env[clientEnv],oldUpstream=process.env[upstreamEnv];
 try{
  const tls=certificate(root,'privacy-device'),now=Date.now(),signer=generateKeyPairSync('ed25519');
  const trust={issuer:'https://identity.example.com',audience:'aidr-platform',keys:new Map([['signer',signer.publicKey]])};
  runtime=await createPlatformRuntime({tenantId:'alpha',databasePath:join(root,'control.sqlite'),encryption:{active:'k1',keys:[{id:'k1',key:randomBytes(32)}]},audit:{keyId:'audit1',key:randomBytes(32)},
   identity:{user:trust,device:trust,provider:trust,roleGroups:{},scopes:[]},policy:{signed:signPolicy(policy({tenantId:'alpha',notBefore:now-1000,expiresAt:now+600000,destinations:[{...policy().destinations[0],id:'provider',origin:'https://api.example.com'}]}),'signer',signer.privateKey),keys:trust.keys},destinations:[],profile:'strict'});
  provisionSession(runtime.state,{sessionId:'installed-session',subjectId:'alice',version:1,deviceId:'device-a',active:true,expiresAt:now+300000},now);
  const thumbprint=createHash('sha256').update(new X509Certificate(tls.cert).raw).digest('base64url');
  const token=purpose=>issueJwt({iss:trust.issuer,aud:trust.audience,sub:'alice',iat:Math.floor(now/1000),exp:Math.floor(now/1000)+300,jti:randomBytes(16).toString('hex'),token_use:purpose,tenant_id:'alpha',sid:'installed-session',session_version:1,
   ...(purpose==='user'?{groups:['engineering']}:{device_id:'device-a'}),...(purpose==='device'?{managed:true,compliant:true,cnf:{'x5t#S256':thumbprint}}:{}),...(purpose==='provider'?{destination:'https://api.example.com',account:'enterprise',verified:true,logged_in:true,scopes:[]}:{})},'signer',signer.privateKey);
  const credentials={userToken:token('user'),deviceToken:token('device'),providerToken:token('provider')};let scans=0;
  const handler=createProtectHandler(runtime,{id:'provider',origin:'https://api.example.com'});runtime.handler=async(req,res)=>{scans++;if(!await handler(req,res)){res.writeHead(404);res.end();}};
  privacy=await listenPlatform(runtime,{key:tls.key,cert:tls.cert,clientCa:tls.cert},await port());
  const clientOptions={origin:'https://127.0.0.1:'+privacy.address().port,destinationId:'provider',tls:{ca:tls.cert,...tls},credentials:()=>credentials},client=new TextGatewayClient(clientOptions);
  const tools=[{name:'search',description:'Search trusted corpus',input_schema:{type:'object'}}],calls=[];let result='Public result';
  process.env[clientEnv]=randomBytes(32).toString('base64url');process.env[upstreamEnv]=randomBytes(32).toString('base64url');
  upstream=createServer({key:tls.key,cert:tls.cert},async(req,res)=>{
   let body='';for await(const b of req)body+=b;const rpc=JSON.parse(body);
   if(req.headers.authorization!=='Bearer '+process.env[upstreamEnv]){res.writeHead(403);res.end();return;}
   calls.push(rpc);res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({jsonrpc:'2.0',id:rpc.id,result:rpc.method==='tools/list'?{resultType:'complete',tools:tools.map(x=>({name:x.name,description:x.description,inputSchema:x.input_schema}))}:{resultType:'complete',content:[{type:'text',text:result}]}}));
  });await new Promise(r=>upstream.listen(0,'127.0.0.1',r));
  const manifest={schema_version:1,server_id:'server-a',sequence:1,issued_at:new Date(now-1000).toISOString(),expires_at:new Date(now+600000).toISOString(),tools};
  const config={stateDir:join(root,'gateway-state'),port:0,maxBodyBytes:65536,routingRequired:true,
   clients:[{id:'host',tenantId:'alpha',tokenSha256:createHash('sha256').update(process.env[clientEnv]).digest('hex'),allowedTools:{'server-a':['search']},probeTokenEnv:clientEnv}],
   servers:[{id:'server-a',tenantId:'alpha',url:'https://mcp.example.test/mcp',transport:'json',sessionMode:'stateless',protocolVersions:['2026-07-28'],upstreamAuthEnv:upstreamEnv,pinnedAddresses:['8.8.8.8'],signedManifest:{key_id:'publisher',manifest,signature_b64:sign(null,Buffer.from('AIDR-MCP-TOOL-MANIFEST-V1\npublisher\n'+canonical(manifest)),signer.privateKey).toString('base64')},trustedSigners:{publisher:signer.publicKey.export({format:'pem',type:'spki'})}}]};
  await t.test('private launcher resolves installed factory and enforces routing even if config tries to disable it',async()=>{
   const value=process.env[clientEnv];delete process.env[clientEnv];
   try{await assert.rejects(startPrivateMcpService({tenantId:'alpha',client:clientOptions,gateway:{...config,stateDir:join(root,'launcher-state'),routingRequired:false}}),/upstream_auth_unavailable/);}finally{process.env[clientEnv]=value;}
  });
  // ONLY transport/DNS is controlled: a real HTTPS sink accepts the isolated upstream token.
  // This does not assert public DNS or host-firewall deployment; production launcher has no overrides.
  gateway=createMcpGateway(config,{...mcpPrivacyGuards(client),lookup:async()=>['8.8.8.8'],pinnedFetch:({init})=>new Promise((resolve,reject)=>{
   const r=request('https://127.0.0.1:'+upstream.address().port+'/mcp',{method:init.method,headers:init.headers,ca:tls.cert,agent:false,signal:init.signal},res=>{const chunks=[];res.on('data',b=>chunks.push(b));res.on('end',()=>resolve(new Response(Buffer.concat(chunks),{status:res.statusCode,headers:{'content-type':res.headers['content-type']??'application/json'}})));res.on('error',reject);});r.on('error',reject);r.end(init.body);
  })});
  const address=await gateway.listen(),base='http://127.0.0.1:'+address.port;
  let rpcId=1;const rpc=async(method,params={})=>{const response=await fetch(base+'/mcp/server-a',{method:'POST',headers:{authorization:'Bearer '+process.env[clientEnv],'content-type':'application/json','mcp-protocol-version':'2026-07-28'},body:JSON.stringify({jsonrpc:'2.0',id:rpcId++,method,params:{...params,_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{},...params._meta}}})});return {status:response.status,body:await response.json()};};
  await rpc('tools/list');const quarantined=(await gateway.storeFor('alpha').read('server-a')).quarantine;assert(quarantined);
  await gateway.approve({tenantId:'alpha',serverId:'server-a',toolsetHash:createHash('sha256').update(canonical(tools)).digest('hex'),bindingSha256:quarantined.bindingSha256,approvedBy:'operator',reason:'Controlled connection regression'});
  await t.test('clean input and output cross both actual gateway and local mTLS scanner',async()=>{const before=scans,reply=await rpc('tools/call',{name:'search',arguments:{query:'Public query'}});assert.equal(reply.body.result.content[0].text,'Public result');assert(scans>before);assert(calls.some(x=>x.method==='tools/call'));});
  await t.test('PII in full envelope metadata never reaches the upstream',async()=>{const before=calls.length,reply=await rpc('tools/call',{name:'search',arguments:{query:'Public query'},_meta:{contact:'alice@example.com'}});assert(reply.body.error);assert.equal(calls.length,before);});
  await t.test('PII in output is withheld after upstream execution',async()=>{result='Email: alice@example.com';const reply=await rpc('tools/call',{name:'search',arguments:{query:'Public query'}});assert(reply.body.error);assert(!JSON.stringify(reply.body).includes('alice@example.com'));});
  await t.test('revoked durable privacy session blocks next call before upstream',async()=>{runtime.state.transaction(tx=>{const row=tx.get('sessions','installed-session');tx.put('sessions','installed-session',{...row.value,version:2,active:false},row.version);});const before=calls.length;const reply=await rpc('tools/call',{name:'search',arguments:{query:'Public query'}});assert(reply.body.error);assert.equal(calls.length,before);});
 }finally{
  await gateway?.close();for(const server of [privacy,upstream])if(server)await new Promise(r=>{server.closeAllConnections();server.close(r);});runtime?.close();
  for(const [name,value]of [[clientEnv,oldClient],[upstreamEnv,oldUpstream]])if(value===undefined)delete process.env[name];else process.env[name]=value;
  rmSync(root,{recursive:true,force:true});
 }
});
