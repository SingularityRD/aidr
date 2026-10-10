import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:https';
import {createHash,generateKeyPairSync,randomBytes,X509Certificate} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {existsSync,mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {ConfiguredSessionBroker,discoverJwtTrust} from '../../dist/platform/broker.js';
import {TextGatewayClient} from '../../dist/platform/client.js';
import {createPlatformRuntime,listenPlatform} from '../../dist/platform/runtime.js';
import {createEgressHandler} from '../../dist/platform/gateway-http.js';
import {EnforcedEgress} from '../../dist/platform/egress.js';
import {issueJwt} from '../../dist/platform/identity.js';
import {signPolicy} from '../../dist/enterprise/policy.js';
import {hash} from '../../dist/enterprise/util.js';
import {privateDirectory,pythonExecutable} from './helpers.mjs';
import {policy} from '../enterprise/helpers.mjs';
import {createProtectHandler} from '../../dist/platform/protect-http.js';
import {createDataHandler} from '../../dist/platform/data-http.js';
import {mcpPrivacyGuards} from '../../dist/platform/mcp-scanner-adapter.js';
import {startPrivateMcpService} from '../../dist/platform/mcp-service.js';

function certificate(root,name){
 const executable=join(process.env.ProgramFiles??'C:\\Program Files','Git','usr','bin','openssl.exe');
 const openssl=process.env.AIDR_OPENSSL??(process.platform==='win32'&&existsSync(executable)?executable:'openssl');
 const certPath=join(root,name+'.pem'),keyPath=join(root,name+'.key');
 execFileSync(openssl,['req','-x509','-newkey','rsa:2048','-nodes','-keyout',keyPath,'-out',certPath,'-days','1','-subj','/CN='+name,'-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore',windowsHide:true});
 return {cert:readFileSync(certPath),key:readFileSync(keyPath)};
}
const json=(res,v,status=200)=>{res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(v));};

test('configured OIDC/MDM broker and final client use real mTLS, JWKS, PKCE and durable lifecycle',async t=>{
 const root=mkdtempSync(join(tmpdir(),'aidr-broker-client-'));privateDirectory(root);
 let brokerServer,runtime,gateway,adapter,brokerHandle;const seen=[],calls=[];
 try{
  const tls=certificate(root,'gateway-broker-device'),other=certificate(root,'other-device');
  const signing=generateKeyPairSync('ed25519'),jwk={...signing.publicKey.export({format:'jwk'}),kid:'signer',use:'sig',alg:'EdDSA'};
  let origin,oidcIssuer,brokerIssuer,nonce,challenge,currentGrant,version=1,activeSid='session-a',wrongBinding=false,wrongIssuer=false,redirectJwks=false,wrongNonce=false,revokeFails=false,grantOverrides={};
  function grant(sid,certificateThumbprint,extra={}){
   const now=Math.floor(Date.now()/1000),sub=sid==='bootstrap'?'service-agent':'alice';
   const token=purpose=>issueJwt({iss:brokerIssuer,aud:'aidr-platform',sub,iat:now,exp:now+300,jti:randomBytes(16).toString('hex'),token_use:purpose,tenant_id:'alpha',sid,session_version:sid==='bootstrap'?1:version,
    ...(purpose==='user'?{groups:['engineering','admins'],oidc_iss:oidcIssuer,oidc_sub:'alice@example.com'}:{device_id:'device-a'}),
    ...(purpose==='device'?{managed:true,compliant:true,cnf:{'x5t#S256':wrongBinding?'wrong-certificate':certificateThumbprint}}:{}),
    ...(purpose==='provider'?{destination:'https://api.example.com',account:'enterprise',verified:true,logged_in:true,scopes:[]}:{}),...extra,...grantOverrides[purpose]},'signer',signing.privateKey);
   return {userToken:token('user'),deviceToken:token('device'),providerToken:token('provider')};
  }
  brokerServer=createServer({key:tls.key,cert:tls.cert,ca:tls.cert,requestCert:true,rejectUnauthorized:true},async(req,res)=>{
   calls.push(req.url);let body='';for await(const b of req)body+=b;
   if(req.url==='/oidc/.well-known/openid-configuration')return json(res,{issuer:wrongIssuer?'https://evil.example.com':oidcIssuer,jwks_uri:redirectJwks?'https://evil.example.com/jwks':origin+'/oidc/jwks',authorization_endpoint:origin+'/oidc/authorize',token_endpoint:origin+'/oidc/token'});
   if(req.url==='/broker/.well-known/openid-configuration')return json(res,{issuer:brokerIssuer,jwks_uri:origin+'/broker/jwks'});
   if(req.url?.endsWith('/jwks'))return json(res,{keys:[jwk]});
   if(req.url==='/oidc/token'){
    const form=new URLSearchParams(body);assert.equal(form.get('grant_type'),'authorization_code');assert.equal(form.get('code'),'verified-code');
    assert.equal(createHash('sha256').update(form.get('code_verifier')).digest('base64url'),challenge);
    assert.equal(req.headers.authorization,'Basic '+Buffer.from('app-client:'+clientSecret).toString('base64'));
    const now=Math.floor(Date.now()/1000);return json(res,{id_token:issueJwt({iss:oidcIssuer,aud:'app-client',sub:'alice@example.com',iat:now,exp:now+300,nonce:wrongNonce?'replayed-nonce':nonce},'signer',signing.privateKey)});
   }
   const data=JSON.parse(body||'{}');
   if(req.url==='/broker/v1/sessions/bootstrap')return json(res,grant('bootstrap',data.certificateThumbprint));
   if(req.url==='/broker/v1/sessions')return json(res,grant(activeSid,data.certificateThumbprint));
   if(req.url==='/broker/v1/sessions/refresh'){version++;return json(res,grant(activeSid,data.certificateThumbprint));}
   if(req.url==='/broker/v1/sessions/revoke')return json(res,{revoked:!revokeFails},revokeFails?503:200);
   return json(res,{error:'UNKNOWN'},404);
  });
  await new Promise(resolve=>brokerServer.listen(0,'127.0.0.1',resolve));origin='https://127.0.0.1:'+brokerServer.address().port;oidcIssuer=origin+'/oidc';brokerIssuer=origin+'/broker';
  const clientSecret=randomBytes(24).toString('hex');
  const config={oidc:{issuer:oidcIssuer,clientId:'app-client',clientSecret,redirectUri:'https://127.0.0.1/approved-callback',tls:{ca:tls.cert,...tls}},broker:{issuer:brokerIssuer,audience:'aidr-platform',destination:'https://api.example.com',tls:{ca:tls.cert,...tls}}};
  await t.test('issuer mismatch and cross-origin JWKS fail before key fetch',async()=>{
   wrongIssuer=true;await assert.rejects(discoverJwtTrust(oidcIssuer,'app-client',config.oidc.tls),/BROKER_ISSUER/);wrongIssuer=false;
   redirectJwks=true;await assert.rejects(discoverJwtTrust(oidcIssuer,'app-client',config.oidc.tls),/BROKER_ENDPOINT/);redirectJwks=false;
  });
  adapter=await ConfiguredSessionBroker.open(config);
  const now=Date.now(),p=policy({tenantId:'alpha',notBefore:now-1000,expiresAt:now+600000,destinations:[{...policy().destinations[0],id:'provider',origin:'https://api.example.com'}]});
  runtime=await createPlatformRuntime({tenantId:'alpha',databasePath:join(root,'control.sqlite'),encryption:{active:'k1',keys:[{id:'k1',key:randomBytes(32)}]},audit:{keyId:'a1',key:randomBytes(32)},
   identity:{user:adapter.trust,device:adapter.trust,provider:adapter.trust,roleGroups:{'security-admin':['admins']},scopes:[]},policy:{signed:signPolicy(p,'signer',signing.privateKey),keys:new Map([['signer',signing.publicKey]])},destinations:[],profile:'strict',dataPolicy:{keyId:'edm1',key:randomBytes(32)}});
  await t.test('malformed bootstrap groups cannot provision any durable session',async()=>{
   grantOverrides={user:{groups:['invalid group']}};
   await assert.rejects(adapter.initialize(runtime,new AbortController().signal));assert.equal(runtime.state.get('sessions','bootstrap'),null);
   grantOverrides={};adapter=await ConfiguredSessionBroker.open(config);
  });
  brokerHandle=await adapter.initialize(runtime,new AbortController().signal);runtime.identity.assertPrincipal(brokerHandle.principal);
  const egress=new EnforcedEgress({state:runtime.state,identity:runtime.identity,gate:()=>runtime.gate,policyEpoch:runtime.policyEpoch,destinations:[{id:'provider',kind:'openai-responses',model:'approved-model',origin:'https://api.example.com',transport:{async send(bytes,_signal,before){before?.();seen.push(Buffer.from(bytes));return {status:200,contentType:'application/json',body:Buffer.from(JSON.stringify({output:[{type:'message',role:'assistant',content:[{type:'output_text',text:'Reply to alice@example.com'}]}]}))};}}}]});
  const handler=createEgressHandler(egress,{allowImages:false,maxBodyBytes:524288}),protectHandler=createProtectHandler(runtime,{id:'provider',origin:'https://api.example.com'});
  const dataHandler=createDataHandler(runtime,{origin:'https://api.example.com'},{python:pythonExecutable(),workerSha256:createHash('sha256').update(readFileSync('parsers/worker.py')).digest('hex')},'silence-all');
  runtime.handler=async(req,res)=>{if(!await brokerHandle.handle(req,res)&&!await protectHandler(req,res)&&!await dataHandler(req,res))await handler(req,res);};
  // listenPlatform disallows port zero, so reserve a concrete ephemeral port without changing production API.
  const reservation=(await import('node:net')).createServer();await new Promise(r=>reservation.listen(0,'127.0.0.1',r));const port=reservation.address().port;await new Promise(r=>reservation.close(r));
  gateway=await listenPlatform(runtime,{key:tls.key,cert:tls.cert,clientCa:Buffer.concat([tls.cert,other.cert])},port,'127.0.0.1');
  const client=new TextGatewayClient({origin:'https://127.0.0.1:'+port,destinationId:'provider',tls:{ca:tls.cert,...tls},credentials:()=>currentGrant});
  await t.test('OIDC state is one-use and bound to actual enrolled certificate',async()=>{
   const begin=await client.session('begin');const url=new URL(begin.location);nonce=url.searchParams.get('nonce');challenge=url.searchParams.get('code_challenge');assert.equal(url.searchParams.get('code_challenge_method'),'S256');
   const another=new TextGatewayClient({origin:'https://127.0.0.1:'+port,destinationId:'provider',tls:{ca:tls.cert,...other},credentials:()=>currentGrant});
   assert.equal((await another.session('complete',{state:begin.state,code:'verified-code'})).error,'SESSION_DENIED');
   currentGrant=await client.session('complete',{state:begin.state,code:'verified-code'});assert.equal(typeof currentGrant.userToken,'string');
   assert.equal((await client.session('complete',{state:begin.state,code:'verified-code'})).error,'SESSION_DENIED');
   assert.equal(runtime.state.get('sessions','session-a').value.version,1);
  });
  await t.test('wrong OIDC nonce is withheld before MDM session creation',async()=>{
   const begin=await client.session('begin'),url=new URL(begin.location);nonce=url.searchParams.get('nonce');challenge=url.searchParams.get('code_challenge');
   const count=calls.filter(p=>p==='/broker/v1/sessions').length;wrongNonce=true;
   assert.equal((await client.session('complete',{state:begin.state,code:'verified-code'})).error,'SESSION_DENIED');wrongNonce=false;
   assert.equal(calls.filter(p=>p==='/broker/v1/sessions').length,count);assert.equal(runtime.state.get('sessions','session-a').value.version,1);
  });
  await t.test('invalid signed groups, scopes and revoked grants leave no initial session',async()=>{
   const attempts=[{user:{groups:['engineering','engineering']}},{provider:{scopes:['invalid scope']}}];
   for(const purpose of ['user','device','provider']){const jti='revoked-'+purpose;runtime.state.transaction(tx=>tx.put('revoked-jti',jti,true,null));attempts.push({[purpose]:{jti}});}
   let n=0;
   for(const override of attempts){activeSid='invalid-grant-'+ ++n;grantOverrides=override;const begin=await client.session('begin'),url=new URL(begin.location);nonce=url.searchParams.get('nonce');challenge=url.searchParams.get('code_challenge');assert.equal((await client.session('complete',{state:begin.state,code:'verified-code'})).error,'SESSION_DENIED');assert.equal(runtime.state.get('sessions',activeSid),null);}
   activeSid='session-a';grantOverrides={};
  });
  await t.test('client final send contains sanitized provider bytes and sanitized response',async()=>{
   const receipt=await client.send('Email: alice@example.com',{requestId:'broker-clean'});assert.equal(receipt.decision,'sent');assert.equal(receipt.outputText,'Reply to [EMAIL]');
   assert.equal(JSON.parse(seen[0]).input[0].content[0].text,'Email: [EMAIL]');assert(!seen[0].includes(Buffer.from('alice@example.com')));
  });
  await t.test('classified input is blocked with no second outbound call',async()=>{
   const receipt=await client.send('TOP SECRET',{requestId:'broker-block'});assert.equal(receipt.decision,'blocked');assert.equal(receipt.outputText,null);assert.equal(seen.length,1);
  });
  await t.test('main MCP guards bind metadata, deny redaction and never claim binary coverage or call provider',async()=>{
   const guards=mcpPrivacyGuards(client),payload={content:[{type:'text',text:'Public result'}]},text=JSON.stringify(payload);
   const context={payload,direction:'to_client',method:'tools/call',signal:new AbortController().signal,tenantId:'alpha',clientId:'host',serverId:'tool-server',requestId:7,inputSha256:'a'.repeat(64),payloadSha256:createHash('sha256').update(text).digest('hex'),runtime:'mcp-gateway',sessionId:'main-protocol-session',protocolVersion:'2025-03-26',toolsetHash:'b'.repeat(64)};
   const clean=await guards.outputGuard(context);assert.equal(clean.allowed,true);assert.equal(clean.coverage,'full');assert.equal(clean.opaqueInspected,false);
   const pii={content:[{type:'text',text:'Email: alice@example.com'}]};assert.equal((await guards.outputGuard({...context,payload:pii,payloadSha256:createHash('sha256').update(JSON.stringify(pii)).digest('hex')})).allowed,false);
   const envelope={jsonrpc:'2.0',id:7,method:'tools/call',params:{name:'public-tool',arguments:{message:'Public text'},_meta:{contact:'alice@example.com'}}};
   assert.equal((await guards.toolGuard({...context,direction:'to_upstream',payload:envelope,payloadSha256:createHash('sha256').update(JSON.stringify(envelope)).digest('hex')})).allowed,false);
   assert.equal((await guards.outputGuard({...context,tenantId:'other'})).allowed,false);assert.equal(seen.length,1);
  });
  await t.test('installed MCP launcher denies wrong tenant, oversized payload and missing real session before package/listener startup',async()=>{
   const clientConfig={origin:'https://127.0.0.1:'+port,destinationId:'provider',tls:{ca:tls.cert,...tls},credentials:()=>({userToken:'invalid',deviceToken:'invalid',providerToken:'invalid'})};
   const gatewayConfig={clients:[{tenantId:'alpha'}],servers:[{tenantId:'alpha'}]};
   await assert.rejects(startPrivateMcpService({tenantId:'other',client:clientConfig,gateway:gatewayConfig}),/MCP_TENANT_CONFIG/);
   await assert.rejects(startPrivateMcpService({tenantId:'alpha',client:clientConfig,gateway:{...gatewayConfig,maxBodyBytes:1048576}}),/MCP_BODY_LIMIT/);
   await assert.rejects(startPrivateMcpService({tenantId:'alpha',client:clientConfig,gateway:gatewayConfig}),/MCP_PRIVACY_UNAVAILABLE/);assert.equal(seen.length,1);
  });
  await t.test('real institution admin labels affect final send and DSPM ACL precedes content release',async()=>{
   const snapshot=[{id:'drawing',text:'Raven turbine production calibration parameters',groups:['engineering'],classification:'restricted'},{id:'public',text:'Shared operations information',groups:['engineering'],classification:'public'},{id:'private-acl',text:'Only accounting has access',groups:['accounting'],classification:'public'}];
   assert.equal((await client.synchronizeSource('approved-source',1,snapshot)).synchronized,true);
   assert.equal((await client.synchronizeSource('malformed-acl',1,[{...snapshot[1],groups:'engineering'}])).synchronized,undefined);assert.equal(runtime.state.get('dspm-sources','malformed-acl'),null);
   const denied=await client.send(snapshot[0].text,{requestId:'institution-label'});assert.equal(denied.decision,'blocked');assert.equal(denied.reason,'TEXT_POLICY');assert.equal(seen.length,1);
   assert.equal((await client.readSource('approved-source','public')).output,'Shared operations information');
   assert.equal((await client.readSource('approved-source','private-acl')).output,null);
   assert.equal((await client.readSource('approved-source','drawing')).output,null);
   assert.equal((await client.synchronizeSource('approved-source',1,snapshot)).synchronized,undefined);
   const userClaims=JSON.parse(Buffer.from(currentGrant.userToken.split('.')[1],'base64url')),nonAdmin={...currentGrant,userToken:issueJwt({...userClaims,groups:['engineering'],jti:randomBytes(16).toString('hex')},'signer',signing.privateKey)};
   const ordinary=new TextGatewayClient({origin:'https://127.0.0.1:'+port,destinationId:'provider',tls:{ca:tls.cert,...tls},credentials:()=>nonAdmin});
   assert.equal((await ordinary.synchronizeSource('unapproved-source',1,snapshot)).synchronized,undefined);assert.equal(runtime.state.get('dspm-sources','unapproved-source'),null);
  });
  await t.test('label update during asynchronous scanning denies the pending final dispatch',async()=>{
   const original=runtime.gate,principal=runtime.identity.authenticate(currentGrant.userToken);
   runtime.gate={async protect(text,context){const result=await original.protect(text,context);runtime.sources.replace(principal,'race-source',1,[{id:'r',text,groups:['engineering'],classification:'restricted'}],true);return result;}};
   try{const receipt=await client.send('Public calibration tolerance for manufacturing equipment',{requestId:'label-change-race'});assert.equal(receipt.decision,'blocked');assert.equal(receipt.reason,'POLICY_CHANGED');assert.equal(seen.length,1);}finally{runtime.gate=original;}
  });
  await t.test('document route uses real Linux parser and denies unsupported host without original output',async()=>{
   const document=await client.protectDocument(Buffer.from('Email: alice@example.com'),'txt');
   if(process.platform!=='linux'){assert.equal(document.output,null);assert.equal(seen.length,1);return;}
   assert.equal(document.output,'Email: [EMAIL]');assert.equal(document.mime,'text/plain');assert.equal(document.filename,'aidr-sanitized.txt');assert.equal(seen.length,1);
   for(const [file,kind]of [['simple.pdf','pdf'],['plain.docx','docx']]){const parsed=await client.protectDocument(readFileSync('fixtures/platform/'+file),kind);assert.equal(parsed.decision,'redact',parsed.reason);assert.equal(parsed.mime,'text/plain');assert.equal(typeof parsed.output,'string');assert(!parsed.output.includes('jane@example.com'));}
   const activeOffice=await client.protectDocument(readFileSync('fixtures/platform/simple.docx'),'docx');assert.equal(activeOffice.output,null);
   const unsupported=await client.protectDocument(Buffer.from('not a PDF'),'pdf');assert.equal(unsupported.output,null);assert.equal(seen.length,1);
  });
  await t.test('PCM audio route actually removes every sample and rejects unsupported compressed audio',async()=>{
   const wav=Buffer.alloc(46);wav.write('RIFF');wav.writeUInt32LE(38,4);wav.write('WAVEfmt ',8);wav.writeUInt32LE(16,16);wav.writeUInt16LE(1,20);wav.writeUInt16LE(1,22);wav.writeUInt32LE(8000,24);wav.writeUInt32LE(16000,28);wav.writeUInt16LE(2,32);wav.writeUInt16LE(16,34);wav.write('data',36);wav.writeUInt32LE(2,40);wav.writeInt16LE(22000,44);
   const result=await client.silenceAudio(wav);assert.equal(result.reason,'ALL_AUDIO_REMOVED');assert.equal(Buffer.from(result.output,'base64').readInt16LE(44),0);assert.equal(result.mime,'audio/wav');assert.equal(seen.length,1);
   assert.equal((await client.silenceAudio(Buffer.from('ID3 unsupported compressed audio'))).output,null);assert.equal(seen.length,1);
  });
  await t.test('refresh advances durable session and invalidates original credentials',async()=>{
   const old=currentGrant;currentGrant=await client.session('refresh');assert.equal(runtime.state.get('sessions','session-a').value.version,2);
   const replay=new TextGatewayClient({origin:'https://127.0.0.1:'+port,destinationId:'provider',tls:{ca:tls.cert,...tls},credentials:()=>old});
   assert.equal((await replay.send('Public text',{requestId:'broker-old'})).decision,'blocked');assert.equal(seen.length,1);
  });
  await t.test('revoke invalidates durable session before external response',async()=>{
   revokeFails=true;assert.equal((await client.session('revoke')).error,'SESSION_DENIED');assert.equal(runtime.state.get('sessions','session-a').value.active,false);
   assert.equal((await client.send('Public text',{requestId:'broker-revoked'})).decision,'blocked');assert.equal(seen.length,1);
  });
  await t.test('bad MDM refresh invalidates the exact prior lease and cannot revive revoked session',async()=>{
   activeSid='bad-refresh-session';version=1;const begin=await client.session('begin'),url=new URL(begin.location);nonce=url.searchParams.get('nonce');challenge=url.searchParams.get('code_challenge');
   currentGrant=await client.session('complete',{state:begin.state,code:'verified-code'});assert.equal(runtime.state.get('sessions',activeSid).value.active,true);
   wrongBinding=true;assert.equal((await client.session('refresh')).error,'SESSION_DENIED');wrongBinding=false;
   assert.equal(runtime.state.get('sessions',activeSid).value.active,false);assert.equal(runtime.state.get('sessions',activeSid).value.version,2);
   assert.equal((await client.send('Public text',{requestId:'bad-refresh-old-lease'})).decision,'blocked');assert.equal(seen.length,1);
  });
  await t.test('malformed signed refresh cannot leave its newly provisioned version active',async()=>{
   activeSid='invalid-user-refresh';version=1;const begin=await client.session('begin'),url=new URL(begin.location);nonce=url.searchParams.get('nonce');challenge=url.searchParams.get('code_challenge');currentGrant=await client.session('complete',{state:begin.state,code:'verified-code'});assert.equal(runtime.state.get('sessions',activeSid).value.version,1);
   grantOverrides={user:{groups:['engineering','engineering']}};assert.equal((await client.session('refresh')).error,'SESSION_DENIED');grantOverrides={};const row=runtime.state.get('sessions',activeSid);assert.equal(row.value.active,false);assert.equal(row.value.version,2);
  });
  assert(calls.includes('/oidc/token'));assert(calls.includes('/broker/v1/sessions/revoke'));
 }finally{
  await brokerHandle?.close();for(const server of [gateway,brokerServer])if(server)await new Promise(resolve=>{server.closeAllConnections();server.close(resolve);});runtime?.close();rmSync(root,{recursive:true,force:true});
 }
});
