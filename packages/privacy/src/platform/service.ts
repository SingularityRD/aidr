import { createSecureContext } from 'node:tls';
import { X509Certificate, createHash } from 'node:crypto';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isIP } from 'node:net';
import { statSync,readFileSync } from 'node:fs';
import {parseJsonStrict} from '../json.js';
import {createProtectHandler} from './protect-http.js';
import {createDataHandler} from './data-http.js';
import {DocumentCdr} from './documents.js';
import { PrivacyEngine } from '../engine.js';
import { LocalNerProcess } from '../ner-process.js';
import { deny, object } from '../enterprise/util.js';
import type { AuthenticatedPrincipal } from './identity.js';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createEgressHandler } from './gateway-http.js';
import { createPlatformRuntime, listenPlatform, type RuntimeOptions } from './runtime.js';

type Runtime = Awaited<ReturnType<typeof createPlatformRuntime>>;
/** Administrator-owned executable configuration, never supplied by an HTTP caller.
 * This service supports one tenant, one fixed provider, bounded text and no streaming. */
export interface TextServiceOptions {
  runtime: Omit<RuntimeOptions, 'ner' | 'profile' | 'clock'>;
  ner: { python: string; manifest: string; manifestSha256: string; startupTimeoutMs?: number };
  documents?:{python:string;workerSha256:string};
  audioMode?:'silence-all';
  tls: { key: Buffer; cert: Buffer; clientCa: Buffer };
  /** The real broker provisions a durable session and authenticates its signed bootstrap token.
   * Return the principal from runtime.identity.authenticate(), never a JSON principal. */
  initializeBroker: (runtime: Runtime, signal: AbortSignal) => Promise<{principal: AuthenticatedPrincipal; close: () => void | Promise<void>; handle?: (req:IncomingMessage,res:ServerResponse)=>Promise<boolean>}>;
  port?: number;
  host?: string;
}

export async function startTextService(options: TextServiceOptions, signal?: AbortSignal) {
  signal?.throwIfAborted();
  object(options, ['runtime', 'ner', 'tls', 'initializeBroker', 'port', 'host','documents','audioMode']);
  if(options.audioMode!==undefined&&options.audioMode!=='silence-all')deny('ASR_REQUIRED');
  object(options.runtime, ['tenantId', 'databasePath', 'encryption', 'audit', 'identity', 'policy', 'destinations','dataPolicy']);
  object(options.ner, ['python', 'manifest', 'manifestSha256', 'startupTimeoutMs']);
  if (typeof options.initializeBroker !== 'function' || !isAbsolute(options.runtime.databasePath)
      || !Array.isArray(options.runtime.destinations) || options.runtime.destinations.length !== 1
      || typeof options.runtime.destinations[0]?.apiKey !== 'string' || !options.runtime.destinations[0].apiKey.trim()) deny('SERVICE_CONFIG');
  const host = options.host ?? '127.0.0.1', port = options.port ?? 8443;
  if (!isIP(host) || !Number.isInteger(port) || port < 1 || port > 65535) deny('SERVICE_LISTEN_CONFIG');
  for (const path of [options.ner.python, options.ner.manifest]) {
    if (typeof path !== 'string' || !isAbsolute(path) || !statSync(path).isFile()) deny('SERVICE_MODEL_CONFIG');
  }
  if (!/^[a-f0-9]{64}$/.test(options.ner.manifestSha256)) deny('SERVICE_MODEL_CONFIG');
  const manifestBytes=readFileSync(options.ner.manifest);
  if(createHash('sha256').update(manifestBytes).digest('hex')!==options.ner.manifestSha256)deny('SERVICE_MODEL_DIGEST_MISMATCH');
  const manifest=parseJsonStrict(manifestBytes.toString('utf8'),16,4096);
  if(!manifest||typeof manifest!=='object'||Array.isArray(manifest)||manifest.approved!==true||manifest.qualificationStatus!=='qualified')deny('SERVICE_MODEL_APPROVAL_REQUIRED');
  object(options.tls, ['key', 'cert', 'clientCa']);
  for (const name of ['key', 'cert', 'clientCa'] as const) if (!Buffer.isBuffer(options.tls[name]) || !options.tls[name].length) deny('SERVICE_TLS_CONFIG');
  const clientCa = new X509Certificate(options.tls.clientCa), certificate = new X509Certificate(options.tls.cert), now = Date.now();
  if (!clientCa.ca || [clientCa, certificate].some(c => now < Date.parse(c.validFrom) || now >= Date.parse(c.validTo))) deny('SERVICE_TLS_CONFIG');
  createSecureContext({key: options.tls.key, cert: options.tls.cert, ca: options.tls.clientCa, minVersion: 'TLSv1.2'});

  let ner: LocalNerProcess | undefined, runtime: Runtime | undefined, server: Awaited<ReturnType<typeof listenPlatform>> | undefined;
  let broker: Awaited<ReturnType<TextServiceOptions['initializeBroker']>> | undefined;
  const abortWorker = () => ner?.close(); signal?.addEventListener('abort', abortWorker, {once: true});
  try {
    // Only the bundled offline worker is launched; arbitrary process adapters are outside this profile.
    ner = await LocalNerProcess.open({command: options.ner.python, args: [fileURLToPath(new URL('../../ner/ner_worker.py', import.meta.url)),
      '--manifest', options.ner.manifest, '--manifest-sha256', options.ner.manifestSha256], startupTimeoutMs: options.ner.startupTimeoutMs ?? 120000}, signal);
    signal?.throwIfAborted();
    const readiness = new PrivacyEngine({profile: 'defense', ner});
    try {
      const result = await readiness.protect('readiness');
      if (result.decision !== 'allow' || result.output !== 'readiness') deny('SERVICE_MODEL_NOT_READY');
    } finally { readiness.dispose(); }
    signal?.throwIfAborted();
    runtime = await createPlatformRuntime({...options.runtime, ner, profile: 'defense'});
    const brokerSignal = signal ? AbortSignal.any([signal, AbortSignal.timeout(30000)]) : AbortSignal.timeout(30000);
    const brokerTask = Promise.resolve().then(() => options.initializeBroker(runtime!, brokerSignal));
    let abortBroker!: () => void;
    const cancelled = new Promise<never>((_, reject) => {abortBroker = () => reject(new Error('SERVICE_BROKER_NOT_READY'));});
    brokerSignal.addEventListener('abort', abortBroker, {once: true});
    try {
      brokerSignal.throwIfAborted();
      broker = await Promise.race([brokerTask, cancelled]);
    } catch (error) {
      // A late callback completion owns resources even though startup has already failed.
      brokerTask.then(value => value?.close?.()).catch(() => {});
      throw error;
    } finally {brokerSignal.removeEventListener('abort', abortBroker);}
    if (!broker || typeof broker.close !== 'function') deny('SERVICE_BROKER_NOT_READY');
    signal?.throwIfAborted();
    runtime.identity.assertPrincipal(broker.principal);
    if(options.documents){
      object(options.documents,['python','workerSha256']);
      const cdr=new DocumentCdr({...options.documents,worker:fileURLToPath(new URL('../../parsers/worker.py',import.meta.url)),protector:{protect:async(text)=>({decision:'allow',output:text})}});
      const result=await cdr.protect(Buffer.from('readiness'),'txt');if(result.output?.toString('utf8')!=='readiness')deny('SERVICE_DOCUMENT_PARSER_NOT_READY');
      signal?.throwIfAborted();
    }
    const egressHandler=createEgressHandler(runtime.egress, {allowImages: false, maxBodyBytes: 524288}),brokerHandler=broker.handle;
    const destination=options.runtime.destinations[0]!,protectHandler=createProtectHandler(runtime,{id:destination.id,origin:destination.kind==='openai-responses'?'https://api.openai.com':'https://generativelanguage.googleapis.com'});
    const dataHandler=createDataHandler(runtime,{origin:destination.kind==='openai-responses'?'https://api.openai.com':'https://generativelanguage.googleapis.com'},options.documents,options.audioMode);
    runtime.handler = async(req,res)=>{try{if(brokerHandler&&await brokerHandler(req,res))return;if(await protectHandler(req,res))return;if(await dataHandler(req,res))return;await egressHandler(req,res);}catch{res.destroy();}};
    runtime.identity.assertPrincipal(broker.principal);
    server = await listenPlatform(runtime, options.tls, port, host);
    signal?.throwIfAborted();
    const activeRuntime = runtime, activeNer = ner, activeBroker = broker, activeServer = server;
    let closing: Promise<void> | undefined;
    return {server: activeServer, close(): Promise<void> {
      return closing ??= (async () => {
        try {
          await new Promise<void>((resolve, reject) => {
            const timer = setTimeout(() => activeServer.closeAllConnections(), 10000); timer.unref();
            activeServer.close(error => {clearTimeout(timer); error ? reject(error) : resolve();});
          });
        } finally {try {await activeBroker.close();} finally {try {activeRuntime.close();} finally {activeNer.close();}}}
      })();
    }};
  } catch (error) {
    if (server) {server.closeAllConnections(); await new Promise<void>(resolve => server!.close(() => resolve()));}
    try {await broker?.close();} finally {try {runtime?.close();} finally {ner?.close();}}
    throw error;
  } finally {signal?.removeEventListener('abort', abortWorker);}
}
