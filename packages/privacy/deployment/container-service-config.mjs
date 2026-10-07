/** Executable service configuration for the optional privacy gateway container image
 * (deploy/privacy-gateway). It accepts the same administrator JSON as
 * examples/platform/service-config.mjs with one deliberate difference: a container has no
 * OS vault, so every *Ref names a file the orchestrator mounts under SECRET_ROOT (Docker
 * Compose secrets or a Kubernetes Secret volume). The JSON still holds references and
 * paths only. The layout is fixed so a configuration cannot point the service at an
 * arbitrary file inside the image. Errors carry fixed codes; serve.js never prints them. */
import {readFileSync, statSync} from 'node:fs';
import {isAbsolute, normalize} from 'node:path';
import {createPublicKey} from 'node:crypto';
import {ConfiguredSessionBroker} from '@singularityrd/aidr-privacy/platform';

const L = Object.freeze({
 config: '/etc/aidr-privacy/config/service.json',
 secrets: '/run/secrets/aidr-privacy',
 trust: '/etc/aidr-privacy',
 models: '/opt/aidr-models',
 state: '/var/lib/aidr-privacy',
 nerPython: '/opt/aidr-ner/bin/python3',
 tlsCert: '/etc/aidr-privacy/tls/server.pem',
 tlsClientCa: '/etc/aidr-privacy/tls/client-ca.pem',
 tlsKeyRef: 'aidr-privacy-tls-key',
 port: 8443,
});
const fail = code => {throw new Error(code);};
const REF = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const within = (path, rootDir) => typeof path === 'string' && isAbsolute(path) && normalize(path) === path && path.startsWith(rootDir + '/') && !path.split('/').includes('..');
// statSync, not lstatSync: Kubernetes Secret and ConfigMap volumes expose each key as a
// symbolic link into an atomically swapped data directory inside the same mount.
const regular = path => {const info = statSync(path); if (!info.isFile() || info.size === 0 || info.size > 1048576) fail('SERVICE_FILE_INVALID'); return readFileSync(path);};

const path = process.env.AIDR_PRIVACY_CONFIG;
if (path !== L.config) fail('SERVICE_CONFIG_PATH');
const config = JSON.parse(regular(path).toString('utf8'));
if (config.secretStore !== 'mounted-files') fail('SERVICE_SECRET_STORE');
if (!['0.0.0.0', '::'].includes(config.host) || config.port !== L.port) fail('SERVICE_LISTEN_CONFIG');
if (!within(config.databasePath, L.state)) fail('SERVICE_STATE_PATH');
if (config.documents !== undefined) fail('SERVICE_DOCUMENTS_NOT_PACKAGED');
if (config.ner?.python !== L.nerPython || !within(config.ner?.manifest, L.models)) fail('SERVICE_MODEL_CONFIG');
if (config.tls?.certPath !== L.tlsCert || config.tls?.clientCaPath !== L.tlsClientCa || config.tls?.keyRef !== L.tlsKeyRef) fail('SERVICE_TLS_CONFIG');

// Mounted secrets: one regular file per reference. A single trailing newline (as written by
// most secret tooling) is not part of the value.
const secret = ref => {if (typeof ref !== 'string' || !REF.test(ref)) fail('SERVICE_SECRET_REF'); const s = regular(`${L.secrets}/${ref}`).toString('utf8').replace(/\r?\n$/, ''); if (!s) fail('SERVICE_SECRET_MISSING'); return s;};
const key32 = ref => {const s = secret(ref), b = Buffer.from(s, 'base64'); if (b.length !== 32 || b.toString('base64') !== s) fail('SERVICE_KEY_INVALID'); return b;};
const file = p => {if (!within(p, L.trust) && !within(p, L.models)) fail('SERVICE_CONFIG_PATH'); return regular(p);};

const broker = await ConfiguredSessionBroker.open({
 oidc: {...config.oidc, clientSecret: secret(config.oidc.clientSecretRef), tls: {ca: file(config.oidc.caPath)}},
 broker: {issuer: config.broker.issuer, audience: config.broker.audience, destination: config.destination.origin,
  tls: {ca: file(config.broker.caPath), cert: file(config.broker.certPath), key: Buffer.from(secret(config.broker.keyRef))}},
}, AbortSignal.timeout(30000));
const destination = config.destination;
if (destination.origin !== (destination.kind === 'openai-responses' ? 'https://api.openai.com' : destination.kind === 'gemini-generate-content' ? 'https://generativelanguage.googleapis.com' : null)) fail('SERVICE_DESTINATION');
export default {
 runtime: {tenantId: config.tenantId, databasePath: config.databasePath,
  encryption: {active: config.encryption.active, keys: config.encryption.keys.map(k => ({id: k.id, key: key32(k.secretRef)}))},
  audit: {keyId: config.audit.keyId, key: key32(config.audit.secretRef)},
  ...(config.dataPolicy ? {dataPolicy: {keyId: config.dataPolicy.keyId, key: key32(config.dataPolicy.secretRef)}} : {}),
  identity: {user: broker.trust, device: broker.trust, provider: broker.trust, roleGroups: config.roleGroups, scopes: config.scopes},
  policy: {signed: JSON.parse(file(config.policy.signedPath).toString('utf8')), keys: new Map(config.policy.keys.map(k => [k.id, createPublicKey(file(k.path))]))},
  destinations: [{id: destination.id, kind: destination.kind, model: destination.model, apiKey: secret(destination.secretRef)}]},
 ner: {python: L.nerPython, manifest: config.ner.manifest, manifestSha256: config.ner.manifestSha256, ...(config.ner.startupTimeoutMs ? {startupTimeoutMs: config.ner.startupTimeoutMs} : {})},
 ...(config.audioMode ? {audioMode: config.audioMode} : {}),
 tls: {key: Buffer.from(secret(L.tlsKeyRef)), cert: file(L.tlsCert), clientCa: file(L.tlsClientCa)},
 initializeBroker: (runtime, signal) => broker.initialize(runtime, signal), host: config.host, port: config.port,
};
