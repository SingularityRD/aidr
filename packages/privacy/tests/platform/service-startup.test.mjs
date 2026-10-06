import test, {mock} from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync, spawnSync} from 'node:child_process';
import {generateKeyPairSync, createHash, X509Certificate, randomBytes} from 'node:crypto';
import {existsSync, mkdtempSync, readFileSync, writeFileSync, rmSync} from 'node:fs';
import {createServer} from 'node:net';
import {request} from 'node:https';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {LocalNerProcess} from '../../dist/ner-process.js';
import {startTextService} from '../../dist/platform/service.js';
import {issueJwt, provisionSession} from '../../dist/platform/identity.js';
import {signPolicy} from '../../dist/enterprise/policy.js';
import {policy} from '../enterprise/helpers.mjs';
import {privateDirectory} from './helpers.mjs';

async function port() {
  const server = createServer();
  await new Promise((resolve, reject) => {server.once('error', reject); server.listen(0, '127.0.0.1', resolve);});
  const value = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return value;
}

test('text service startup: required trust inputs, authenticated principal, cancellation and defense profile', async t => {
  const root = mkdtempSync(join(tmpdir(), 'aidr-service-start-')); privateDirectory(root);
  const gitOpenSsl = join(process.env.ProgramFiles ?? 'C:\\Program Files', 'Git', 'usr', 'bin', 'openssl.exe');
  const openssl = process.env.AIDR_OPENSSL ?? (process.platform === 'win32' && existsSync(gitOpenSsl) ? gitOpenSsl : 'openssl');
  const certPath = join(root, 'tls.pem'), keyPath = join(root, 'tls.key');
  execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', certPath,
    '-days', '1', '-subj', '/CN=service-test', '-addext', 'subjectAltName=IP:127.0.0.1'], {stdio: 'ignore', windowsHide: true});
  const cert = readFileSync(certPath), tls = {cert, key: readFileSync(keyPath), clientCa: cert};
  const manifest = join(root, 'unqualified-test-manifest.json'); writeFileSync(manifest, '{}');
  const keys = generateKeyPairSync('ed25519'), now = Date.now(), seconds = Math.floor(now / 1000);
  const trust = {issuer: 'https://test-issuer.example.com', audience: 'aidr', keys: new Map([['signer', keys.publicKey]])};
  let next = 0;
  const options = () => ({runtime: {tenantId: 'tenant-a', databasePath: join(root, 'state-' + ++next + '.sqlite'),
    encryption: {active: 'k1', keys: [{id: 'k1', key: Buffer.alloc(32, 18)}]}, audit: {keyId: 'audit1', key: Buffer.alloc(32, 22)},
    identity: {user: trust, device: trust, provider: trust, roleGroups: {}, scopes: []},
    policy: {signed: signPolicy(policy({notBefore: now - 1000, expiresAt: now + 600000,
      destinations: [{...policy().destinations[0], id: 'provider', origin: 'https://api.openai.com'}]}), 'signer', keys.privateKey), keys: trust.keys},
    destinations: [{id: 'provider', kind: 'openai-responses', model: 'approved-model', apiKey: randomBytes(24).toString('hex')}]},
    ner: {python: process.execPath, manifest, manifestSha256: 'a'.repeat(64), startupTimeoutMs: 1000}, tls,
    initializeBroker: async () => {throw new Error('TEST_BROKER_SHOULD_NOT_RUN');}});
  const realOpen = LocalNerProcess.open.bind(LocalNerProcess);
  let model;
  const modelFixture = () => mock.method(LocalNerProcess, 'open', async (config, signal) => {
    assert.equal(config.command, process.execPath);
    assert.equal(config.args[0], resolve('ner/ner_worker.py'));
    assert.deepEqual(config.args.slice(1), ['--manifest', manifest, '--manifest-sha256', 'a'.repeat(64)]);
    // Deterministic child-process fixture, not real learned-model qualification.
    model = await realOpen({command: process.execPath, args: [resolve('tests/fixtures/mock-ner.mjs')], startupTimeoutMs: 1000}, signal);
    return model;
  });
  const token = (purpose, extra = {}) => issueJwt({iss: trust.issuer, aud: trust.audience, sub: 'alice', iat: seconds,
    exp: seconds + 300, jti: purpose + '-test', token_use: purpose, tenant_id: 'tenant-a', sid: 'session', session_version: 1,
    ...(purpose === 'user' ? {groups: ['engineering']} : {device_id: 'device'}), ...extra}, 'signer', keys.privateKey);
  try {
    for (const name of ['key', 'cert', 'clientCa']) await t.test('missing TLS ' + name + ' fails before model launch', async () => {
      const config = options(); config.tls = {...tls}; delete config.tls[name];
      await assert.rejects(startTextService(config), /SERVICE_TLS_CONFIG/);
    });
    await t.test('missing broker, provider credential and strict override cannot start', async () => {
      const config = options(); delete config.initializeBroker;
      await assert.rejects(startTextService(config), /SERVICE_CONFIG/);
      const emptyKey = options(); emptyKey.runtime.destinations[0].apiKey = '';
      await assert.rejects(startTextService(emptyKey), /SERVICE_CONFIG/);
      const strict = options(); strict.runtime.profile = 'strict';
      await assert.rejects(startTextService(strict));
      const missingModel = options(); missingModel.ner.manifest = join(root, 'absent-model.json');
      await assert.rejects(startTextService(missingModel));
    });
    await t.test('unloadable bundled worker fails before listener/broker', async () => {
      // Node cannot execute the Python worker. This deliberately unavailable inference environment must not start.
      await assert.rejects(startTextService(options()), /NER_STARTUP_FAILURE/);
    });
    await t.test('downloaded unqualified candidate cannot start production listener',async()=>{
      writeFileSync(manifest,JSON.stringify({approved:false,qualificationStatus:'independent-corpus-required'}));
      try{await assert.rejects(startTextService(options()),/SERVICE_MODEL_APPROVAL_REQUIRED/);}finally{writeFileSync(manifest,'{}');}
    });
    const mocked = modelFixture();
    await t.test('signed token without a provisioned durable session fails startup and closes worker', async () => {
      const config = options(); config.initializeBroker = async runtime => ({principal: runtime.identity.authenticate(token('user')), close() {}});
      await assert.rejects(startTextService(config), /AUTH_SESSION_REVOKED/);
      await assert.rejects(model.detect('readiness', new AbortController().signal), /NER_UNAVAILABLE/);
    });
    await t.test('fabricated principal fails startup and closes broker/worker', async () => {
      let closed = 0; const config = options(); config.initializeBroker = async () => ({principal: {}, close() {closed++;}});
      await assert.rejects(startTextService(config), /AUTH_PRINCIPAL_REQUIRED/);
      assert.equal(closed, 1);
      await assert.rejects(model.detect('readiness', new AbortController().signal), /NER_UNAVAILABLE/);
    });
    await t.test('broker cancellation closes worker and a late returned broker', async () => {
      const controller = new AbortController(); let begun, finish, closed = 0;
      const called = new Promise(resolve => {begun = resolve;}), config = options();
      config.initializeBroker = async (runtime, signal) => {assert.equal(signal.aborted, false); begun(); return new Promise(resolve => {finish = resolve;});};
      const starting = startTextService(config, controller.signal); await called; controller.abort();
      await assert.rejects(starting, /SERVICE_BROKER_NOT_READY/);
      finish({principal: {}, close() {closed++;}}); await new Promise(resolve => setImmediate(resolve));
      assert.equal(closed, 1);
      await assert.rejects(model.detect('readiness', new AbortController().signal), /NER_UNAVAILABLE/);
    });
    await t.test('authenticated bootstrap starts actual mTLS listener and defense blocks API secret; close is idempotent', async () => {
      let closed = 0; const config = options(); config.port = await port();
      config.initializeBroker = async runtime => {
        provisionSession(runtime.state, {subjectId: 'alice', sessionId: 'session', version: 1, deviceId: 'device', active: true, expiresAt: now + 600000});
        return {principal: runtime.identity.authenticate(token('user')), close() {closed++;}};
      };
      const service = await startTextService(config);
      try {
        assert.equal(service.server.listening, true);
        const fingerprint = createHash('sha256').update(new X509Certificate(cert).raw).digest('base64url');
        const reply = await new Promise((resolve, reject) => {
          const req = request(`https://127.0.0.1:${config.port}/v1/egress`, {method: 'POST', ca: cert, key: tls.key, cert, agent: false,
            headers: {'content-type': 'application/json', authorization: 'Bearer ' + token('user'),
              'x-aidr-device': token('device', {managed: true, compliant: true, cnf: {'x5t#S256': fingerprint}}),
              'x-aidr-provider': token('provider', {destination: 'https://api.openai.com', account: 'enterprise', verified: true, logged_in: true})}}, res => {
            let body = ''; res.on('data', data => {body += data;}); res.on('end', () => resolve({status: res.statusCode, body: JSON.parse(body)})); res.on('error', reject);
          });
          req.on('error', reject); req.setTimeout(5000, () => req.destroy());
          req.end(JSON.stringify({requestId: 'secret-block', destinationId: 'provider', text: 'API key: ' + ['sk', randomBytes(24).toString('hex')].join('-')}));
        });
        assert.equal(reply.status, 403); assert.equal(reply.body.reason, 'TEXT_POLICY'); assert.equal(reply.body.output, null);
      } finally {await service.close(); await service.close();}
      assert.equal(closed, 1); assert.equal(service.server.listening, false);
      await assert.rejects(model.detect('readiness', new AbortController().signal), /NER_UNAVAILABLE/);
    });
    mocked.mock.restore();
    await t.test('launcher logs fixed startup code without the missing configuration path', () => {
      const result = spawnSync(process.execPath, ['dist/platform/serve.js', '--config', join(root, 'secret-config-name.mjs')], {encoding: 'utf8'});
      assert.equal(result.status, 1); assert.equal(result.stdout, '');
      // Node 22.16 also emits its own static SQLite experimental warning when importing the runtime.
      assert.match(result.stderr, /SERVICE_START_FAILED\r?\n$/);
      assert(!result.stderr.includes('secret-config-name')); assert(!result.stderr.includes(root));
    });
  } finally {mock.restoreAll(); model?.close(); rmSync(root, {recursive: true, force: true});}
});
