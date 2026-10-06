import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash, generateKeyPairSync, X509Certificate, randomBytes} from 'node:crypto';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {request} from 'node:https';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {signPolicy} from '../../dist/enterprise/policy.js';
import {EnforcedEgress} from '../../dist/platform/egress.js';
import {createEgressHandler} from '../../dist/platform/gateway-http.js';
import {issueJwt, provisionSession} from '../../dist/platform/identity.js';
import {createPlatformRuntime, listenPlatform} from '../../dist/platform/runtime.js';
import {hash} from '../../dist/enterprise/util.js';
import {policy} from '../enterprise/helpers.mjs';
import {NOW, privateDirectory} from './helpers.mjs';

function certificate(root, name) {
  const gitOpenSsl = join(process.env.ProgramFiles ?? 'C:\\Program Files', 'Git', 'usr', 'bin', 'openssl.exe');
  const openssl = process.env.AIDR_OPENSSL ?? (process.platform === 'win32' && existsSync(gitOpenSsl) ? gitOpenSsl : 'openssl');
  const certPath = join(root, name + '.pem'), keyPath = join(root, name + '.key');
  execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', certPath,
    '-days', '1', '-subj', '/CN=' + name, '-addext', 'subjectAltName=IP:127.0.0.1'], {stdio: 'ignore', windowsHide: true});
  const cert = readFileSync(certPath);
  return {cert, key: readFileSync(keyPath), fingerprint: createHash('sha256').update(new X509Certificate(cert).raw).digest('base64url')};
}

async function availablePort() {
  const reservation = createServer();
  await new Promise((resolve, reject) => { reservation.once('error', reject); reservation.listen(0, '127.0.0.1', resolve); });
  const port = reservation.address().port;
  await new Promise((resolve, reject) => reservation.close(error => error ? reject(error) : resolve()));
  return port;
}

function post(url, serverCertificate, client, credentials, requestId, text, omitHeader, fields = {}) {
  const headers = {'content-type': 'application/json', authorization: 'Bearer ' + credentials.userToken,
    'x-aidr-device': credentials.deviceToken, 'x-aidr-provider': credentials.providerToken};
  if (omitHeader) delete headers[omitHeader];
  return new Promise((resolve, reject) => {
    const req = request(url, {method: 'POST', ca: serverCertificate, ...(client ? {cert: client.cert, key: client.key} : {}),
      rejectUnauthorized: true, agent: false, headers}, res => {
      let data = '';
      res.on('data', bytes => { data += bytes; });
      res.on('end', () => { try { resolve({status: res.statusCode, headers: res.headers, body: JSON.parse(data)}); } catch (error) { reject(error); } });
      res.on('error', reject);
    });
    req.on('error', reject);
    req.setTimeout(5000, () => req.destroy(new Error('TEST_REQUEST_TIMEOUT')));
    req.end(JSON.stringify({requestId, destinationId: 'provider', text, ...fields}));
  });
}

test('service mTLS boundary: strict rules-only TEST runtime protects real HTTP requests before controlled sink', async t => {
  const root = mkdtempSync(join(tmpdir(), 'aidr-service-mtls-'));
  privateDirectory(root);
  let runtime, server;
  try {
    const serverTls = certificate(root, 'server'), device = certificate(root, 'device'), otherDevice = certificate(root, 'other-device');
    const signing = generateKeyPairSync('ed25519');
    const trust = {issuer: 'https://identity.example.com', audience: 'aidr-platform', keys: new Map([['signer', signing.publicKey]])};
    const signedPolicy = policy({tenantId: 'alpha', destinations: [{...policy().destinations[0], id: 'provider', origin: 'https://api.example.com'}]});
    // TEST profile proves rule and transport enforcement; it does not qualify learned TR/EN PERSON+ADDRESS coverage.
    runtime = await createPlatformRuntime({tenantId: 'alpha', databasePath: join(root, 'control.sqlite'),
      encryption: {active: 'k1', keys: [{id: 'k1', key: Buffer.alloc(32, 18)}]}, audit: {keyId: 'audit1', key: Buffer.alloc(32, 22)},
      identity: {user: trust, device: trust, provider: trust, roleGroups: {}, scopes: []},
      policy: {signed: signPolicy(signedPolicy, 'signer', signing.privateKey), keys: trust.keys},
      destinations: [], profile: 'strict', clock: () => NOW});
    provisionSession(runtime.state, {sessionId: 'active-session', subjectId: 'alice', version: 1,
      deviceId: 'managed-device', active: true, expiresAt: NOW + 60000}, NOW);

    function credentials(sessionId = 'active-session') {
      const token = purpose => issueJwt({iss: trust.issuer, aud: trust.audience, sub: 'alice', iat: NOW / 1000,
        exp: NOW / 1000 + 60, jti: purpose + '-' + sessionId, token_use: purpose, tenant_id: 'alpha', sid: sessionId, session_version: 1,
        ...(purpose === 'user' ? {groups: ['engineering']} : {device_id: 'managed-device'}),
        ...(purpose === 'device' ? {managed: true, compliant: true, cnf: {'x5t#S256': device.fingerprint}} : {}),
        ...(purpose === 'provider' ? {destination: 'https://api.example.com', account: 'enterprise', verified: true, logged_in: true, scopes: []} : {})
      }, 'signer', signing.privateKey);
      return {userToken: token('user'), deviceToken: token('device'), providerToken: token('provider')};
    }

    const seen = [];
    // Only the outbound transport is controlled. The actual runtime identity, signed policy, durable state and privacy gate remain in this path.
    const egress = new EnforcedEgress({state: runtime.state, identity: runtime.identity, gate: () => runtime.gate,
      policyEpoch: () => hash(runtime.registry.active(NOW)), clock: () => NOW,
      destinations: [{id: 'provider', origin: 'https://api.example.com', kind: 'openai-responses', model: 'approved-model',
        transport: {async send(bytes, signal, beforeDispatch) {
          await Promise.resolve();
          beforeDispatch?.();
          seen.push(Buffer.from(bytes));
          return {status: 200, contentType: 'application/json', body: Buffer.from(JSON.stringify({output: [{type: 'message', role: 'assistant',
            content: [{type: 'output_text', text: 'Reply to bob@example.com'}]}]}))};
        }}
      }]});
    runtime.handler = createEgressHandler(egress, {allowImages: false, maxBodyBytes: 524288});
    server = await listenPlatform(runtime, {key: serverTls.key, cert: serverTls.cert, clientCa: Buffer.concat([device.cert, otherDevice.cert])}, await availablePort());
    const url = `https://127.0.0.1:${server.address().port}/v1/egress`;
    const goodCredentials = credentials();

    await t.test('PII is masked before final bytes and provider response is masked before HTTP release', async () => {
      const response = await post(url, serverTls.cert, device, goodCredentials, 'sanitized', 'Email: alice@example.com');
      assert.equal(response.status, 200);
      assert.equal(response.headers['cache-control'], 'no-store');
      assert.equal(response.body.decision, 'sent');
      assert.equal(response.body.reason, 'POLICY_PASSED');
      assert.equal(seen.length, 1);
      assert.equal(JSON.parse(seen[0]).input[0].content[0].text, 'Email: [EMAIL]');
      assert(!seen[0].includes(Buffer.from('alice@example.com')));
      assert.deepEqual(JSON.parse(response.body.output), {outputText: 'Reply to [EMAIL]'});
      assert(!JSON.stringify(response.body).includes('bob@example.com'));
      assert.equal(runtime.state.get('dispatch', 'sanitized').value.status, 'completed');
    });

    await t.test('classified secret blocks with no sink call', async () => {
      const response = await post(url, serverTls.cert, device, goodCredentials, 'classified-secret', 'TOP SECRET\nAPI key: ' + ['sk', randomBytes(24).toString('hex')].join('-'));
      assert.equal(response.status, 403);
      assert.equal(response.body.decision, 'blocked');
      assert.equal(response.body.reason, 'TEXT_POLICY');
      assert.equal(response.body.output, null);
      assert.equal(seen.length, 1);
    });

    await t.test('text-only route rejects even an empty image field before sink', async () => {
      const response = await post(url, serverTls.cert, device, goodCredentials, 'unsupported-image', 'Public text', undefined, {images: []});
      assert.equal(response.status, 403);
      assert.equal(response.body.output, null);
      assert.equal(seen.length, 1);
    });

    await t.test('missing client certificate is rejected by TLS before HTTP dispatch', async () => {
      await assert.rejects(post(url, serverTls.cert, null, goodCredentials, 'missing-cert', 'Public text'));
      assert.equal(seen.length, 1);
    });

    for (const header of ['authorization', 'x-aidr-device', 'x-aidr-provider']) {
      await t.test('missing ' + header + ' credential is denied', async () => {
        const response = await post(url, serverTls.cert, device, goodCredentials, 'missing-' + header, 'Public text', header);
        assert.equal(response.status, 403);
        assert.equal(response.body.decision, 'blocked');
        assert.equal(response.body.output, null);
        assert.equal(seen.length, 1);
      });
    }

    await t.test('valid signed credentials without a provisioned session are denied', async () => {
      const response = await post(url, serverTls.cert, device, credentials('missing-session'), 'missing-session', 'Public text');
      assert.equal(response.status, 403);
      assert.equal(response.body.reason, 'AUTH_SESSION_REVOKED');
      assert.equal(response.body.output, null);
      assert.equal(seen.length, 1);
    });

    await t.test('another enrolled certificate cannot replay device-bound credentials', async () => {
      const response = await post(url, serverTls.cert, otherDevice, goodCredentials, 'wrong-device-certificate', 'Public text');
      assert.equal(response.status, 403);
      assert.equal(response.body.reason, 'AUTH_DEVICE_CHANNEL_BINDING');
      assert.equal(response.body.output, null);
      assert.equal(seen.length, 1);
    });
  } finally {
    if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    runtime?.close();
    rmSync(root, {recursive: true, force: true});
  }
});
