import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer, request} from 'node:https';
import {createHash, generateKeyPairSync, randomBytes, X509Certificate} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {NOW, privateDirectory} from './helpers.mjs';

// Allows the same regression to run against an isolated package build.
const dist = process.env.AIDR_PRIVACY_TEST_DIST
  ? pathToFileURL(process.env.AIDR_PRIVACY_TEST_DIST + '/') : new URL('../../dist/', import.meta.url);
const {createPlatformRuntime} = await import(new URL('platform/runtime.js', dist));
const {createDataHandler} = await import(new URL('platform/data-http.js', dist));
const {issueJwt, provisionSession, revokeSession} = await import(new URL('platform/identity.js', dist));
const {signPolicy} = await import(new URL('enterprise/policy.js', dist));

function certificate(root, name) {
  const gitOpenSsl = join(process.env.ProgramFiles ?? 'C:\\Program Files', 'Git', 'usr', 'bin', 'openssl.exe');
  const openssl = process.env.AIDR_OPENSSL ?? (process.platform === 'win32' && existsSync(gitOpenSsl) ? gitOpenSsl : 'openssl');
  const keyPath = join(root, name + '.key'), certPath = join(root, name + '.pem');
  execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', certPath,
    '-days', '1', '-subj', '/CN=' + name, '-addext', 'subjectAltName=IP:127.0.0.1'], {stdio: 'ignore', windowsHide: true});
  const cert = readFileSync(certPath);
  return {key: readFileSync(keyPath), cert, fingerprint: createHash('sha256').update(new X509Certificate(cert).raw).digest('base64url')};
}

function post(url, tls, credentials, path, body) {
  return new Promise((resolve, reject) => {
    const req = request(new URL(path, url), {method: 'POST', ca: tls.cert, cert: tls.cert, key: tls.key,
      rejectUnauthorized: true, agent: false, headers: {'content-type': 'application/json',
        authorization: 'Bearer ' + credentials.userToken, 'x-aidr-device': credentials.deviceToken,
        'x-aidr-provider': credentials.providerToken}}, res => {
      let text = '';
      res.on('data', bytes => { text += bytes; });
      res.on('error', reject);
      res.on('end', () => { try { resolve({status: res.statusCode, body: JSON.parse(text)}); } catch (error) { reject(error); } });
    });
    req.on('error', reject);
    req.setTimeout(5000, () => req.destroy(new Error('TEST_REQUEST_TIMEOUT')));
    req.end(JSON.stringify(body));
  });
}

test('source reads enforce authoritative classification and configured data policy over real mTLS', async t => {
  const root = mkdtempSync(join(tmpdir(), 'aidr-source-read-'));
  privateDirectory(root);
  let runtime, server;
  const closeListener = async () => {
    if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); server = undefined; }
  };
  try {
    const tls = certificate(root, 'source-reader'), signing = generateKeyPairSync('ed25519');
    const trust = {issuer: 'https://identity.example.com', audience: 'aidr-platform', keys: new Map([['signer', signing.publicKey]])};
    const policy = {schemaVersion: 1, tenantId: 'alpha', policyId: 'source-policy', revision: 1,
      notBefore: NOW - 1000, expiresAt: NOW + 600000, destinations: [{id: 'provider', origin: 'https://api.example.com',
        accounts: ['enterprise'], requireVerifiedAccount: true, requireManagedDevice: true, requireProvenance: false,
        maxClassification: 'internal', groups: ['engineering']}], unknownDestination: 'block', piiAction: 'redact',
      injectionAction: 'review', blockActiveContent: true, maxInputBytes: 65536};
    // This rules-only TEST runtime proves source authorization, not learned PERSON/ADDRESS accuracy.
    const options = {tenantId: 'alpha', databasePath: join(root, 'control.sqlite'),
      encryption: {active: 'k1', keys: [{id: 'k1', key: randomBytes(32)}]}, audit: {keyId: 'audit1', key: randomBytes(32)},
      identity: {user: trust, device: trust, provider: trust, roleGroups: {'security-admin': ['admins']}, scopes: []},
      policy: {signed: signPolicy(policy, 'signer', signing.privateKey), keys: trust.keys},
      destinations: [], profile: 'strict', clock: () => NOW, dataPolicy: {keyId: 'data1', key: randomBytes(32)}};
    runtime = await createPlatformRuntime(options);
    let sessionVersion = 1;
    const establishSession = () => provisionSession(runtime.state, {sessionId: 'session', subjectId: 'alice', deviceId: 'device',
      version: sessionVersion, active: true, expiresAt: NOW + 600000}, NOW);
    establishSession();
    const token = purpose => issueJwt({iss: trust.issuer, aud: trust.audience, sub: 'alice', iat: NOW / 1000,
      exp: NOW / 1000 + 300, jti: purpose + '-source-read-' + sessionVersion, token_use: purpose, tenant_id: 'alpha', sid: 'session', session_version: sessionVersion,
      ...(purpose === 'user' ? {groups: ['engineering', 'admins']} : {device_id: 'device'}),
      ...(purpose === 'device' ? {managed: true, compliant: true, cnf: {'x5t#S256': tls.fingerprint}} : {}),
      ...(purpose === 'provider' ? {destination: 'https://api.example.com', account: 'enterprise', verified: true, logged_in: true, scopes: []} : {})
    }, 'signer', signing.privateKey);
    const issueCredentials = () => ({userToken: token('user'), deviceToken: token('device'), providerToken: token('provider')});
    let credentials = issueCredentials();
    const openListener = async () => {
      const handler = createDataHandler(runtime, {origin: 'https://api.example.com'});
      server = createServer({key: tls.key, cert: tls.cert, ca: tls.cert, requestCert: true, rejectUnauthorized: true}, handler);
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
      return `https://127.0.0.1:${server.address().port}`;
    };
    let url = await openListener();
    const documents = [
      {id: 'public', text: 'Public source controls', groups: ['engineering'], classification: 'public'},
      {id: 'public-symbols', text: '$%!', groups: ['engineering'], classification: 'public'},
      {id: 'public-empty', text: '', groups: ['engineering'], classification: 'public'},
      {id: 'restricted-symbols', text: '$%!', groups: ['engineering'], classification: 'restricted'},
      {id: 'restricted-empty', text: '', groups: ['engineering'], classification: 'restricted'},
      {id: 'wrong-acl', text: 'Public source', groups: ['accounting'], classification: 'public'},
      {id: 'public-matched-restricted', text: 'Stored controls for calibration tolerances', groups: ['engineering'], classification: 'public'},
      {id: 'restricted-words', text: 'Stored controls for calibration tolerances', groups: ['engineering'], classification: 'restricted'},
    ];
    const ingestion = await post(url, tls, credentials, '/v1/admin/data-source', {sourceId: 'source', generation: 1, documents, complete: true});
    assert.equal(ingestion.status, 200);
    assert.equal(ingestion.body.synchronized, true);
    const read = documentId => post(url, tls, credentials, '/v1/source/read', {sourceId: 'source', documentId});

    await t.test('public text, symbol-only text and empty text remain readable', async () => {
      for (const document of documents.slice(0, 3)) {
        const response = await read(document.id);
        assert.equal(response.status, 200);
        assert.equal(response.body.decision, 'allow');
        assert.equal(response.body.output, document.text);
      }
    });
    await t.test('restricted symbol-only and empty content are withheld without fingerprint matches', async () => {
      for (const document of documents.slice(3, 5)) {
        const response = await read(document.id);
        assert.equal(response.status, 200);
        assert.equal(response.body.decision, 'block');
        assert.equal(response.body.output, null);
        assert.equal(response.body.classification, 'restricted');
      }
    });
    await t.test('stored source ACL still denies an unauthorized group', async () => {
      const response = await read('wrong-acl');
      assert.equal(response.status, 403);
      assert.equal(response.body.output, null);
    });
    await t.test('a stricter fingerprint match can raise the stored classification', async () => {
      const response = await read('public-matched-restricted');
      assert.equal(response.status, 200);
      assert.equal(response.body.decision, 'block');
      assert.equal(response.body.output, null);
    });
    await t.test('the trusted source method rejects unsupported classification values', async () => {
      await assert.rejects(runtime.gate.protectSource('Public source', {tenantId: 'alpha', subjectId: 'alice', sessionId: 'session',
        groups: ['engineering'], scopes: [], device: 'managed', account: 'enterprise', accountVerified: true,
        destination: 'https://api.example.com', channel: 'retrieval', assetIds: []}, 'secret'), /CONTROL_INVALID/);
    });
    await t.test('session revocation during the asynchronous scan withholds the result', async () => {
      const original = runtime.gate;
      runtime.gate = {async protectSource(...args) {
        const result = await original.protectSource(...args);
        revokeSession(runtime.state, 'session', NOW);
        return result;
      }};
      try {
        const response = await read('public');
        assert.equal(response.status, 403);
        assert.equal(response.body.output, null);
      } finally {
        runtime.gate = original;
        sessionVersion += 2;
        establishSession();
        credentials = issueCredentials();
      }
    });
    await t.test('a source revision during the asynchronous scan withholds the result', async () => {
      const original = runtime.gate, admin = runtime.identity.authenticate(credentials.userToken);
      runtime.gate = {async protectSource(...args) {
        const result = await original.protectSource(...args);
        runtime.sources.replace(admin, 'source', 2, documents, true);
        return result;
      }};
      try {
        const response = await read('public');
        assert.equal(response.status, 403);
        assert.equal(response.body.output, null);
      } finally { runtime.gate = original; }
    });
    await t.test('reopening the stored source without data policy denies every read', async () => {
      await closeListener();
      runtime.close();
      const {dataPolicy, ...withoutDataPolicy} = options;
      runtime = await createPlatformRuntime(withoutDataPolicy);
      url = await openListener();
      for (const documentId of ['public', 'restricted-symbols', 'restricted-empty']) {
        const response = await read(documentId);
        assert.equal(response.status, 403);
        assert.equal(response.body.decision, 'block');
        assert.equal(response.body.output, null);
      }
    });
  } finally {
    await closeListener();
    runtime?.close();
    rmSync(root, {recursive: true, force: true});
  }
});
