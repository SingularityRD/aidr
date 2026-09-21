import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { diagnose } from './external-gates-doctor.mjs';

function fixture() {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'external-gates-doctor-'));
  const cursor = path.join(cwd, 'Cursor.exe');
  const vscode = path.join(cwd, 'Code.exe');
  fs.writeFileSync(cursor, 'cursor');
  fs.writeFileSync(vscode, 'vscode');
  fs.mkdirSync(path.join(cwd, 'node_modules', '.pnpm'), { recursive: true });
  fs.writeFileSync(path.join(cwd, 'node_modules', '.pnpm', 'lock.yaml'), 'lockfileVersion: 9');
  const digest = crypto.createHash('sha256').update('candidate').digest('hex');
  for (const gate of ['18-native-host', '19-release-e2e', '27-empty-path-package-install']) {
    fs.mkdirSync(path.join(cwd, '.release-evidence', 'v8-logs'), { recursive: true });
    fs.writeFileSync(path.join(cwd, '.release-evidence', 'v8-logs', `${gate}.log.result.json`), JSON.stringify({ candidate_digest: digest }));
  }
  return { cwd, cursor, vscode, digest };
}

test('reports editor candidates, env names, evidence and cache without values', () => {
  const f = fixture();
  const report = diagnose({ cwd: f.cwd, home: f.cwd, platform: 'win32', env: {
    PATH: '', AIDR_CURSOR_PATH: f.cursor, AIDR_VSCODE_PATH: f.vscode,
    AIDR_E2E_RC_DIGEST: f.digest, AIDR_CANDIDATE_SHA256: f.digest,
  } });
  assert.equal(report.ok, true);
  assert.deepEqual(report.editors.cursor.found, [path.resolve(f.cursor)]);
  assert.equal(report.evidence.gate19.candidateBinding, 'match');
  assert.equal(report.pnpmCacheMetadata.some((item) => item.exists), true);
  assert.equal(JSON.stringify(report).includes(f.digest), false);
});

test('fails closed for missing prerequisites, mismatched binding, and directory candidates', () => {
  const f = fixture();
  const directoryCandidate = path.join(f.cwd, 'cursor-directory');
  fs.mkdirSync(directoryCandidate);
  const report = diagnose({ cwd: f.cwd, home: f.cwd, platform: 'win32', env: {
    PATH: '', AIDR_CURSOR_PATH: directoryCandidate, AIDR_CANDIDATE_SHA256: 'wrong',
  } });
  assert.equal(report.ok, false);
  assert.equal(report.gates.gate18.pass, false);
  assert.deepEqual(report.editors.cursor.found, []);
  assert.equal(report.evidence.gate18.candidateBinding, 'mismatch');
  assert.equal(report.requiredEnv.gate19.find((item) => item.name === 'AIDR_E2E_RC_DIGEST').present, false);
});
