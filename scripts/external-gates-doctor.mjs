#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const envNames = {
  gate18: ['AIDR_CURSOR_PATH', 'AIDR_VSCODE_PATH'],
  gate19: [
    'AIDR_E2E_RC_DIGEST',
    'AIDR_CURSOR_PATH',
    'AIDR_VSCODE_PATH',
    'ANTHROPIC_API_KEY',
    'OPENCLAW_GATEWAY_TOKEN',
    'OPENCLAW_E2E_HOST',
    'OPENCODE_API_KEY',
    'AIDR_AGENT_PATH',
    'AIDR_AIG_E2E_EVIDENCE',
    'AIDR_SUPABASE_E2E_EVIDENCE',
    'AIDR_DASHBOARD_BROWSER_EVIDENCE',
  ],
  gate27: [],
};

function exists(filePath) {
  try { return fs.statSync(filePath).isFile(); } catch { return false; }
}

function isSha256(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value.trim());
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function executableCandidates(env = process.env, platform = process.platform) {
  const names = platform === 'win32' ? ['.exe', '.cmd', ''] : [''];
  const pathEntries = (env.PATH ?? '').split(path.delimiter).filter(Boolean);
  const configured = {
    cursor: env.AIDR_CURSOR_PATH,
    vscode: env.AIDR_VSCODE_PATH ?? env.VSCODE_EXECUTABLE_PATH,
  };
  const defaults = platform === 'win32'
    ? {
        cursor: [path.join(env.LOCALAPPDATA ?? '', 'Programs', 'cursor', 'Cursor.exe'), path.join(env.ProgramFiles ?? '', 'Cursor', 'Cursor.exe')],
        vscode: [path.join(env.LOCALAPPDATA ?? '', 'Programs', 'Microsoft VS Code', 'Code.exe'), path.join(env.ProgramFiles ?? '', 'Microsoft VS Code', 'Code.exe')],
      }
    : {
        cursor: ['/Applications/Cursor.app/Contents/MacOS/Cursor', '/usr/bin/cursor', '/usr/local/bin/cursor'],
        vscode: ['/Applications/Visual Studio Code.app/Contents/MacOS/Electron', '/usr/bin/code', '/usr/local/bin/code'],
      };
  const result = {};
  for (const [kind, command] of [['cursor', 'cursor'], ['vscode', 'code']]) {
    const candidates = [configured[kind], ...defaults[kind], ...pathEntries.flatMap((dir) => names.map((ext) => path.join(dir, command + ext)))]
      .filter(Boolean).map((item) => path.resolve(item));
    result[kind] = [...new Set(candidates)].map((candidate) => ({ path: candidate, exists: exists(candidate) }));
    result[kind].found = result[kind].filter((candidate) => candidate.exists).map((candidate) => candidate.path);
  }
  return result;
}

function evidenceCheck(filePath, candidateDigest) {
  const result = { path: filePath, exists: exists(filePath), candidateBinding: 'not-configured' };
  if (!result.exists) return result;
  if (!candidateDigest) return result;
  result.candidateBinding = 'not-present';
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (typeof parsed.candidate_digest === 'string') {
      result.candidateBinding = parsed.candidate_digest.toLowerCase() === candidateDigest.toLowerCase() ? 'match' : 'mismatch';
    }
    result.sha256 = sha256(filePath);
  } catch {
    result.candidateBinding = 'unreadable';
  }
  return result;
}

function pnpmCacheMetadata(env = process.env, home = os.homedir(), cwd = root) {
  const candidates = [
    env.PNPM_STORE_DIR,
    env.npm_config_store_dir,
    path.join(home, '.local', 'share', 'pnpm', 'store'),
    env.LOCALAPPDATA && path.join(env.LOCALAPPDATA, 'pnpm', 'store'),
    path.join(cwd, 'node_modules', '.pnpm', 'lock.yaml'),
  ].filter(Boolean).map((item) => path.resolve(item));
  return [...new Set(candidates)].map((candidate) => ({ path: candidate, exists: exists(candidate) }));
}

export function diagnose({ env = process.env, cwd = root, platform = process.platform, home = os.homedir() } = {}) {
  const editors = executableCandidates(env, platform);
  const candidateDigest = env.AIDR_CANDIDATE_SHA256 ?? env.AIDR_RELEASE_CANDIDATE_SHA256;
  const releaseDigestValid = isSha256(env.AIDR_E2E_RC_DIGEST);
  const evidence = {
    gate18: evidenceCheck(env.AIDR_GATE18_EVIDENCE ?? path.join(cwd, '.release-evidence', 'v8-logs', '18-native-host.log.result.json'), candidateDigest),
    gate19: evidenceCheck(env.AIDR_GATE19_EVIDENCE ?? path.join(cwd, '.release-evidence', 'v8-logs', '19-release-e2e.log.result.json'), candidateDigest),
    gate27: evidenceCheck(env.AIDR_GATE27_EVIDENCE ?? path.join(cwd, '.release-evidence', 'v8-logs', '27-empty-path-package-install.log.result.json'), candidateDigest),
  };
  const envReport = Object.fromEntries(Object.entries(envNames).map(([gate, names]) => [gate, names.map((name) => ({ name, present: Boolean(env[name]) }))]));
  const cache = pnpmCacheMetadata(env, home, cwd);
  const gates = {
    gate18: { prerequisites: { cursor: editors.cursor.found.length > 0, vscode: editors.vscode.found.length > 0, evidence: evidence.gate18.exists }, pass: editors.cursor.found.length > 0 && editors.vscode.found.length > 0 && evidence.gate18.exists },
    gate19: { prerequisites: { cursor: editors.cursor.found.length > 0, vscode: editors.vscode.found.length > 0, releaseDigest: releaseDigestValid, evidence: evidence.gate19.exists }, pass: editors.cursor.found.length > 0 && editors.vscode.found.length > 0 && releaseDigestValid && evidence.gate19.exists },
    gate27: { prerequisites: { evidence: evidence.gate27.exists, pnpmCacheMetadata: cache.some((item) => item.exists) }, pass: evidence.gate27.exists && cache.some((item) => item.exists) },
  };
  for (const gate of Object.keys(gates)) if (evidence[gate].candidateBinding === 'mismatch' || evidence[gate].candidateBinding === 'not-present' || evidence[gate].candidateBinding === 'unreadable') gates[gate].pass = false;
  return { ok: Object.values(gates).every((gate) => gate.pass), gates, editors, requiredEnv: envReport, evidence, pnpmCacheMetadata: cache, note: 'Diagnostics do not assert credentials, acceptance, evidence validity, or PASS.' };
}

function main() {
  const report = diagnose();
  if (process.argv.includes('--json')) console.log(JSON.stringify(report, null, 2));
  else {
    console.log(`external gates doctor: ${report.ok ? 'READY' : 'NOT READY'}`);
    for (const [gate, result] of Object.entries(report.gates)) console.log(`${gate}: ${result.pass ? 'ready' : 'missing prerequisites'}`);
    for (const [kind, candidates] of Object.entries(report.editors)) console.log(`${kind}: ${candidates.found.length ? candidates.found.join(', ') : 'not found'}`);
    console.log('Required environment variables: ' + Object.values(report.requiredEnv).flat().map((item) => `${item.name}=${item.present ? 'present' : 'missing'}`).join(', '));
  }
  process.exitCode = report.ok ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) main();
