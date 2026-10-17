import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import {
  COMPANION_HOST_NAME, REGISTRY_KEYS, buildHostConfig, buildHostManifest, chooseOcrLanguages, cmdLauncher,
  companionStatus, defaultInstallDir, detectBrowserGuardInstalls, installCompanion, launcherSource, memoryRegistry,
  uninstallCompanion, unpackedExtensionId, verifyCompanion,
} from '../../dist/companion/index.js';

const ROOT = new URL('../../', import.meta.url);
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'aidr-companion-'));
const ID = 'abcdefghijklmnopabcdefghijklmnop', ID2 = 'ponmlkjihgfedcbaponmlkjihgfedcba';

// --- extension ids --------------------------------------------------------------------------------

test('unpacked extension id: Chromium algorithm (UTF-16LE path, upper-case drive on Windows)', () => {
  const dir = 'C:\\Users\\user\\Desktop\\AIDR-Demo\\browser-guard-chrome';
  const hex = createHash('sha256').update(Buffer.from(dir, 'utf16le')).digest('hex').slice(0, 32);
  const expected = [...hex].map(d => String.fromCharCode(97 + parseInt(d, 16))).join('');
  assert.equal(unpackedExtensionId(dir, 'win32'), expected);
  assert.equal(unpackedExtensionId('c:\\Users\\user\\Desktop\\AIDR-Demo\\browser-guard-chrome', 'win32'), expected);
  assert.match(unpackedExtensionId('/home/user/ext', 'linux'), /^[a-p]{32}$/);
  assert.notEqual(unpackedExtensionId('/home/user/ext', 'linux'), unpackedExtensionId('/home/user/ext2', 'linux'));
});

function fakeProfiles() {
  const local = tmp();
  const ext = path.join(local, 'ext', 'browser-guard-chrome'), other = path.join(local, 'ext', 'other');
  fs.mkdirSync(path.join(ext, '_locales', 'en'), { recursive: true });
  fs.writeFileSync(path.join(ext, 'manifest.json'), JSON.stringify({ name: '__MSG_extName__', default_locale: 'en' }));
  fs.writeFileSync(path.join(ext, '_locales', 'en', 'messages.json'), JSON.stringify({ extName: { message: 'Singularity AIDR Browser Guard' } }));
  fs.mkdirSync(other, { recursive: true });
  fs.writeFileSync(path.join(other, 'manifest.json'), JSON.stringify({ name: 'Something else' }));
  const prefs = (dir, file, settings) => { fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(path.join(dir, file), JSON.stringify({ extensions: { settings } })); };
  const chrome = path.join(local, 'Google', 'Chrome', 'User Data');
  prefs(path.join(chrome, 'Default'), 'Secure Preferences', {
    [ID]: { location: 4, path: ext, granted_permissions: { api: ['storage', 'nativeMessaging'] } },
    [ID2]: { location: 4, path: other },
  });
  prefs(path.join(chrome, 'Default'), 'Preferences', { [ID]: { location: 4, path: ext } });
  prefs(path.join(chrome, 'Profile 1'), 'Secure Preferences', { [ID]: { location: 4, path: ext, granted_permissions: { api: ['storage'] } } });
  prefs(path.join(local, 'Microsoft', 'Edge', 'User Data', 'Default'), 'Secure Preferences', { [ID2]: { location: 1, path: `${ID2}/1.0.0` } });
  return { local, ext };
}

test('detects Browser Guard installs from Preferences (read only), per browser profile', () => {
  const { local, ext } = fakeProfiles();
  const before = fs.readFileSync(path.join(local, 'Google', 'Chrome', 'User Data', 'Default', 'Secure Preferences'));
  const found = detectBrowserGuardInstalls({ localAppData: local });
  assert.deepEqual(found.map(f => [f.browser, f.profile, f.id, f.source, f.nativeMessagingGranted]), [
    ['chrome', 'Default', ID, 'unpacked', true],
    ['chrome', 'Profile 1', ID, 'unpacked', false],
  ]);
  assert.equal(found[0].path, ext);
  // A store id is reported only when listed; an unrelated unpacked extension never is.
  assert.deepEqual(detectBrowserGuardInstalls({ localAppData: local, storeIds: [ID2] }).filter(f => f.source === 'store').map(f => f.browser), ['edge']);
  // Restricting to a folder.
  assert.deepEqual(detectBrowserGuardInstalls({ localAppData: local, unpackedPath: path.join(local, 'ext', 'other') }).map(f => f.id), [ID2]);
  assert.deepEqual(fs.readFileSync(path.join(local, 'Google', 'Chrome', 'User Data', 'Default', 'Secure Preferences')), before);
  assert.deepEqual(detectBrowserGuardInstalls({ localAppData: path.join(local, 'missing') }), []);
});

// --- manifest, config, launcher -------------------------------------------------------------------

test('host manifest: name, stdio, absolute launcher, exact origins', () => {
  assert.deepEqual(buildHostManifest('C:\\x\\aidr-privacy-host.exe', [ID, ID2, ID]), {
    name: COMPANION_HOST_NAME,
    description: 'Singularity AIDR local text and screenshot privacy scanner',
    path: 'C:\\x\\aidr-privacy-host.exe',
    type: 'stdio',
    allowed_origins: [`chrome-extension://${ID}/`, `chrome-extension://${ID2}/`],
  });
  assert.throws(() => buildHostManifest('relative.exe', [ID]), /NOT_ABSOLUTE/);
  assert.throws(() => buildHostManifest('C:\\x.exe', []), /EXTENSION_ID_INVALID/);
  assert.throws(() => buildHostManifest('C:\\x.exe', ['not-an-id']), /EXTENSION_ID_INVALID/);
});

test('host config: text strict/label; OCR block uses the Windows engine and decision-only policy', () => {
  const text = buildHostConfig([ID], null);
  assert.deepEqual(text, { version: 1, allowedExtensionIds: [ID], browserPolicyJSON: '{}', text: { profile: 'strict', mask: 'label', maxInputBytes: 1048576 } });
  const ocr = buildHostConfig([ID], { python: 'C:\\v\\python.exe', powershell: 'C:\\W\\powershell.exe', manifest: 'C:\\i\\ocr-manifest.json' });
  assert.equal(ocr.visual.backend.ocrEngine, 'windows');
  assert.equal(ocr.visual.policy.release, 'manual');
  assert.equal(ocr.visual.policy.barcodeUnavailable, 'review');
  assert.equal(buildHostConfig([ID], { python: 'a', powershell: 'b', manifest: 'c' }, 'allow').visual.policy.barcodeUnavailable, 'allow');
});

test('launcher: repo C# template with base64 paths; .cmd fallback refuses cmd metacharacters', () => {
  const template = fs.readFileSync(new URL('native/windows-launcher.cs', ROOT), 'utf8');
  const paths = { node: 'C:\\Program Files\\nodejs\\node.exe', host: 'C:\\Users\\user\\Ayşe\\host.js', config: 'C:\\c\\host-config.json' };
  const source = launcherSource(template, paths);
  assert.ok(!source.includes('__NODE_BASE64__') && !source.includes('__CONFIG_BASE64__'));
  assert.ok(source.includes(Buffer.from(paths.host, 'utf8').toString('base64')));
  assert.ok(source.includes('to.Flush()'), 'every forwarded chunk is flushed');
  assert.equal(cmdLauncher(paths), `@echo off\r\n"${paths.node}" "${paths.host}" --config "${paths.config}" %*\r\n`);
  assert.throws(() => cmdLauncher({ ...paths, host: 'C:\\a&b\\host.js' }), /UNSAFE/);
});

test('OCR language choice: Turkish required, English added when installed', () => {
  assert.deepEqual(chooseOcrLanguages(['tr']), ['tr']);
  assert.deepEqual(chooseOcrLanguages(['en-US', 'tr']), ['tr', 'en-US']);
  assert.deepEqual(chooseOcrLanguages(['en-US', 'de-DE']), []);
});

// --- registry layer -------------------------------------------------------------------------------

test('registry layer: HKCU only', async () => {
  const reg = memoryRegistry();
  await reg.setDefault(REGISTRY_KEYS.chrome, 'C:\\m.json');
  assert.equal(await reg.getDefault(REGISTRY_KEYS.chrome), 'C:\\m.json');
  for (const key of ['HKLM\\Software\\Google\\Chrome\\NativeMessagingHosts\\x', 'HKCU\\System\\x', 'HKCU\\Software\\a\\\\b', 'HKCU\\Software\\x\\'])
    assert.throws(() => reg.setDefault(key, 'v'), /KEY_INVALID/);
  assert.deepEqual(Object.values(REGISTRY_KEYS), [
    'HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\com.singularity.aidr_privacy',
    'HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.singularity.aidr_privacy',
    'HKCU\\Software\\Chromium\\NativeMessagingHosts\\com.singularity.aidr_privacy',
  ]);
  assert.match(defaultInstallDir({ LOCALAPPDATA: 'C:\\Users\\u\\AppData\\Local' }), /SingularityAIDR\\PrivacyCompanion$/);
});

// --- install / uninstall with fake processes and registry -----------------------------------------

/** Records every program run; simulates python, pip, PowerShell and the C# compiler. */
function fakeRunner({ languages = 'tr\nen-US\n', zbar = 1, pip = 0 } = {}) {
  const calls = [];
  const ok = (stdout = '') => ({ code: 0, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0) });
  const runner = async (file, args, options = {}) => {
    calls.push([path.basename(file), ...args]);
    if (file === 'py') return ok(' -V:3.14 *        C:\\Py\\Python314\\python.exe\n -V:3.12          C:\\Py\\Python312\\python.exe\n');
    if (args.includes('import sys;print("%d.%d" % sys.version_info[:2])')) return ok(file.includes('314') ? '3.14' : '3.12');
    if (args[0] === '-m' && args[1] === 'venv') { fs.mkdirSync(path.join(args[2], 'Scripts'), { recursive: true }); fs.writeFileSync(path.join(args[2], 'Scripts', 'python.exe'), ''); return ok(); }
    if (args[1] === 'pip') return { code: pip, stdout: Buffer.alloc(0), stderr: Buffer.from('pip failed') };
    if (args.includes('from pyzbar.pyzbar import decode')) return { code: zbar, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
    if (args.some(a => String(a).endsWith('build_manifest.py'))) { fs.writeFileSync(args[args.indexOf('--output') + 1], '{}'); return ok(); }
    const command = args[args.length - 1];
    if (String(command).includes('AvailableRecognizerLanguages')) return ok(languages);
    if (String(command).startsWith('Add-Type')) { fs.writeFileSync(options.env.AIDR_LAUNCHER_OUT, 'MZ'); return ok(); }
    return { code: 1, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
  };
  return { runner, calls };
}

test('install: stages the host, pins OCR, writes manifest/config/receipt and exactly the HKCU keys', async () => {
  const { local } = fakeProfiles(), installDir = path.join(tmp(), 'PrivacyCompanion');
  const registry = memoryRegistry(), { runner, calls } = fakeRunner();
  const report = await installCompanion({ installDir, localAppData: local, registry, runner, node: 'C:\\node\\node.exe', extensionIds: [ID2], ocr: 'windows' });
  const manifestPath = path.join(installDir, 'com.singularity.aidr_privacy.json');
  assert.deepEqual([...registry.entries], [[REGISTRY_KEYS.chrome, manifestPath], [REGISTRY_KEYS.edge, manifestPath]]);
  assert.deepEqual(report.extensionIds, [ID2, ID]);
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  assert.equal(manifest.path, path.join(installDir, 'aidr-privacy-host.exe'));
  assert.deepEqual(manifest.allowed_origins, [`chrome-extension://${ID2}/`, `chrome-extension://${ID}/`]);
  const config = JSON.parse(fs.readFileSync(path.join(installDir, 'host-config.json'), 'utf8'));
  assert.deepEqual(config.allowedExtensionIds, [ID2, ID]);
  assert.equal(config.visual.backend.python, path.join(installDir, 'venv', 'Scripts', 'python.exe'));
  assert.ok(fs.existsSync(path.join(installDir, 'app', 'dist', 'native', 'host.js')));
  assert.ok(fs.existsSync(path.join(installDir, 'app', 'vision', 'windows_ocr.ps1')));
  assert.ok(!fs.readdirSync(path.join(installDir, 'app', 'dist')).some(f => f.endsWith('.map')));
  assert.equal(JSON.parse(fs.readFileSync(path.join(installDir, 'app', 'package.json'), 'utf8')).type, 'module');
  // Python 3.12 is preferred over 3.14; pip runs with the hash lock only.
  assert.equal(report.ocr.python, 'C:\\Py\\Python312\\python.exe');
  const pip = calls.find(c => c[2] === 'pip');
  for (const flag of ['--require-hashes', '--only-binary=:all:', '--no-deps']) assert.ok(pip.includes(flag), flag);
  assert.ok(pip.at(-1).endsWith('requirements.lock.txt'));
  const manifestCall = calls.find(c => c.some(a => String(a).endsWith('build_manifest.py')));
  assert.deepEqual(manifestCall.slice(manifestCall.indexOf('--languages'), manifestCall.indexOf('--languages') + 4), ['--languages', 'tr,en-US', '--barcode-engine', 'none']);
  assert.ok(report.warnings.some(w => w.startsWith('BARCODE_UNAVAILABLE')));
  assert.deepEqual(report.nextSteps.length, 1);
  assert.match(report.nextSteps[0], /Profile 1.*Use the AIDR Privacy helper app/);
  const receipt = JSON.parse(fs.readFileSync(path.join(installDir, 'install.json'), 'utf8'));
  assert.equal(receipt.hostName, COMPANION_HOST_NAME);
  assert.deepEqual(receipt.registry.map(r => r.key), [REGISTRY_KEYS.chrome, REGISTRY_KEYS.edge]);

  // A second install with an unchanged launcher does not recompile it.
  const compiles = calls.filter(c => String(c.at(-1)).startsWith('Add-Type')).length;
  await installCompanion({ installDir, localAppData: local, registry, runner, node: 'C:\\node\\node.exe', extensionIds: [ID2], ocr: 'windows' });
  assert.equal(calls.filter(c => String(c.at(-1)).startsWith('Add-Type')).length, compiles);

  const status = await companionStatus({ installDir, registry, localAppData: local });
  assert.equal(status.installed, true);
  assert.equal(status.ocr, true);
  assert.deepEqual(status.registry.map(r => r.ours), [true, true]);
  assert.ok(status.problems.includes('PERMISSION_NOT_GRANTED: chrome Profile 1 (Options > "Use the AIDR Privacy helper app")'));
});

test('install: no Browser Guard and no id is refused; no Turkish OCR installs text-only with a warning', async () => {
  const empty = tmp();
  await assert.rejects(installCompanion({ installDir: path.join(empty, 'c'), localAppData: empty, registry: memoryRegistry(), runner: fakeRunner().runner }), /NO_EXTENSION_ID/);
  const registry = memoryRegistry(), installDir = path.join(empty, 'd');
  const report = await installCompanion({ installDir, localAppData: empty, extensionIds: [ID], registry, runner: fakeRunner({ languages: 'de-DE\n' }).runner, node: 'C:\\n\\node.exe', ocr: 'windows' });
  assert.equal(report.ocr, null);
  assert.ok(report.warnings.some(w => w.startsWith('OCR_UNAVAILABLE')));
  assert.equal(JSON.parse(fs.readFileSync(path.join(installDir, 'host-config.json'), 'utf8')).visual, undefined);
  await assert.rejects(installCompanion({ installDir: path.join(empty, 'e'), localAppData: empty, extensionIds: [ID], registry: memoryRegistry(), runner: fakeRunner({ pip: 1 }).runner, node: 'C:\\n\\node.exe', ocr: 'windows' }), /PIP_FAILED/);
});

test('uninstall: removes only keys pointing at this install, and only a directory with the receipt', async () => {
  const { local } = fakeProfiles(), installDir = path.join(tmp(), 'PrivacyCompanion');
  const registry = memoryRegistry();
  await installCompanion({ installDir, localAppData: local, registry, runner: fakeRunner().runner, node: 'C:\\n\\node.exe', browsers: ['chrome', 'edge', 'chromium'] });
  await registry.setDefault(REGISTRY_KEYS.chromium, 'C:\\other-product\\manifest.json');
  const r = await uninstallCompanion({ installDir, registry });
  assert.deepEqual(r.removedKeys, [REGISTRY_KEYS.chrome, REGISTRY_KEYS.edge]);
  assert.deepEqual(r.keptKeys, [REGISTRY_KEYS.chromium]);
  assert.equal(r.removedDir, true);
  assert.ok(!fs.existsSync(installDir));
  assert.deepEqual([...registry.entries.keys()], [REGISTRY_KEYS.chromium]);
  const foreign = tmp();
  fs.writeFileSync(path.join(foreign, 'keep.txt'), 'x');
  const r2 = await uninstallCompanion({ installDir: foreign, registry });
  assert.equal(r2.removedDir, false);
  assert.ok(fs.existsSync(path.join(foreign, 'keep.txt')));
  assert.ok(r2.warnings.some(w => w.startsWith('NO_RECEIPT')));
});

// --- the real host process ------------------------------------------------------------------------

const windows = process.platform === 'win32' ? {} : { skip: 'the launcher and verify step are Windows-only' };

test('verify: the installed .cmd launcher starts the real host, which masks text', windows, async () => {
  const installDir = path.join(tmp(), 'PrivacyCompanion');
  await installCompanion({ installDir, extensionIds: [ID], detect: false, ocr: 'none', launcher: 'cmd', registry: memoryRegistry() });
  const r = await verifyCompanion({ installDir, texts: ['TC Kimlik No: 10000000146, e-posta ali@example.com'] });
  assert.equal(r.ok, true, r.error);
  assert.equal(r.persistent, true);
  assert.equal(r.ocr, false);
  assert.equal(r.texts[0].decision, 'redact');
  assert.deepEqual({ ...r.texts[0].counts }, { TC_KIMLIK: 1, EMAIL: 1 });
  // A caller the host does not admit gets no answer.
  const refused = await verifyCompanion({ installDir, extensionId: ID2, texts: ['x'], timeoutMs: 15000 });
  assert.equal(refused.ok, false);
});

// Real Windows OCR through the companion installed for this user (installCompanion with OCR).
const installed = defaultInstallDir();
const withOcr = (() => { try { return !!JSON.parse(fs.readFileSync(path.join(installed, 'host-config.json'), 'utf8')).visual; } catch { return false; } })();
test('verify: the installed companion OCRs a screenshot and blocks its personal data', withOcr ? {} : { skip: `no companion with OCR installed in ${installed}` }, async () => {
  const image = fs.readFileSync(new URL('fixtures/visual/english-dark.png', ROOT));
  const r = await verifyCompanion({ installDir: installed, images: [{ name: 'english-dark.png', bytes: image }] });
  assert.equal(r.ok, true, r.error);
  assert.equal(r.ocr, true);
  assert.equal(r.images[0].decision, 'block', JSON.stringify(r.images[0]));
  assert.ok(Object.keys(r.images[0].counts).length > 0);
});
