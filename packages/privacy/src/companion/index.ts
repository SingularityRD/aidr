/**
 * AIDR Privacy companion: per-user install, registration, status, verification and removal of the
 * `com.singularity.aidr_privacy` native messaging host for Browser Guard on Windows.
 *
 * What an install puts in place (no administrator rights, nothing outside the user's profile):
 *   <installDir>\app\...                     the host (this package's dist), vision worker, OCR helper
 *   <installDir>\venv\                       Python venv with the hash-locked Pillow/pyzbar wheels
 *   <installDir>\ocr-manifest.json           pinned hashes of the OCR installation (vision/build_manifest.py)
 *   <installDir>\host-config.json            host config: allowed extension ids, text + OCR settings
 *   <installDir>\aidr-privacy-host.exe       launcher (repo native/windows-launcher.cs; .cmd fallback)
 *   <installDir>\com.singularity.aidr_privacy.json   native messaging manifest
 *   <installDir>\install.json                receipt (what was written, for status and uninstall)
 *   HKCU\Software\Google\Chrome\NativeMessagingHosts\com.singularity.aidr_privacy  (default) = manifest
 *   HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.singularity.aidr_privacy (default) = manifest
 *
 * OCR uses the Windows built-in recognizer (Windows.Media.Ocr, vision/windows_ocr.ps1): no OCR model
 * is downloaded. The only download is `pip install --require-hashes` of vision/requirements.lock.txt.
 * Registry access and child processes go through injectable layers (RegistryLayer, Runner).
 */
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CHUNK_BYTES } from '../browser/transport.js';
import { FrameDecoder, encodeFrame } from '../native/framing.js';
import { COMPANION_BROWSERS, type CompanionBrowser, type DetectedExtension, EXTENSION_ID, detectBrowserGuardInstalls } from './ids.js';

export * from './ids.js';

export const COMPANION_HOST_NAME = 'com.singularity.aidr_privacy';
export const COMPANION_DESCRIPTION = 'Singularity AIDR local text and screenshot privacy scanner';
/** Browser Guard store ids admitted by default. None is published yet; add them here when they are. */
export const BROWSER_GUARD_STORE_IDS: readonly string[] = Object.freeze([]);
export const DEFAULT_BROWSERS: readonly CompanionBrowser[] = Object.freeze(['chrome', 'edge']);
/** Per-user registry key under which each browser looks up native messaging hosts. */
export const REGISTRY_KEYS: Readonly<Record<CompanionBrowser, string>> = Object.freeze({
  chrome: `HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\${COMPANION_HOST_NAME}`,
  edge: `HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\${COMPANION_HOST_NAME}`,
  chromium: `HKCU\\Software\\Chromium\\NativeMessagingHosts\\${COMPANION_HOST_NAME}`,
});
const RECEIPT = 'install.json', MANIFEST = `${COMPANION_HOST_NAME}.json`, CONFIG = 'host-config.json', OCR_MANIFEST = 'ocr-manifest.json';
/** Windows OCR recognizer tags the vision worker accepts (vision/worker.py WINDOWS_LANGUAGE). */
const WINDOWS_OCR_TAGS = ['tr', 'tr-TR', 'en', 'en-US', 'en-GB'];
const CMD_UNSAFE = /["%^&|<>!\r\n]/;

// --- injectable layers -------------------------------------------------------------------------

/** Registry access (HKCU default values). Sync or async implementations are both accepted. */
export interface RegistryLayer {
  setDefault(key: string, value: string): void | Promise<void>;
  /** The default value; null when the key does not exist. */
  getDefault(key: string): string | null | Promise<string | null>;
  deleteKey(key: string): void | Promise<void>;
}

const HKCU_KEY = /^HKCU\\Software\\[A-Za-z0-9 ._\\-]{1,240}$/;
export function assertUserKey(key: string): void {
  if (!HKCU_KEY.test(key) || key.includes('\\\\') || key.endsWith('\\')) throw new Error('COMPANION_REGISTRY_KEY_INVALID');
}

export interface RunResult { readonly code: number; readonly stdout: Buffer; readonly stderr: Buffer }
export interface RunOptions { readonly input?: Uint8Array | string; readonly timeoutMs?: number; readonly env?: NodeJS.ProcessEnv }
/** Runs a program without a shell and collects its output. */
export type Runner = (file: string, args: readonly string[], options?: RunOptions) => Promise<RunResult>;

export const processRunner: Runner = (file, args, options = {}) => new Promise((resolve) => {
  const child = spawn(file, [...args], { shell: false, windowsHide: true, env: options.env ?? process.env, stdio: ['pipe', 'pipe', 'pipe'] });
  const out: Buffer[] = [], err: Buffer[] = [];
  let settled = false;
  const done = (code: number) => { if (settled) return; settled = true; clearTimeout(timer); resolve({ code, stdout: Buffer.concat(out), stderr: Buffer.concat(err) }); };
  const timer = setTimeout(() => { child.kill(); done(-2); }, options.timeoutMs ?? 120_000);
  child.stdout.on('data', (c: Buffer) => out.push(c));
  child.stderr.on('data', (c: Buffer) => err.push(c));
  child.on('error', () => done(-1));
  child.on('close', (code) => done(code ?? -1));
  child.stdin.on('error', () => {});
  child.stdin.end(options.input ?? '');
});

function systemPath(...parts: string[]): string {
  return path.win32.join(process.env.SystemRoot ?? process.env.SYSTEMROOT ?? 'C:\\Windows', 'System32', ...parts);
}
export const WINDOWS_POWERSHELL = (): string => systemPath('WindowsPowerShell', 'v1.0', 'powershell.exe');

/**
 * The real Windows registry: writes through reg.exe (arguments reach it as UTF-16, so non-ASCII
 * profile paths are stored exactly), reads through Windows PowerShell with base64 output (reg.exe
 * prints in the OEM code page and localises "(Default)"). HKCU only.
 */
export function windowsRegistry(runner: Runner = processRunner): RegistryLayer {
  return {
    async setDefault(key, value) {
      assertUserKey(key);
      if (!value || /[\0\r\n]/.test(value)) throw new Error('COMPANION_REGISTRY_VALUE_INVALID');
      const r = await runner(systemPath('reg.exe'), ['add', key, '/ve', '/t', 'REG_SZ', '/d', value, '/f'], { timeoutMs: 15_000 });
      if (r.code !== 0) throw new Error(`COMPANION_REGISTRY_WRITE_FAILED: ${key}`);
    },
    async getDefault(key) {
      assertUserKey(key);
      const psPath = `Registry::HKEY_CURRENT_USER\\${key.slice('HKCU\\'.length)}`;
      const script = [
        `$k = '${psPath}'`,
        'if (-not (Test-Path -LiteralPath $k)) { exit 3 }',
        "$v = (Get-Item -LiteralPath $k).GetValue('')",
        "if ($null -eq $v) { $v = '' }",
        '[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$v)))',
      ].join('; ');
      const r = await runner(WINDOWS_POWERSHELL(), ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script], { timeoutMs: 30_000 });
      if (r.code === 3) return null;
      if (r.code !== 0) throw new Error(`COMPANION_REGISTRY_READ_FAILED: ${key}`);
      return Buffer.from(r.stdout.toString('ascii').trim(), 'base64').toString('utf8');
    },
    async deleteKey(key) {
      assertUserKey(key);
      const r = await runner(systemPath('reg.exe'), ['delete', key, '/f'], { timeoutMs: 15_000 });
      if (r.code !== 0) throw new Error(`COMPANION_REGISTRY_DELETE_FAILED: ${key}`);
    },
  };
}

/** In-memory registry (tests, dry runs); `entries` shows exactly what was written. */
export function memoryRegistry(initial: Record<string, string> = {}): RegistryLayer & { readonly entries: Map<string, string> } {
  const entries = new Map(Object.entries(initial));
  return {
    entries,
    setDefault(key, value) { assertUserKey(key); entries.set(key, value); },
    getDefault(key) { assertUserKey(key); return entries.get(key) ?? null; },
    deleteKey(key) { assertUserKey(key); entries.delete(key); },
  };
}

// --- pure builders -----------------------------------------------------------------------------

export function defaultInstallDir(env: NodeJS.ProcessEnv = process.env): string {
  const base = env.LOCALAPPDATA ?? path.join(env.USERPROFILE ?? '', 'AppData', 'Local');
  return path.win32.join(base, 'SingularityAIDR', 'PrivacyCompanion');
}

/** The native messaging manifest the browsers read. */
export function buildHostManifest(launcherPath: string, extensionIds: readonly string[]): Record<string, unknown> {
  if (!path.win32.isAbsolute(launcherPath) && !path.posix.isAbsolute(launcherPath)) throw new Error('COMPANION_LAUNCHER_NOT_ABSOLUTE');
  const ids = uniqueIds(extensionIds);
  return { name: COMPANION_HOST_NAME, description: COMPANION_DESCRIPTION, path: launcherPath, type: 'stdio', allowed_origins: ids.map(id => `chrome-extension://${id}/`) };
}

export interface CompanionOcrConfig {
  readonly python: string;
  readonly powershell: string;
  readonly manifest: string;
  /** Absolute path of the installed vision/windows_ocr.ps1 (hash-pinned in the manifest). */
  readonly windowsOcrScript?: string;
}

/**
 * Host config (packages/privacy/src/native/host.ts). Text: strict profile with label masking (what
 * Browser Guard's span recovery expects). OCR: decision-only `image-scan` through the Windows
 * recognizer; `barcodeUnavailable` decides whether clean text without a barcode decoder is `review`.
 */
export function buildHostConfig(extensionIds: readonly string[], ocr: CompanionOcrConfig | null, barcodeUnavailable: 'review' | 'allow' = 'review'): Record<string, unknown> {
  const config: Record<string, unknown> = {
    version: 1,
    allowedExtensionIds: uniqueIds(extensionIds),
    browserPolicyJSON: '{}',
    text: { profile: 'strict', mask: 'label', maxInputBytes: 1048576 },
  };
  if (ocr) {
    config.visual = {
      backend: { python: ocr.python, ocrEngine: 'windows', powershell: ocr.powershell, manifest: ocr.manifest, processTimeoutMs: 30000, ...(ocr.windowsOcrScript ? { windowsOcrScript: ocr.windowsOcrScript } : {}) },
      policy: { release: 'manual', mode: 'pii', granularity: 'line', barcodeAction: 'block', uncertainText: 'review', barcodeUnavailable, policyId: 'aidr-companion-visual-v1' },
    };
  }
  return config;
}

function uniqueIds(ids: readonly string[]): string[] {
  const list = [...new Set(ids)];
  if (!list.length || list.some(id => !EXTENSION_ID.test(id))) throw new Error('COMPANION_EXTENSION_ID_INVALID: expected one or more 32-letter (a-p) extension ids');
  return list;
}

/** Launcher source: the repo's C# launcher with the node, host and config paths embedded (base64). */
export function launcherSource(template: string, paths: { node: string; host: string; config: string }): string {
  let source = template;
  for (const [field, value] of Object.entries(paths)) {
    if (!path.win32.isAbsolute(value)) throw new Error('COMPANION_PATH_NOT_ABSOLUTE');
    const marker = `__${field.toUpperCase()}_BASE64__`;
    if (!source.includes(marker)) throw new Error('COMPANION_LAUNCHER_TEMPLATE_INVALID');
    source = source.replaceAll(marker, Buffer.from(value, 'utf8').toString('base64'));
  }
  return source;
}

export function cmdLauncher(paths: { node: string; host: string; config: string }): string {
  for (const value of Object.values(paths)) if (!path.win32.isAbsolute(value) || CMD_UNSAFE.test(value)) throw new Error('COMPANION_PATH_UNSAFE');
  // stdout is the binary native-messaging channel: nothing else may print to it.
  return `@echo off\r\n"${paths.node}" "${paths.host}" --config "${paths.config}" %*\r\n`;
}

// --- install -----------------------------------------------------------------------------------

export interface InstallOptions {
  /** Default: %LOCALAPPDATA%\SingularityAIDR\PrivacyCompanion. */
  readonly installDir?: string;
  /** Extension ids to admit in addition to the detected ones. */
  readonly extensionIds?: readonly string[];
  /** Store ids to admit (default BROWSER_GUARD_STORE_IDS). */
  readonly storeIds?: readonly string[];
  /** Read the browser profiles for Browser Guard installs (default true). */
  readonly detect?: boolean;
  /** Only detect the unpacked Browser Guard loaded from this folder. */
  readonly unpackedPath?: string;
  /** Browsers to register for (default chrome, edge). */
  readonly browsers?: readonly CompanionBrowser[];
  /** Node.js >= 22.16 that runs the host (default: the running node). */
  readonly node?: string;
  /** Base Python >= 3.11 for the venv (default: discovered through the py launcher). */
  readonly python?: string;
  /** `windows` (default on Windows): Windows built-in OCR; `none`: text only. */
  readonly ocr?: 'windows' | 'none';
  readonly barcodeUnavailable?: 'review' | 'allow';
  /** `exe` (default; falls back to `cmd` when it cannot be compiled) or `cmd`. */
  readonly launcher?: 'exe' | 'cmd';
  readonly registry?: RegistryLayer;
  readonly runner?: Runner;
  readonly localAppData?: string;
  /** Root of the built @singularityrd/aidr-privacy package (default: this module's package). */
  readonly packageRoot?: string;
  readonly log?: (line: string) => void;
}

export interface InstallReport {
  readonly ok: true;
  readonly hostName: string;
  readonly installDir: string;
  readonly manifestPath: string;
  readonly configPath: string;
  readonly launcherPath: string;
  readonly extensionIds: readonly string[];
  readonly detected: readonly DetectedExtension[];
  readonly registry: readonly { browser: CompanionBrowser; key: string; value: string }[];
  readonly ocr: { engine: 'windows'; languages: readonly string[]; barcodeEngine: 'pyzbar' | 'none'; python: string } | null;
  readonly warnings: readonly string[];
  readonly nextSteps: readonly string[];
}

export function packageRootOf(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
}

function copyTree(from: string, to: string, keep: (file: string) => boolean): void {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    const source = path.join(from, entry.name), target = path.join(to, entry.name);
    if (entry.isDirectory()) copyTree(source, target, keep);
    else if (entry.isFile() && keep(entry.name)) fs.copyFileSync(source, target);
  }
}

/** Copies the host runtime into `<installDir>\app` (replacing an earlier copy). */
export function stageApp(packageRoot: string, appDir: string): void {
  const dist = path.join(packageRoot, 'dist');
  if (!fs.existsSync(path.join(dist, 'native', 'host.js'))) throw new Error('COMPANION_BUILD_REQUIRED: build @singularityrd/aidr-privacy first');
  fs.rmSync(appDir, { recursive: true, force: true });
  copyTree(dist, path.join(appDir, 'dist'), name => name.endsWith('.js') || name.endsWith('.json'));
  fs.mkdirSync(path.join(appDir, 'vision'), { recursive: true });
  for (const file of ['worker.py', 'windows_ocr.ps1', 'build_manifest.py', 'requirements.lock.txt'])
    fs.copyFileSync(path.join(packageRoot, 'vision', file), path.join(appDir, 'vision', file));
  fs.mkdirSync(path.join(appDir, 'native'), { recursive: true });
  fs.copyFileSync(path.join(packageRoot, 'native', 'windows-launcher.cs'), path.join(appDir, 'native', 'windows-launcher.cs'));
  const pkg = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8')) as { version?: unknown };
  fs.writeFileSync(path.join(appDir, 'package.json'), `${JSON.stringify({ name: 'aidr-privacy-companion-app', private: true, type: 'module', version: pkg.version }, null, 2)}\n`);
}

const PY_ORDER = ['3.12', '3.13', '3.11', '3.14'];

/** A base Python >= 3.11: explicit, else the py launcher's list (3.12 preferred: the locks were tested with it). */
export async function findPython(runner: Runner, explicit?: string): Promise<string> {
  const check = async (exe: string) => {
    const r = await runner(exe, ['-I', '-c', 'import sys;print("%d.%d" % sys.version_info[:2])'], { timeoutMs: 30_000 });
    const v = r.stdout.toString().trim();
    return r.code === 0 && /^3\.(1[1-9]|[2-9]\d)$/.test(v);
  };
  if (explicit) { if (await check(explicit)) return explicit; throw new Error('COMPANION_PYTHON_UNSUITABLE: Python 3.11 or newer is required'); }
  const listed = await runner('py', ['-0p'], { timeoutMs: 30_000 });
  const found = new Map<string, string>();
  for (const line of listed.stdout.toString().split(/\r?\n/)) {
    const m = line.match(/^\s*-V:(\d+\.\d+)\S*\s+\*?\s*(\S.*\.exe)\s*$/i) ?? line.match(/^\s*-(\d+\.\d+)(?:-64)?\s+\*?\s*(\S.*\.exe)\s*$/i);
    if (m && !found.has(m[1]!)) found.set(m[1]!, m[2]!.trim());
  }
  for (const version of PY_ORDER) { const exe = found.get(version); if (exe && await check(exe)) return exe; }
  if (await check('python')) return 'python';
  throw new Error('COMPANION_PYTHON_MISSING: install Python 3.12 (python.org, per user) or pass --python');
}

/** Windows OCR recognizer languages installed for this user (e.g. ["tr"]). */
export async function windowsOcrLanguages(runner: Runner): Promise<string[]> {
  const script = '$null = [Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime]; [Windows.Media.Ocr.OcrEngine]::AvailableRecognizerLanguages | ForEach-Object { $_.LanguageTag }';
  const r = await runner(WINDOWS_POWERSHELL(), ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script], { timeoutMs: 60_000 });
  if (r.code !== 0) return [];
  return r.stdout.toString().split(/\r?\n/).map(s => s.trim()).filter(Boolean);
}

/** The recognizer tags to use: Turkish (required) plus English when installed. */
export function chooseOcrLanguages(available: readonly string[]): string[] {
  const pick = (prefix: string) => WINDOWS_OCR_TAGS.find(t => t.split('-')[0] === prefix && available.some(a => a.toLowerCase() === t.toLowerCase()));
  const tr = pick('tr'), en = pick('en');
  return tr ? [tr, ...(en ? [en] : [])] : [];
}

function writeJson(file: string, value: unknown): void {
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`);
  fs.renameSync(tmp, file);
}

function sha256(text: string): string { return createHash('sha256').update(text).digest('hex'); }

/** Installs (or updates) the companion for the current user and registers it for the browsers. */
export async function installCompanion(options: InstallOptions = {}): Promise<InstallReport> {
  const log = options.log ?? (() => {});
  const runner = options.runner ?? processRunner;
  const registry = options.registry ?? windowsRegistry(runner);
  const installDir = path.resolve(options.installDir ?? defaultInstallDir());
  const browsers = [...new Set(options.browsers ?? DEFAULT_BROWSERS)];
  if (!browsers.length || browsers.some(b => !COMPANION_BROWSERS.includes(b))) throw new Error('COMPANION_BROWSER_INVALID');
  const warnings: string[] = [];

  // 1. Which extensions may call the host.
  const storeIds = options.storeIds ?? BROWSER_GUARD_STORE_IDS;
  const detected = options.detect === false ? [] : detectBrowserGuardInstalls({
    ...(options.localAppData ? { localAppData: options.localAppData } : {}),
    ...(options.unpackedPath ? { unpackedPath: options.unpackedPath } : {}),
    storeIds, browsers: COMPANION_BROWSERS,
  });
  const extensionIds = [...new Set([...(options.extensionIds ?? []), ...storeIds, ...detected.map(d => d.id)])];
  if (!extensionIds.length) throw new Error('COMPANION_NO_EXTENSION_ID: no Browser Guard install was found in Chrome/Edge; load it first or pass --extension-id');
  uniqueIds(extensionIds);
  log(`extension ids: ${extensionIds.join(', ')}`);

  // 2. Host runtime.
  fs.mkdirSync(installDir, { recursive: true });
  const appDir = path.join(installDir, 'app');
  stageApp(options.packageRoot ?? packageRootOf(), appDir);
  const host = path.join(appDir, 'dist', 'native', 'host.js');
  const node = options.node ?? process.execPath;
  const configPath = path.join(installDir, CONFIG);
  log(`staged host runtime in ${appDir}`);

  // 3. OCR: venv with the hash-locked wheels, Windows recognizer, pinned manifest.
  let ocr: InstallReport['ocr'] = null, ocrConfig: CompanionOcrConfig | null = null;
  if ((options.ocr ?? (process.platform === 'win32' ? 'windows' : 'none')) === 'windows') {
    const languages = chooseOcrLanguages(await windowsOcrLanguages(runner));
    if (!languages.length) warnings.push('OCR_UNAVAILABLE: no Turkish Windows OCR recognizer is installed (Settings > Time & language > Language: add Turkish with OCR); pictures cannot be inspected');
    else {
      const basePython = await findPython(runner, options.python);
      const venv = path.join(installDir, 'venv'), python = path.join(venv, 'Scripts', 'python.exe');
      if (!fs.existsSync(python)) {
        log('creating the Python venv');
        const made = await runner(basePython, ['-m', 'venv', venv], { timeoutMs: 300_000 });
        if (made.code !== 0) throw new Error('COMPANION_VENV_FAILED');
      }
      log('installing the hash-locked OCR wheels (pip --require-hashes)');
      const pip = await runner(python, ['-m', 'pip', 'install', '--disable-pip-version-check', '--no-input', '--require-hashes', '--only-binary=:all:', '--no-deps', '-r', path.join(appDir, 'vision', 'requirements.lock.txt')], { timeoutMs: 900_000 });
      if (pip.code !== 0) throw new Error(`COMPANION_PIP_FAILED: ${pip.stderr.toString().trim().split(/\r?\n/).slice(-1)[0] ?? ''}`);
      const zbar = await runner(python, ['-I', '-c', 'from pyzbar.pyzbar import decode'], { timeoutMs: 60_000 });
      const barcodeEngine = zbar.code === 0 ? 'pyzbar' as const : 'none' as const;
      if (barcodeEngine === 'none') warnings.push('BARCODE_UNAVAILABLE: pyzbar cannot load libzbar (it needs the Visual C++ 2013 runtime); QR codes/barcodes are not checked and clean pictures are reported as not fully checked');
      const manifest = path.join(installDir, OCR_MANIFEST), powershell = WINDOWS_POWERSHELL(), script = path.join(appDir, 'vision', 'windows_ocr.ps1');
      fs.rmSync(manifest, { force: true });
      const built = await runner(python, ['-I', path.join(appDir, 'vision', 'build_manifest.py'), '--ocr-engine', 'windows', '--powershell', powershell, '--windows-ocr-script', script, '--languages', languages.join(','), '--barcode-engine', barcodeEngine, '--output', manifest], { timeoutMs: 60_000 });
      if (built.code !== 0) throw new Error('COMPANION_OCR_MANIFEST_FAILED');
      ocrConfig = { python, powershell, manifest };
      ocr = { engine: 'windows', languages, barcodeEngine, python: basePython };
      log(`OCR: Windows recognizer ${languages.join('+')}, barcodes ${barcodeEngine}`);
    }
  }
  writeJson(configPath, buildHostConfig(extensionIds, ocrConfig, options.barcodeUnavailable ?? 'review'));

  // 4. Launcher.
  const paths = { node, host, config: configPath };
  let launcherPath = '';
  if ((options.launcher ?? 'exe') === 'exe') {
    const exe = path.join(installDir, 'aidr-privacy-host.exe'), settings = path.join(installDir, 'launcher.sha256');
    const source = launcherSource(fs.readFileSync(path.join(appDir, 'native', 'windows-launcher.cs'), 'utf8'), paths);
    if (fs.existsSync(exe) && fs.existsSync(settings) && fs.readFileSync(settings, 'utf8') === sha256(source)) launcherPath = exe;
    else {
      const sourceFile = path.join(installDir, 'windows-launcher.cs'), out = path.join(installDir, 'aidr-privacy-host.new.exe');
      fs.writeFileSync(sourceFile, source);
      fs.rmSync(out, { force: true });
      const compile = await runner(WINDOWS_POWERSHELL(), ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
        'Add-Type -TypeDefinition ([IO.File]::ReadAllText($env:AIDR_LAUNCHER_SOURCE)) -Language CSharp -OutputAssembly $env:AIDR_LAUNCHER_OUT -OutputType ConsoleApplication'],
      { timeoutMs: 180_000, env: { ...process.env, AIDR_LAUNCHER_SOURCE: sourceFile, AIDR_LAUNCHER_OUT: out } });
      if (compile.code === 0 && fs.existsSync(out)) {
        try { fs.rmSync(exe, { force: true }); fs.renameSync(out, exe); fs.writeFileSync(settings, sha256(source)); launcherPath = exe; }
        catch { fs.rmSync(out, { force: true }); throw new Error('COMPANION_HOST_RUNNING: the host is in use; close Chrome/Edge and install again'); }
      } else warnings.push('LAUNCHER_COMPILE_FAILED: using the .cmd launcher instead');
    }
  }
  if (!launcherPath) {
    launcherPath = path.join(installDir, 'aidr-privacy-host.cmd');
    fs.writeFileSync(launcherPath, cmdLauncher(paths));
  }
  log(`launcher: ${launcherPath}`);

  // 5. Manifest and per-user registration.
  const manifestPath = path.join(installDir, MANIFEST);
  writeJson(manifestPath, buildHostManifest(launcherPath, extensionIds));
  const written: { browser: CompanionBrowser; key: string; value: string }[] = [];
  for (const browser of browsers) {
    const key = REGISTRY_KEYS[browser];
    await registry.setDefault(key, manifestPath);
    if ((await registry.getDefault(key)) !== manifestPath) throw new Error(`COMPANION_REGISTRY_VERIFY_FAILED: ${key}`);
    written.push({ browser, key, value: manifestPath });
  }
  writeJson(path.join(installDir, RECEIPT), { schema: 1, hostName: COMPANION_HOST_NAME, installDir, manifestPath, configPath, launcherPath, extensionIds, registry: written, ocr, installedAt: new Date().toISOString() });

  const nextSteps = detected.filter(d => !d.nativeMessagingGranted).map(d =>
    `${d.browser} (${d.profile}): open Browser Guard Options > Protection, turn on "Use the AIDR Privacy helper app" and click Allow in the permission prompt`);
  return { ok: true, hostName: COMPANION_HOST_NAME, installDir, manifestPath, configPath, launcherPath, extensionIds, detected, registry: written, ocr, warnings, nextSteps };
}

// --- uninstall / status ------------------------------------------------------------------------

export interface UninstallOptions {
  readonly installDir?: string;
  /** Browsers whose registration is removed (default all known). */
  readonly browsers?: readonly CompanionBrowser[];
  /** Keep the install directory (only remove the registration). */
  readonly keepFiles?: boolean;
  readonly registry?: RegistryLayer;
  readonly runner?: Runner;
}

const samePath = (a: string, b: string) => path.win32.resolve(a).toLowerCase() === path.win32.resolve(b).toLowerCase();

interface Receipt { hostName?: unknown; manifestPath?: unknown }
function readReceipt(installDir: string): Receipt | null {
  try { const r = JSON.parse(fs.readFileSync(path.join(installDir, RECEIPT), 'utf8')) as Receipt; return r?.hostName === COMPANION_HOST_NAME ? r : null; } catch { return null; }
}

/**
 * Removes the registration (only keys that point at this install's manifest; another product's
 * registration is left alone) and the install directory (only when it holds this companion's receipt).
 */
export async function uninstallCompanion(options: UninstallOptions = {}): Promise<{ ok: true; removedKeys: string[]; keptKeys: string[]; removedDir: boolean; warnings: string[] }> {
  const registry = options.registry ?? windowsRegistry(options.runner ?? processRunner);
  const installDir = path.resolve(options.installDir ?? defaultInstallDir());
  const receipt = readReceipt(installDir);
  const manifestPath = typeof receipt?.manifestPath === 'string' ? receipt.manifestPath : path.join(installDir, MANIFEST);
  const removedKeys: string[] = [], keptKeys: string[] = [], warnings: string[] = [];
  for (const browser of options.browsers ?? COMPANION_BROWSERS) {
    const key = REGISTRY_KEYS[browser], value = await registry.getDefault(key);
    if (value === null) continue;
    if (value && samePath(value, manifestPath)) { await registry.deleteKey(key); removedKeys.push(key); }
    else { keptKeys.push(key); warnings.push(`KEY_NOT_OURS: ${key} points at another manifest; left in place`); }
  }
  let removedDir = false;
  if (!options.keepFiles && fs.existsSync(installDir)) {
    if (!receipt) warnings.push('NO_RECEIPT: the install directory has no companion receipt; files left in place');
    else {
      try { fs.rmSync(installDir, { recursive: true, force: true }); removedDir = true; }
      catch { warnings.push('FILES_IN_USE: close Chrome/Edge (the host may be running) and run uninstall again to remove the files'); }
    }
  }
  return { ok: true, removedKeys, keptKeys, removedDir, warnings };
}

export interface StatusReport {
  readonly installed: boolean;
  readonly installDir: string;
  readonly registry: readonly { browser: CompanionBrowser; key: string; value: string | null; ours: boolean }[];
  readonly allowedExtensionIds: readonly string[];
  readonly ocr: boolean;
  readonly detected: readonly (DetectedExtension & { allowed: boolean })[];
  readonly problems: readonly string[];
}

/** What is installed and registered, which Browser Guard installs are admitted, and what is missing. */
export async function companionStatus(options: { installDir?: string; registry?: RegistryLayer; runner?: Runner; localAppData?: string; browsers?: readonly CompanionBrowser[] } = {}): Promise<StatusReport> {
  const registry = options.registry ?? windowsRegistry(options.runner ?? processRunner);
  const installDir = path.resolve(options.installDir ?? defaultInstallDir());
  const receipt = readReceipt(installDir);
  const manifestPath = path.join(installDir, MANIFEST), problems: string[] = [];
  let allowed: string[] = [], ocr = false;
  try {
    const config = JSON.parse(fs.readFileSync(path.join(installDir, CONFIG), 'utf8')) as { allowedExtensionIds?: unknown; visual?: unknown };
    allowed = Array.isArray(config.allowedExtensionIds) ? config.allowedExtensionIds.filter((x): x is string => typeof x === 'string') : [];
    ocr = !!config.visual;
  } catch { problems.push('CONFIG_MISSING'); }
  try {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as { path?: unknown };
    if (typeof manifest.path !== 'string' || !fs.existsSync(manifest.path)) problems.push('LAUNCHER_MISSING');
  } catch { problems.push('MANIFEST_MISSING'); }
  const reg: { browser: CompanionBrowser; key: string; value: string | null; ours: boolean }[] = [];
  for (const browser of options.browsers ?? DEFAULT_BROWSERS) {
    const key = REGISTRY_KEYS[browser], value = await registry.getDefault(key);
    const ours = !!value && samePath(value, manifestPath);
    if (!ours) problems.push(`NOT_REGISTERED: ${browser}`);
    reg.push({ browser, key, value, ours });
  }
  const detected = detectBrowserGuardInstalls({ ...(options.localAppData ? { localAppData: options.localAppData } : {}), storeIds: BROWSER_GUARD_STORE_IDS })
    .map(d => ({ ...d, allowed: allowed.includes(d.id) }));
  for (const d of detected) {
    if (!d.allowed) problems.push(`EXTENSION_NOT_ADMITTED: ${d.browser} ${d.profile} ${d.id} (install again to admit it)`);
    if (!d.nativeMessagingGranted) problems.push(`PERMISSION_NOT_GRANTED: ${d.browser} ${d.profile} (Options > "Use the AIDR Privacy helper app")`);
  }
  if (!ocr) problems.push('OCR_OFF');
  return { installed: !!receipt, installDir, registry: reg, allowedExtensionIds: allowed, ocr, detected, problems };
}

// --- verify through the real host process ------------------------------------------------------

export interface VerifyOptions {
  readonly installDir?: string;
  /** Extension id the host sees as its caller (default: the first admitted id). */
  readonly extensionId?: string;
  /** Text documents scanned through the host (counts only are reported). */
  readonly texts?: readonly string[];
  /** Images inspected through the host's OCR (`image-scan`). */
  readonly images?: readonly { name: string; bytes: Uint8Array }[];
  readonly timeoutMs?: number;
}

export interface VerifyReport {
  readonly ok: boolean;
  readonly launcherPath: string;
  readonly startMs: number;
  readonly ocr: boolean;
  readonly persistent: boolean;
  readonly texts: readonly { decision: unknown; counts: unknown; coverage: unknown; ms: number }[];
  readonly images: readonly { name: string; decision: unknown; counts: unknown; reasons: unknown; coverage: unknown; ms: number }[];
  readonly error?: string;
}

function digest(bytes: Uint8Array): string { return createHash('sha256').update(bytes).digest('hex'); }

/**
 * Starts the installed launcher exactly as the browser does (`<launcher> chrome-extension://<id>/
 * --parent-window=0`, through cmd.exe as Chrome does on Windows) and speaks the native messaging
 * protocol to it: hello, then each text and image. Reports decisions, per-type counts and timings
 * only (never text or pixels).
 */
export async function verifyCompanion(options: VerifyOptions = {}): Promise<VerifyReport> {
  const installDir = path.resolve(options.installDir ?? defaultInstallDir());
  const manifest = JSON.parse(fs.readFileSync(path.join(installDir, MANIFEST), 'utf8')) as { path: string; allowed_origins: string[] };
  const origin = options.extensionId ? `chrome-extension://${options.extensionId}/` : manifest.allowed_origins[0]!;
  const launcherPath = manifest.path;
  const comspec = process.env.ComSpec ?? systemPath('cmd.exe');
  const child = spawn(comspec, ['/d', '/s', '/c', `""${launcherPath}" ${origin} --parent-window=0"`], { windowsVerbatimArguments: true, windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'] });
  const decoder = new FrameDecoder(), waiting: ((m: Record<string, unknown>) => void)[] = [], queued: Record<string, unknown>[] = [];
  let failure: Error | null = null, seq = 0;
  const fail = (e: Error) => { failure ??= e; for (const w of waiting.splice(0)) w({ ok: false, code: e.message }); };
  child.stdout.on('data', (chunk: Buffer) => {
    try { for (const m of decoder.push(chunk)) { const w = waiting.shift(); if (w) w(m); else queued.push(m); } } catch (e) { fail(e as Error); }
  });
  child.on('close', () => fail(new Error('HOST_EXITED')));
  child.on('error', () => fail(new Error('HOST_START_FAILED')));
  child.stdin.on('error', () => {});
  const timeoutMs = options.timeoutMs ?? 90_000;
  const rpc = (op: string, extra: Record<string, unknown> = {}) => new Promise<Record<string, unknown>>((resolve, reject) => {
    if (failure) { reject(failure); return; }
    const id = `v${++seq}`, timer = setTimeout(() => reject(new Error(`TIMEOUT_${op}`)), timeoutMs);
    waiting.push((m) => { clearTimeout(timer); if (m.ok !== true || m.id !== id) reject(new Error(`HOST_REFUSED_${op}: ${String(m.code ?? '')}`)); else resolve(m); });
    const next = queued.shift(); if (next) waiting.shift()!(next);
    child.stdin.write(encodeFrame({ v: 1, id, op, ...extra }));
  });
  const send = async (kind: string, bytes: Uint8Array, policyDigest: unknown) => {
    await rpc('begin', { kind, size: bytes.length, sha256: digest(bytes), policyDigest });
    for (let offset = 0; offset < bytes.length; offset += CHUNK_BYTES)
      await rpc('write', { offset, data: Buffer.from(bytes.subarray(offset, offset + CHUNK_BYTES)).toString('base64') });
    return rpc('commit');
  };
  const started = performance.now();
  const texts: VerifyReport['texts'][number][] = [], images: VerifyReport['images'][number][] = [];
  try {
    const hello = await rpc('hello', { persistent: true });
    const startMs = Math.round(performance.now() - started);
    for (const text of options.texts ?? []) {
      const t = performance.now(), r = await send('text', Buffer.from(text, 'utf8'), hello.policyDigest);
      if (typeof r.outputBytes === 'number' && r.outputBytes > 0) {
        for (let offset = 0, done = false; !done;) { const chunk = await rpc('read', { offset }); done = chunk.done === true; offset += Buffer.from(String(chunk.data), 'base64').length; }
      }
      texts.push({ decision: r.decision, counts: r.counts, coverage: r.coverage, ms: Math.round(performance.now() - t) });
    }
    for (const image of options.images ?? []) {
      const t = performance.now(), r = await send('image-scan', image.bytes, hello.policyDigest);
      images.push({ name: image.name, decision: r.decision, counts: r.counts, reasons: r.reasons, coverage: r.coverage, ms: Math.round(performance.now() - t) });
    }
    return { ok: true, launcherPath, startMs, ocr: hello.ocr === true, persistent: hello.persistent === true, texts, images };
  } catch (e) {
    return { ok: false, launcherPath, startMs: -1, ocr: false, persistent: false, texts, images, error: (e as Error).message };
  } finally {
    child.stdin.end();
    setTimeout(() => { if (child.exitCode === null) child.kill(); }, 2000).unref();
  }
}
