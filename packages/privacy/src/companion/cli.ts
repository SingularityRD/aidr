#!/usr/bin/env node
/**
 * aidr-privacy-companion: per-user install of the AIDR Privacy companion (native host + Windows OCR)
 * for Browser Guard. See packages/privacy/README.md "AIDR Privacy companion".
 *
 *   aidr-privacy-companion install   [--install-dir D] [--extension-id ID]... [--store-id ID]... [--unpacked-path P]
 *                                    [--no-detect] [--browser chrome,edge] [--node N] [--python P] [--no-ocr]
 *                                    [--barcode-unavailable review|allow] [--launcher exe|cmd] [--json]
 *   aidr-privacy-companion uninstall [--install-dir D] [--browser chrome,edge,chromium] [--keep-files] [--json]
 *   aidr-privacy-companion status    [--install-dir D] [--json]
 *   aidr-privacy-companion verify    [--install-dir D] [--extension-id ID] [--image FILE]... [--text TEXT]... [--json]
 *   aidr-privacy-companion detect    [--unpacked-path P] [--json]
 *   aidr-privacy-companion extension-id <unpacked extension folder>
 *
 * Exit codes: 0 ok, 1 failed (`{ ok:false, error }` with --json), 2 usage. Verify exits 1 when the
 * host could not be reached.
 */
import { readFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { BROWSER_GUARD_STORE_IDS, type CompanionBrowser, companionStatus, detectBrowserGuardInstalls, installCompanion, uninstallCompanion, unpackedExtensionId, verifyCompanion } from './index.js';

class UsageError extends Error {}

function browsersOf(value: string | undefined): CompanionBrowser[] | undefined {
  if (value === undefined) return undefined;
  const list = value.split(',').map(s => s.trim()).filter(Boolean);
  if (!list.length || list.some(b => !['chrome', 'edge', 'chromium'].includes(b))) throw new UsageError('--browser expects chrome, edge and/or chromium');
  return list as CompanionBrowser[];
}

export async function main(argv: string[], out: (s: string) => void = s => process.stdout.write(`${s}\n`)): Promise<number> {
  const [command, ...rest] = argv;
  let json = false;
  try {
    const { values, positionals } = parseArgs({
      args: rest, allowPositionals: true, strict: true,
      options: {
        json: { type: 'boolean', default: false },
        'install-dir': { type: 'string' }, 'extension-id': { type: 'string', multiple: true }, 'store-id': { type: 'string', multiple: true },
        'unpacked-path': { type: 'string' }, 'no-detect': { type: 'boolean', default: false }, browser: { type: 'string' },
        node: { type: 'string' }, python: { type: 'string' }, 'no-ocr': { type: 'boolean', default: false },
        'barcode-unavailable': { type: 'string' }, launcher: { type: 'string' }, 'keep-files': { type: 'boolean', default: false },
        image: { type: 'string', multiple: true }, text: { type: 'string', multiple: true },
      },
    });
    json = values.json === true;
    const installDir = values['install-dir'] ? { installDir: resolve(values['install-dir']) } : {};
    const browsers = browsersOf(values.browser);
    let result: unknown;
    switch (command) {
      case 'install': {
        const barcode = values['barcode-unavailable'];
        if (barcode !== undefined && barcode !== 'review' && barcode !== 'allow') throw new UsageError('--barcode-unavailable expects review or allow');
        const launcher = values.launcher;
        if (launcher !== undefined && launcher !== 'exe' && launcher !== 'cmd') throw new UsageError('--launcher expects exe or cmd');
        result = await installCompanion({
          ...installDir,
          extensionIds: values['extension-id'] ?? [],
          storeIds: [...BROWSER_GUARD_STORE_IDS, ...(values['store-id'] ?? [])],
          detect: !values['no-detect'],
          ...(values['unpacked-path'] ? { unpackedPath: resolve(values['unpacked-path']) } : {}),
          ...(browsers ? { browsers } : {}),
          ...(values.node ? { node: resolve(values.node) } : {}),
          ...(values.python ? { python: values.python } : {}),
          ocr: values['no-ocr'] ? 'none' : 'windows',
          ...(barcode ? { barcodeUnavailable: barcode } : {}),
          ...(launcher ? { launcher } : {}),
          log: json ? () => {} : line => out(`[companion] ${line}`),
        });
        break;
      }
      case 'uninstall':
        result = await uninstallCompanion({ ...installDir, ...(browsers ? { browsers } : {}), keepFiles: values['keep-files'] === true });
        break;
      case 'status':
        result = await companionStatus({ ...installDir });
        break;
      case 'verify': {
        result = await verifyCompanion({
          ...installDir,
          ...(values['extension-id']?.[0] ? { extensionId: values['extension-id'][0] } : {}),
          texts: values.text ?? [],
          images: (values.image ?? []).map(file => ({ name: basename(file), bytes: readFileSync(file) })),
        });
        out(JSON.stringify(result, null, json ? 0 : 2));
        return (result as { ok: boolean }).ok ? 0 : 1;
      }
      case 'detect':
        result = detectBrowserGuardInstalls({ storeIds: BROWSER_GUARD_STORE_IDS, ...(values['unpacked-path'] ? { unpackedPath: resolve(values['unpacked-path']) } : {}) });
        break;
      case 'extension-id':
        if (positionals.length !== 1) throw new UsageError('extension-id needs one folder');
        result = { extensionId: unpackedExtensionId(positionals[0]!) };
        break;
      default:
        throw new UsageError(command ? `unknown command ${command}` : 'missing command (install, uninstall, status, verify, detect, extension-id)');
    }
    out(JSON.stringify(result, null, json ? 0 : 2));
    return 0;
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    if (e instanceof UsageError || (e as { code?: unknown })?.code === 'ERR_PARSE_ARGS_UNKNOWN_OPTION') { process.stderr.write(`${message}\n`); return 2; }
    if (json) out(JSON.stringify({ ok: false, error: message }));
    else process.stderr.write(`[companion] ${message}\n`);
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]).toLowerCase() === fileURLToPath(import.meta.url).toLowerCase()) {
  process.exitCode = await main(process.argv.slice(2));
}
