import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, posix, win32 } from 'node:path';

/** Browsers whose per-user profiles and native-messaging registration the companion handles. */
export type CompanionBrowser = 'chrome' | 'edge' | 'chromium';
export const COMPANION_BROWSERS: readonly CompanionBrowser[] = ['chrome', 'edge', 'chromium'];
export const EXTENSION_ID = /^[a-p]{32}$/;

/**
 * The id Chromium gives an unpacked extension loaded from `dir`: the first 128 bits of
 * SHA-256 over the absolute path, hex digits mapped to a-p. On Windows the path is hashed as
 * UTF-16LE with an upper-case drive letter (Chromium's MaybeNormalizePath); elsewhere as UTF-8.
 * The id changes when the folder is moved or renamed.
 */
export function unpackedExtensionId(dir: string, platform: NodeJS.Platform = process.platform): string {
  let bytes: Buffer;
  if (platform === 'win32') {
    let p = win32.resolve(dir);
    if (/^[a-z]:/.test(p)) p = p[0]!.toUpperCase() + p.slice(1);
    bytes = Buffer.from(p, 'utf16le');
  } else bytes = Buffer.from(posix.resolve(dir), 'utf8');
  const hex = createHash('sha256').update(bytes).digest('hex').slice(0, 32);
  return [...hex].map(d => String.fromCharCode(97 + Number.parseInt(d, 16))).join('');
}

/** Per-user profile root of each browser (Windows layout). */
export function profileRoots(localAppData: string): Record<CompanionBrowser, string> {
  return {
    chrome: join(localAppData, 'Google', 'Chrome', 'User Data'),
    edge: join(localAppData, 'Microsoft', 'Edge', 'User Data'),
    chromium: join(localAppData, 'Chromium', 'User Data'),
  };
}

export interface DetectedExtension {
  readonly browser: CompanionBrowser;
  /** Profile directory name (`Default`, `Profile 1`, ...). */
  readonly profile: string;
  readonly id: string;
  /** `unpacked` (loaded with "Load unpacked") or `store` (a known store id). */
  readonly source: 'unpacked' | 'store';
  /** Folder the unpacked extension is loaded from (absent for store installs). */
  readonly path?: string;
  /** Whether the user has already granted the optional `nativeMessaging` permission. */
  readonly nativeMessagingGranted: boolean;
}

export interface DetectOptions {
  /** %LOCALAPPDATA% (default: the environment's). */
  readonly localAppData?: string;
  /** Only unpacked extensions loaded from this folder (case-insensitive on Windows). */
  readonly unpackedPath?: string;
  /** Store ids to report when installed (e.g. BROWSER_GUARD_STORE_IDS). */
  readonly storeIds?: readonly string[];
  readonly browsers?: readonly CompanionBrowser[];
}

const PREFERENCE_FILES = ['Secure Preferences', 'Preferences'];
const MAX_PREFERENCES = 64 * 1024 * 1024;
/** Chromium `Manifest::Location`: 4 = unpacked (loaded from a folder). */
const LOCATION_UNPACKED = 4;

function readJson(file: string, limit: number): unknown {
  try {
    if (!existsSync(file) || statSync(file).size > limit) return undefined;
    return JSON.parse(readFileSync(file, 'utf8').replace(/^﻿/, ''));
  } catch { return undefined; }
}

/** Whether the unpacked folder holds Singularity AIDR Browser Guard (manifest name or its locale name). */
export function isBrowserGuardFolder(dir: string): boolean {
  const manifest = readJson(join(dir, 'manifest.json'), 1024 * 1024) as { name?: unknown; default_locale?: unknown } | undefined;
  if (!manifest || typeof manifest.name !== 'string') return false;
  let name = manifest.name;
  const key = name.match(/^__MSG_(\w+)__$/)?.[1];
  if (key) {
    const locale = typeof manifest.default_locale === 'string' && /^[A-Za-z_]{2,8}$/.test(manifest.default_locale) ? manifest.default_locale : 'en';
    const messages = readJson(join(dir, '_locales', locale, 'messages.json'), 1024 * 1024) as Record<string, { message?: unknown }> | undefined;
    const entry = messages && Object.entries(messages).find(([k]) => k.toLowerCase() === key.toLowerCase())?.[1];
    name = typeof entry?.message === 'string' ? entry.message : '';
  }
  return /Singularity AIDR Browser Guard/i.test(name);
}

const samePath = (a: string, b: string) => win32.resolve(a).toLowerCase() === win32.resolve(b).toLowerCase();

/**
 * Reads (never writes) the browsers' Preferences / Secure Preferences and lists Browser Guard
 * installs: unpacked folders that contain Browser Guard (or exactly `unpackedPath`), and installed
 * store ids from `storeIds`. Each id appears once per browser profile.
 */
export function detectBrowserGuardInstalls(options: DetectOptions = {}): DetectedExtension[] {
  const localAppData = options.localAppData ?? process.env.LOCALAPPDATA;
  if (!localAppData) return [];
  const roots = profileRoots(localAppData), found: DetectedExtension[] = [];
  const storeIds = new Set((options.storeIds ?? []).filter(id => EXTENSION_ID.test(id)));
  for (const browser of options.browsers ?? COMPANION_BROWSERS) {
    const root = roots[browser];
    let profiles: string[];
    try { profiles = readdirSync(root, { withFileTypes: true }).filter(d => d.isDirectory()).map(d => d.name); } catch { continue; }
    for (const profile of profiles.sort()) {
      for (const file of PREFERENCE_FILES) {
        const prefs = readJson(join(root, profile, file), MAX_PREFERENCES) as { extensions?: { settings?: Record<string, unknown> } } | undefined;
        const settings = prefs?.extensions?.settings;
        if (!settings || typeof settings !== 'object') continue;
        for (const [id, raw] of Object.entries(settings)) {
          if (!EXTENSION_ID.test(id) || !raw || typeof raw !== 'object') continue;
          const entry = raw as { location?: unknown; path?: unknown; granted_permissions?: { api?: unknown }; active_permissions?: { api?: unknown } };
          const api = [entry.granted_permissions?.api, entry.active_permissions?.api].flatMap(a => Array.isArray(a) ? a : []);
          const granted = api.includes('nativeMessaging');
          let match: DetectedExtension | undefined;
          if (entry.location === LOCATION_UNPACKED && typeof entry.path === 'string' && win32.isAbsolute(entry.path)) {
            const wanted = options.unpackedPath ? samePath(entry.path, options.unpackedPath) : isBrowserGuardFolder(entry.path);
            if (wanted) match = { browser, profile, id, source: 'unpacked', path: entry.path, nativeMessagingGranted: granted };
          } else if (storeIds.has(id)) match = { browser, profile, id, source: 'store', nativeMessagingGranted: granted };
          if (!match) continue;
          // The same entry can be in both files: keep one, and keep the granted permission if either reports it.
          const i = found.findIndex(f => f.browser === browser && f.profile === profile && f.id === id);
          if (i < 0) found.push(match);
          else if (granted) found[i] = { ...found[i]!, nativeMessagingGranted: true };
        }
      }
    }
  }
  return found;
}
