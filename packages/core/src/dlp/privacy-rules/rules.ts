// GENERATED from packages/privacy/src/rules.ts by scripts/sync-privacy-rules.mjs — do not edit
// Regenerate: pnpm sync:privacy-rules (verify: pnpm verify:privacy-rules)
import { detectRules } from './detectors.js';
import { LiteralMatcher } from './dictionary.js';
import { fail, PrivacyError, requireInt } from './errors.js';
import { detectionViews, sourceSpan, type TextView } from './normalize.js';
import { mergeFindings } from './spans.js';
import { IBAN_LENGTHS } from './validators.js';
import { ENTITY_TYPES, type EntityType, type Finding, type LiteralRule } from './types.js';

/**
 * Pure, synchronous rule layer: the same normalization, detectors, validators and span
 * merging as the engines, with no NER, no crypto, no timers and no I/O. Safe to vendor into
 * other runtimes (the AIDR core DLP engine consumes a generated copy of this file).
 */
export interface RuleFinding {
  readonly type: EntityType;
  /** Half-open offsets in the ORIGINAL JavaScript string, in UTF-16 code units. */
  readonly start: number;
  readonly end: number;
  /** Heuristic score, NOT a calibrated probability. */
  readonly score: number;
}
export interface ScanTextOptions {
  /** Entity types to report. Omitted means every type the rules can emit. */
  readonly enabled?: readonly EntityType[];
  /** Administrator literals matched with the bounded Aho-Corasick dictionary. */
  readonly literals?: readonly LiteralRule[];
  /** Inputs longer than this many UTF-16 code units are not scanned (incomplete). */
  readonly maxChars?: number;
}
export interface ScanTextResult {
  readonly findings: readonly RuleFinding[];
  /** true when part of the input could not be inspected; findings are then only a lower bound. */
  readonly incomplete: boolean;
  /** Static reason codes (never input text) explaining an incomplete scan. */
  readonly reasons: readonly string[];
}
export type RuleMaskMode = 'label' | 'redact';

export const DEFAULT_MAX_CHARS = 1048576;

/** Complete SWIFT IBAN registry lengths. validators.ts keeps a narrower declared-validated subset. */
export const IBAN_REGISTRY_LENGTHS: Readonly<Record<string, number>> = Object.freeze({
  AD:24,AE:23,AL:28,AT:20,AZ:28,BA:20,BE:16,BG:22,BH:22,BI:27,BR:29,BY:28,CH:21,CR:22,CY:28,
  CZ:24,DE:22,DJ:27,DK:18,DO:28,EE:20,EG:29,ES:24,FI:18,FK:18,FO:18,FR:27,GB:22,GE:22,GI:23,
  GL:18,GR:27,GT:28,HN:28,HR:21,HU:28,IE:22,IL:23,IQ:23,IS:26,IT:27,JO:30,KW:30,KZ:20,LB:28,
  LC:32,LI:21,LT:20,LU:20,LV:21,LY:25,MC:27,MD:24,ME:22,MK:19,MN:20,MR:27,MT:31,MU:30,NI:28,
  NL:18,NO:15,OM:23,PK:24,PL:28,PS:29,PT:25,QA:29,RO:24,RS:22,RU:33,SA:24,SC:31,SD:18,SE:24,
  SI:19,SK:24,SM:27,SO:23,ST:25,SV:28,TL:23,TN:24,TR:26,UA:29,VA:22,VG:24,XK:20,YE:30,
});

/** ISO 13616 mod-97 check for any registered country. Syntax/check digits only, never existence. */
export function validIbanAnyCountry(value: string): boolean {
  const s = value.replace(/[ \t-]/g, '').toUpperCase();
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(s) || IBAN_REGISTRY_LENGTHS[s.slice(0, 2)] !== s.length) return false;
  let remainder = 0;
  for (const c of s.slice(4) + s.slice(0, 4)) {
    const n = c >= 'A' && c <= 'Z' ? String(c.charCodeAt(0) - 55) : c;
    for (const d of n) remainder = (remainder * 10 + Number(d)) % 97;
  }
  return remainder === 1;
}

/** Same bounded, exact-length scan as detectors.ts, for registry countries it does not declare. */
function detectRegistryIbans(text: string, emit: (start: number, end: number) => void): void {
  for (const m of text.matchAll(/(?<![\p{L}\p{N}])[A-Za-z]{2}[ -]?[0-9]{2}/gu)) {
    const country = m[0].slice(0, 2).toUpperCase(), expected = IBAN_REGISTRY_LENGTHS[country];
    // detectors.ts owns (and more strictly validates) the declared subset.
    if (!expected || IBAN_LENGTHS[country]) continue;
    let i = m.index, count = 0, spaces = 0;
    for (; i < text.length && count < expected; i++) {
      const c = text[i] ?? '';
      if (/[A-Za-z0-9]/.test(c)) { count++; spaces = 0; }
      else if (/[ \t-]/.test(c) && spaces++ < 3) continue;
      else break;
    }
    if (count === expected && !/[A-Za-z0-9]/.test(text[i] ?? '') && validIbanAnyCountry(text.slice(m.index, i))) emit(m.index, i);
  }
}

function enabledSet(enabled: readonly EntityType[] | undefined): ReadonlySet<EntityType> {
  if (enabled === undefined) return new Set(ENTITY_TYPES);
  if (!Array.isArray(enabled)) fail('INVALID_CONFIGURATION');
  for (const type of enabled) if (!ENTITY_TYPES.includes(type)) fail('INVALID_CONFIGURATION');
  return new Set(enabled);
}

function reasonCode(error: unknown): string {
  return error instanceof PrivacyError && /^[A-Z_]{1,64}$/.test(error.code) ? error.code : 'RULE_SCAN_FAILURE';
}

/**
 * Scan text with the deterministic TR/EN rules. Configuration errors throw PrivacyError;
 * content that cannot be fully inspected never throws and is reported as `incomplete`,
 * which callers enforcing policy must treat as a failed (not clean) inspection.
 */
export function scanText(text: string, options: ScanTextOptions = {}): ScanTextResult {
  if (typeof text !== 'string') fail('INVALID_INPUT');
  const maxChars = requireInt(options.maxChars ?? DEFAULT_MAX_CHARS, 1, 16777216);
  const enabled = enabledSet(options.enabled);
  const literals = options.literals ?? [];
  for (const rule of literals) if (!rule || typeof rule.value !== 'string' || !ENTITY_TYPES.includes(rule.type)) fail('INVALID_CONFIGURATION');
  const matcher = literals.length ? new LiteralMatcher(literals) : undefined;
  if (text.length > maxChars) return Object.freeze({ findings: Object.freeze([]), incomplete: true, reasons: Object.freeze(['INPUT_LIMIT']) });
  const found: Finding[] = [], seen = new Set<string>(), reasons = new Set<string>();
  const push = (view: TextView, a: number, b: number, type: EntityType, score: number, evidence: Finding['evidence']): void => {
    if (!enabled.has(type)) return;
    const [start, end] = sourceSpan(view, a, b), key = `${start}:${end}:${type}`;
    if (seen.has(key)) return;
    seen.add(key); found.push({ start, end, type, score, evidence });
  };
  let views: TextView[] = [];
  try { views = detectionViews(text); } catch (error) { reasons.add(reasonCode(error)); }
  for (const view of views) {
    // Each stage is isolated: a malformed field must not silence the remaining detectors.
    try { detectRules(view.text, (a, b, type, score, evidence) => push(view, a, b, type, score, evidence), type => enabled.has(type)); }
    catch (error) { reasons.add(reasonCode(error)); }
    try { if (enabled.has('IBAN')) detectRegistryIbans(view.text, (a, b) => push(view, a, b, 'IBAN', 0.99, 'checksum')); }
    catch (error) { reasons.add(reasonCode(error)); }
    try { matcher?.scan(view.text, (a, b, type) => push(view, a, b, type, 1, 'dictionary')); }
    catch (error) { reasons.add(reasonCode(error)); }
  }
  const findings = mergeFindings(found).map(f => Object.freeze({ type: f.type, start: f.start, end: f.end, score: f.score }));
  return Object.freeze({ findings: Object.freeze(findings), incomplete: reasons.size > 0, reasons: Object.freeze([...reasons].sort()) });
}

/** Replace every finding span with a constant placeholder. Overlaps are unioned, never partially exposed. */
export function maskText(text: string, findings: readonly RuleFinding[], mode: RuleMaskMode = 'label'): string {
  if (typeof text !== 'string' || !Array.isArray(findings) || (mode !== 'label' && mode !== 'redact')) fail('INVALID_CONFIGURATION');
  for (const f of findings) {
    if (!f || !ENTITY_TYPES.includes(f.type) || !Number.isSafeInteger(f.start) || !Number.isSafeInteger(f.end)
      || f.start < 0 || f.end <= f.start || f.end > text.length) fail('INVALID_SPAN');
  }
  const merged = mergeFindings(findings.map(f => ({ start: f.start, end: f.end, type: f.type, score: f.score, evidence: 'pattern' as const })));
  const chunks: string[] = [];
  let pos = 0;
  for (const f of merged) { chunks.push(text.slice(pos, f.start), mode === 'redact' ? '[REDACTED]' : `[${f.type}]`); pos = f.end; }
  chunks.push(text.slice(pos));
  return chunks.join('');
}
