// GENERATED from packages/privacy/src/errors.ts by scripts/sync-privacy-rules.mjs — do not edit
// Regenerate: pnpm sync:privacy-rules (verify: pnpm verify:privacy-rules)
export class PrivacyError extends Error {
  constructor(readonly code: string) { super(code); this.name = 'PrivacyError'; }
}
export function fail(code: string): never { throw new PrivacyError(code); }
export function requireInt(n: number, min: number, max: number): number {
  if (!Number.isSafeInteger(n) || n < min || n > max) fail('INVALID_CONFIGURATION');
  return n;
}
