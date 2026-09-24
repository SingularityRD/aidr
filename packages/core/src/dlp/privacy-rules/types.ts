// GENERATED from packages/privacy/src/types.ts by scripts/sync-privacy-rules.mjs — do not edit
// Regenerate: pnpm sync:privacy-rules (verify: pnpm verify:privacy-rules)
export const ENTITY_TYPES = [
  'PERSON', 'EMAIL', 'PHONE', 'TC_KIMLIK', 'IBAN', 'CREDIT_CARD', 'ADDRESS',
  'US_SSN', 'DATE_OF_BIRTH', 'PASSPORT', 'NATIONAL_ID', 'TAX_ID', 'BANK_ACCOUNT',
  'IP_ADDRESS', 'MAC_ADDRESS', 'SECRET', 'PRIVATE_KEY', 'INTERNAL', 'CLASSIFIED',
  'LOCATION', 'USERNAME', 'HEALTH_ID', 'LICENSE_PLATE',
] as const;
export type EntityType = typeof ENTITY_TYPES[number];
export type Profile = 'balanced' | 'strict' | 'defense';
export type MaskMode = 'label' | 'redact' | 'token';
export type Action = 'redact' | 'review' | 'block';
export type Language = 'tr' | 'en';
export type Evidence = 'checksum' | 'pattern' | 'context' | 'dictionary' | 'ner' | 'schema';
export interface Finding {
  /** Half-open offsets in the ORIGINAL JavaScript string, in UTF-16 code units. */
  readonly start: number;
  readonly end: number;
  readonly type: EntityType;
  /** Heuristic score, NOT a calibrated probability. */
  readonly score: number;
  readonly evidence: Evidence;
}
export interface LiteralRule {
  readonly value: string;
  readonly type: EntityType;
}
export interface NerEntity {
  readonly start: number;
  readonly end: number;
  readonly type: EntityType;
  readonly score: number;
}
export interface NerCapabilities {
  readonly local: true;
  readonly offsetUnit: 'utf16';
  /** Language/type declarations are not measured quality guarantees. */
  readonly languages: readonly Language[];
  readonly entities: readonly EntityType[];
  readonly revision: string;
  readonly entitiesByLanguage?: Readonly<Partial<Record<Language, readonly EntityType[]>>>;
}
export interface NerResponse {
  readonly complete: true;
  readonly entities: readonly NerEntity[];
}
/** Trusted in-process code or the bundled local child-process provider. Never pass untrusted code. */
export interface NerProvider {
  readonly capabilities: NerCapabilities;
  detect(text: string, signal: AbortSignal): Promise<NerResponse>;
}
export interface EngineOptions {
  readonly profile?: Profile;
  readonly mask?: MaskMode;
  readonly tenantId?: string;
  readonly keyId?: string;
  readonly tokenKey?: Uint8Array;
  readonly literals?: readonly LiteralRule[];
  readonly actions?: Readonly<Partial<Record<EntityType, Action>>>;
  readonly ner?: NerProvider;
  readonly maxInputBytes?: number;
  readonly maxFindings?: number;
  readonly maxScanMs?: number;
  readonly nerTimeoutMs?: number;
  readonly maxConcurrent?: number;
  readonly maxJsonDepth?: number;
  readonly maxJsonNodes?: number;
  readonly policyId?: string;
}
export interface AuditSummary {
  readonly engineVersion: string;
  readonly policyId: string;
  readonly profile: Profile;
  readonly coverage: 'rules-only' | 'rules-and-ner';
  readonly inputBytes: number;
  readonly counts: Readonly<Partial<Record<EntityType, number>>>;
  readonly elapsedMs: number;
}
export interface TextResult {
  readonly decision: 'allow' | 'redact' | 'review' | 'block';
  /** null is never forwardable. Never fall back to the original text. */
  readonly output: string | null;
  readonly findings: readonly Finding[];
  /** Static codes only: no input, exception messages, model words or secrets. */
  readonly reasons: readonly string[];
  readonly audit: AuditSummary;
}
export interface JsonResult {
  readonly decision: TextResult['decision'];
  readonly output: string | null;
  readonly reasons: readonly string[];
  /** Deliberately omits raw JSON paths and keys, which themselves may contain PII. */
  readonly audit: AuditSummary;
}
export type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };
