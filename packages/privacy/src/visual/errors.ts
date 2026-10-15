export const VISUAL_CODES = new Set([
  'IMAGE_INPUT_INVALID', 'IMAGE_INPUT_LIMIT', 'IMAGE_FORMAT_UNSUPPORTED', 'IMAGE_DECODE_FAILED',
  'IMAGE_ANIMATION_BLOCKED', 'IMAGE_PIXEL_LIMIT', 'IMAGE_DIMENSION_LIMIT', 'IMAGE_PROTOCOL_INVALID',
  'IMAGE_HASH_MISMATCH', 'IMAGE_NO_TEXT', 'IMAGE_OCR_UNCERTAIN', 'IMAGE_OCR_LIMIT',
  'IMAGE_BARCODE_BLOCKED', 'IMAGE_BARCODE_UNAVAILABLE', 'IMAGE_OCR_UNAVAILABLE', 'IMAGE_OCR_FAILED',
  'IMAGE_OCR_TIMEOUT', 'IMAGE_WORKER_FAILED', 'IMAGE_WORKER_OUTPUT_LIMIT', 'IMAGE_TIMEOUT',
  'IMAGE_ABORTED', 'IMAGE_CONCURRENCY_LIMIT', 'IMAGE_REGION_LIMIT', 'IMAGE_GEOMETRY_INVALID',
  'IMAGE_POLICY_BLOCK', 'IMAGE_TEXT_BLOCK', 'IMAGE_TEXT_REVIEW', 'IMAGE_MANUAL_REVIEW',
  'IMAGE_NER_REQUIRED', 'IMAGE_PIXEL_VERIFICATION_FAILED', 'IMAGE_RESIDUAL_PII',
  'IMAGE_RESIDUAL_BARCODE', 'IMAGE_UNVERIFIED_OUTPUT', 'IMAGE_CONFIGURATION_INVALID',
  'IMAGE_DISPOSED', 'IMAGE_INTERNAL_FAILURE', 'IMAGE_ARTIFACT_MISMATCH',
  'IMAGE_SENSITIVE_TEXT', 'IMAGE_TEXT_PRESENT', 'IMAGE_BARCODE_NOT_INSPECTED', 'IMAGE_BARCODE_NOT_CHECKED',
]);
export class VisualError extends Error { constructor(readonly code: string) { super(code); this.name = 'VisualError'; } }
export function imageFail(code: string): never { throw new VisualError(code); }
export function imageCode(error: unknown): string {
  return error instanceof VisualError && VISUAL_CODES.has(error.code) ? error.code : 'IMAGE_INTERNAL_FAILURE';
}
export function integer(n: unknown, min: number, max: number, code = 'IMAGE_PROTOCOL_INVALID'): number {
  if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < min || n > max) imageFail(code);
  return n;
}
