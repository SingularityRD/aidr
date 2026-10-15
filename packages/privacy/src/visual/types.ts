import type { EntityType, TextResult } from '../types.js';
/** Half-open pixel rectangle in the EXIF-oriented, opaque output canvas. */
export interface Box { readonly x: number; readonly y: number; readonly width: number; readonly height: number }
export interface OcrWord extends Box {
  readonly text: string; readonly confidence: number; readonly line: number;
}
export interface OcrPage { readonly words: readonly OcrWord[] }
export interface ImageScan {
  readonly protocol: 1; readonly complete: true;
  readonly inputSha256: string; readonly pixelSha256: string;
  readonly width: number; readonly height: number;
  readonly format: 'PNG' | 'JPEG' | 'WEBP';
  readonly pages: readonly OcrPage[];
  /** Payloads deliberately never cross the process boundary. */
  readonly barcodes: readonly Box[];
  readonly languages: readonly string[];
  /** Present (`windows`) when the worker used Windows.Media.Ocr instead of Tesseract. */
  readonly ocrEngine?: 'windows';
  /** Present (`none`) when the endpoint has no barcode decoder: `barcodes` is then empty but NOT a clean result. */
  readonly barcodeCoverage?: 'none';
}
export interface RenderScan {
  readonly protocol: 1; readonly complete: true;
  readonly png: Uint8Array; readonly width: number; readonly height: number;
  readonly pages: readonly OcrPage[]; readonly barcodes: readonly Box[];
  readonly ocrEngine?: 'windows'; readonly barcodeCoverage?: 'none';
}
/** Trusted backend; no HTTP URLs, untrusted plugins or client-supplied OCR accepted. */
export interface ImageBackend {
  inspect(input: Uint8Array, signal: AbortSignal): Promise<ImageScan>;
  render(input: Uint8Array, scan: ImageScan, regions: readonly Box[], signal: AbortSignal): Promise<RenderScan>;
}
export interface VisualRegion extends Box { readonly types: readonly (EntityType | 'OCR_UNCERTAIN' | 'ALL_TEXT' | 'BARCODE')[] }
export interface VisualOptions {
  readonly backend: ImageBackend;
  readonly textEngine: { protect(text: string): Promise<TextResult> };
  /** Default manual: inspection can NEVER release bytes. Approval workflow is external. */
  readonly release?: 'manual' | 'automatic';
  readonly mode?: 'pii' | 'all-text' | 'block';
  readonly granularity?: 'line' | 'word';
  readonly barcodeAction?: 'block' | 'redact';
  readonly uncertainText?: 'review' | 'redact-line';
  readonly minConfidence?: number;
  readonly minWordHeight?: number;
  readonly paddingPx?: number;
  readonly maxInputBytes?: number; readonly maxPixels?: number; readonly maxDimension?: number;
  readonly maxWords?: number; readonly maxTextBytes?: number; readonly maxRegions?: number;
  readonly timeoutMs?: number; readonly maxConcurrent?: number;
  readonly policyId?: string;
  /** Require underlying engine's declared rules-and-ner coverage, not a quality guarantee. */
  readonly requireNer?: boolean;
  /**
   * Backend without a barcode decoder (`barcodeCoverage: 'none'`). `review` (default): an image
   * that would otherwise be clean is reported `review` / IMAGE_BARCODE_NOT_CHECKED, because a QR
   * code or barcode in it was never looked for. `allow`: an administrator accepts that gap.
   * Sensitive text is blocked either way; `protect` never releases bytes without barcode coverage.
   */
  readonly barcodeUnavailable?: 'review' | 'allow';
}
export interface VisualAudit {
  readonly version: string; readonly policyId: string; readonly inputBytes: number;
  readonly width: number; readonly height: number; readonly wordCount: number;
  readonly regionCount: number; readonly barcodeCount: number;
  readonly elapsedMs: number;
  readonly textCoverage: 'unknown' | 'rules-only' | 'rules-and-ner';
  readonly verification: 'not-released' | 'pixel-and-residual-scan';
}
/**
 * Decision-only OCR inspection (`VisualPrivacyEngine.inspect`): no image bytes are produced.
 * `allow` = every OCR word was inspected and no sensitive text was found; `block` = sensitive text
 * (see `counts`) or a policy that blocks images/all text; `review` = not fully inspected, never clean.
 */
export interface VisualInspection {
  readonly decision: 'allow' | 'block' | 'review';
  /** Findings per entity type in the OCR text (counts only; never text or positions). */
  readonly counts: Readonly<Partial<Record<EntityType, number>>>;
  readonly reasons: readonly string[];
  readonly audit: VisualAudit;
}
export interface VisualResult {
  readonly decision: 'allow' | 'redact' | 'review' | 'block';
  /** The ONLY image bytes allowed to be forwarded. Original input is NEVER a fallback. */
  readonly output: Buffer | null;
  readonly contentType: 'image/png' | null;
  readonly filename: 'aidr-sanitized.png' | null;
  readonly outputSha256: string | null;
  readonly regions: readonly VisualRegion[];
  readonly reasons: readonly string[];
  /** No original content hashes, filenames, OCR text, QR payloads, or exception messages. */
  readonly audit: VisualAudit;
}
