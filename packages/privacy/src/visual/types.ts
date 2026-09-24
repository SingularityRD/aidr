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
}
export interface RenderScan {
  readonly protocol: 1; readonly complete: true;
  readonly png: Uint8Array; readonly width: number; readonly height: number;
  readonly pages: readonly OcrPage[]; readonly barcodes: readonly Box[];
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
}
export interface VisualAudit {
  readonly version: string; readonly policyId: string; readonly inputBytes: number;
  readonly width: number; readonly height: number; readonly wordCount: number;
  readonly regionCount: number; readonly barcodeCount: number;
  readonly elapsedMs: number;
  readonly textCoverage: 'unknown' | 'rules-only' | 'rules-and-ner';
  readonly verification: 'not-released' | 'pixel-and-residual-scan';
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
