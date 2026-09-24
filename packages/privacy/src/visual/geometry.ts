import { assertWellFormed } from '../normalize.js';
import { imageFail, integer } from './errors.js';
import type { Box, OcrPage, OcrWord, ImageScan } from './types.js';
export interface GeometryLimits { maxPixels: number; maxDimension: number; maxWords: number; maxTextBytes: number }
interface WordSpan { readonly start: number; readonly end: number; readonly word: OcrWord; readonly row: number }
export interface OcrDocument { readonly text: string; readonly spans: readonly WordSpan[]; readonly rows: readonly (readonly OcrWord[])[] }
export function checkBox(box: Box, width: number, height: number): void {
  if (!box || typeof box !== 'object') imageFail('IMAGE_GEOMETRY_INVALID');
  integer(box.x, 0, width - 1, 'IMAGE_GEOMETRY_INVALID'); integer(box.y, 0, height - 1, 'IMAGE_GEOMETRY_INVALID');
  integer(box.width, 1, width, 'IMAGE_GEOMETRY_INVALID'); integer(box.height, 1, height, 'IMAGE_GEOMETRY_INVALID');
  if (box.x + box.width > width || box.y + box.height > height) imageFail('IMAGE_GEOMETRY_INVALID');
}
export function validatePages(pages: readonly OcrPage[], width: number, height: number, limits: GeometryLimits): number {
  if (!Array.isArray(pages) || pages.length < 1 || pages.length > 4) imageFail('IMAGE_PROTOCOL_INVALID');
  let count = 0, bytes = 0;
  for (const page of pages) {
    if (!page || !Array.isArray(page.words)) imageFail('IMAGE_PROTOCOL_INVALID');
    for (const word of page.words) {
      if (++count > limits.maxWords) imageFail('IMAGE_OCR_LIMIT');
      checkBox(word, width, height);
      if (typeof word.text !== 'string' || word.text.length < 1 || word.text.length > 1024 || /\s/u.test(word.text)) imageFail('IMAGE_PROTOCOL_INVALID');
      try { assertWellFormed(word.text); } catch { imageFail('IMAGE_PROTOCOL_INVALID'); }
      bytes += Buffer.byteLength(word.text) + 1;
      if (bytes > limits.maxTextBytes) imageFail('IMAGE_OCR_LIMIT');
      if (typeof word.confidence !== 'number' || !Number.isFinite(word.confidence) || word.confidence < 0 || word.confidence > 100) imageFail('IMAGE_PROTOCOL_INVALID');
      integer(word.line, 0, limits.maxWords, 'IMAGE_PROTOCOL_INVALID');
    }
  }
  return count;
}
export function validateScan(scan: ImageScan, hash: string, limits: GeometryLimits): number {
  if (!scan || scan.protocol !== 1 || scan.complete !== true) imageFail('IMAGE_PROTOCOL_INVALID');
  if (scan.inputSha256 !== hash || !/^[a-f0-9]{64}$/.test(scan.pixelSha256)) imageFail('IMAGE_HASH_MISMATCH');
  const width = integer(scan.width, 1, limits.maxDimension, 'IMAGE_DIMENSION_LIMIT');
  const height = integer(scan.height, 1, limits.maxDimension, 'IMAGE_DIMENSION_LIMIT');
  if (width * height > limits.maxPixels) imageFail('IMAGE_PIXEL_LIMIT');
  if (!['PNG', 'JPEG', 'WEBP'].includes(scan.format)) imageFail('IMAGE_FORMAT_UNSUPPORTED');
  if (!Array.isArray(scan.languages) || !['eng', 'tur'].every(x => scan.languages.includes(x))) imageFail('IMAGE_OCR_UNAVAILABLE');
  if (!Array.isArray(scan.barcodes) || scan.barcodes.length > 256) imageFail('IMAGE_PROTOCOL_INVALID');
  for (const box of scan.barcodes) checkBox(box, width, height);
  return validatePages(scan.pages, width, height, limits);
}
/** Geometric reading rows repair sparse OCR blocks split between labels and values.
 * These are heuristics, not a general table/reading-order model. Native order is scanned too. */
export function rowGroups(words: readonly OcrWord[]): OcrWord[][] {
  const sorted = [...words].sort((a, b) => (a.y + a.height / 2) - (b.y + b.height / 2) || a.x - b.x);
  const rows: OcrWord[][] = [];
  for (const word of sorted) {
    const last = rows.at(-1), ref = last?.[0];
    if (ref && Math.abs(word.y + word.height / 2 - ref.y - ref.height / 2) <= Math.min(word.height, ref.height) * 0.5) last!.push(word);
    else rows.push([word]);
  }
  for (const row of rows) row.sort((a, b) => a.x - b.x);
  return rows;
}
function document(rows: readonly (readonly OcrWord[])[]): OcrDocument {
  const chunks: string[] = [], spans: WordSpan[] = []; let offset = 0;
  for (let row = 0; row < rows.length; row++) {
    if (row) { chunks.push('\n'); offset++; }
    for (const [i, word] of rows[row]!.entries()) {
      if (i) { chunks.push(' '); offset++; }
      chunks.push(word.text); spans.push({ start: offset, end: offset + word.text.length, word, row }); offset += word.text.length;
    }
  }
  return { text: chunks.join(''), spans, rows };
}
export function documents(page: OcrPage): OcrDocument[] {
  const native = new Map<number, OcrWord[]>();
  for (const w of page.words) { if (!native.has(w.line)) native.set(w.line, []); native.get(w.line)!.push(w); }
  const a = document([...native.values()]), b = document(rowGroups(page.words));
  const out = a.text === b.text ? [a] : [a, b];
  // Replacing a newline by one space preserves every source offset.
  const joined = b.text.replace(/([:=])\n/g, '$1 ');
  if (joined !== b.text) out.push({ ...b, text: joined });
  return out;
}
export function enclosing(boxes: readonly Box[]): Box {
  if (!boxes.length) imageFail('IMAGE_GEOMETRY_INVALID');
  let x = Infinity, y = Infinity, right = 0, bottom = 0;
  for (const b of boxes) { x = Math.min(x, b.x); y = Math.min(y, b.y); right = Math.max(right, b.x + b.width); bottom = Math.max(bottom, b.y + b.height); }
  return { x, y, width: right - x, height: bottom - y };
}
export function padded(box: Box, width: number, height: number, pixels: number): Box {
  checkBox(box, width, height); integer(pixels, 0, 256, 'IMAGE_GEOMETRY_INVALID');
  const pad = pixels + Math.ceil(box.height * .15);
  const x = Math.max(0, box.x - pad), y = Math.max(0, box.y - pad);
  return { x, y, width: Math.min(width, box.x + box.width + pad) - x, height: Math.min(height, box.y + box.height + pad) - y };
}
export function contains(outer: Box, inner: Box): boolean {
  return outer.x <= inner.x && outer.y <= inner.y && outer.x + outer.width >= inner.x + inner.width && outer.y + outer.height >= inner.y + inner.height;
}
/** Select WHOLE OCR words/rows. Never estimate subword pixel widths from character counts. */
export function spanBoxes(doc: OcrDocument, start: number, end: number, granularity: 'line' | 'word'): Box[] {
  integer(start, 0, Math.max(0, doc.text.length - 1), 'IMAGE_GEOMETRY_INVALID');
  integer(end, start + 1, doc.text.length, 'IMAGE_GEOMETRY_INVALID');
  const selected = doc.spans.filter(w => w.end > start && w.start < end);
  if (!selected.length) imageFail('IMAGE_GEOMETRY_INVALID');
  if (granularity === 'word') return selected.map(s => ({ x: s.word.x, y: s.word.y, width: s.word.width, height: s.word.height }));
  return [...new Set(selected.map(s => s.row))].map(row => enclosing(doc.rows[row]!));
}
