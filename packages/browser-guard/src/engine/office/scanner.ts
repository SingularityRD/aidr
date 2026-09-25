/**
 * What the document handlers (OOXML, PDF) need from the file sanitiser: batched detection over
 * many small text segments, placeholder substitution through the tab's vault, and the
 * column-header dictionary. `engine/files.ts` implements it on top of its scan helpers, so the
 * document code never talks to the detection engine or the vault directly.
 */
import type { EntityType, Finding, ImageInspection, SignalCode } from "../../types.js";

export interface ScanInput {
	/** Detection context scanned in front of the value (column header), or "". */
	readonly context: string;
	readonly value: string;
	/** Header-implied type: the whole value counts as one finding of this type. */
	readonly forced?: EntityType;
}

export interface SegmentScan {
	/** Sorted, non-overlapping findings per input, in value coordinates. */
	readonly perSegment: readonly (readonly Finding[])[];
	readonly signals: ReadonlySet<SignalCode>;
}

export interface DocScanner {
	scan(inputs: readonly ScanInput[]): Promise<SegmentScan>;
	/** Masks `value` (all of it, as `finding.type`) through the vault; returns its replacement. */
	replace(value: string, finding: Finding): string;
	/** Enabled entity type implied by a column header, if any. */
	headerType(header: string): EntityType | undefined;
	/** Throws when the document's scan time budget is spent (the caller fails closed). */
	checkDeadline(): void;
	/**
	 * OCR of one embedded image through the native host, when available. Null (or absent): the
	 * image is not inspected. Never throws.
	 */
	inspectImage?(bytes: Uint8Array): Promise<ImageInspection | null>;
}
