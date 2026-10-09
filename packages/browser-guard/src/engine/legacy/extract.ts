/**
 * Text extraction from legacy binary Office files (OLE2 compound files: .doc/.dot, .xls/.xlt/
 * .xla, .ppt/.pps/.pot/.ppa), for detection only. The file is never rewritten: patching text
 * inside a binary record format (piece tables, BIFF string tables, persist directories) is
 * not safe, so the caller blocks a file with findings and allows only a complete, clean one.
 *
 *   ./cfb.ts         the compound file container (bounded, fails on cycles / truncation);
 *   ./word.ts        WordDocument + 0Table/1Table piece table;
 *   ./excel.ts       Workbook (BIFF8) records;
 *   ./powerpoint.ts  PowerPoint Document records;
 *   ./properties.ts  SummaryInformation / DocumentSummaryInformation strings.
 *
 * Embedded objects are opened and scanned the same way (Word `ObjectPool` storages, Excel
 * `MBD...` storages, PowerPoint ExOleObjStg records, optionally zlib-compressed), up to
 * `maxEmbedDepth` levels and `maxEmbedded` objects; an embedded object that is not itself a
 * Word/Excel/PowerPoint compound file is refused (DOCUMENT_EMBEDDED_OBJECT), as for OOXML.
 *
 * Outcomes:
 *   - `DocumentUnreadable("DOCUMENT_UNPARSEABLE")`: not a compound file at all;
 *   - `DocumentRefused`: DOCUMENT_ENCRYPTED (password protection, IRM, encrypted OOXML in a
 *     compound file), DOCUMENT_MACROS (VBA projects, Excel 4.0 macro sheets),
 *     DOCUMENT_EMBEDDED_OBJECT, DOCUMENT_MALFORMED (corrupt or adversarial container: cyclic
 *     FAT/directory, sectors outside the file, truncation), DOCUMENT_LIMIT_EXCEEDED;
 *   - otherwise the extracted segments, with `complete: false` and LEGACY_OFFICE_PARTIAL /
 *     LEGACY_OFFICE_UNSUPPORTED when any text may be missing (a record or piece table that
 *     does not fit, a character budget reached, pivot caches, Word 6/95 or Excel 5/95, a
 *     compound file that is not a Word/Excel/PowerPoint document).
 */
import { InflateLimitError, inflateBounded } from "../office/deflate.js";
import { DocumentRefused, DocumentUnreadable } from "../office/ooxml.js";
import {
	type CfbEntry,
	CfbError,
	type CfbLimits,
	type CompoundFile,
	childEntry,
	DEFAULT_CFB_LIMITS,
	readCompoundFile,
} from "./cfb.js";
import { extractExcel } from "./excel.js";
import { extractPowerPoint } from "./powerpoint.js";
import { extractProperties } from "./properties.js";
import {
	Collector,
	DEFAULT_LEGACY_LIMITS,
	type LegacyGap,
	type LegacyLimits,
	type LegacySegment,
} from "./text.js";
import { extractWord } from "./word.js";

type LegacyFormat = "word" | "excel" | "powerpoint" | "unknown";

export interface LegacyExtraction {
	readonly format: LegacyFormat;
	/** Text values in document order; spreadsheet cells carry their column header as context. */
	readonly segments: readonly LegacySegment[];
	/** False when text may be missing; `reasons` says why. */
	readonly complete: boolean;
	readonly reasons: readonly LegacyGap[];
	/** The file contains pictures, which are not inspected. */
	readonly images: boolean;
}

const ENCRYPTION_STREAMS =
	/^(?:EncryptedPackage|EncryptionInfo|EncryptedSummary|\u0006DataSpaces)$/i;
const MACRO_STORAGES = /^(?:Macros|_VBA_PROJECT_CUR|_VBA_PROJECT|VBA)$/i;
const EXCEL_EMBEDDING = /^MBD[0-9A-F]{8}$/i;

function formatOf(storage: CfbEntry): LegacyFormat {
	if (childEntry(storage, "WordDocument")) return "word";
	if (childEntry(storage, "Workbook") || childEntry(storage, "Book")) return "excel";
	if (childEntry(storage, "PowerPoint Document")) return "powerpoint";
	return "unknown";
}

/** Encryption (password, IRM, encrypted OOXML) and VBA storages are refused outright. */
function refuseProtected(storage: CfbEntry): void {
	for (const entry of storage.children) {
		if (ENCRYPTION_STREAMS.test(entry.name)) throw new DocumentRefused(["DOCUMENT_ENCRYPTED"]);
		if (entry.type === "storage" && MACRO_STORAGES.test(entry.name))
			throw new DocumentRefused(["DOCUMENT_MACROS"]);
	}
}

class Extractor {
	constructor(
		readonly out: Collector,
		readonly cfbLimits: CfbLimits,
	) {}

	async storage(cfb: CompoundFile, storage: CfbEntry, depth: number): Promise<LegacyFormat> {
		refuseProtected(storage);
		const format = formatOf(storage);
		await this.content(cfb, storage, format, depth);
		extractProperties(cfb, storage, this.out);
		return format;
	}

	/** The format's own text, then the embedded objects it holds. */
	private async content(
		cfb: CompoundFile,
		storage: CfbEntry,
		format: LegacyFormat,
		depth: number,
	): Promise<void> {
		const { out } = this;
		if (format === "word") {
			extractWord(cfb, storage, out);
			const pool = childEntry(storage, "ObjectPool");
			for (const object of pool?.children ?? []) await this.embeddedStorage(cfb, object, depth);
		} else if (format === "excel") {
			extractExcel(cfb, storage, out);
			const objects = storage.children.filter((c) => EXCEL_EMBEDDING.test(c.name));
			for (const object of objects) await this.embeddedStorage(cfb, object, depth);
		} else if (format === "powerpoint") {
			for (const object of extractPowerPoint(cfb, storage, out))
				await this.embeddedBytes(object.compressed, object.data, depth);
		} else if (depth > 0) {
			// An embedded object of another kind cannot be inspected: refused, as for OOXML.
			throw new DocumentRefused(["DOCUMENT_EMBEDDED_OBJECT"]);
		} else out.gap("LEGACY_OFFICE_UNSUPPORTED");
	}

	private admit(depth: number): boolean {
		const { out } = this;
		out.embedded++;
		if (depth + 1 > out.limits.maxEmbedDepth || out.embedded > out.limits.maxEmbedded) {
			out.gap("LEGACY_OFFICE_PARTIAL");
			return false;
		}
		out.checkDeadline();
		return true;
	}

	private async embeddedStorage(cfb: CompoundFile, object: CfbEntry, depth: number) {
		if (object.type !== "storage") throw new DocumentRefused(["DOCUMENT_EMBEDDED_OBJECT"]);
		if (this.admit(depth)) await this.storage(cfb, object, depth + 1);
	}

	private async embeddedBytes(compressed: boolean, data: Uint8Array, depth: number) {
		if (!this.admit(depth)) return;
		let bytes = data;
		if (compressed) {
			// ExOleObjStgCompressedAtom: decompressed size (u32), then a zlib stream.
			const max = this.out.limits.maxEmbeddedBytes;
			try {
				const result = await inflateBounded(data.subarray(4), "deflate", max);
				if (!result.complete) throw new DocumentRefused(["DOCUMENT_MALFORMED"]);
				bytes = result.bytes;
			} catch (error) {
				if (error instanceof InflateLimitError)
					throw new DocumentRefused(["DOCUMENT_LIMIT_EXCEEDED"]);
				throw error;
			}
		}
		let cfb: CompoundFile;
		try {
			cfb = readCompoundFile(bytes, this.cfbLimits);
		} catch (error) {
			if (error instanceof CfbError && error.code === "NOT_CFB")
				throw new DocumentRefused(["DOCUMENT_EMBEDDED_OBJECT"]);
			throw error;
		}
		await this.storage(cfb, cfb.root, depth + 1);
	}
}

/**
 * Extracts the text of a legacy Office file. `checkDeadline` is called between units of work
 * and may throw to abort (the caller's scan budget). See the module comment for outcomes.
 */
export async function extractLegacyOffice(
	bytes: Uint8Array,
	checkDeadline: () => void = () => {},
	limits: LegacyLimits = DEFAULT_LEGACY_LIMITS,
	cfbLimits: CfbLimits = DEFAULT_CFB_LIMITS,
): Promise<LegacyExtraction> {
	const out = new Collector(limits, checkDeadline);
	let format: LegacyFormat;
	try {
		const cfb = readCompoundFile(bytes, cfbLimits);
		format = await new Extractor(out, cfbLimits).storage(cfb, cfb.root, 0);
	} catch (error) {
		if (error instanceof CfbError) {
			if (error.code === "NOT_CFB") throw new DocumentUnreadable("DOCUMENT_UNPARSEABLE");
			throw new DocumentRefused([
				error.code === "LIMIT" ? "DOCUMENT_LIMIT_EXCEEDED" : "DOCUMENT_MALFORMED",
			]);
		}
		throw error;
	}
	const reasons = [...out.gaps].sort();
	return {
		format,
		segments: out.segments,
		complete: reasons.length === 0,
		reasons,
		images: out.images,
	};
}
