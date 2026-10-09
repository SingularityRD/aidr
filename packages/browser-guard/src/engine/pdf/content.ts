/**
 * Content-stream interpretation for text extraction (ISO 32000-1 §9.4, §8.4, §8.10).
 *
 * Handles the text operators (`BT/ET`, `Tf`, `Td/TD/Tm/T*`, `Tj`, `TJ`, `'`, `"`,
 * `Tc/Tw/Tz/TL`), the graphics state needed to place text (`q/Q/cm`), Form XObjects (`Do`,
 * nested up to `maxFormDepth`, cycles refused) and steps over inline image data (`BI ... EI`).
 * Drawn images (image XObjects and inline images) are handed to `ContentContext.images`.
 * Glyph advances come from the fonts' widths, so line breaks and word gaps are inserted the
 * way the page lays them out rather than wherever the producer split its strings.
 */
import type { PdfDocument } from "./document.js";
import { DEFAULT_FONT, type Font, loadFont } from "./fonts.js";
import { inlineImageDict, type PdfImageCollector } from "./images.js";
import {
	binaryString,
	Lexer,
	PdfCmd,
	type PdfDict,
	PdfName,
	PdfStream,
	PdfString,
	type PdfValue,
} from "./lexer.js";

type Matrix = readonly [number, number, number, number, number, number];
const IDENTITY: Matrix = [1, 0, 0, 1, 0, 0];

function mul(m1: Matrix, m2: Matrix): Matrix {
	return [
		m1[0] * m2[0] + m1[1] * m2[2],
		m1[0] * m2[1] + m1[1] * m2[3],
		m1[2] * m2[0] + m1[3] * m2[2],
		m1[2] * m2[1] + m1[3] * m2[3],
		m1[4] * m2[0] + m1[5] * m2[2] + m2[4],
		m1[4] * m2[1] + m1[5] * m2[3] + m2[5],
	];
}

function translate(tx: number, ty: number, m: Matrix): Matrix {
	return mul([1, 0, 0, 1, tx, ty], m);
}

function toMatrix(values: readonly PdfValue[]): Matrix | null {
	const [a, b, c, d, e, f] = values.slice(-6);
	return typeof a === "number" &&
		typeof b === "number" &&
		typeof c === "number" &&
		typeof d === "number" &&
		typeof e === "number" &&
		typeof f === "number"
		? [a, b, c, d, e, f]
		: null;
}

/** Accumulates one page's text, inserting spaces and newlines from glyph positions. */
export class PageText {
	private out = "";
	private lastX = 0;
	private lastY = 0;
	private lastSize = 0;
	private started = false;
	glyphs = 0;
	unmapped = 0;
	images = 0;

	get text(): string {
		return this.out;
	}

	/** Separator before text shown at (x, y) with effective size `size`. */
	moveTo(x: number, y: number, size: number): void {
		if (this.started) {
			const ref = Math.max(size, this.lastSize, 1e-6);
			if (Math.abs(y - this.lastY) > ref * 0.5) this.append("\n");
			else if (x - this.lastX > size * 0.2 || this.lastX - x > size) this.append(" ");
		}
		this.started = true;
	}

	endAt(x: number, y: number, size: number): void {
		this.lastX = x;
		this.lastY = y;
		this.lastSize = size;
	}

	/** One shown glyph: its text, or an unmapped glyph (counted for the reliability check). */
	glyph(text: string | undefined): void {
		this.glyphs++;
		if (text === undefined) this.unmapped++;
		else this.append(text);
	}

	append(s: string): void {
		const separator = s === " " || s === "\n";
		if (!separator || !(this.out === "" || /[ \n]$/.test(this.out))) {
			this.out += s;
			return;
		}
		if (s === "\n" && this.out.endsWith(" ")) this.out = `${this.out.slice(0, -1)}\n`;
	}
}

export interface ContentContext {
	readonly doc: PdfDocument;
	readonly fonts: Map<PdfDict, Font>;
	readonly page: PageText;
	readonly checkDeadline: () => void;
	forms: number;
	/** Receives every image the page draws (image XObjects and inline images). */
	readonly images?: PdfImageCollector;
}

interface TextState {
	font: Font;
	size: number;
	charSpacing: number;
	wordSpacing: number;
	scale: number;
	leading: number;
}

interface InlineImage {
	/** Position after `EI`. */
	readonly end: number;
	/** `BI` operands as key/value pairs (abbreviated keys), and the raw data between ID and EI. */
	readonly entries: Array<readonly [string, PdfValue]>;
	readonly data: string;
}

/** Reads an inline image (`BI <dict> ID <data> EI`) whose `BI` was just read. */
function readInlineImage(lexer: Lexer): InlineImage {
	const entries: Array<readonly [string, PdfValue]> = [];
	let key: string | null = null;
	for (let guard = 0; guard < 4096; guard++) {
		const v = lexer.readObject();
		if (v === undefined) return { end: lexer.end, entries, data: "" };
		if (v instanceof PdfCmd && v.op === "ID") break;
		if (key === null && v instanceof PdfName) key = v.name;
		else if (key !== null) {
			entries.push([key, v]);
			key = null;
		}
	}
	const start = lexer.pos + 1; // one white-space byte follows ID
	const re = /[\0\t\n\f\r ]EI(?=[\0\t\n\f\r ]|$)/g;
	re.lastIndex = start;
	const m = re.exec(lexer.src);
	const end = m && m.index < lexer.end ? m.index : lexer.end;
	return { end: Math.min(lexer.end, end + 3), entries, data: lexer.src.slice(start, end) };
}

type SyncOperator = (i: Interpreter) => void;

/** Operators that only update state or emit text. */
const OPERATORS: Readonly<Record<string, SyncOperator>> = {
	q: (i) => i.save(),
	Q: (i) => i.restore(),
	cm: (i) => i.concat(),
	BT: (i) => i.beginText(),
	Tc: (i) => {
		i.state.charSpacing = i.number(i.state.charSpacing);
	},
	Tw: (i) => {
		i.state.wordSpacing = i.number(i.state.wordSpacing);
	},
	Tz: (i) => {
		i.state.scale = i.number(i.state.scale * 100) / 100;
	},
	TL: (i) => {
		i.state.leading = i.number(i.state.leading);
	},
	Td: (i) => i.moveTextOperator(false),
	TD: (i) => i.moveTextOperator(true),
	Tm: (i) => i.setTextMatrix(),
	"T*": (i) => i.nextLine(),
	Tj: (i) => i.show(i.operands.slice(-1)),
	"'": (i) => {
		i.nextLine();
		i.show(i.operands.slice(-1));
	},
	'"': (i) => i.showWithSpacing(),
	TJ: (i) => {
		const arr = i.operands[i.operands.length - 1];
		if (Array.isArray(arr)) i.show(arr);
	},
};

class Interpreter {
	readonly operands: PdfValue[] = [];
	private readonly stack: Array<{ ctm: Matrix; state: TextState }> = [];
	state: TextState = {
		font: DEFAULT_FONT,
		size: 0,
		charSpacing: 0,
		wordSpacing: 0,
		scale: 1,
		leading: 0,
	};
	private tm: Matrix = IDENTITY;
	private tlm: Matrix = IDENTITY;

	constructor(
		private readonly ctx: ContentContext,
		private readonly resources: PdfDict | undefined,
		private ctm: Matrix,
		private readonly depth: number,
		private readonly active: Set<PdfStream>,
	) {}

	async run(src: string): Promise<void> {
		const lexer = new Lexer(src, 0, src.length, false);
		for (let v = lexer.readObject(); v !== undefined; v = lexer.readObject()) {
			if (!(v instanceof PdfCmd)) {
				if (this.operands.length < 1024) this.operands.push(v);
				continue;
			}
			if (!this.count()) return;
			await this.operator(v.op, lexer);
			this.operands.length = 0;
		}
	}

	private count(): boolean {
		const { doc } = this.ctx;
		if (++doc.operators > doc.limits.maxOperators) {
			doc.partial = true;
			return false;
		}
		if (doc.operators % 20_000 === 0) this.ctx.checkDeadline();
		return true;
	}

	private async operator(op: string, lexer: Lexer): Promise<void> {
		const sync = OPERATORS[op];
		if (sync) sync(this);
		else if (op === "Tf") await this.setFont();
		else if (op === "Do") await this.xobject();
		else if (op === "BI") {
			const inline = readInlineImage(lexer);
			lexer.pos = inline.end;
			this.ctx.page.images++;
			this.ctx.images?.addInline(
				inlineImageDict(inline.entries),
				Uint8Array.from(inline.data, (c) => c.charCodeAt(0)),
				this.resources,
			);
		}
	}

	/** The last operand as a number, or `fallback`. */
	number(fallback: number): number {
		const v = this.operands[this.operands.length - 1];
		return typeof v === "number" ? v : fallback;
	}

	save(): void {
		if (this.stack.length < 64) this.stack.push({ ctm: this.ctm, state: { ...this.state } });
	}

	restore(): void {
		const saved = this.stack.pop();
		if (!saved) return;
		this.ctm = saved.ctm;
		this.state = saved.state;
	}

	concat(): void {
		const m = toMatrix(this.operands);
		if (m) this.ctm = mul(m, this.ctm);
	}

	beginText(): void {
		this.tm = IDENTITY;
		this.tlm = IDENTITY;
	}

	private moveText(tx: number, ty: number): void {
		this.tlm = translate(tx, ty, this.tlm);
		this.tm = this.tlm;
	}

	moveTextOperator(setLeading: boolean): void {
		const [tx, ty] = this.operands.slice(-2);
		if (typeof tx !== "number" || typeof ty !== "number") return;
		if (setLeading) this.state.leading = -ty;
		this.moveText(tx, ty);
	}

	setTextMatrix(): void {
		const m = toMatrix(this.operands);
		if (!m) return;
		this.tm = m;
		this.tlm = m;
	}

	nextLine(): void {
		this.moveText(0, -this.state.leading);
	}

	showWithSpacing(): void {
		const [aw, ac, text] = this.operands.slice(-3);
		if (typeof aw === "number") this.state.wordSpacing = aw;
		if (typeof ac === "number") this.state.charSpacing = ac;
		this.nextLine();
		if (text !== undefined) this.show([text]);
	}

	show(items: readonly PdfValue[]): void {
		const { page } = this.ctx;
		const m = mul(this.tm, this.ctm);
		const size =
			Math.abs(this.state.size * Math.hypot(m[2], m[3])) || Math.abs(this.state.size) || 1;
		page.moveTo(m[4], m[5], size);
		for (const item of items) {
			if (typeof item === "number") this.adjust(item);
			else if (item instanceof PdfString) this.showString(item);
		}
		const end = mul(this.tm, this.ctm);
		page.endAt(end[4], end[5], size);
	}

	/** A TJ number: move left by item/1000 em; a large gap reads as a word break. */
	private adjust(item: number): void {
		if (-item / 1000 > 0.2) this.ctx.page.append(" ");
		this.tm = translate((-item / 1000) * this.state.size * this.state.scale, 0, this.tm);
	}

	private showString(item: PdfString): void {
		const { page } = this.ctx;
		const { font, size, charSpacing, wordSpacing, scale } = this.state;
		for (const g of font.decode(item.bytes)) {
			if (!font.symbolic) page.glyph(g.text);
			const tx = (g.width * size + charSpacing + (g.space ? wordSpacing : 0)) * scale;
			this.tm = translate(tx, 0, this.tm);
		}
	}

	private async setFont(): Promise<void> {
		const [name, size] = this.operands.slice(-2);
		if (name instanceof PdfName) this.state.font = await this.font(name.name);
		if (typeof size === "number") this.state.size = size;
	}

	private async font(name: string): Promise<Font> {
		const { doc, fonts } = this.ctx;
		const dict = doc.dict(doc.dict(this.resources?.get("Font"))?.get(name));
		if (!dict) return DEFAULT_FONT;
		let font = fonts.get(dict);
		if (!font) {
			font = await loadFont(doc, dict);
			fonts.set(dict, font);
		}
		return font;
	}

	private async xobject(): Promise<void> {
		const name = this.operands[this.operands.length - 1];
		if (!(name instanceof PdfName)) return;
		const { doc } = this.ctx;
		const xobject = doc.resolve(doc.dict(this.resources?.get("XObject"))?.get(name.name));
		if (!(xobject instanceof PdfStream)) return;
		const subtype = doc.name(xobject.dict.get("Subtype"));
		if (subtype === "Image") {
			this.ctx.page.images++;
			this.ctx.images?.addStream(xobject);
		} else if (subtype === "Form" && !this.active.has(xobject)) await this.form(xobject);
	}

	private async form(xobject: PdfStream): Promise<void> {
		const { doc } = this.ctx;
		if (this.depth >= doc.limits.maxFormDepth || ++this.ctx.forms > 4096) {
			doc.partial = true;
			return;
		}
		const decoded = await doc.stream(xobject);
		if (!decoded?.complete) doc.partial = true;
		if (!decoded) return;
		const matrix = toMatrix(doc.array(xobject.dict.get("Matrix")) ?? []) ?? IDENTITY;
		const resources = doc.dict(xobject.dict.get("Resources")) ?? this.resources;
		this.active.add(xobject);
		try {
			const nested = new Interpreter(
				this.ctx,
				resources,
				mul(matrix, this.ctm),
				this.depth + 1,
				this.active,
			);
			await nested.run(binaryString(decoded.data));
		} finally {
			this.active.delete(xobject);
		}
	}
}

/** Interprets a page's (concatenated) content stream into `ctx.page`. */
export async function interpretContent(
	ctx: ContentContext,
	src: string,
	resources: PdfDict | undefined,
): Promise<void> {
	await new Interpreter(ctx, resources, IDENTITY, 0, new Set()).run(src);
}
