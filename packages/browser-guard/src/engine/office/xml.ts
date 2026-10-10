/**
 * Small, strict XML scanner for Office Open XML parts, plus a text model that lets the
 * sanitiser mask text split across runs while leaving every other byte of the part as it was.
 *
 * `walkXml` reports start/end tags and character data with raw offsets and enforces
 * well-formed nesting. It refuses DOCTYPE declarations (no entity expansion, no XXE) and any
 * entity reference other than the five predefined ones and numeric character references.
 *
 * Namespaces are resolved (Namespaces in XML 1.0, with scoping): every element and attribute
 * gets a canonical name, `cname`, built from its namespace URI and local name - never from the
 * prefix the document happens to use. Well-known Office / OpenDocument namespace URIs map to
 * their conventional prefix (`w:p` is the WordprocessingML paragraph whether the document
 * writes `w:p`, `x:p` or a default-namespace `p`); any other URI gives `{uri}local`; a name
 * without a namespace is its local name. All matching in the Office/ODF specs is on `cname`,
 * so re-binding prefixes cannot hide text from masking or a macro / OLE / external-link
 * marker from the refusal checks. A prefix that is not declared at all is refused with
 * `strictNamespaces` (what the document sanitisers use: such a part is not
 * namespace-well-formed, Office does not open it, and it must not be read under a guessed
 * meaning); otherwise (bare fragments) it is kept literally (`w:p` stays `w:p`).
 *
 * `extractText` builds {@link TextSegment}s from a part using a {@link TextSpec}:
 *   - `leaves`      elements whose character data is text (`w:t`, `a:t`, `t`...);
 *   - `paragraphs`  elements whose leaves are concatenated into one segment (`w:p`, `a:p`,
 *                   `si`...), so an e-mail address split over three runs is scanned whole;
 *                   a leaf outside any paragraph is a segment on its own;
 *   - `breaks`      empty elements that stand for a character inside a paragraph
 *                   (`<w:tab/>` -> "\t", `<w:br/>` -> "\n") when their parent matches;
 *   - `attributes`  attribute values scanned as their own segments (comment authors,
 *                   external hyperlink targets...).
 * Each segment carries an `apply(edits)` that turns span replacements (in segment
 * coordinates) into raw replacements of the part: a masked span is written into the first
 * leaf it touches and removed from the others, so only the runs that held sensitive text
 * change and their formatting is kept.
 */

import type { EntityType } from "../../types.js";

/** `w:t` -> `t`; `{urn:x}t` -> `t` (canonical names included). */
export function localName(qname: string): string {
	return qname.slice(Math.max(qname.lastIndexOf(":"), qname.lastIndexOf("}")) + 1);
}

const XML_NS = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NS = "http://www.w3.org/2000/xmlns/";

/**
 * Canonical prefixes of the namespaces the Office / OpenDocument specs match on (transitional
 * and strict OOXML URIs map to the same prefix). Keys of `http:` URIs are written without
 * the scheme (see {@link namespaceKey}): namespace names are identifiers, never fetched, and
 * the build refuses URL literals for hosts outside its allowlist in shipped code.
 */
const CANONICAL_PREFIX: ReadonlyMap<string, string> = new Map([
	["www.w3.org/XML/1998/namespace", "xml"],
	// Office Open XML
	["schemas.openxmlformats.org/wordprocessingml/2006/main", "w"],
	["purl.oclc.org/ooxml/wordprocessingml/main", "w"],
	["schemas.openxmlformats.org/officeDocument/2006/math", "m"],
	["purl.oclc.org/ooxml/officeDocument/math", "m"],
	["schemas.openxmlformats.org/drawingml/2006/main", "a"],
	["purl.oclc.org/ooxml/drawingml/main", "a"],
	["schemas.openxmlformats.org/drawingml/2006/chart", "c"],
	["purl.oclc.org/ooxml/drawingml/chart", "c"],
	["schemas.microsoft.com/office/drawing/2014/chartex", "cx"],
	["schemas.openxmlformats.org/presentationml/2006/main", "p"],
	["purl.oclc.org/ooxml/presentationml/main", "p"],
	["schemas.openxmlformats.org/spreadsheetml/2006/main", "x"],
	["purl.oclc.org/ooxml/spreadsheetml/main", "x"],
	["schemas.openxmlformats.org/officeDocument/2006/relationships", "r"],
	["purl.oclc.org/ooxml/officeDocument/relationships", "r"],
	["schemas.microsoft.com/office/word/2012/wordml", "w15"],
	// OpenDocument
	["urn:oasis:names:tc:opendocument:xmlns:office:1.0", "office"],
	["urn:oasis:names:tc:opendocument:xmlns:text:1.0", "text"],
	["urn:oasis:names:tc:opendocument:xmlns:table:1.0", "table"],
	["urn:oasis:names:tc:opendocument:xmlns:drawing:1.0", "draw"],
	["urn:oasis:names:tc:opendocument:xmlns:script:1.0", "script"],
	["urn:oasis:names:tc:opendocument:xmlns:meta:1.0", "meta"],
	["urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0", "svg"],
	["urn:oasis:names:tc:opendocument:xmlns:presentation:1.0", "presentation"],
	["urn:org:documentfoundation:names:experimental:calc:xmlns:calcext:1.0", "calcext"],
	["www.w3.org/1999/xlink", "xlink"],
	["purl.org/dc/elements/1.1/", "dc"],
]);

/**
 * Lookup key of a namespace URI: `http://` removed. A document that spells a known namespace
 * without its scheme is therefore matched as that namespace too - only ever more scanning and
 * more refusals, never less.
 */
function namespaceKey(ns: string): string {
	return ns.startsWith("http://") ? ns.slice(7) : ns;
}

function canonicalName(ns: string, local: string): string {
	const prefix = CANONICAL_PREFIX.get(namespaceKey(ns));
	return prefix ? `${prefix}:${local}` : `{${ns}}${local}`;
}

export class XmlError extends Error {
	constructor(readonly code: string) {
		super(`XML_${code}`);
		this.name = "XmlError";
	}
}

export interface XmlAttr {
	/** Raw (prefixed) name as written. */
	readonly name: string;
	/** Canonical name: namespace-resolved, prefix-independent (see the module comment). */
	readonly cname: string;
	/** Decoded value. */
	readonly value: string;
	/** Raw value span (inside the quotes). */
	readonly valueStart: number;
	readonly valueEnd: number;
	readonly quote: '"' | "'";
}

export interface XmlTag {
	/** Raw (prefixed) name as written. */
	readonly name: string;
	/** Canonical name: namespace-resolved, prefix-independent (see the module comment). */
	readonly cname: string;
	readonly start: number;
	/** Index just past `>`. */
	readonly end: number;
	readonly selfClosing: boolean;
	readonly attrs: readonly XmlAttr[];
}

export interface XmlVisitor {
	/** `parent` is the canonical name of the enclosing element. */
	start?(tag: XmlTag, parent: string | undefined): void;
	/**
	 * `name` is the element's canonical name; `start`/`end` span the end tag (or equal the
	 * start tag's end for a self-closing tag).
	 */
	end?(name: string, start: number, end: number): void;
	text?(start: number, end: number, cdata: boolean): void;
}

const NAME_START = /[A-Za-z_:\u00c0-\ufffd]/;
const NAME_RE = /[A-Za-z_:\u00c0-\ufffd][A-Za-z0-9_:.\-\u00b7\u00c0-\ufffd]*/y;
const WS = /[ \t\r\n]*/y;

const ENTITIES: Readonly<Record<string, string>> = {
	amp: "&",
	lt: "<",
	gt: ">",
	quot: '"',
	apos: "'",
};

/** Decodes character data / attribute values. Unknown entities throw (fail closed). */
export function decodeXmlText(raw: string): string {
	if (!raw.includes("&")) return raw;
	return raw.replace(/&([^;&\s]{1,10});/g, (_m, ref: string) => {
		const named = ENTITIES[ref];
		if (named !== undefined) return named;
		let code = Number.NaN;
		if (/^#x[0-9A-Fa-f]{1,6}$/.test(ref)) code = Number.parseInt(ref.slice(2), 16);
		else if (/^#[0-9]{1,7}$/.test(ref)) code = Number.parseInt(ref.slice(1), 10);
		if (!(code >= 0 && code <= 0x10ffff) || (code >= 0xd800 && code <= 0xdfff))
			throw new XmlError("BAD_ENTITY");
		return String.fromCodePoint(code);
	});
}

export function escapeXmlText(s: string): string {
	return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export function escapeXmlAttr(s: string, quote: '"' | "'"): string {
	const out = s
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/\t/g, "&#9;")
		.replace(/\n/g, "&#10;")
		.replace(/\r/g, "&#13;");
	return quote === '"' ? out.replace(/"/g, "&quot;") : out.replace(/'/g, "&apos;");
}

function readName(xml: string, pos: number): string {
	NAME_RE.lastIndex = pos;
	const m = NAME_RE.exec(xml);
	if (!m) throw new XmlError("BAD_NAME");
	// Namespaces in XML: at most one colon, neither first nor last.
	const name = m[0];
	const colon = name.indexOf(":");
	if (colon === 0 || colon === name.length - 1 || name.indexOf(":", colon + 1) >= 0)
		throw new XmlError("BAD_NAME");
	return name;
}

function skipWs(xml: string, pos: number): number {
	WS.lastIndex = pos;
	WS.exec(xml);
	return WS.lastIndex;
}

type RawAttr = Omit<XmlAttr, "cname">;
type RawTag = Omit<XmlTag, "cname" | "attrs"> & { readonly attrs: readonly RawAttr[] };

/** Parses one `name="value"` attribute at `at` into `attrs`; returns the index after it. */
function parseAttribute(xml: string, at: number, attrs: RawAttr[]): number {
	const name = readName(xml, at);
	let pos = skipWs(xml, at + name.length);
	if (xml[pos] !== "=") throw new XmlError("BAD_ATTRIBUTE");
	pos = skipWs(xml, pos + 1);
	const quote = xml[pos];
	if (quote !== '"' && quote !== "'") throw new XmlError("BAD_ATTRIBUTE");
	const close = xml.indexOf(quote, pos + 1);
	if (close < 0) throw new XmlError("UNTERMINATED");
	const raw = xml.slice(pos + 1, close);
	if (raw.includes("<")) throw new XmlError("BAD_ATTRIBUTE");
	if (attrs.some((a) => a.name === name)) throw new XmlError("DUPLICATE_ATTRIBUTE");
	attrs.push({ name, value: decodeXmlText(raw), valueStart: pos + 1, valueEnd: close, quote });
	return close + 1;
}

function parseStartTag(xml: string, lt: number): RawTag {
	const name = readName(xml, lt + 1);
	let pos = lt + 1 + name.length;
	const attrs: RawAttr[] = [];
	for (;;) {
		const afterWs = skipWs(xml, pos);
		const c = xml[afterWs];
		if (c === ">") return { name, start: lt, end: afterWs + 1, selfClosing: false, attrs };
		if (c === "/" && xml[afterWs + 1] === ">")
			return { name, start: lt, end: afterWs + 2, selfClosing: true, attrs };
		if (afterWs === pos || c === undefined || !NAME_START.test(c)) throw new XmlError("BAD_TAG");
		pos = parseAttribute(xml, afterWs, attrs);
	}
}

function skipTo(xml: string, from: number, terminator: string): number {
	const i = xml.indexOf(terminator, from);
	if (i < 0) throw new XmlError("UNTERMINATED");
	return i + terminator.length;
}

/** One open element: its raw name (nesting check), canonical name and namespace bindings. */
interface Frame {
	readonly name: string;
	readonly cname: string;
	/** Prefix ("" = default namespace) -> URI ("" = undeclared default) declared here. */
	readonly bindings: ReadonlyMap<string, string> | null;
}

export interface WalkOptions {
	/** Refuse (`UNBOUND_PREFIX`) element/attribute prefixes that are not declared. */
	readonly strictNamespaces?: boolean;
}

/** Options of the document sanitisers. */
export const STRICT_NAMESPACES: WalkOptions = Object.freeze({ strictNamespaces: true });

interface WalkState {
	readonly stack: Frame[];
	readonly strict: boolean;
	rootSeen: boolean;
}

/** The `xmlns` / `xmlns:p` declarations of a start tag. */
function declarations(attrs: readonly RawAttr[]): Map<string, string> | null {
	let out: Map<string, string> | null = null;
	for (const a of attrs) {
		let prefix: string;
		if (a.name === "xmlns") prefix = "";
		else if (a.name.startsWith("xmlns:")) prefix = a.name.slice(6);
		else continue;
		const uri = a.value;
		if (prefix === "xmlns" || uri === XMLNS_NS) throw new XmlError("BAD_NAMESPACE");
		if ((prefix === "xml") !== (uri === XML_NS)) throw new XmlError("BAD_NAMESPACE");
		if (prefix && !uri) throw new XmlError("BAD_NAMESPACE"); // no un-declaring a prefix
		out ??= new Map();
		out.set(prefix, uri);
	}
	return out;
}

/** URI bound to `prefix` in scope, or undefined when it is not declared. */
function lookup(
	stack: readonly Frame[],
	own: ReadonlyMap<string, string> | null,
	prefix: string,
): string | undefined {
	const here = own?.get(prefix);
	if (here !== undefined) return here;
	for (let i = stack.length - 1; i >= 0; i--) {
		const bound = stack[i]?.bindings?.get(prefix);
		if (bound !== undefined) return bound;
	}
	return prefix === "xml" ? XML_NS : undefined;
}

/**
 * Canonical name of an element (`element`: unprefixed names take the default namespace) or
 * attribute (unprefixed names have no namespace).
 */
function resolveName(
	stack: readonly Frame[],
	own: ReadonlyMap<string, string> | null,
	qname: string,
	element: boolean,
	strict: boolean,
): string {
	const colon = qname.indexOf(":");
	if (colon < 0) {
		const ns = element ? (lookup(stack, own, "") ?? "") : "";
		return ns ? canonicalName(ns, qname) : qname;
	}
	const prefix = qname.slice(0, colon);
	if (prefix === "xmlns") return qname;
	const ns = lookup(stack, own, prefix);
	if (ns !== undefined) return canonicalName(ns, qname.slice(colon + 1));
	// Undeclared prefix (not namespace-well-formed): refused, or kept literally for fragments.
	if (strict) throw new XmlError("UNBOUND_PREFIX");
	return qname;
}

/** Resolves a parsed start tag against the bindings in scope; returns it and its own bindings. */
function resolveTag(
	raw: RawTag,
	stack: readonly Frame[],
	strict: boolean,
): { tag: XmlTag; bindings: Map<string, string> | null } {
	const bindings = declarations(raw.attrs);
	const seen = new Set<string>();
	const attrs = raw.attrs.map((a): XmlAttr => {
		const cname = resolveName(stack, bindings, a.name, false, strict);
		// Two prefixes bound to one URI must not smuggle a second copy of an attribute.
		if (seen.has(cname)) throw new XmlError("DUPLICATE_ATTRIBUTE");
		seen.add(cname);
		return { ...a, cname };
	});
	const cname = resolveName(stack, bindings, raw.name, true, strict);
	return { tag: { ...raw, cname, attrs }, bindings };
}

/** Character data between markup: reported inside the root, refused (unless blank) outside. */
function textRun(
	xml: string,
	from: number,
	to: number,
	state: WalkState,
	visitor: XmlVisitor,
): void {
	if (to <= from) return;
	if (state.stack.length > 0) visitor.text?.(from, to, false);
	else if (xml.slice(from, to).trim()) throw new XmlError("TEXT_OUTSIDE_ROOT");
}

/** Walks `xml`, reporting tags and character data. Throws {@link XmlError} if not well-formed. */
export function walkXml(xml: string, visitor: XmlVisitor, options: WalkOptions = {}): void {
	const state: WalkState = { stack: [], strict: !!options.strictNamespaces, rootSeen: false };
	let pos = xml.charCodeAt(0) === 0xfeff ? 1 : 0;
	while (pos < xml.length) {
		const lt = xml.indexOf("<", pos);
		textRun(xml, pos, lt < 0 ? xml.length : lt, state, visitor);
		if (lt < 0) break;
		if (state.stack.length === 0 && NAME_START.test(xml[lt + 1] ?? "")) {
			if (state.rootSeen) throw new XmlError("MULTIPLE_ROOTS");
			state.rootSeen = true;
		}
		pos = step(xml, lt, state, visitor);
	}
	if (state.stack.length > 0) throw new XmlError("UNCLOSED");
	if (!state.rootSeen) throw new XmlError("NO_ROOT");
}

/** `<!...>` markup: comments and CDATA; anything else (DOCTYPE, ENTITY...) is refused. */
function declaration(xml: string, lt: number, stack: Frame[], visitor: XmlVisitor): number {
	if (xml.startsWith("<!--", lt)) return skipTo(xml, lt + 4, "-->");
	if (!xml.startsWith("<![CDATA[", lt)) throw new XmlError("DOCTYPE_REFUSED");
	if (stack.length === 0) throw new XmlError("TEXT_OUTSIDE_ROOT");
	const end = skipTo(xml, lt + 9, "]]>");
	visitor.text?.(lt + 9, end - 3, true);
	return end;
}

function endTag(xml: string, lt: number, stack: Frame[], visitor: XmlVisitor): number {
	const name = readName(xml, lt + 2);
	const close = skipWs(xml, lt + 2 + name.length);
	if (xml[close] !== ">") throw new XmlError("BAD_TAG");
	const frame = stack.pop();
	if (frame?.name !== name) throw new XmlError("MISMATCHED_TAG");
	visitor.end?.(frame.cname, lt, close + 1);
	return close + 1;
}

/** Handles the markup at `lt`; returns the index after it. */
function step(xml: string, lt: number, state: WalkState, visitor: XmlVisitor): number {
	const { stack } = state;
	const next = xml[lt + 1];
	if (next === "?") return skipTo(xml, lt + 2, "?>");
	if (next === "!") return declaration(xml, lt, stack, visitor);
	if (next === "/") return endTag(xml, lt, stack, visitor);
	const { tag, bindings } = resolveTag(parseStartTag(xml, lt), stack, state.strict);
	visitor.start?.(tag, stack[stack.length - 1]?.cname);
	if (tag.selfClosing) visitor.end?.(tag.cname, tag.end, tag.end);
	else stack.push({ name: tag.name, cname: tag.cname, bindings });
	return tag.end;
}

/** Throws unless `xml` is well-formed (used to verify rewritten parts). */
export function assertWellFormed(xml: string, options: WalkOptions = {}): void {
	walkXml(xml, {}, options);
}

// ---------------------------------------------------------------------------------------------
// Text model
// ---------------------------------------------------------------------------------------------

/** A replacement of `[start, end)` in segment text by `text`. */
export interface Edit {
	readonly start: number;
	readonly end: number;
	readonly text: string;
}

/** A replacement of `[start, end)` in the raw XML by `raw`. */
export interface RawReplacement {
	readonly start: number;
	readonly end: number;
	readonly raw: string;
}

export interface TextSegment {
	readonly text: string;
	/** Detection context scanned in front of the value (e.g. a column header). */
	context: string;
	/** Header-implied type: the whole value is masked as this type (sensitive column). */
	forced?: EntityType;
	/** `apply` must run even without findings (the segment rewrites structure, e.g. drops a formula). */
	readonly rewrite?: boolean;
	apply(edits: readonly Edit[]): RawReplacement[];
}

/** Element names are canonical names (`w:p`, see the module comment), whatever the prefixes. */
export interface TextSpec {
	readonly paragraphs: ReadonlySet<string>;
	readonly leaves: ReadonlySet<string>;
	/** Break element name -> [text it stands for, required parent element]. */
	readonly breaks?: ReadonlyMap<string, readonly [string, string]>;
	/** Leaves that need `xml:space="preserve"` to keep leading/trailing whitespace. */
	readonly preserveSpace?: ReadonlySet<string>;
	/** Canonical attribute names on `tag` whose values are scanned as standalone segments. */
	attributes?(tag: XmlTag): readonly string[];
	/** Generic fallback: every text node is a standalone segment (leaves/paragraphs unused). */
	readonly allText?: boolean;
	/** Match `paragraphs`/`leaves`/`breaks` by local name (prefix-agnostic SpreadsheetML). */
	readonly localNames?: boolean;
}

export interface Leaf {
	readonly tag: XmlTag;
	/** The raw start tag. */
	readonly open: string;
	contentEnd: number;
	text: string;
	/** False when the leaf holds child markup (it cannot be rewritten as plain text). */
	rewritable: boolean;
}

export interface Piece {
	readonly leaf: Leaf | null;
	readonly text: string;
}

function hasPreserve(tag: XmlTag): boolean {
	return tag.attrs.some((a) => a.cname === "xml:space" && a.value === "preserve");
}

function preserves(set: ReadonlySet<string> | undefined, name: string): boolean {
	return !!set && (set.has(name) || set.has(localName(name)));
}

/** Raw replacement for a leaf whose text becomes `text`. */
function leafReplacement(leaf: Leaf, text: string, preserve: boolean): RawReplacement {
	if (preserve && /^\s|\s$/.test(text) && !hasPreserve(leaf.tag)) {
		const open = `${leaf.open.slice(0, -1)} xml:space="preserve">`;
		return { start: leaf.tag.start, end: leaf.contentEnd, raw: open + escapeXmlText(text) };
	}
	return { start: leaf.tag.end, end: leaf.contentEnd, raw: escapeXmlText(text) };
}

/**
 * Distributes edits (segment coordinates) over the pieces of a paragraph: each edit's text
 * goes into the first leaf it overlaps; the rest of its span is removed from later leaves.
 */
function applyToPieces(
	pieces: readonly Piece[],
	edits: readonly Edit[],
	preserve: ReadonlySet<string> | undefined,
): RawReplacement[] {
	const out: RawReplacement[] = [];
	const sorted = [...edits].sort((a, b) => a.start - b.start);
	const placed = new Set<Edit>();
	let offset = 0;
	for (const piece of pieces) {
		const a = offset;
		const b = offset + piece.text.length;
		offset = b;
		if (!piece.leaf) continue;
		const touching = sorted.filter((e) => e.start < b && e.end > a);
		if (touching.length === 0) continue;
		if (!piece.leaf.rewritable) throw new XmlError("LEAF_NOT_REWRITABLE");
		let text = "";
		let cursor = a;
		for (const e of touching) {
			const from = Math.max(e.start, a);
			text += piece.text.slice(cursor - a, from - a);
			if (!placed.has(e)) {
				text += e.text;
				placed.add(e);
			}
			cursor = Math.min(e.end, b);
		}
		text += piece.text.slice(cursor - a);
		if (text !== piece.text)
			out.push(leafReplacement(piece.leaf, text, preserves(preserve, piece.leaf.tag.name)));
	}
	return out;
}

/** Applies edits (sorted or not, non-overlapping) to a plain string. */
export function spliceEdits(value: string, edits: readonly Edit[]): string {
	let out = "";
	let cursor = 0;
	for (const e of [...edits].sort((x, y) => x.start - y.start)) {
		out += value.slice(cursor, e.start) + e.text;
		cursor = e.end;
	}
	return out + value.slice(cursor);
}

export function attributeSegment(attr: XmlAttr): TextSegment {
	return {
		text: attr.value,
		context: "",
		apply(edits) {
			if (!edits.length) return [];
			const raw = escapeXmlAttr(spliceEdits(attr.value, edits), attr.quote);
			return [{ start: attr.valueStart, end: attr.valueEnd, raw }];
		},
	};
}

/** A bare text node (generic mode); a CDATA section is rewritten as escaped text. */
export function textNodeSegment(
	start: number,
	end: number,
	text: string,
	cdata: boolean,
): TextSegment {
	return {
		text,
		context: "",
		apply(edits) {
			if (!edits.length) return [];
			const raw = escapeXmlText(spliceEdits(text, edits));
			return cdata ? [{ start: start - 9, end: end + 3, raw }] : [{ start, end, raw }];
		},
	};
}

/** A segment over concatenated pieces (a paragraph, a shared string, an inline string). */
export function piecesSegment(
	pieces: readonly Piece[],
	preserveSpace?: ReadonlySet<string>,
): TextSegment {
	return {
		text: pieces.map((p) => p.text).join(""),
		context: "",
		apply: (edits) => applyToPieces(pieces, edits, preserveSpace),
	};
}

/** Tracks one open leaf element while walking (shared with format-specific walkers). */
export class LeafTracker {
	private leaf: Leaf | null = null;
	private depth = 0;

	constructor(private readonly xml: string) {}

	get open(): boolean {
		return this.leaf !== null;
	}

	begin(tag: XmlTag): void {
		this.leaf = {
			tag,
			open: this.xml.slice(tag.start, tag.end),
			contentEnd: tag.end,
			text: "",
			rewritable: true,
		};
		this.depth = 0;
	}

	/** A child start tag inside the open leaf. */
	child(): void {
		if (!this.leaf) return;
		this.leaf.rewritable = false;
		this.depth++;
	}

	text(start: number, end: number, cdata: boolean): void {
		if (!this.leaf) return;
		const raw = this.xml.slice(start, end);
		this.leaf.text += cdata ? raw : decodeXmlText(raw);
	}

	/** An end tag while a leaf is open; returns the finished leaf when it closes it. */
	end(start: number): Leaf | null {
		if (!this.leaf) return null;
		if (this.depth > 0) {
			this.depth--;
			return null;
		}
		const done = this.leaf;
		done.contentEnd = start;
		this.leaf = null;
		return done;
	}
}

/** Walk state of {@link extractText}. */
class TextExtractor {
	readonly segments: TextSegment[] = [];
	private readonly paragraphs: Piece[][] = [];
	private readonly leaves: LeafTracker;
	private readonly key: (name: string) => string;

	constructor(
		private readonly xml: string,
		private readonly spec: TextSpec,
	) {
		this.leaves = new LeafTracker(xml);
		this.key = spec.localNames ? localName : (name) => name;
	}

	start(tag: XmlTag, parent: string | undefined): void {
		if (this.leaves.open) return this.leaves.child();
		this.addAttributes(tag);
		if (this.spec.allText) return;
		const name = this.key(tag.cname);
		if (this.spec.paragraphs.has(name)) {
			this.paragraphs.push([]);
			return;
		}
		const brk = this.spec.breaks?.get(name);
		if (brk && parent !== undefined && this.key(parent) === brk[1]) {
			this.paragraphs[this.paragraphs.length - 1]?.push({ leaf: null, text: brk[0] });
			return;
		}
		if (this.spec.leaves.has(name) && !tag.selfClosing) this.leaves.begin(tag);
	}

	text(start: number, end: number, cdata: boolean): void {
		if (this.leaves.open) return this.leaves.text(start, end, cdata);
		if (!this.spec.allText) return;
		const raw = this.xml.slice(start, end);
		const text = cdata ? raw : decodeXmlText(raw);
		if (text.trim()) this.segments.push(textNodeSegment(start, end, text, cdata));
	}

	end(name: string, start: number): void {
		if (this.leaves.open) return this.endLeaf(start);
		if (this.spec.allText || !this.spec.paragraphs.has(this.key(name))) return;
		const pieces = this.paragraphs.pop();
		if (pieces?.some((p) => p.leaf && p.text.trim()))
			this.segments.push(piecesSegment(pieces, this.spec.preserveSpace));
	}

	private endLeaf(start: number): void {
		const leaf = this.leaves.end(start);
		if (!leaf) return;
		const open = this.paragraphs[this.paragraphs.length - 1];
		if (open) open.push({ leaf, text: leaf.text });
		else if (leaf.text.trim())
			this.segments.push(piecesSegment([{ leaf, text: leaf.text }], this.spec.preserveSpace));
	}

	private addAttributes(tag: XmlTag): void {
		for (const name of this.spec.attributes?.(tag) ?? []) {
			const attr = tag.attrs.find((a) => a.cname === name);
			if (attr?.value.trim()) this.segments.push(attributeSegment(attr));
		}
	}
}

/** Builds the text segments of one XML part. */
export function extractText(xml: string, spec: TextSpec, options: WalkOptions = {}): TextSegment[] {
	const extractor = new TextExtractor(xml, spec);
	walkXml(
		xml,
		{
			start: (tag, parent) => extractor.start(tag, parent),
			text: (start, end, cdata) => extractor.text(start, end, cdata),
			end: (name, start) => extractor.end(name, start),
		},
		options,
	);
	return extractor.segments;
}

/** Applies non-overlapping raw replacements to `xml`. */
export function applyReplacements(xml: string, replacements: readonly RawReplacement[]): string {
	if (!replacements.length) return xml;
	const sorted = [...replacements].sort((a, b) => a.start - b.start);
	let out = "";
	let cursor = 0;
	for (const r of sorted) {
		if (r.start < cursor) throw new XmlError("OVERLAPPING_REPLACEMENTS");
		out += xml.slice(cursor, r.start) + r.raw;
		cursor = r.end;
	}
	return out + xml.slice(cursor);
}
