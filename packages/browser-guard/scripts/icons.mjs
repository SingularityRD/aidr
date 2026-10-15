#!/usr/bin/env node
/**
 * Generates the extension toolbar/store icons (16, 32, 48, 128 px) and the UI logo
 * from the Singularity product mark `branding/singularity-mark.svg`, dependency-free:
 *
 *   1. the SVG (a circle clip path plus polygons, `fill="currentColor"`) is parsed and
 *      rasterised by a small scanline renderer (exact coverage along x, 16 sub-rows per
 *      pixel) into the master PNG `images/icon-master.png` (1024 px, ICON_COLOR);
 *   2. the master is area-averaged (box resampled) to each icon size;
 *   3. `static/ui.css` `--logo` is the same SVG as a data URL, used as a CSS mask so
 *      the popup/options/blocked pages colour it per theme.
 *
 *   node scripts/icons.mjs            # regenerate the master, static/icons/icon-<size>.png and --logo
 *   node scripts/icons.mjs --check    # exit 1 when any of them is stale
 *
 * The output is deterministic (IEEE double arithmetic only, fixed zlib level, no
 * ancillary chunks), so the committed files only change when the mark changes. The
 * renderer accepts only the SVG subset the mark uses and refuses anything else, so a
 * redrawn mark with paths or gradients fails loudly instead of rendering wrong.
 */
import { readFileSync, mkdirSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateSync, inflateSync } from "node:zlib";
import { crc32 } from "./zip.mjs";

export const ICON_SIZES = Object.freeze([16, 32, 48, 128]);
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const CHANNELS_BY_COLOR_TYPE = { 0: 1, 2: 3, 4: 2, 6: 4 };

/**
 * Decodes an 8-bit, non-interlaced greyscale/RGB/RGBA PNG to RGBA pixels.
 * @returns {{ width: number; height: number; data: Uint8Array }}
 */
export function decodePng(buffer) {
	if (!buffer.subarray(0, 8).equals(PNG_SIGNATURE)) throw new Error("PNG_BAD_SIGNATURE");
	let offset = 8;
	let header = null;
	const idat = [];
	while (offset < buffer.length) {
		const length = buffer.readUInt32BE(offset);
		const type = buffer.toString("latin1", offset + 4, offset + 8);
		const body = buffer.subarray(offset + 8, offset + 8 + length);
		if (crc32(buffer.subarray(offset + 4, offset + 8 + length)) !== buffer.readUInt32BE(offset + 8 + length)) {
			throw new Error(`PNG_BAD_CRC: ${type}`);
		}
		if (type === "IHDR") {
			header = {
				width: body.readUInt32BE(0),
				height: body.readUInt32BE(4),
				bitDepth: body[8],
				colorType: body[9],
				interlace: body[12],
			};
		} else if (type === "IDAT") idat.push(body);
		else if (type === "IEND") break;
		offset += 12 + length;
	}
	if (!header) throw new Error("PNG_NO_IHDR");
	const channels = CHANNELS_BY_COLOR_TYPE[header.colorType];
	if (header.bitDepth !== 8 || !channels || header.interlace !== 0) {
		throw new Error("PNG_UNSUPPORTED_FORMAT (need 8-bit, non-interlaced, non-palette)");
	}
	const { width, height } = header;
	const raw = inflateSync(Buffer.concat(idat));
	const stride = width * channels;
	const pixels = new Uint8Array(stride * height);
	for (let y = 0; y < height; y++) {
		const filter = raw[y * (stride + 1)];
		const line = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
		const out = y * stride;
		for (let x = 0; x < stride; x++) {
			const a = x >= channels ? pixels[out + x - channels] : 0;
			const b = y > 0 ? pixels[out - stride + x] : 0;
			const c = x >= channels && y > 0 ? pixels[out - stride + x - channels] : 0;
			let predictor;
			switch (filter) {
				case 0:
					predictor = 0;
					break;
				case 1:
					predictor = a;
					break;
				case 2:
					predictor = b;
					break;
				case 3:
					predictor = (a + b) >> 1;
					break;
				case 4: {
					const p = a + b - c;
					const pa = Math.abs(p - a);
					const pb = Math.abs(p - b);
					const pc = Math.abs(p - c);
					predictor = pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
					break;
				}
				default:
					throw new Error(`PNG_BAD_FILTER: ${filter}`);
			}
			pixels[out + x] = (line[x] + predictor) & 0xff;
		}
	}
	const rgba = new Uint8Array(width * height * 4);
	for (let i = 0; i < width * height; i++) {
		const s = i * channels;
		const grey = channels <= 2;
		rgba[i * 4] = pixels[s];
		rgba[i * 4 + 1] = grey ? pixels[s] : pixels[s + 1];
		rgba[i * 4 + 2] = grey ? pixels[s] : pixels[s + 2];
		rgba[i * 4 + 3] = channels === 4 ? pixels[s + 3] : channels === 2 ? pixels[s + 1] : 255;
	}
	return { width, height, data: rgba };
}

/** Encodes RGBA pixels as an 8-bit RGBA PNG (filter 0 rows, zlib level 9). */
export function encodePng({ width, height, data }) {
	const stride = width * 4;
	const raw = Buffer.alloc((stride + 1) * height);
	for (let y = 0; y < height; y++) {
		raw[y * (stride + 1)] = 0;
		Buffer.from(data.buffer, data.byteOffset + y * stride, stride).copy(raw, y * (stride + 1) + 1);
	}
	const chunk = (type, body) => {
		const length = Buffer.alloc(4);
		length.writeUInt32BE(body.length);
		const typed = Buffer.concat([Buffer.from(type, "latin1"), body]);
		const crc = Buffer.alloc(4);
		crc.writeUInt32BE(crc32(typed));
		return Buffer.concat([length, typed, crc]);
	};
	const ihdr = Buffer.alloc(13);
	ihdr.writeUInt32BE(width, 0);
	ihdr.writeUInt32BE(height, 4);
	ihdr[8] = 8; // bit depth
	ihdr[9] = 6; // RGBA
	return Buffer.concat([
		PNG_SIGNATURE,
		chunk("IHDR", ihdr),
		chunk("IDAT", deflateSync(raw, { level: 9 })),
		chunk("IEND", Buffer.alloc(0)),
	]);
}

/**
 * Area-average resampling in premultiplied alpha, so transparent edge pixels do
 * not bleed dark fringes into the shield outline at 16 px.
 */
export function resize(image, size) {
	const { width, height, data } = image;
	if (width === size && height === size) return { width, height, data: Uint8Array.from(data) };
	const out = new Uint8Array(size * size * 4);
	const sx = width / size;
	const sy = height / size;
	for (let oy = 0; oy < size; oy++) {
		const y0 = oy * sy;
		const y1 = y0 + sy;
		for (let ox = 0; ox < size; ox++) {
			const x0 = ox * sx;
			const x1 = x0 + sx;
			let r = 0;
			let g = 0;
			let b = 0;
			let a = 0;
			let area = 0;
			for (let y = Math.floor(y0); y < Math.ceil(y1); y++) {
				const wy = Math.min(y + 1, y1) - Math.max(y, y0);
				for (let x = Math.floor(x0); x < Math.ceil(x1); x++) {
					const w = wy * (Math.min(x + 1, x1) - Math.max(x, x0));
					const i = (y * width + x) * 4;
					const alpha = data[i + 3] / 255;
					r += data[i] * alpha * w;
					g += data[i + 1] * alpha * w;
					b += data[i + 2] * alpha * w;
					a += alpha * w;
					area += w;
				}
			}
			const o = (oy * size + ox) * 4;
			if (a > 0) {
				out[o] = Math.round(r / a);
				out[o + 1] = Math.round(g / a);
				out[o + 2] = Math.round(b / a);
			}
			out[o + 3] = Math.round((a / area) * 255);
		}
	}
	return { width: size, height: size, data: out };
}

/** @returns {Map<number, Buffer>} size -> PNG bytes */
export function renderIcons(masterPng) {
	const master = decodePng(masterPng);
	return new Map(ICON_SIZES.map((size) => [size, encodePng(resize(master, size))]));
}

// ---------------------------------------------------------------------------
// SVG mark -> master PNG
// ---------------------------------------------------------------------------

/** Icon colour: the Browser Guard accent (static/ui.css `--accent`), legible on light and dark toolbars. */
export const ICON_COLOR = Object.freeze([0x38, 0x62, 0xe8]);
export const MASTER_SIZE = 1024;
const SUBROWS = 16;

function numbers(text, what) {
	const list = String(text ?? "")
		.trim()
		.split(/[\s,]+/)
		.filter((part) => part !== "")
		.map(Number);
	if (list.length === 0 || list.some((n) => !Number.isFinite(n))) throw new Error(`SVG_BAD_NUMBERS: ${what}`);
	return list;
}

function attr(tag, name) {
	const match = new RegExp(`\\s${name}="([^"]*)"`).exec(tag);
	return match ? match[1] : undefined;
}

const MARK_ELEMENTS = new Set(["svg", "title", "desc", "defs", "clipPath", "circle", "g", "polygon"]);

/**
 * Parses the subset of SVG the product mark uses: a square `viewBox`, at most one
 * `<circle>` (inside a `<clipPath>`) and `<polygon>`s. Any other drawing element is refused.
 * @returns {{ viewBox: number[]; clip: { cx: number; cy: number; r: number } | null; polygons: number[][][] }}
 */
export function parseMark(svgText) {
	const svg = String(svgText);
	const root = /<svg\b[^>]*>/.exec(svg)?.[0];
	if (!root) throw new Error("SVG_NO_ROOT");
	const viewBox = numbers(attr(root, "viewBox"), "viewBox");
	if (viewBox.length !== 4 || viewBox[2] <= 0 || viewBox[2] !== viewBox[3]) throw new Error("SVG_VIEWBOX_NOT_SQUARE");
	for (const [, name] of svg.matchAll(/<([A-Za-z][\w:-]*)/g)) {
		if (!MARK_ELEMENTS.has(name)) throw new Error(`SVG_UNSUPPORTED_ELEMENT: ${name}`);
	}
	const circles = [...svg.matchAll(/<circle\b[^>]*>/g)].map(([tag]) => tag);
	if (circles.length > 1) throw new Error("SVG_UNSUPPORTED_CLIP");
	if (circles.length === 1 && !/<clipPath\b[^>]*>\s*<circle\b/.test(svg)) throw new Error("SVG_CIRCLE_OUTSIDE_CLIP");
	const clip = circles[0]
		? {
				cx: numbers(attr(circles[0], "cx"), "cx")[0],
				cy: numbers(attr(circles[0], "cy"), "cy")[0],
				r: numbers(attr(circles[0], "r"), "r")[0],
			}
		: null;
	const polygons = [...svg.matchAll(/<polygon\b[^>]*>/g)].map(([tag]) => {
		const pts = numbers(attr(tag, "points"), "points");
		if (pts.length < 6 || pts.length % 2 !== 0) throw new Error("SVG_BAD_POLYGON");
		const out = [];
		for (let i = 0; i < pts.length; i += 2) out.push([pts[i], pts[i + 1]]);
		return out;
	});
	if (polygons.length === 0) throw new Error("SVG_NO_POLYGONS");
	return { viewBox, clip, polygons };
}

/** Sorted, merged [x0, x1] intervals of the union of `polygons` (even-odd per polygon) on the line y. */
function spansAt(polygons, y) {
	const spans = [];
	for (const poly of polygons) {
		const xs = [];
		for (let i = 0; i < poly.length; i++) {
			const [x0, y0] = poly[i];
			const [x1, y1] = poly[(i + 1) % poly.length];
			if (y0 === y1 || y < Math.min(y0, y1) || y >= Math.max(y0, y1)) continue;
			xs.push(x0 + ((y - y0) / (y1 - y0)) * (x1 - x0));
		}
		xs.sort((a, b) => a - b);
		for (let i = 0; i + 1 < xs.length; i += 2) spans.push([xs[i], xs[i + 1]]);
	}
	spans.sort((a, b) => a[0] - b[0]);
	const merged = [];
	for (const s of spans) {
		const last = merged[merged.length - 1];
		if (last && s[0] <= last[1]) last[1] = Math.max(last[1], s[1]);
		else merged.push([s[0], s[1]]);
	}
	return merged;
}

/**
 * Rasterises a parsed mark to `size` x `size` RGBA in `color`: each pixel's alpha is its
 * covered area (exact along x, SUBROWS samples along y).
 */
export function rasterizeMark(mark, size, color = ICON_COLOR) {
	const [minX, minY, extent] = mark.viewBox;
	const scale = size / extent;
	const coverage = new Float64Array(size * size);
	for (let py = 0; py < size; py++) {
		for (let s = 0; s < SUBROWS; s++) {
			const y = minY + (py + (s + 0.5) / SUBROWS) / scale;
			let spans = spansAt(mark.polygons, y);
			if (mark.clip) {
				const dy = y - mark.clip.cy;
				if (Math.abs(dy) >= mark.clip.r) continue;
				const half = Math.sqrt(mark.clip.r * mark.clip.r - dy * dy);
				const c0 = mark.clip.cx - half;
				const c1 = mark.clip.cx + half;
				spans = spans.map(([a, b]) => [Math.max(a, c0), Math.min(b, c1)]).filter(([a, b]) => b > a);
			}
			for (const [a, b] of spans) {
				const x0 = Math.max(0, (a - minX) * scale);
				const x1 = Math.min(size, (b - minX) * scale);
				for (let px = Math.floor(x0); px < Math.ceil(x1); px++) {
					const w = Math.min(px + 1, x1) - Math.max(px, x0);
					if (w > 0) coverage[py * size + px] += w / SUBROWS;
				}
			}
		}
	}
	const data = new Uint8Array(size * size * 4);
	for (let i = 0; i < size * size; i++) {
		const a = Math.round(Math.min(1, coverage[i]) * 255);
		if (a === 0) continue;
		data[i * 4] = color[0];
		data[i * 4 + 1] = color[1];
		data[i * 4 + 2] = color[2];
		data[i * 4 + 3] = a;
	}
	return { width: size, height: size, data };
}

/** Renders the master PNG (MASTER_SIZE, ICON_COLOR) from the mark's SVG text. */
export function renderMaster(svgText) {
	return encodePng(rasterizeMark(parseMark(svgText), MASTER_SIZE));
}

/**
 * The mark as a data URL for the CSS `--logo` (used as a mask, so only its alpha
 * matters: `currentColor` becomes black). Title, ARIA attributes and line breaks are dropped.
 */
export function logoDataUrl(svgText) {
	parseMark(svgText);
	const svg = String(svgText)
		.replace(/<title>[\s\S]*?<\/title>/g, "")
		.replace(/\s(role|aria-label)="[^"]*"/g, "")
		.replace(/currentColor/g, "black")
		.replace(/\s*\n\s*/g, "")
		.replace(/"/g, "'");
	return `data:image/svg+xml,${svg.replace(/[<>#%]/g, (c) => encodeURIComponent(c))}`;
}

const LOGO_LINE = /(\t--logo: url\(")[^"]*("\);)/;

/** Returns `css` with its `--logo` set to the mark; throws when the stylesheet has no `--logo` line. */
export function withLogo(css, svgText) {
	if (!LOGO_LINE.test(css)) throw new Error("static/ui.css has no --logo line");
	return css.replace(LOGO_LINE, (_m, before, after) => `${before}${logoDataUrl(svgText)}${after}`);
}

const scriptDir = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(scriptDir, "..");
export const MARK_SVG = resolve(packageRoot, "../../branding/singularity-mark.svg");
export const MASTER_ICON = join(packageRoot, "images", "icon-master.png");
export const ICON_DIR = join(packageRoot, "static", "icons");
export const UI_CSS = join(packageRoot, "static", "ui.css");

/** Every generated file and the bytes it must hold (path -> Buffer). */
export function expectedOutputs(svgText = readFileSync(MARK_SVG, "utf8")) {
	const master = renderMaster(svgText);
	const files = new Map([[MASTER_ICON, master]]);
	for (const [size, png] of renderIcons(master)) files.set(join(ICON_DIR, `icon-${size}.png`), png);
	files.set(UI_CSS, Buffer.from(withLogo(readFileSync(UI_CSS, "utf8"), svgText), "utf8"));
	return files;
}

function main(argv) {
	const files = expectedOutputs();
	const rel = (file) => relative(packageRoot, file).split(sep).join("/");
	if (argv.includes("--check")) {
		const stale = [...files].filter(([file, bytes]) => !existsSync(file) || !readFileSync(file).equals(bytes));
		if (stale.length > 0) {
			console.error(`[icons] stale: ${stale.map(([f]) => rel(f)).join(", ")}; run node scripts/icons.mjs`);
			return 1;
		}
		console.log("[icons] up to date");
		return 0;
	}
	for (const [file, bytes] of files) {
		mkdirSync(dirname(file), { recursive: true });
		writeFileSync(file, bytes);
	}
	console.log(`[icons] wrote ${[...files.keys()].map(rel).join(", ")}`);
	return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	process.exitCode = main(process.argv.slice(2));
}
