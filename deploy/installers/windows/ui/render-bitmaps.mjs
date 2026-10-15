#!/usr/bin/env node
// Rasterise the installer wizard's SVG sources (banner.svg, dialog.svg) into
// the 24-bit BMP files WiX embeds (WixUIBannerBmp 493x58, WixUIDialogBmp
// 493x312). Pure JavaScript and integer output, so the same SVG gives the same
// bytes on every machine: no font, no system rasteriser, no dependency.
//
// The SVG subset is deliberately small: <rect>, <polygon>, <circle> with a
// solid `fill` or `fill="url(#id)"` of a userSpaceOnUse <linearGradient>, and
// an optional `opacity`. Anything else is an error rather than a silent
// mis-render.
//
//   node deploy/installers/windows/ui/render-bitmaps.mjs          # write the .bmp files
//   node deploy/installers/windows/ui/render-bitmaps.mjs --check  # fail if they are stale

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

/** The wizard bitmaps and the exact sizes Windows Installer's dialogs expect. */
export const WIZARD_BITMAPS = [
	{ svg: join(here, "banner.svg"), bmp: join(here, "banner.bmp"), width: 493, height: 58 },
	{ svg: join(here, "dialog.svg"), bmp: join(here, "dialog.bmp"), width: 493, height: 312 },
];

/** Samples per pixel edge (SAMPLES^2 per pixel) for edge anti-aliasing. */
const SAMPLES = 4;

function attributes(tag) {
	const out = {};
	for (const match of tag.matchAll(/([a-zA-Z][a-zA-Z0-9-]*)="([^"]*)"/g)) out[match[1]] = match[2];
	return out;
}

function number(value, name) {
	const parsed = Number(value);
	if (value === undefined || !Number.isFinite(parsed)) throw new Error(`SVG: ${name} must be a number (got ${value})`);
	return parsed;
}

function hexColor(value) {
	const match = /^#([0-9a-fA-F]{6})$/.exec(value ?? "");
	if (!match) throw new Error(`SVG: colour must be #RRGGBB (got ${value})`);
	const n = Number.parseInt(match[1], 16);
	return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

/** Parse the supported subset into a canvas size, gradients and an ordered shape list. */
function parseSvg(text) {
	const body = text.replace(/<!--[\s\S]*?-->/g, "");
	const root = /<svg\b[^>]*>/.exec(body);
	if (!root) throw new Error("SVG: no <svg> element");
	const rootAttrs = attributes(root[0]);
	const width = number(rootAttrs.width, "width");
	const height = number(rootAttrs.height, "height");
	if (rootAttrs.viewBox !== `0 0 ${width} ${height}`) throw new Error("SVG: viewBox must be 0 0 <width> <height>");

	const gradients = new Map();
	for (const match of body.matchAll(/<linearGradient\b([^>]*)>([\s\S]*?)<\/linearGradient>/g)) {
		const attrs = attributes(match[1]);
		if (attrs.gradientUnits !== "userSpaceOnUse") throw new Error("SVG: gradients must use gradientUnits=\"userSpaceOnUse\"");
		const stops = [...match[2].matchAll(/<stop\b[^>]*>/g)].map((stop) => {
			const s = attributes(stop[0]);
			return { offset: number(s.offset, "stop offset"), color: hexColor(s["stop-color"]) };
		});
		if (stops.length < 2) throw new Error(`SVG: gradient ${attrs.id} needs two stops`);
		gradients.set(attrs.id, {
			x1: number(attrs.x1, "x1"),
			y1: number(attrs.y1, "y1"),
			x2: number(attrs.x2, "x2"),
			y2: number(attrs.y2, "y2"),
			stops,
		});
	}

	const shapes = [];
	const drawable = body.replace(/<defs>[\s\S]*?<\/defs>/g, "");
	for (const match of drawable.matchAll(/<(\w+)\b([^>]*?)\/?>/g)) {
		const [, name, raw] = match;
		if (name === "svg") continue;
		if (!["rect", "circle", "polygon"].includes(name)) {
			throw new Error(`SVG: <${name}> is not supported by render-bitmaps.mjs`);
		}
		const attrs = attributes(raw);
		const opacity = attrs.opacity === undefined ? 1 : number(attrs.opacity, "opacity");
		const ref = /^url\(#([\w-]+)\)$/.exec(attrs.fill ?? "");
		let paint;
		if (ref) {
			paint = gradients.get(ref[1]);
			if (!paint) throw new Error(`SVG: unknown gradient ${ref[1]}`);
		} else {
			paint = { solid: hexColor(attrs.fill) };
		}
		if (name === "rect") {
			const x = number(attrs.x, "x");
			const y = number(attrs.y, "y");
			const w = number(attrs.width, "width");
			const h = number(attrs.height, "height");
			shapes.push({ inside: (px, py) => px >= x && px < x + w && py >= y && py < y + h, bounds: [x, y, x + w, y + h], paint, opacity });
		} else if (name === "circle") {
			const cx = number(attrs.cx, "cx");
			const cy = number(attrs.cy, "cy");
			const r = number(attrs.r, "r");
			shapes.push({
				inside: (px, py) => (px - cx) ** 2 + (py - cy) ** 2 <= r * r,
				bounds: [cx - r, cy - r, cx + r, cy + r],
				paint,
				opacity,
			});
		} else {
			const values = (attrs.points ?? "").trim().split(/[\s,]+/).map((v) => number(v, "points"));
			if (values.length < 6 || values.length % 2) throw new Error("SVG: polygon needs at least three points");
			const pts = [];
			for (let i = 0; i < values.length; i += 2) pts.push([values[i], values[i + 1]]);
			const xs = pts.map((p) => p[0]);
			const ys = pts.map((p) => p[1]);
			shapes.push({ inside: (px, py) => insidePolygon(pts, px, py), bounds: [Math.min(...xs), Math.min(...ys), Math.max(...xs), Math.max(...ys)], paint, opacity });
		}
	}
	return { width, height, shapes };
}

/** Even-odd rule. */
function insidePolygon(pts, x, y) {
	let inside = false;
	for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
		const [xi, yi] = pts[i];
		const [xj, yj] = pts[j];
		if (yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
	}
	return inside;
}

function paintAt(paint, x, y) {
	if (paint.solid) return paint.solid;
	const dx = paint.x2 - paint.x1;
	const dy = paint.y2 - paint.y1;
	const t = Math.min(1, Math.max(0, ((x - paint.x1) * dx + (y - paint.y1) * dy) / (dx * dx + dy * dy)));
	const { stops } = paint;
	let k = 0;
	while (k < stops.length - 2 && t > stops[k + 1].offset) k++;
	const a = stops[k];
	const b = stops[k + 1];
	const u = b.offset === a.offset ? 0 : Math.min(1, Math.max(0, (t - a.offset) / (b.offset - a.offset)));
	return a.color.map((c, i) => c + (b.color[i] - c) * u);
}

/** Render to a 24-bit bottom-up BMP (BITMAPINFOHEADER, 72 dpi). */
export function renderSvgToBmp(text) {
	const { width, height, shapes } = parseSvg(text);
	const rgb = new Float64Array(width * height * 3);
	const step = 1 / SAMPLES;
	for (const shape of shapes) {
		const [bx0, by0, bx1, by1] = shape.bounds;
		const x0 = Math.max(0, Math.floor(bx0));
		const y0 = Math.max(0, Math.floor(by0));
		const x1 = Math.min(width - 1, Math.ceil(bx1));
		const y1 = Math.min(height - 1, Math.ceil(by1));
		for (let py = y0; py <= y1; py++) {
			for (let px = x0; px <= x1; px++) {
				let hits = 0;
				for (let sy = 0; sy < SAMPLES; sy++) {
					for (let sx = 0; sx < SAMPLES; sx++) {
						if (shape.inside(px + (sx + 0.5) * step, py + (sy + 0.5) * step)) hits++;
					}
				}
				if (hits === 0) continue;
				const alpha = (hits / (SAMPLES * SAMPLES)) * shape.opacity;
				const color = paintAt(shape.paint, px + 0.5, py + 0.5);
				const o = (py * width + px) * 3;
				for (let c = 0; c < 3; c++) rgb[o + c] = rgb[o + c] * (1 - alpha) + color[c] * alpha;
			}
		}
	}
	const stride = Math.ceil((width * 3) / 4) * 4;
	const imageSize = stride * height;
	const out = Buffer.alloc(54 + imageSize);
	out.write("BM", 0, "ascii");
	out.writeUInt32LE(out.length, 2);
	out.writeUInt32LE(54, 10);
	out.writeUInt32LE(40, 14);
	out.writeInt32LE(width, 18);
	out.writeInt32LE(height, 22);
	out.writeUInt16LE(1, 26);
	out.writeUInt16LE(24, 28);
	out.writeUInt32LE(0, 30);
	out.writeUInt32LE(imageSize, 34);
	out.writeInt32LE(2835, 38);
	out.writeInt32LE(2835, 42);
	for (let y = 0; y < height; y++) {
		const row = 54 + (height - 1 - y) * stride;
		for (let x = 0; x < width; x++) {
			const o = (y * width + x) * 3;
			// BMP stores blue, green, red.
			out[row + x * 3] = Math.round(rgb[o + 2]);
			out[row + x * 3 + 1] = Math.round(rgb[o + 1]);
			out[row + x * 3 + 2] = Math.round(rgb[o]);
		}
	}
	return out;
}

/** Width, height and bit depth from a BMP header (throws on anything that is not one). */
export function bmpInfo(buffer) {
	if (buffer.length < 54 || buffer.toString("ascii", 0, 2) !== "BM") throw new Error("not a BMP file");
	return { width: buffer.readInt32LE(18), height: Math.abs(buffer.readInt32LE(22)), bitsPerPixel: buffer.readUInt16LE(28) };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	const check = process.argv.includes("--check");
	let stale = 0;
	for (const bitmap of WIZARD_BITMAPS) {
		const rendered = renderSvgToBmp(readFileSync(bitmap.svg, "utf8"));
		const info = bmpInfo(rendered);
		if (info.width !== bitmap.width || info.height !== bitmap.height) {
			console.error(`ERROR: ${bitmap.svg} renders ${info.width}x${info.height}, expected ${bitmap.width}x${bitmap.height}`);
			process.exit(1);
		}
		if (check) {
			let current = null;
			try {
				current = readFileSync(bitmap.bmp);
			} catch {}
			if (!current?.equals(rendered)) {
				console.error(`STALE: ${bitmap.bmp} does not match ${bitmap.svg}; run render-bitmaps.mjs`);
				stale++;
			}
		} else {
			writeFileSync(bitmap.bmp, rendered);
			console.log(`wrote ${bitmap.bmp} (${bitmap.width}x${bitmap.height})`);
		}
	}
	if (stale) process.exit(1);
}
