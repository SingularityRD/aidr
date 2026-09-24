#!/usr/bin/env node
/**
 * Generates the extension toolbar/store icons (16, 32, 48, 128 px) from the
 * brand master `images/aidr-icon.png` with a dependency-free PNG decoder,
 * area-average (box) resampler and PNG encoder.
 *
 *   node scripts/icons.mjs            # regenerate static/icons/icon-<size>.png
 *   node scripts/icons.mjs --check    # exit 1 when the committed icons are stale
 *
 * The output is deterministic (fixed zlib level, no ancillary chunks), so the
 * committed PNGs only change when the master image changes.
 */
import { readFileSync, mkdirSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
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

const scriptDir = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(scriptDir, "..");
export const MASTER_ICON = resolve(packageRoot, "../../images/aidr-icon.png");
export const ICON_DIR = join(packageRoot, "static", "icons");

function main(argv) {
	const icons = renderIcons(readFileSync(MASTER_ICON));
	if (argv.includes("--check")) {
		const stale = [...icons].filter(([size, png]) => {
			const file = join(ICON_DIR, `icon-${size}.png`);
			return !existsSync(file) || !readFileSync(file).equals(png);
		});
		if (stale.length > 0) {
			console.error(`[icons] stale: ${stale.map(([s]) => `icon-${s}.png`).join(", ")}; run node scripts/icons.mjs`);
			return 1;
		}
		console.log("[icons] up to date");
		return 0;
	}
	mkdirSync(ICON_DIR, { recursive: true });
	for (const [size, png] of icons) writeFileSync(join(ICON_DIR, `icon-${size}.png`), png);
	console.log(`[icons] wrote ${ICON_SIZES.map((s) => `icon-${s}.png`).join(", ")}`);
	return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	process.exitCode = main(process.argv.slice(2));
}
