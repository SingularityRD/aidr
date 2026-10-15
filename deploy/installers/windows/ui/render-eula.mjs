#!/usr/bin/env node
// Render the licence text shown on the MSI wizard's licence page
// (windows/ui/eula.<culture>.rtf) from its Markdown source in docs/legal/.
// The Markdown is the text Legal reviews; the RTF is generated from it, so the
// two cannot drift. Output is pure ASCII (non-ASCII characters become RTF \uN?
// escapes) and byte-for-byte deterministic.
//
// The Markdown subset is small on purpose: "# " title, "## " heading, "> "
// notice, "- " bullet, other lines as paragraphs, **bold** and `code` inline.
// Anything else (tables, HTML, images, nested lists) is an error rather than a
// silent mis-render.
//
//   node deploy/installers/windows/ui/render-eula.mjs          # write the .rtf files
//   node deploy/installers/windows/ui/render-eula.mjs --check  # fail if they are stale

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const legal = resolve(here, "../../../../docs/legal");

/** One licence page per wizard culture, with the RTF code page its font needs. */
export const EULA_PAGES = [
	{ culture: "en-US", markdown: join(legal, "eula.en.md"), rtf: join(here, "eula.en-US.rtf"), codepage: 1252, charset: 0 },
	{ culture: "tr-TR", markdown: join(legal, "eula.tr.md"), rtf: join(here, "eula.tr-TR.rtf"), codepage: 1254, charset: 162 },
];

/** Escape RTF control characters and turn every non-ASCII character into \uN?. */
function escapeText(text) {
	let out = "";
	for (const char of text) {
		const code = char.codePointAt(0);
		if (char === "\\" || char === "{" || char === "}") out += `\\${char}`;
		else if (code >= 0x20 && code < 0x7f) out += char;
		else if (code <= 0x7fff) out += `\\u${code}?`;
		else if (code <= 0xffff) out += `\\u${code - 0x10000}?`;
		else throw new Error(`character U+${code.toString(16)} outside the Basic Multilingual Plane is not supported`);
	}
	return out;
}

/** Inline markup: **bold** and `code` (shown as plain text). */
function inline(text) {
	if (/<[a-z/!]|!\[|\]\(/i.test(text)) throw new Error(`unsupported inline markup: ${text}`);
	const parts = text.replace(/`([^`]*)`/g, "$1").split("**");
	if (parts.length % 2 === 0) throw new Error(`unbalanced ** in: ${text}`);
	return parts.map((part, i) => (i % 2 === 1 ? `{\\b ${escapeText(part)}}` : escapeText(part))).join("");
}

/** Markdown blocks: [{kind, text}] where kind is title, heading, notice, bullet or paragraph. */
function blocks(markdown) {
	const out = [];
	let current = null;
	const flush = () => {
		if (current) out.push(current);
		current = null;
	};
	for (const raw of markdown.replace(/\r\n/g, "\n").split("\n")) {
		const line = raw.trimEnd();
		if (line.trim() === "") {
			flush();
			continue;
		}
		if (/^\s*(?:\||<|!\[|```)|^\s+[-*]\s/.test(line)) throw new Error(`unsupported Markdown line: ${line}`);
		const title = line.match(/^# (.+)$/);
		const heading = line.match(/^## (.+)$/);
		const notice = line.match(/^> ?(.*)$/);
		const bullet = line.match(/^- (.+)$/);
		if (/^#{3,}\s/.test(line)) throw new Error(`only # and ## headings are supported: ${line}`);
		if (title || heading) {
			flush();
			out.push({ kind: title ? "title" : "heading", text: (title ?? heading)[1] });
		} else if (bullet) {
			flush();
			current = { kind: "bullet", text: bullet[1] };
		} else if (notice) {
			if (current?.kind !== "notice") {
				flush();
				current = { kind: "notice", text: notice[1] };
			} else current.text += ` ${notice[1]}`;
		} else if (current) {
			current.text += ` ${line.trim()}`;
		} else {
			current = { kind: "paragraph", text: line.trim() };
		}
	}
	flush();
	return out;
}

/** The RTF document for one licence page. */
export function renderEulaRtf(markdown, { codepage, charset }) {
	const body = blocks(markdown).map(({ kind, text }) => {
		const content = inline(text);
		if (kind === "title") return `{\\b\\fs20 ${content}}\\par`;
		if (kind === "heading") return `{\\b ${content}}\\par`;
		if (kind === "notice") return `{\\b ${content}}\\par`;
		if (kind === "bullet") return `{\\pard\\sa60\\li240\\fi-180 \\u8226? ${content}\\par}`;
		return `${content}\\par`;
	});
	return [
		`{\\rtf1\\ansi\\ansicpg${codepage}\\deff0\\uc1{\\fonttbl{\\f0\\fswiss\\fcharset${charset} Tahoma;}}`,
		"\\viewkind4\\pard\\sa120\\f0\\fs17",
		...body,
		"}",
		"",
	].join("\n");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
	const check = process.argv.includes("--check");
	let stale = 0;
	for (const page of EULA_PAGES) {
		const rendered = renderEulaRtf(readFileSync(page.markdown, "utf8"), page);
		if (check) {
			let current = null;
			try {
				current = readFileSync(page.rtf, "utf8");
			} catch {}
			if (current !== rendered) {
				console.error(`STALE: ${page.rtf} does not match ${page.markdown}; run render-eula.mjs`);
				stale++;
			}
		} else {
			writeFileSync(page.rtf, rendered);
			console.log(`wrote ${page.rtf}`);
		}
	}
	if (stale) process.exit(1);
}
