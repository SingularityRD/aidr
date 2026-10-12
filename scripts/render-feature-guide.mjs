#!/usr/bin/env node
/**
 * Render the Singularity AIDR feature guide (docs/product/features/<lang>/0N-*.md) into one
 * self-contained, print-ready HTML file and one A4 PDF per language.
 *
 *   node scripts/render-feature-guide.mjs               # both languages: HTML + PDF
 *   node scripts/render-feature-guide.mjs --lang=tr     # one language
 *   node scripts/render-feature-guide.mjs --check       # convert and check the layout, write nothing
 *   node scripts/render-feature-guide.mjs --force       # write output even when a check fails
 *
 * Output (next to the chapters):
 *   docs/product/features/singularity-aidr-feature-guide-<lang>.html
 *   docs/product/features/singularity-aidr-feature-guide-<lang>.pdf
 *
 * The Markdown converter below is deliberately small and dependency-free. It covers what the
 * guide uses: ATX headings with GitHub-style ids, paragraphs, emphasis, inline code, fenced
 * code, GFM tables, nested lists, blockquotes, rules and links. Links between the chapters
 * become in-document links; links to other repository files are printed as text plus the
 * repository path, because the PDF is read on its own.
 *
 * The table of contents carries real page numbers. The PDF is rendered once, the page of
 * every heading is read back from the PDF's named destinations, and the PDF is rendered
 * again with those numbers (repeated until the numbers are stable).
 *
 * playwright-core is a devDependency of packages/browser-guard and is resolved from there;
 * the Chromium build comes from PLAYWRIGHT_BROWSERS_PATH (or AIDR_CHROMIUM_PATH). On Linux only
 * the fonts in scripts/lib/render-fonts.conf are visible (scripts/lib/render-browser.mjs).
 */
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { launchRenderBrowser, loadChromium } from "./lib/render-browser.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const featuresDir = path.join(repositoryRoot, "docs", "product", "features");
const logoPath = path.join(repositoryRoot, "images", "aidr-logo-shaded.svg");
export const LANGUAGES = ["tr", "en"];
const CHAPTER_FILE = /^0\d-[\w-]+\.md$/;
/** A4 minus the left and right @page margins (17 mm each), in CSS pixels. */
const CONTENT_WIDTH_PX = Math.round((176 * 96) / 25.4);
const MAX_NUMBERING_PASSES = 4;

const STRINGS = {
	en: {
		docTitle: "Singularity AIDR — Feature Guide",
		guide: "Feature guide",
		description:
			"Singularity AIDR feature guide: AI coding agent security, Browser Guard and AIDR Privacy, control plane and deployment.",
		tagline: "Detection, response and data privacy for AI agents and the people who use them",
		part: "Part",
		contents: "Contents",
		audience:
			"For security leaders, security engineers, IT administrators and procurement teams.",
		footer: "Singularity AIDR · Feature guide",
		edition: (date) => `Edition ${date}`,
	},
	tr: {
		docTitle: "Singularity AIDR — Özellik Rehberi",
		guide: "Özellik rehberi",
		description:
			"Singularity AIDR özellik rehberi: yapay zekâ kodlama ajanı güvenliği, Browser Guard ve AIDR Privacy, kontrol düzlemi ve dağıtım.",
		tagline: "Yapay zekâ ajanları ve çalışanlarınız için tespit, müdahale ve veri gizliliği",
		part: "Kısım",
		contents: "İçindekiler",
		audience:
			"Güvenlik yöneticileri, güvenlik mühendisleri, BT yöneticileri ve satın alma ekipleri için.",
		footer: "Singularity AIDR · Özellik rehberi",
		edition: (date) => `Sürüm tarihi ${date}`,
	},
};

// ---------------------------------------------------------------------------------------
// Markdown → HTML
// ---------------------------------------------------------------------------------------

export function escapeHtml(text) {
	return text
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;");
}

/** The visible text of an inline Markdown string (what GitHub slugs a heading from). */
export function plainText(markdown) {
	return markdown
		.replace(/`+([^`]*?)`+/g, "$1")
		.replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1")
		.replace(/(\*\*|__)(.+?)\1/g, "$2")
		.replace(/(^|[^\w*])\*(?!\s)([^*]+?)\*(?!\w)/g, "$1$2")
		.replace(/(^|[^\w])_(?!\s)([^_]+?)_(?!\w)/g, "$1$2")
		.replace(/\\([\\`*_{}[\]()#+\-.!|<>~])/g, "$1")
		.trim();
}

/** GitHub heading slug: lower case, punctuation removed, spaces become hyphens. */
export function slugify(text) {
	return plainText(text)
		.toLowerCase()
		.replace(/[^\p{L}\p{M}\p{N}\p{Pc} -]/gu, "")
		.replace(/ /g, "-");
}

/** Assigns unique slugs the way GitHub does (`name`, `name-1`, `name-2`, ...). */
export class Slugger {
	#seen = new Map();

	slug(text) {
		const base = slugify(text);
		let candidate = base;
		while (this.#seen.has(candidate)) {
			const next = this.#seen.get(base) + 1;
			this.#seen.set(base, next);
			candidate = `${base}-${next}`;
		}
		this.#seen.set(candidate, 0);
		return candidate;
	}
}

const FENCE = /^( {0,3})(`{3,}|~{3,})\s*([^`\s]*)[^`]*$/;
const HEADING = /^ {0,3}(#{1,6})[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*$/;
const RULE = /^ {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*$/;
const QUOTE = /^ {0,3}>/;
const LIST_ITEM = /^( {0,3})([-*+]|\d{1,9}[.)])([ \t]+|$)/;
const TABLE_SEPARATOR = /^ {0,3}\|?[ \t]*:?-+:?[ \t]*(\|[ \t]*:?-+:?[ \t]*)*\|?[ \t]*$/;

const isBlank = (line) => line.trim() === "";
const indentOf = (line) => line.length - line.trimStart().length;

function isTableStart(lines, index) {
	return (
		lines[index].includes("|") &&
		index + 1 < lines.length &&
		lines[index + 1].includes("|") &&
		TABLE_SEPARATOR.test(lines[index + 1])
	);
}

function startsBlock(lines, index) {
	const line = lines[index];
	return (
		FENCE.test(line) ||
		HEADING.test(line) ||
		RULE.test(line) ||
		QUOTE.test(line) ||
		LIST_ITEM.test(line) ||
		isTableStart(lines, index)
	);
}

/**
 * Split a table row on unescaped pipes. Pipes inside a code span stay in the cell (GitHub
 * would split there; the guide's tables contain regexes such as `^(Bash|apply_patch)$`).
 */
export function splitTableRow(row) {
	let text = row.trim();
	if (text.startsWith("|")) text = text.slice(1);
	if (text.endsWith("|") && !text.endsWith("\\|")) text = text.slice(0, -1);
	const cells = [];
	let current = "";
	let codeTicks = 0;
	for (let index = 0; index < text.length; index++) {
		const char = text[index];
		if (char === "\\" && text[index + 1] === "|") {
			current += "\\|";
			index++;
			continue;
		}
		if (char === "`") {
			let run = 1;
			while (text[index + run] === "`") run++;
			if (codeTicks === 0) codeTicks = run;
			else if (codeTicks === run) codeTicks = 0;
			current += "`".repeat(run);
			index += run - 1;
			continue;
		}
		if (char === "|" && codeTicks === 0) {
			cells.push(current.trim());
			current = "";
			continue;
		}
		current += char;
	}
	cells.push(current.trim());
	return cells.map((cell) => cell.replaceAll("\\|", "|"));
}

/**
 * Converts one Markdown document. `resolveLink(href)` decides what a link becomes; it returns
 * `{ kind: "anchor", href }`, `{ kind: "external", href }` or `{ kind: "reference", path }`.
 */
export class MarkdownRenderer {
	constructor({ idPrefix = "", resolveLink = (href) => ({ kind: "external", href }) } = {}) {
		this.idPrefix = idPrefix;
		this.resolveLink = resolveLink;
		this.slugger = new Slugger();
		/** Every heading in document order: `{ level, text, html, slug, id }`. */
		this.headings = [];
		/** In-document anchors this document links to (for the unresolved-anchor check). */
		this.anchorsUsed = new Set();
	}

	render(markdown) {
		const lines = markdown.replace(/\r\n?/g, "\n").replace(/\t/g, "    ").split("\n");
		return this.blocks(lines);
	}

	blocks(lines) {
		const out = [];
		let index = 0;
		while (index < lines.length) {
			const line = lines[index];
			if (isBlank(line)) {
				index++;
				continue;
			}
			const fence = FENCE.exec(line);
			if (fence) {
				index = this.fencedCode(lines, index, fence, out);
				continue;
			}
			const heading = HEADING.exec(line);
			if (heading) {
				out.push(this.heading(heading[1].length, heading[2]));
				index++;
				continue;
			}
			if (RULE.test(line)) {
				out.push("<hr>");
				index++;
				continue;
			}
			if (QUOTE.test(line)) {
				const quoted = [];
				while (index < lines.length && QUOTE.test(lines[index])) {
					quoted.push(lines[index].replace(/^ {0,3}> ?/, ""));
					index++;
				}
				out.push(`<blockquote>${this.blocks(quoted)}</blockquote>`);
				continue;
			}
			if (isTableStart(lines, index)) {
				index = this.table(lines, index, out);
				continue;
			}
			if (LIST_ITEM.test(line)) {
				index = this.list(lines, index, out);
				continue;
			}
			const paragraph = [line.trim()];
			index++;
			while (index < lines.length && !isBlank(lines[index]) && !startsBlock(lines, index)) {
				paragraph.push(lines[index].trim());
				index++;
			}
			// A bold-only first line ("**How it works**" followed by text) is a run-in label.
			if (/^\*\*[^*]+\*\*:?$/.test(paragraph[0])) {
				out.push(`<p class="label">${this.inline(paragraph.shift())}</p>`);
			}
			if (paragraph.length > 0) out.push(`<p>${this.inline(paragraph.join("\n"))}</p>`);
		}
		return out.join("\n");
	}

	fencedCode(lines, start, fence, out) {
		const [, fenceIndent, marker, language] = fence;
		const closing = new RegExp(`^ {0,3}${marker[0] === "`" ? "`" : "~"}{${marker.length},}[ \\t]*$`);
		const code = [];
		let index = start + 1;
		while (index < lines.length && !closing.test(lines[index])) {
			const line = lines[index];
			const strip = Math.min(fenceIndent.length, indentOf(line));
			code.push(line.slice(strip));
			index++;
		}
		const lang = language.toLowerCase();
		const langAttr = lang ? ` data-lang="${escapeHtml(lang)}"` : "";
		out.push(`<pre${langAttr}><code>${highlight(code.join("\n"), lang)}</code></pre>`);
		return index + 1;
	}

	heading(level, source) {
		const text = plainText(source);
		const slug = this.slugger.slug(source);
		const id = `${this.idPrefix}${slug}`;
		const html = this.inline(source);
		this.headings.push({ level, text, html, slug, id });
		return `<h${level} id="${escapeHtml(id)}">${html}</h${level}>`;
	}

	table(lines, start, out) {
		const header = splitTableRow(lines[start]);
		const aligns = splitTableRow(lines[start + 1]).map((cell) => {
			const left = cell.startsWith(":");
			const right = cell.endsWith(":");
			if (left && right) return "center";
			if (right) return "right";
			return "";
		});
		const rows = [];
		let index = start + 2;
		while (index < lines.length && !isBlank(lines[index]) && lines[index].includes("|")) {
			rows.push(splitTableRow(lines[index]));
			index++;
		}
		const cell = (tag, content, column) => {
			const align = aligns[column] ? ` style="text-align:${aligns[column]}"` : "";
			return `<${tag}${align}>${this.inline(content ?? "")}</${tag}>`;
		};
		const width = header.length;
		const classes = width >= 5 ? ' class="wide"' : width >= 4 ? ' class="medium"' : "";
		// A header row with no text (`| | |`) is layout only; do not print an empty bar.
		const head = header.every((text) => text === "")
			? ""
			: `<thead><tr>${header.map((text, column) => cell("th", text, column)).join("")}</tr></thead>`;
		const body = rows
			.map(
				(row) =>
					`<tr>${Array.from({ length: width }, (_, column) => cell("td", row[column], column)).join("")}</tr>`,
			)
			.join("\n");
		out.push(`<div class="table"><table${classes}>${head}<tbody>${body}</tbody></table></div>`);
		return index;
	}

	list(lines, start, out) {
		const first = LIST_ITEM.exec(lines[start]);
		const ordered = /\d/.test(first[2]);
		const items = [];
		let loose = false;
		let index = start;
		while (index < lines.length) {
			const match = LIST_ITEM.exec(lines[index]);
			if (!match || /\d/.test(match[2]) !== ordered) break;
			const spacing = match[3].length;
			const contentIndent =
				match[1].length + match[2].length + (spacing >= 1 && spacing <= 4 ? spacing : 1);
			const itemLines = [lines[index].slice(Math.min(contentIndent, lines[index].length))];
			index++;
			while (index < lines.length) {
				const line = lines[index];
				if (isBlank(line)) {
					let next = index;
					while (next < lines.length && isBlank(lines[next])) next++;
					if (next < lines.length && indentOf(lines[next]) >= contentIndent) {
						for (let blank = index; blank < next; blank++) itemLines.push("");
						index = next;
						continue;
					}
					break;
				}
				if (indentOf(line) >= contentIndent) {
					itemLines.push(line.slice(contentIndent));
					index++;
					continue;
				}
				// Lazy continuation of the item's last paragraph.
				const previous = itemLines[itemLines.length - 1];
				if (!startsBlock(lines, index) && previous !== undefined && !isBlank(previous)) {
					itemLines.push(line.trim());
					index++;
					continue;
				}
				break;
			}
			items.push(itemLines);
			let next = index;
			while (next < lines.length && isBlank(lines[next])) next++;
			const continues =
				next < lines.length &&
				LIST_ITEM.test(lines[next]) &&
				/\d/.test(LIST_ITEM.exec(lines[next])[2]) === ordered;
			if (!continues) break;
			if (next > index) loose = true;
			index = next;
		}
		const tag = ordered ? "ol" : "ul";
		const startNumber = ordered ? Number.parseInt(first[2], 10) : 1;
		const startAttr = ordered && startNumber !== 1 ? ` start="${startNumber}"` : "";
		const looseAttr = loose ? ' class="loose"' : "";
		const body = items.map((item) => `<li>${this.blocks(item)}</li>`).join("\n");
		out.push(`<${tag}${startAttr}${looseAttr}>\n${body}\n</${tag}>`);
		return index;
	}

	inline(source) {
		const tokens = [];
		const hold = (html) => `\u0000${tokens.push(html) - 1}\u0000`;
		let text = source.replace(/(`+)([\s\S]*?[^`])\1(?!`)/g, (_, _ticks, code) =>
			hold(`<code>${breakableCode(code.replace(/\n/g, " ").replace(/^ (.+) $/, "$1"))}</code>`),
		);
		text = text.replace(/\\([\\`*_{}[\]()#+\-.!|<>~])/g, (_, char) => hold(escapeHtml(char)));
		text = text.replace(/<(https?:\/\/[^\s>]+)>/g, (_, url) =>
			hold(`<a class="ext" href="${escapeHtml(url)}">${escapeHtml(url)}</a>`),
		);
		text = text.replace(
			/\[((?:[^\]\\]|\\.)+)\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g,
			(_, label, href) => hold(this.link(label, href, tokens)),
		);
		text = escapeHtml(text);
		text = emphasis(text);
		text = text.replace(/ {2,}\n/g, "<br>\n");
		return restore(text, tokens);
	}

	link(label, href, tokens) {
		const labelHtml = restore(emphasis(escapeHtml(label)), tokens);
		const target = this.resolveLink(href);
		if (target.kind === "anchor") {
			this.anchorsUsed.add(target.href.slice(1));
			return `<a href="${escapeHtml(target.href)}">${labelHtml}</a>`;
		}
		if (target.kind === "external") {
			return `<a class="ext" href="${escapeHtml(target.href)}">${labelHtml}</a>`;
		}
		const label_ = plainText(restore(label, tokens).replace(/<[^>]+>/g, ""));
		const base = path.posix.basename(target.path.split("#")[0]);
		const file = target.path.split("#")[0];
		if (label_ === base || label_ === `${base}/` || file === label_ || file.endsWith(`/${label_}`)) {
			return `<code class="path">${escapeHtml(target.path)}</code>`;
		}
		return `<span class="xref">${labelHtml}</span> <span class="path">(${escapeHtml(target.path)})</span>`;
	}
}

/**
 * Escape an inline code span and, when it is long, allow line breaks after path and
 * identifier separators. Table columns are then sized by the separated pieces instead of
 * the whole token, and short identifiers never break mid-word.
 */
export function breakableCode(code) {
	if (code.length <= 18) return escapeHtml(code);
	return code
		.split(/(?<=[/_.:=,&?])(?=.)/)
		.map(escapeHtml)
		.join("<wbr>");
}

function emphasis(html) {
	return html
		.replace(/\*\*(?!\s)([\s\S]+?)(?<!\s)\*\*/g, "<strong>$1</strong>")
		.replace(/(^|[^\w])__(?!\s)([\s\S]+?)(?<!\s)__(?!\w)/g, "$1<strong>$2</strong>")
		.replace(/(^|[^\w*])\*(?![\s*])([^*]+?)(?<!\s)\*(?!\w)/g, "$1<em>$2</em>")
		.replace(/(^|[^\w])_(?![\s_])([^_]+?)(?<!\s)_(?!\w)/g, "$1<em>$2</em>");
}

function restore(text, tokens) {
	let result = text;
	// Tokens can nest (a code span inside a link label), so resolve until none are left.
	for (let pass = 0; pass < 4 && result.includes("\u0000"); pass++) {
		result = result.replace(/\u0000(\d+)\u0000/g, (_, index) => tokens[Number(index)]);
	}
	return result;
}

/** Minimal highlighting: comments in shell-like languages, keys and strings in JSON. */
export function highlight(code, lang) {
	const escaped = escapeHtml(code);
	if (["sh", "bash", "shell", "powershell", "ps1", "toml", "yaml", "yml"].includes(lang)) {
		return escaped.replace(/(^|\s)(#[^\n]*)/g, '$1<span class="c">$2</span>');
	}
	if (lang === "json" || lang === "jsonc") {
		return escaped.replace(
			/(&quot;(?:[^&\n]|&(?!quot;))*?&quot;)(\s*:)?/g,
			(_, string, colon) =>
				colon ? `<span class="k">${string}</span>${colon}` : `<span class="s">${string}</span>`,
		);
	}
	return escaped;
}

// ---------------------------------------------------------------------------------------
// Assembling the guide
// ---------------------------------------------------------------------------------------

export function chapterFiles(lang) {
	return readdirSync(path.join(featuresDir, lang))
		.filter((name) => CHAPTER_FILE.test(name))
		.sort();
}

/** Drop the chapter's own "Contents" section; the guide has one table of contents. */
export function stripLocalContents(markdown) {
	const lines = markdown.split("\n");
	const start = lines.findIndex((line) => /^##\s+(Contents|İçindekiler)\s*$/i.test(line));
	if (start < 0) return markdown;
	let end = start + 1;
	while (end < lines.length && !/^##\s/.test(lines[end]) && !RULE.test(lines[end])) end++;
	if (end < lines.length && RULE.test(lines[end])) end++;
	return [...lines.slice(0, start), ...lines.slice(end)].join("\n");
}

/** "Feature guide 2: AIDR Browser Guard and AIDR Privacy" → "AIDR Browser Guard and AIDR Privacy". */
export function shortTitle(title, lang) {
	const locale = lang === "tr" ? "tr-TR" : "en-US";
	const trimmed = title
		.replace(
			/^(?:Singularity AIDR\s+)?(?:feature guide|özellik rehberi)(?:,?\s*(?:part|bölüm|kısım))?\s*\d+\s*:\s*/i,
			"",
		)
		.replace(/\s+[—–-]\s+(?:feature guide|özellik rehberi)\s*$/i, "")
		.trim();
	if (!trimmed) return title;
	return trimmed.charAt(0).toLocaleUpperCase(locale) + trimmed.slice(1);
}

function editionDate(lang) {
	try {
		const date = execFileSync("git", ["log", "-1", "--format=%cs", "--", `docs/product/features/${lang}`], {
			cwd: repositoryRoot,
			encoding: "utf8",
		}).trim();
		if (/^\d{4}-\d{2}-\d{2}$/.test(date)) return date;
	} catch {
		// Not a git checkout; fall back to today.
	}
	return new Date().toISOString().slice(0, 10);
}

/**
 * Build the complete guide for one language. `pageNumbers` maps heading ids to PDF pages;
 * without it the table of contents gets same-width placeholders.
 */
export function buildGuide(lang, { pageNumbers = null, date = editionDate(lang) } = {}) {
	const strings = STRINGS[lang];
	const files = chapterFiles(lang);
	if (files.length === 0) throw new Error(`No chapters found in docs/product/features/${lang}`);
	const chapterIndex = new Map(files.map((name, index) => [path.join(featuresDir, lang, name), index + 1]));
	const chapters = [];
	const problems = [];

	for (const [index, name] of files.entries()) {
		const number = index + 1;
		const sourcePath = path.join(featuresDir, lang, name);
		const sourceDir = path.dirname(sourcePath);
		const prefix = `p${number}-`;
		const resolveLink = (href) => {
			if (/^(https?:|mailto:)/i.test(href)) return { kind: "external", href };
			if (href.startsWith("#")) return { kind: "anchor", href: `#${prefix}${decodeURIComponent(href.slice(1))}` };
			const [file, anchor] = href.split("#");
			const resolved = path.resolve(sourceDir, decodeURIComponent(file));
			const target = chapterIndex.get(resolved);
			if (target) {
				const id = anchor ? `p${target}-${decodeURIComponent(anchor)}` : `part-${target}`;
				return { kind: "anchor", href: `#${id}` };
			}
			const relative = path.relative(repositoryRoot, resolved).split(path.sep).join("/");
			return { kind: "reference", path: anchor ? `${relative}#${anchor}` : relative };
		};
		const renderer = new MarkdownRenderer({ idPrefix: prefix, resolveLink });
		const markdown = stripLocalContents(readFileSync(sourcePath, "utf8"));
		let body = renderer.render(markdown);
		const titleHeading = renderer.headings.find((heading) => heading.level === 1);
		const title = titleHeading?.text ?? name;
		// The chapter title is shown in the chapter opener; drop the duplicate <h1>.
		if (titleHeading) {
			body = body.replace(new RegExp(`<h1 id="${escapeRegExp(escapeHtml(titleHeading.id))}">[\\s\\S]*?</h1>\\n?`), "");
		}
		chapters.push({ number, name, title, short: shortTitle(title, lang), body, renderer, titleHeading });
	}

	const ids = new Set();
	for (const chapter of chapters) {
		ids.add(`part-${chapter.number}`);
		for (const heading of chapter.renderer.headings) ids.add(heading.id);
	}
	for (const chapter of chapters) {
		for (const anchor of chapter.renderer.anchorsUsed) {
			if (!ids.has(anchor)) problems.push(`${lang}/${chapter.name}: link target #${anchor.replace(/^p\d+-/, "")} does not exist`);
		}
	}

	const pageOf = (id) => {
		const page = pageNumbers?.get(id);
		return page === undefined ? "000" : String(page);
	};
	const tocEntry = (level, id, html, extra = "") =>
		`<li class="toc-${level}"><a href="#${escapeHtml(id)}">${extra}<span class="toc-text">${html}</span><span class="toc-leader"></span><span class="toc-page">${pageOf(id)}</span></a></li>`;
	const toc = chapters
		.map((chapter) => {
			const rows = [
				tocEntry(
					"part",
					`part-${chapter.number}`,
					escapeHtml(chapter.short),
					`<span class="toc-num">${String(chapter.number).padStart(2, "0")}</span>`,
				),
			];
			for (const heading of chapter.renderer.headings) {
				if (heading === chapter.titleHeading) continue;
				if (heading.level <= 3) {
					rows.push(tocEntry(`h${heading.level}`, heading.id, stripLinks(heading.html)));
				}
			}
			return rows.join("\n");
		})
		.join("\n");

	const logoSvg = readFileSync(logoPath, "utf8")
		.replace(/<\?xml[^>]*>\s*/, "")
		.replace(/^<svg\b[^>]*>/, "")
		.replace(/<\/svg>\s*$/, "");
	const partsCards = chapters
		.map(
			(chapter) =>
				`<a class="cover-part" href="#part-${chapter.number}"><span class="n">${strings.part} ${chapter.number}</span><span class="t">${escapeHtml(chapter.short)}</span></a>`,
		)
		.join("\n");
	const chaptersHtml = chapters
		.map(
			(chapter) => `<section class="chapter" aria-labelledby="part-${chapter.number}">
<header class="chapter-head">
<div class="chapter-kicker"><span class="chapter-num">${String(chapter.number).padStart(2, "0")}</span>${strings.part} ${chapter.number} / ${chapters.length} · ${strings.guide}</div>
<h1 id="part-${chapter.number}">${escapeHtml(chapter.short)}</h1>
${chapter.titleHeading ? `<span id="${escapeHtml(chapter.titleHeading.id)}" class="anchor"></span>` : ""}
</header>
${chapter.body}
</section>`,
		)
		.join("\n\n");

	const html = `<!doctype html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(strings.docTitle)}</title>
<meta name="description" content="${escapeHtml(strings.description)}">
<meta name="generator" content="scripts/render-feature-guide.mjs from docs/product/features/${lang}/*.md">
<style>
${styles(strings)}
</style>
</head>
<body>
<section class="cover" aria-label="Cover">
<svg class="sprite" aria-hidden="true"><symbol id="aidr-logo" viewBox="0 0 2400 3100">${logoSvg}</symbol></svg>
<div class="cover-top"><span class="co" lang="en"><svg aria-hidden="true"><use href="#aidr-logo"/></svg>SingularityRD</span><span>${escapeHtml(strings.guide)} · ${escapeHtml(strings.edition(date))}</span></div>
<div class="cover-hero">
<svg class="cover-logo" role="img" aria-label="Singularity AIDR logo"><use href="#aidr-logo"/></svg>
<div class="eyebrow" lang="en">AI Agent Detection &amp; Response</div>
<div class="cover-title">Singularity <span>AIDR</span></div>
<div class="cover-sub">${escapeHtml(strings.guide)}</div>
<p class="tagline">${escapeHtml(strings.tagline)}</p>
<div class="rule"></div>
</div>
<nav class="cover-parts">${partsCards}</nav>
<div class="cover-foot"><span>${escapeHtml(strings.audience)}</span><span><b>singularityrd.com</b></span></div>
</section>

<nav class="toc" aria-labelledby="toc-title">
<h2 id="toc-title" class="toc-title">${escapeHtml(strings.contents)}</h2>
<ol class="toc-list">
${toc}
</ol>
</nav>

<main>
${chaptersHtml}
</main>
</body>
</html>
`;
	const headingIds = chapters.flatMap((chapter) => [
		`part-${chapter.number}`,
		...chapter.renderer.headings
			.filter((heading) => heading.level <= 3 && heading !== chapter.titleHeading)
			.map((heading) => heading.id),
	]);
	return { html, problems, chapters, headingIds };
}

function stripLinks(html) {
	return html.replace(/<a\b[^>]*>([\s\S]*?)<\/a>/g, "$1");
}

function escapeRegExp(text) {
	return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function styles(strings) {
	const footer = strings.footer.replaceAll('"', '\\"');
	return `@page {
	size: A4;
	margin: 17mm 17mm 19mm;
	@bottom-left {
		content: "${footer}";
		font-family: "Inter", "Segoe UI", "Helvetica Neue", Helvetica, "Liberation Sans", Arial, "DejaVu Sans", sans-serif;
		font-size: 7pt;
		color: #8a91a3;
		vertical-align: top;
		padding-top: 5mm;
	}
	@bottom-right {
		content: counter(page) " / " counter(pages);
		font-family: "Inter", "Segoe UI", "Helvetica Neue", Helvetica, "Liberation Sans", Arial, "DejaVu Sans", sans-serif;
		font-size: 7pt;
		font-weight: 700;
		color: #2448bb;
		vertical-align: top;
		padding-top: 5mm;
	}
}
@page :first {
	margin: 0;
	@bottom-left { content: none; }
	@bottom-right { content: none; }
}
:root {
	--accent: #3862e8;
	--accent-deep: #2448bb;
	--accent-soft: #8fa9f5;
	--ink: #0a0a0a;
	--text: #1c2130;
	--muted: #586074;
	--faint: #8a91a3;
	--line: #e2e6ef;
	--tint: #f3f6fe;
	--tint-2: #e8eefd;
	--code-bg: #f6f8fc;
	--sans: "Inter", "Segoe UI", "Helvetica Neue", Helvetica, "Liberation Sans", Arial, "DejaVu Sans", sans-serif;
	--mono: "JetBrains Mono", "SFMono-Regular", Menlo, Consolas, "Liberation Mono", "DejaVu Sans Mono", monospace;
}
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; background: #d9dee8; }
body {
	margin: 0 auto;
	max-width: 210mm;
	padding: 0 17mm 17mm;
	background: #fff;
	color: var(--text);
	font-family: var(--sans);
	font-size: 9.2pt;
	line-height: 1.5;
	-webkit-font-smoothing: antialiased;
	text-rendering: optimizeLegibility;
	font-kerning: normal;
	orphans: 3;
	widows: 3;
}
@media print {
	html { background: #fff; }
	body { max-width: none; padding: 0; }
}
.sprite { position: absolute; width: 0; height: 0; overflow: hidden; }
a { color: var(--accent-deep); text-decoration: none; }
a.ext { text-decoration: underline; text-decoration-color: var(--accent-soft); text-underline-offset: 0.4mm; overflow-wrap: anywhere; }

/* ---------- cover ---------- */
.cover {
	position: relative;
	display: flex;
	flex-direction: column;
	height: 296.5mm;
	margin: 0 -17mm;
	padding: 14mm 16mm 13mm;
	overflow: hidden;
	break-after: page;
	color: #fff;
	background:
		radial-gradient(120mm 110mm at 50% 34%, rgba(56, 98, 232, 0.34), rgba(56, 98, 232, 0) 70%),
		radial-gradient(160mm 90mm at 50% 112%, rgba(36, 72, 187, 0.35), rgba(36, 72, 187, 0) 70%),
		#0a0a0a;
}
@media print { .cover { margin: 0; width: 210mm; } }
.cover a { color: inherit; }
.cover-top { display: flex; justify-content: space-between; align-items: center; font-size: 7.6pt; letter-spacing: 0.16em; text-transform: uppercase; color: rgba(255, 255, 255, 0.62); }
.cover-top .co { display: flex; align-items: center; gap: 2.4mm; color: #fff; font-weight: 700; letter-spacing: 0.12em; }
.cover-top .co svg { width: 4.2mm; height: 5.4mm; }
.cover-hero { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; }
.cover-logo { width: 46mm; height: 59.4mm; filter: drop-shadow(0 6mm 14mm rgba(56, 98, 232, 0.45)); }
.cover .eyebrow { margin-top: 10mm; font-size: 8.4pt; font-weight: 700; letter-spacing: 0.3em; text-transform: uppercase; color: var(--accent-soft); }
.cover-title { margin-top: 3mm; font-size: 42pt; line-height: 1.02; font-weight: 800; letter-spacing: -0.035em; }
.cover-title span { color: var(--accent-soft); }
.cover-sub { margin-top: 4mm; font-size: 20pt; font-weight: 300; letter-spacing: -0.01em; color: #fff; }
.cover .tagline { text-wrap: balance; margin: 5mm 0 0; max-width: 150mm; font-size: 12.5pt; line-height: 1.4; color: rgba(255, 255, 255, 0.78); }
.cover .rule { width: 18mm; height: 0.8mm; border-radius: 1mm; background: var(--accent); margin: 8mm auto 0; }
.cover-parts { display: grid; grid-template-columns: repeat(3, 1fr); gap: 4mm; }
.cover-part { display: flex; flex-direction: column; gap: 2mm; padding: 5mm 4.6mm; border-radius: 3mm; background: rgba(255, 255, 255, 0.045); border: 0.3mm solid rgba(255, 255, 255, 0.14); }
.cover-part .n { font-size: 7pt; font-weight: 700; letter-spacing: 0.16em; text-transform: uppercase; color: var(--accent-soft); }
.cover-part .t { font-size: 10.5pt; line-height: 1.3; font-weight: 700; color: #fff; text-wrap: balance; }
.cover-foot { display: flex; justify-content: space-between; align-items: center; gap: 6mm; margin-top: 7mm; padding-top: 4mm; border-top: 0.3mm solid rgba(255, 255, 255, 0.14); font-size: 7.6pt; color: rgba(255, 255, 255, 0.6); }
.cover-foot b { color: #fff; font-weight: 600; }

/* ---------- table of contents ---------- */
.toc { break-after: page; padding-top: 6mm; }
.toc-title { margin: 0 0 6mm; padding: 0; border: 0; font-size: 24pt; font-weight: 800; letter-spacing: -0.02em; color: var(--ink); }
.toc-list { list-style: none; margin: 0; padding: 0; }
.toc-list li { break-inside: avoid; }
.toc-list a { display: flex; align-items: baseline; color: inherit; }
.toc-text { min-width: 0; }
.toc-leader { flex: 1; min-width: 6mm; margin: 0 2mm; border-bottom: 0.3mm dotted #b9c0d0; transform: translateY(-0.9mm); }
.toc-page { flex: none; min-width: 7mm; text-align: right; font-variant-numeric: tabular-nums; color: var(--muted); }
.toc-part { margin-top: 5mm; break-after: avoid; }
.toc-part:first-child { margin-top: 0; }
.toc-part a { padding: 2.2mm 0 1.8mm; border-top: 0.6mm solid var(--accent); font-size: 12pt; font-weight: 800; color: var(--ink); }
.toc-part .toc-num { flex: none; margin-right: 3mm; color: var(--accent); font-variant-numeric: tabular-nums; }
.toc-part .toc-page { color: var(--accent-deep); font-weight: 800; }
.toc-h1 a { padding: 2.6mm 0 0.4mm; font-size: 8pt; font-weight: 800; letter-spacing: 0.1em; text-transform: uppercase; color: var(--accent-deep); }
.toc-h1 .toc-page { color: var(--accent-deep); font-weight: 800; }
.toc-h2 a { padding: 1.3mm 0 0.3mm; font-size: 9.2pt; font-weight: 700; color: var(--ink); }
.toc-h3 a { padding: 0.35mm 0 0 5mm; font-size: 8.4pt; color: var(--text); }
.toc-h3 .toc-page { font-size: 8pt; }
.toc code { font-size: 0.9em; background: none; padding: 0; color: inherit; }

/* ---------- chapters ---------- */
.chapter { break-before: page; }
.chapter-head { margin: 0 0 7mm; padding: 6mm 0 5mm; border-bottom: 0.3mm solid var(--line); }
.chapter-kicker { display: flex; align-items: center; gap: 2.5mm; font-size: 7.6pt; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase; color: var(--accent-deep); }
.chapter-num { display: inline-grid; place-items: center; width: 8mm; height: 8mm; border-radius: 2mm; background: var(--accent); color: #fff; letter-spacing: 0; font-size: 9pt; }
.chapter-head h1 { margin: 4mm 0 0; font-size: 26pt; line-height: 1.12; font-weight: 800; letter-spacing: -0.025em; color: var(--ink); text-wrap: balance; }
.anchor { display: block; height: 0; }
h2, h3, h4, h5, h6 { color: var(--ink); break-after: avoid; page-break-after: avoid; break-inside: avoid; text-wrap: balance; }
.chapter > h1 { margin: 10mm 0 4mm; padding: 3.5mm 4mm; border-radius: 1.5mm; background: var(--ink); color: #fff; font-size: 14pt; line-height: 1.2; font-weight: 800; letter-spacing: -0.01em; break-after: avoid; }
.chapter > h1 + h2 { margin-top: 4mm; border-top: 0; padding-top: 0; }
h2 { margin: 9mm 0 3.5mm; padding-top: 3mm; border-top: 0.6mm solid var(--accent); font-size: 15pt; line-height: 1.2; font-weight: 800; letter-spacing: -0.015em; }
h3 { margin: 7mm 0 2.5mm; padding-left: 2.6mm; border-left: 0.9mm solid var(--accent); font-size: 11.6pt; line-height: 1.25; font-weight: 800; }
h4 { margin: 5mm 0 2mm; font-size: 10pt; font-weight: 700; }
h2 code, h3 code, h4 code { font-size: 0.9em; }
hr + h2, .chapter-head + h2 { margin-top: 4mm; }
p { margin: 0 0 2.4mm; text-wrap: pretty; }
p > strong:first-child { color: var(--ink); }
p.label { margin: 3.2mm 0 1mm; break-after: avoid; }
p.label strong { color: var(--accent-deep); }
strong { font-weight: 700; color: var(--ink); }
hr { border: 0; border-top: 0.3mm solid var(--line); margin: 6mm 0; }
hr:has(+ h1, + h2), hr:last-child { display: none; }
ul, ol { margin: 0 0 2.6mm; padding-left: 5.5mm; }
li { margin: 0.6mm 0; }
li::marker { color: var(--accent); font-weight: 700; }
li > p { margin: 0; }
ul.loose > li, ol.loose > li { margin: 1.4mm 0; }
li > p + *, li > * + p { margin-top: 1.4mm; }
li > ul, li > ol { margin: 0.8mm 0 0.8mm; }
code {
	font-family: var(--mono);
	font-size: 0.86em;
	padding: 0.1mm 0.7mm;
	border-radius: 0.8mm;
	background: var(--tint);
	color: #1f3a9e;
	overflow-wrap: anywhere;
}
code.path { color: var(--muted); background: #f1f2f5; }
.path { font-family: var(--mono); font-size: 0.78em; color: var(--faint); overflow-wrap: anywhere; }
pre {
	position: relative;
	margin: 1.6mm 0 3.2mm;
	padding: 2.6mm 3.2mm;
	border: 0.25mm solid var(--line);
	border-left: 0.9mm solid var(--accent);
	border-radius: 1.2mm;
	background: var(--code-bg);
	font-size: 7.3pt;
	line-height: 1.5;
	white-space: pre-wrap;
	overflow-wrap: anywhere;
}
pre code { padding: 0; background: none; color: #1c2130; font-size: 1em; }
pre[data-lang]::before {
	content: attr(data-lang);
	float: right;
	margin: -1.2mm -1.6mm 0 3mm;
	font-family: var(--sans);
	font-size: 6pt;
	font-weight: 700;
	letter-spacing: 0.12em;
	text-transform: uppercase;
	color: var(--faint);
}
pre .c { color: #6b7385; font-style: italic; }
pre .k { color: #2448bb; }
pre .s { color: #177a4f; }
blockquote {
	margin: 2mm 0 3.6mm;
	padding: 3mm 4mm;
	border-left: 1mm solid var(--accent);
	border-radius: 0 1.5mm 1.5mm 0;
	background: var(--tint);
	break-inside: avoid;
}
blockquote > :last-child { margin-bottom: 0; }
blockquote code { background: #fff; }
.table { margin: 2mm 0 4mm; }
table { width: 100%; border-collapse: collapse; font-size: 7.8pt; line-height: 1.4; }
table.medium { font-size: 7.4pt; }
table.wide { font-size: 7pt; }
thead { display: table-header-group; }
th {
	padding: 1.6mm 1.8mm;
	background: var(--tint-2);
	border-bottom: 0.4mm solid var(--accent);
	text-align: left;
	vertical-align: bottom;
	font-weight: 700;
	color: var(--ink);
}
td { padding: 1.4mm 1.8mm; border-bottom: 0.25mm solid var(--line); vertical-align: top; overflow-wrap: break-word; }
tbody tr:nth-child(even) td { background: #fafbfe; }
tr { break-inside: avoid; }
td code, th code { font-size: 0.92em; overflow-wrap: break-word; }
`;
}

// ---------------------------------------------------------------------------------------
// PDF helpers
// ---------------------------------------------------------------------------------------

/** Count page objects in a PDF produced by Chromium (pages are never inside object streams there). */
export function countPdfPages(buffer) {
	return (buffer.toString("latin1").match(/\/Type\s*\/Page(?![s\w])/g) ?? []).length;
}

function decodePdfName(name) {
	const bytes = [];
	for (let index = 0; index < name.length; index++) {
		if (name[index] === "#" && /^[0-9a-f]{2}$/i.test(name.slice(index + 1, index + 3))) {
			bytes.push(Number.parseInt(name.slice(index + 1, index + 3), 16));
			index += 2;
		} else bytes.push(name.charCodeAt(index));
	}
	const text = Buffer.from(bytes).toString("utf8");
	// Chromium percent-encodes non-ASCII fragment ids before writing them as PDF names.
	try {
		return decodeURIComponent(text);
	} catch {
		return text;
	}
}

/**
 * Map each named destination in a Chromium PDF to its 1-based page number. Chromium writes a
 * `/Dests` dictionary in the catalog for every in-document link target, with plain
 * (uncompressed) page and destination objects.
 */
export function pdfDestinationPages(buffer) {
	const source = buffer.toString("latin1");
	const objects = new Map();
	for (const match of source.matchAll(/(?:^|\s)(\d+) 0 obj\b([\s\S]*?)\bendobj/g)) {
		objects.set(Number(match[1]), match[2]);
	}
	const catalog = [...objects.values()].find((body) => /\/Type\s*\/Catalog\b/.test(body));
	if (!catalog) throw new Error("PDF catalog not found");
	const pagesRef = /\/Pages\s+(\d+) 0 R/.exec(catalog);
	if (!pagesRef) throw new Error("PDF page tree not found");
	const order = [];
	const walk = (number, depth) => {
		const body = objects.get(number);
		if (!body || depth > 32) return;
		if (/\/Type\s*\/Pages\b/.test(body)) {
			const kids = /\/Kids\s*\[([^\]]*)\]/.exec(body);
			for (const kid of kids?.[1].matchAll(/(\d+) 0 R/g) ?? []) walk(Number(kid[1]), depth + 1);
		} else if (/\/Type\s*\/Page\b/.test(body)) {
			order.push(number);
		}
	};
	walk(Number(pagesRef[1]), 0);
	const pageIndex = new Map(order.map((number, index) => [number, index + 1]));
	const destsRef = /\/Dests\s+(\d+) 0 R/.exec(catalog);
	const dests = destsRef ? objects.get(Number(destsRef[1])) : /\/Dests\s*(<<[\s\S]*?>>)/.exec(catalog)?.[1];
	const result = new Map();
	for (const match of (dests ?? "").matchAll(/\/([^\s/[\]<>()]+)\s*\[\s*(\d+) 0 R/g)) {
		const page = pageIndex.get(Number(match[2]));
		if (page !== undefined) result.set(decodePdfName(match[1]), page);
	}
	return { pages: order.length, destinations: result };
}

// ---------------------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------------------

/** Runs in the page (print media, viewport = A4 content width): returns layout problems. */
export function inspectLayout(limit) {
	const problems = [];
	const seen = new Set();
	const describe = (element) => {
		const heading = (() => {
			let node = element;
			while (node && node !== document.body) {
				let sibling = node.previousElementSibling;
				while (sibling) {
					if (/^H[1-4]$/.test(sibling.tagName)) return sibling.textContent.trim().slice(0, 60);
					sibling = sibling.previousElementSibling;
				}
				node = node.parentElement;
			}
			return "?";
		})();
		return `<${element.tagName.toLowerCase()}> after "${heading}"`;
	};
	const add = (message) => {
		if (seen.has(message)) return;
		seen.add(message);
		problems.push(message);
	};
	for (const element of document.querySelectorAll("main *, .toc *")) {
		const rect = element.getBoundingClientRect();
		if (rect.width === 0 && rect.height === 0) continue;
		if (rect.right > limit + 0.5) add(`${describe(element)} extends ${Math.round(rect.right - limit)}px past the right margin`);
		if (element.matches("pre, table, td, th, .table") && element.scrollWidth > element.clientWidth + 1) {
			add(`${describe(element)} overflows its box horizontally`);
		}
	}
	const ids = new Set([...document.querySelectorAll("[id]")].map((node) => node.id));
	for (const link of document.querySelectorAll('a[href^="#"]')) {
		const id = decodeURIComponent(link.getAttribute("href").slice(1));
		if (!ids.has(id)) add(`link target #${id} is missing`);
	}
	return problems;
}

export async function renderGuide(lang, { chromium, check = false, force = false } = {}) {
	const browser = await launchRenderBrowser(chromium);
	try {
		const context = await browser.newContext({ viewport: { width: CONTENT_WIDTH_PX, height: 1000 } });
		const page = await context.newPage();
		const blocked = [];
		await page.route("**/*", (route) => {
			const url = route.request().url();
			if (url.startsWith("data:") || url === "about:blank") return route.continue();
			blocked.push(url);
			return route.abort();
		});
		await page.emulateMedia({ media: "print" });

		const date = editionDate(lang);
		let pageNumbers = null;
		let guide;
		let pdf;
		let stable = false;
		for (let pass = 0; pass < MAX_NUMBERING_PASSES && !stable; pass++) {
			guide = buildGuide(lang, { pageNumbers, date });
			await page.setContent(guide.html, { waitUntil: "load" });
			await page.evaluate(() => document.fonts.ready);
			pdf = await page.pdf({ format: "A4", printBackground: true, preferCSSPageSize: true, outline: true, tagged: true });
			const { destinations } = pdfDestinationPages(pdf);
			stable = pageNumbers !== null && guide.headingIds.every((id) => destinations.get(id) === pageNumbers.get(id));
			pageNumbers = destinations;
		}

		const problems = [...guide.problems];
		// Layout is checked on the final HTML: overflow past the right margin, clipped
		// tables and code, and links whose target does not exist.
		problems.push(...(await page.evaluate(inspectLayout, CONTENT_WIDTH_PX)));
		if (!stable) problems.push(`table-of-contents page numbers did not settle after ${MAX_NUMBERING_PASSES} passes`);
		const missing = guide.headingIds.filter((id) => !pageNumbers.has(id));
		if (missing.length > 0) problems.push(`no PDF destination for: ${missing.slice(0, 5).join(", ")}`);
		if (blocked.length > 0) problems.push(`external requests are not allowed: ${blocked.join(", ")}`);
		const pdfPages = countPdfPages(pdf);
		if (check || (problems.length > 0 && !force)) return { lang, pdfPages, problems, written: [] };

		const base = path.join(featuresDir, `singularity-aidr-feature-guide-${lang}`);
		writeFileSync(`${base}.html`, guide.html);
		writeFileSync(`${base}.pdf`, pdf);
		return { lang, pdfPages, problems, written: [`${base}.html`, `${base}.pdf`] };
	} finally {
		await browser.close();
	}
}

function parseArgs(argv) {
	const args = { langs: LANGUAGES, check: false, force: false };
	for (const arg of argv) {
		if (arg === "--check") args.check = true;
		else if (arg === "--force") args.force = true;
		else if (arg.startsWith("--lang=")) {
			const lang = arg.slice("--lang=".length);
			if (!LANGUAGES.includes(lang)) throw new Error(`Unknown language ${lang}; use ${LANGUAGES.join(" or ")}`);
			args.langs = [lang];
		} else if (arg === "--help" || arg === "-h") {
			console.log("Usage: node scripts/render-feature-guide.mjs [--lang=tr|en] [--check] [--force]");
			process.exit(0);
		} else throw new Error(`Unknown argument: ${arg}`);
	}
	return args;
}

async function main() {
	const args = parseArgs(process.argv.slice(2));
	const chromium = loadChromium();
	let failed = false;
	for (const lang of args.langs) {
		const result = await renderGuide(lang, { chromium, check: args.check, force: args.force });
		if (result.problems.length > 0) {
			failed = true;
			console.error(`feature guide (${lang}): checks FAILED`);
			for (const problem of result.problems) console.error(`  - ${problem}`);
		} else {
			console.log(`feature guide (${lang}): ${result.pdfPages} pages, layout clean`);
		}
		for (const file of result.written) console.log(`  wrote ${path.relative(repositoryRoot, file)}`);
	}
	if (failed) process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	main().catch((error) => {
		console.error(error.message ?? error);
		process.exitCode = 1;
	});
}
