import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
	LANGUAGES,
	MarkdownRenderer,
	Slugger,
	breakableCode,
	buildGuide,
	chapterFiles,
	pdfDestinationPages,
	shortTitle,
	slugify,
	splitTableRow,
	stripLocalContents,
} from "./render-feature-guide.mjs";

describe("slugify", () => {
	it("matches GitHub heading anchors", () => {
		assert.equal(slugify("1. Connectors"), "1-connectors");
		assert.equal(slugify("Verdicts: allow, ask, deny"), "verdicts-allow-ask-deny");
		assert.equal(slugify("CLI (`aidr`) command reference"), "cli-aidr-command-reference");
		assert.equal(slugify("Reputation checks (URL, file, package)"), "reputation-checks-url-file-package");
		assert.equal(slugify("18. Ortak TR/EN kural katmanı"), "18-ortak-tren-kural-katmanı");
		assert.equal(slugify("Kararlar: **allow**, ask"), "kararlar-allow-ask");
		assert.equal(slugify("[Linked](other.md) heading"), "linked-heading");
	});

	it("numbers duplicate headings like GitHub", () => {
		const slugger = new Slugger();
		assert.deepEqual(
			["Limitations", "Limitations", "Limitations", "Limitations-1"].map((text) => slugger.slug(text)),
			["limitations", "limitations-1", "limitations-2", "limitations-1-1"],
		);
	});
});

describe("splitTableRow", () => {
	it("splits on unescaped pipes outside code spans", () => {
		assert.deepEqual(splitTableRow("| a | `^(Bash|apply_patch)$` | c |"), ["a", "`^(Bash|apply_patch)$`", "c"]);
		assert.deepEqual(splitTableRow("| `jsonl\\|csv` | x\\|y |"), ["`jsonl|csv`", "x|y"]);
		assert.deepEqual(splitTableRow("a | b"), ["a", "b"]);
	});
});

describe("breakableCode", () => {
	it("keeps short identifiers whole and escapes HTML", () => {
		assert.equal(breakableCode("DATE_OF_BIRTH"), "DATE_OF_BIRTH");
		assert.equal(breakableCode("<id>"), "&lt;id&gt;");
	});

	it("allows breaks after separators in long tokens", () => {
		assert.equal(breakableCode("packages/core/src/x.ts"), "packages/<wbr>core/<wbr>src/<wbr>x.<wbr>ts");
	});
});

function render(markdown, options) {
	const renderer = new MarkdownRenderer(options);
	return { html: renderer.render(markdown), renderer };
}

describe("MarkdownRenderer", () => {
	it("renders headings with prefixed GitHub ids and records them", () => {
		const { html, renderer } = render("# Title\n\n## 1. Connectors\n\n### Codex CLI connector", {
			idPrefix: "p1-",
		});
		assert.match(html, /<h1 id="p1-title">Title<\/h1>/);
		assert.match(html, /<h2 id="p1-1-connectors">1\. Connectors<\/h2>/);
		assert.deepEqual(
			renderer.headings.map((heading) => [heading.level, heading.id]),
			[
				[1, "p1-title"],
				[2, "p1-1-connectors"],
				[3, "p1-codex-cli-connector"],
			],
		);
	});

	it("renders inline markup and escapes HTML", () => {
		const { html } = render("A **bold** and *em* and `<code>` & _it_ but not snake_case_name.");
		assert.equal(
			html,
			"<p>A <strong>bold</strong> and <em>em</em> and <code>&lt;code&gt;</code> &amp; <em>it</em> but not snake_case_name.</p>",
		);
	});

	it("nests lists and keeps fenced code inside list items", () => {
		const markdown = [
			"1. First step:",
			"   ```bash",
			"   aidr doctor # check",
			"   ```",
			"2. Second step",
			"   - nested **item**",
			"   - another",
			"3. Third",
		].join("\n");
		const { html } = render(markdown);
		assert.match(html, /^<ol>/);
		assert.match(html, /<li><p>First step:<\/p>\n<pre data-lang="bash"><code>aidr doctor <span class="c"># check<\/span><\/code><\/pre><\/li>/);
		assert.match(html, /<ul>\n<li><p>nested <strong>item<\/strong><\/p><\/li>\n<li><p>another<\/p><\/li>\n<\/ul>/);
		assert.equal((html.match(/<li>/g) ?? []).length, 5);
	});

	it("lets a list interrupt a paragraph and starts ordered lists at their number", () => {
		const { html } = render("**How to use.**\n3. Third\n4. Fourth");
		assert.match(html, /<p class="label"><strong>How to use\.<\/strong><\/p>\n<ol start="3">/);
	});

	it("turns a bold-only first line into a run-in label", () => {
		const { html } = render("**What it does**\nThe connector checks calls.");
		assert.equal(html, '<p class="label"><strong>What it does</strong></p>\n<p>The connector checks calls.</p>');
	});

	it("renders GFM tables, alignment and header-less tables", () => {
		const { html } = render("| A | B |\n| --- | ---: |\n| `x|y` | 2 |\n\n| | |\n|---|---|\n| k | v |");
		assert.match(html, /<thead><tr><th>A<\/th><th style="text-align:right">B<\/th><\/tr><\/thead>/);
		assert.match(html, /<td><code>x\|y<\/code><\/td><td style="text-align:right">2<\/td>/);
		assert.match(html, /<table><tbody><tr><td>k<\/td><td>v<\/td><\/tr><\/tbody><\/table>/);
	});

	it("renders blockquotes and rules", () => {
		const { html } = render("> **Note.** one\n> two\n\n---\n\ntext");
		assert.equal(html, "<blockquote><p><strong>Note.</strong> one\ntwo</p></blockquote>\n<hr>\n<p>text</p>");
	});

	it("resolves anchors, external links and repository references", () => {
		const resolveLink = (href) => {
			if (href.startsWith("#")) return { kind: "anchor", href: `#p1-${href.slice(1)}` };
			if (href.startsWith("https:")) return { kind: "external", href };
			return { kind: "reference", path: `docs/${href}` };
		};
		const { html, renderer } = render(
			"See [DLP](#dlp), [site](https://example.com/a), [the guide](guide.md) and [guide.md](guide.md).",
			{ resolveLink },
		);
		assert.match(html, /<a href="#p1-dlp">DLP<\/a>/);
		assert.match(html, /<a class="ext" href="https:\/\/example.com\/a">site<\/a>/);
		assert.match(html, /<span class="xref">the guide<\/span> <span class="path">\(docs\/guide\.md\)<\/span>/);
		assert.match(html, /and <code class="path">docs\/guide\.md<\/code>\./);
		assert.deepEqual([...renderer.anchorsUsed], ["p1-dlp"]);
	});
});

describe("chapter helpers", () => {
	it("removes a chapter's own contents section", () => {
		const markdown = "# T\n\nIntro\n\n## Contents\n\n1. [A](#a)\n\n---\n\n## A\n\nBody";
		assert.equal(stripLocalContents(markdown), "# T\n\nIntro\n\n\n## A\n\nBody");
		assert.equal(stripLocalContents("## İçindekiler\n- x\n## B"), "## B");
	});

	it("shortens the chapter titles for the cover and table of contents", () => {
		assert.equal(shortTitle("Singularity AIDR for AI coding agents — feature guide", "en"), "Singularity AIDR for AI coding agents");
		assert.equal(shortTitle("Feature guide 2: AIDR Browser Guard and AIDR Privacy", "en"), "AIDR Browser Guard and AIDR Privacy");
		assert.equal(shortTitle("Singularity AIDR feature guide, part 3: control plane and deployment", "en"), "Control plane and deployment");
		assert.equal(shortTitle("Singularity AIDR özellik rehberi, bölüm 3: kontrol düzlemi ve dağıtım", "tr"), "Kontrol düzlemi ve dağıtım");
		assert.equal(shortTitle("Özellik rehberi 2: İçerik", "tr"), "İçerik");
		assert.equal(shortTitle("Something else", "en"), "Something else");
	});
});

describe("pdfDestinationPages", () => {
	it("maps named destinations to page numbers through a nested page tree", () => {
		const pdf = Buffer.from(
			[
				"%PDF-1.4",
				"1 0 obj\n<</Type /Catalog\n/Pages 2 0 R\n/Dests 9 0 R>>\nendobj",
				"2 0 obj\n<</Type /Pages\n/Count 3\n/Kids [3 0 R 4 0 R]>>\nendobj",
				"3 0 obj\n<</Type /Page\n/Parent 2 0 R>>\nendobj",
				"4 0 obj\n<</Type /Pages\n/Count 2\n/Kids [5 0 R 6 0 R]>>\nendobj",
				"5 0 obj\n<</Type /Page\n/Parent 4 0 R>>\nendobj",
				"6 0 obj\n<</Type /Page\n/Parent 4 0 R>>\nendobj",
				"9 0 obj\n<</part-1 [3 0 R /XYZ 0 700 0]\n/p1-connector#25C4#25B1 [6 0 R /XYZ 0 400 0]\n/p2-x [5 0 R /XYZ 0 1 0]>>\nendobj",
				"%%EOF",
			].join("\n"),
			"latin1",
		);
		const { pages, destinations } = pdfDestinationPages(pdf);
		assert.equal(pages, 3);
		assert.deepEqual(
			[...destinations],
			[
				["part-1", 1],
				["p1-connectorı", 3],
				["p2-x", 2],
			],
		);
	});
});

describe("buildGuide", () => {
	for (const lang of LANGUAGES) {
		it(`builds a self-contained ${lang} guide whose links all resolve`, () => {
			assert.deepEqual(chapterFiles(lang), chapterFiles("en"), "both languages have the same chapter files");
			const guide = buildGuide(lang, { date: "2026-01-01" });
			assert.deepEqual(guide.problems, []);
			assert.equal(new Set(guide.headingIds).size, guide.headingIds.length, "heading ids are unique");
			assert.doesNotMatch(guide.html, /<script|<link\b|<img\b|\bsrc=|url\(\s*["']?https?:/i);
			assert.match(guide.html, new RegExp(`<html lang="${lang}">`));
			assert.match(guide.html, /<symbol id="aidr-logo"/);
			for (const chapter of guide.chapters) {
				assert.match(guide.html, new RegExp(`<h1 id="part-${chapter.number}">`));
			}
			const ids = new Set([...guide.html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]));
			for (const match of guide.html.matchAll(/href="#([^"]+)"/g)) {
				assert.ok(ids.has(match[1]), `#${match[1]} resolves`);
			}
			assert.equal((guide.html.match(/class="toc-page">000</g) ?? []).length, guide.headingIds.length);
		});
	}
});
