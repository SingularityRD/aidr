/**
 * Tests for the Markdown internal link checker, plus the repository-wide gate:
 * every tracked Markdown file links only to files and headings that exist.
 *
 *   node --test scripts/check-doc-links.test.mjs
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { anchorOf, checkLinks, extractLinks, headingAnchors, stripCode, trackedMarkdownFiles } from "./check-doc-links.mjs";

test("links inside fenced and inline code are ignored", () => {
	const markdown = ["See [guide](a.md).", "```", "[not a link](b.md)", "```", "Run `[x](c.md)` here.", "[ref]: d.md"].join("\n");
	assert.deepEqual(
		extractLinks(markdown).map((link) => [link.line, link.target]),
		[
			[1, "a.md"],
			[6, "d.md"],
		],
	);
	assert.equal(stripCode("a\n```\nb\n```\nc").split("\n").length, 5, "line numbers stay stable");
});

test("heading anchors follow GitHub's slug rules", () => {
	const anchors = headingAnchors(
		["# Title", "## VS Code/Cursor Extension Publishing", "### `prompt_protection`", "## 8. Yol Haritası (Kapalı Kaynak)", "## Title", '<a id="custom"></a>', "```", "# not a heading", "```"].join("\n"),
	);
	for (const expected of ["title", "vs-codecursor-extension-publishing", "prompt_protection", "8-yol-haritası-kapalı-kaynak", "title-1", "custom"]) {
		assert.ok(anchors.has(expected), `missing anchor ${expected}`);
	}
	assert.ok(!anchors.has("not-a-heading"));
});

test("anchorOf skips external links and GitHub line references", () => {
	assert.equal(anchorOf("docs/a.md#Some%20Thing"), "Some Thing");
	assert.equal(anchorOf("#local"), "local");
	assert.equal(anchorOf("docs/a.md#L10-L20"), null);
	assert.equal(anchorOf("https://example.com/#x"), null);
	assert.equal(anchorOf("docs/a.md"), null);
});

test("checkLinks reports missing files and anchors, and skips generated paths", (t) => {
	const root = mkdtempSync(path.join(tmpdir(), "aidr-doc-links-"));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	execFileSync("git", ["init", "-q"], { cwd: root });
	mkdirSync(path.join(root, "docs"));
	writeFileSync(path.join(root, ".gitignore"), "dist/\n");
	writeFileSync(path.join(root, "docs", "target.md"), "# Target\n\n## Real section\n");
	writeFileSync(
		path.join(root, "docs", "index.md"),
		[
			"[ok](target.md)",
			"[ok anchor](target.md#real-section)",
			"[dead](../doc/build_extension.md)",
			"[dead anchor](target.md#missing-section)",
			"[self](#index)",
			"[generated](../dist/out.txt)",
			"[sibling repo](../../elsewhere/README.md)",
			"[web](https://example.com/missing.md)",
			"# Index",
		].join("\n"),
	);
	const { broken, unverifiable } = checkLinks(["docs/index.md"], root);
	assert.deepEqual(
		broken.map((link) => link.target).sort(),
		["../doc/build_extension.md", "target.md#missing-section"].sort(),
	);
	assert.deepEqual(unverifiable.map((link) => link.reason).sort(), ["git-ignored", "outside-repository"]);
});

test("the repository has no broken internal Markdown links", () => {
	const files = trackedMarkdownFiles();
	assert.ok(files.length > 100, "expected the repository's Markdown files to be found");
	const { broken } = checkLinks(files);
	assert.deepEqual(
		broken.map(({ file, line, target }) => `${file}:${line} -> ${target}`),
		[],
		"fix or remove these links (node scripts/check-doc-links.mjs lists them)",
	);
});
