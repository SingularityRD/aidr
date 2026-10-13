#!/usr/bin/env node
/**
 * Internal link checker for the repository's Markdown documentation.
 *
 *   node scripts/check-doc-links.mjs            # check every tracked *.md file, exit 1 on a broken link
 *   node scripts/check-doc-links.mjs --json     # machine-readable list of broken links
 *
 * A link is internal when its target is a relative path (or a path starting with `/`, which
 * GitHub resolves from the repository root). External URLs, `mailto:` and pure `#anchor`
 * links are not checked. Fenced code blocks and inline code are ignored, so command examples
 * are never mistaken for links. Third-party trees (`vendor/`, `node_modules/`) are skipped.
 *
 * Two kinds of missing target are reported separately and do not fail the check, because
 * this checkout cannot verify them: a target in a git-ignored location (build output such as
 * `dist/`, or local evidence under `.release-evidence/`, `.tmp-test/`, `coverage/`), and a
 * target outside the repository (a sibling checkout).
 *
 * Tested by scripts/check-doc-links.test.mjs.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** Path prefixes that hold third-party or generated Markdown we do not maintain. */
export const IGNORED_PREFIXES = ["vendor/", "node_modules/", "services/aig-bridge/vendor/"];

const EXTERNAL = /^(?:[a-z][a-z0-9+.-]*:|\/\/|#|<|\{)/i;

/** Tracked Markdown files, relative to `root`, excluding third-party trees. */
export function trackedMarkdownFiles(root = repositoryRoot) {
	const out = execFileSync("git", ["ls-files", "-z", "--", "*.md"], { cwd: root, encoding: "utf8" });
	return out
		.split("\0")
		.filter(Boolean)
		.filter((file) => !IGNORED_PREFIXES.some((prefix) => file.startsWith(prefix) || file.includes(`/${prefix}`)))
		.filter((file) => existsSync(path.join(root, file)));
}

/** The lines of `markdown` with fenced code blocks blanked (line numbers stay stable). */
function unfencedLines(markdown) {
	let fence = null;
	return markdown.split("\n").map((line) => {
		const marker = line.match(/^\s*(`{3,}|~{3,})/);
		if (fence) {
			if (marker && marker[1][0] === fence[0] && marker[1].length >= fence.length) fence = null;
			return "";
		}
		if (marker) {
			fence = marker[1];
			return "";
		}
		return line;
	});
}

/** Blank out fenced code blocks and inline code while keeping line numbers stable. */
export function stripCode(markdown) {
	return unfencedLines(markdown)
		.map((line) => line.replace(/(`+)[^`]*?\1/g, ""))
		.join("\n");
}

/**
 * The anchors GitHub generates for the headings of `markdown` (lower-case, punctuation
 * removed, spaces to hyphens, `-1`, `-2` ... for repeats), plus explicit `<a id|name>` anchors.
 */
export function headingAnchors(markdown) {
	const anchors = new Set();
	const seen = new Map();
	for (const line of unfencedLines(markdown)) {
		const heading = line.match(/^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$/);
		if (!heading) continue;
		const slug = heading[1]
			.replace(/<[^>]+>/g, "")
			.replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1")
			.toLowerCase()
			.replace(/[^\p{L}\p{M}\p{N}\s_-]/gu, "")
			.replace(/ /g, "-");
		const count = seen.get(slug) ?? 0;
		seen.set(slug, count + 1);
		anchors.add(count === 0 ? slug : `${slug}-${count}`);
	}
	for (const match of markdown.matchAll(/<a\s+(?:name|id)="([^"]+)"/g)) anchors.add(match[1]);
	return anchors;
}

/** Every `[text](target)` and `[label]: target` link in `markdown`, with 1-based line numbers. */
export function extractLinks(markdown) {
	const links = [];
	const lines = stripCode(markdown).split("\n");
	lines.forEach((line, index) => {
		for (const match of line.matchAll(/!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g)) {
			links.push({ line: index + 1, target: match[1] });
		}
		const definition = line.match(/^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+"[^"]*")?\s*$/);
		if (definition) links.push({ line: index + 1, target: definition[1] });
	});
	return links;
}

/** Resolve an internal link target to a repository path, or null for an external link. */
export function resolveTarget(file, target, root = repositoryRoot) {
	if (EXTERNAL.test(target)) return null;
	let clean = target.split("#")[0].split("?")[0];
	if (!clean) return null;
	try {
		clean = decodeURIComponent(clean);
	} catch {
		// Keep the raw target; a malformed escape is reported as missing below.
	}
	return clean.startsWith("/") ? path.join(root, clean) : path.resolve(root, path.dirname(file), clean);
}

/**
 * The decoded `#fragment` of an internal link, or null when there is none or it is a GitHub
 * source-view line reference (`#L10`, `#L10-L20`), which no heading produces.
 */
export function anchorOf(target) {
	if (/^[a-z][a-z0-9+.-]*:|^\/\//i.test(target)) return null;
	const hash = target.indexOf("#");
	if (hash < 0 || hash === target.length - 1) return null;
	let anchor = target.slice(hash + 1);
	try {
		anchor = decodeURIComponent(anchor);
	} catch {
		// Compare the raw fragment.
	}
	return /^L\d+(?:-L\d+)?$/.test(anchor) ? null : anchor;
}

/** Repository-relative paths (from `paths`) that git ignores, i.e. build or local evidence output. */
function ignoredByGit(paths, root) {
	if (paths.length === 0) return new Set();
	try {
		const out = execFileSync("git", ["check-ignore", "--no-index", "--stdin", "-z"], {
			cwd: root,
			input: `${paths.join("\0")}\0`,
			encoding: "utf8",
		});
		return new Set(out.split("\0").filter(Boolean));
	} catch (error) {
		// Exit status 1 means "none of the paths is ignored".
		if (error.status === 1) return new Set();
		throw error;
	}
}

/**
 * Check the internal links in the given files (paths relative to `root`).
 * Returns `broken` (fails the check) and `unverifiable` (generated or outside the repository).
 */
export function checkLinks(files, root = repositoryRoot) {
	const missing = [];
	const unverifiable = [];
	const brokenAnchors = [];
	const anchorCache = new Map();
	const anchorsOf = (absolute) => {
		if (!anchorCache.has(absolute)) anchorCache.set(absolute, headingAnchors(readFileSync(absolute, "utf8")));
		return anchorCache.get(absolute);
	};
	for (const file of files) {
		const markdown = readFileSync(path.join(root, file), "utf8");
		for (const { line, target } of extractLinks(markdown)) {
			const resolved = resolveTarget(file, target, root);
			const anchor = anchorOf(target);
			if (anchor !== null) {
				const page = target.startsWith("#") ? path.join(root, file) : resolved;
				if (page?.endsWith(".md") && existsSync(page) && !anchorsOf(page).has(anchor)) {
					brokenAnchors.push({ file, line, target });
				}
			}
			if (!resolved || existsSync(resolved)) continue;
			const relative = path.relative(root, resolved);
			if (relative.startsWith("..") || path.isAbsolute(relative)) {
				unverifiable.push({ file, line, target, reason: "outside-repository" });
			} else {
				missing.push({ file, line, target, relative: relative.split(path.sep).join("/") });
			}
		}
	}
	const ignored = ignoredByGit([...new Set(missing.map((link) => link.relative))], root);
	const broken = [...brokenAnchors];
	for (const { relative, ...link } of missing) {
		if (ignored.has(relative)) unverifiable.push({ ...link, reason: "git-ignored" });
		else broken.push(link);
	}
	return { broken, unverifiable };
}

/** Broken internal links in the given files (paths relative to `root`). */
export function findBrokenLinks(files, root = repositoryRoot) {
	return checkLinks(files, root).broken;
}

function main(argv) {
	const json = argv.includes("--json");
	const files = trackedMarkdownFiles();
	const { broken, unverifiable } = checkLinks(files);
	if (json) {
		console.log(JSON.stringify({ files: files.length, broken, unverifiable }, null, 2));
	} else {
		for (const { file, line, target } of broken) console.error(`${file}:${line} -> ${target}`);
		console.log(
			`Checked ${files.length} Markdown files: ${broken.length} broken internal link(s); ${unverifiable.length} link(s) to generated or out-of-repository paths not checked.`,
		);
	}
	process.exitCode = broken.length === 0 ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	main(process.argv.slice(2));
}
