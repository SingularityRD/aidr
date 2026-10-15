/**
 * Every console page shows its text through the EN/TR catalogs (src/i18n).
 *
 * A pragmatic source check, not a renderer: it parses each page under
 * src/ui/pages (and the shared components those pages render) and fails on
 *   - JSX text containing a word,
 *   - a word in a user-facing attribute (aria-label, title, placeholder, alt, label),
 *   - a string or template literal that reads like an English sentence
 *     (a capitalised word followed by two lower-case words), wherever it is.
 * Code, product names and developer-only text are allowed: text inside
 * <code>/<pre>/<kbd>/<samp>, `new Error(...)`/`console.*` arguments, and the
 * names in ALLOWED_TEXT, and literals marked `// i18n-exempt: <reason>`.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const SRC = resolve(__dirname, "..");

/** Directories whose .tsx files render console UI. */
const UI_DIRS = ["ui/pages", "ui", "enterprise", "onboarding", "billing", "components"];

/** Product, protocol and format names shown as-is in every language. */
const ALLOWED_TEXT = new Set([
	"AIDR",
	"Singularity AIDR",
	"Singularity",
	"Browser Guard",
	"AutoSecOps",
	"Claude Code",
	"Cursor",
	"VS Code",
	"Codex",
	"OpenCode",
	"OpenClaw",
	"Windows",
	"Linux",
	"macOS",
	"Chrome",
	"Edge",
	"Firefox",
	"GitHub",
	"Google",
	"Microsoft",
	"Microsoft Entra ID",
	"Okta",
	"English",
	"Türkçe",
	"SIEM",
	"SCIM",
	"OIDC",
	"SAML",
	"SSO",
	"MFA",
	"API",
	"YAML",
	"JSON",
	"CSV",
	"PDF",
	"SHA-256",
	"CVSS",
	"CVE",
	"ID",
	"OWASP",
	"MITRE ATLAS",
	"Ed25519",
	"OK",
	"EN",
	"TR",
]);

const ATTRIBUTES = new Set(["aria-label", "title", "placeholder", "alt", "label"]);
const CODE_TAGS = new Set(["code", "pre", "kbd", "samp"]);
const SENTENCE = /[A-Z][a-z]+(?:[ ,]+[a-z][a-z'’-]*){2,}/;
const WORD = /[A-Za-z]{2,}/;

function tsxFiles(dir: string, out: string[] = []): string[] {
	for (const entry of readdirSync(dir)) {
		const path = join(dir, entry);
		if (statSync(path).isDirectory()) {
			if (entry !== "__tests__") tsxFiles(path, out);
		} else if (entry.endsWith(".tsx")) out.push(path);
	}
	return out;
}

/** Tokens that are addresses, paths or code (`a@b.c`, `https://…`, `t=…`), not words. */
const CODE_TOKEN = /\S*[@:/.=_]\S*/g;

function allowed(text: string): boolean {
	const trimmed = text.replace(/\s+/g, " ").trim();
	return ALLOWED_TEXT.has(trimmed) || !WORD.test(trimmed.replace(CODE_TOKEN, ""));
}

function insideCode(node: ts.Node): boolean {
	for (let current = node.parent; current; current = current.parent) {
		if (ts.isJsxElement(current)) {
			const opening = current.openingElement;
			if (CODE_TAGS.has(opening.tagName.getText())) return true;
			// <span className="mono"> marks commands, ids and other literal values.
			const className = opening.attributes.properties.find(
				(attribute) => ts.isJsxAttribute(attribute) && attribute.name.getText() === "className",
			);
			if (className && /\bmono\b/.test(className.getText())) return true;
		}
	}
	return false;
}

function developerOnly(node: ts.Node): boolean {
	for (let current = node.parent; current; current = current.parent) {
		if (ts.isNewExpression(current) && /Error$/.test(current.expression.getText())) return true;
		if (ts.isCallExpression(current) && /^console\./.test(current.expression.getText()))
			return true;
		if (ts.isImportDeclaration(current) || ts.isExportDeclaration(current)) return true;
	}
	return false;
}

/** Whether a sentence-like literal is shown to a user (not code or a developer message). */
function userSentence(node: ts.Node, text: string): boolean {
	return SENTENCE.test(text) && !developerOnly(node) && !insideCode(node);
}

/**
 * The UI text a single node contributes, and whether its children still need
 * a visit (attributes and string literals are leaves).
 */
function uiTextOf(node: ts.Node): { text: string | null; leaf: boolean } {
	if (ts.isJsxText(node)) {
		const flagged = !allowed(node.getText()) && !insideCode(node);
		return { text: flagged ? node.getText().trim() : null, leaf: true };
	}
	if (
		ts.isJsxAttribute(node) &&
		ATTRIBUTES.has(node.name.getText()) &&
		node.initializer &&
		ts.isStringLiteral(node.initializer)
	) {
		const value = node.initializer.text;
		return { text: allowed(value) ? null : value, leaf: true };
	}
	if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
		return { text: userSentence(node, node.text) ? node.text : null, leaf: true };
	}
	if (ts.isTemplateExpression(node)) {
		const text = [node.head.text, ...node.templateSpans.map((span) => span.literal.text)].join(" ");
		return { text: userSentence(node, text) ? text : null, leaf: false };
	}
	return { text: null, leaf: false };
}

/** English UI text written directly in `file`. */

function literalUiText(file: string): string[] {
	const source = ts.createSourceFile(
		file,
		readFileSync(file, "utf8"),
		ts.ScriptTarget.Latest,
		true,
		ts.ScriptKind.TSX,
	);
	const lines = source.text.split("\n");
	// `// i18n-exempt: <why>` on the line above (or the same line) marks stored
	// content or other text that is deliberately not UI copy.
	const exempt = (node: ts.Node): boolean => {
		const line = source.getLineAndCharacterOfPosition(node.getStart()).line;
		return [lines[line], lines[line - 1]].some((text) => text?.includes("i18n-exempt"));
	};
	const found: string[] = [];
	// A declaration or property whose leading comment says i18n-exempt is
	// skipped whole (for example an English prompt written for an AI agent).
	const exemptSubtree = (node: ts.Node): boolean =>
		(ts.getLeadingCommentRanges(source.text, node.getFullStart()) ?? []).some((range) =>
			source.text.slice(range.pos, range.end).includes("i18n-exempt"),
		);
	const visit = (node: ts.Node): void => {
		if (exemptSubtree(node)) return;
		const isLiteral =
			ts.isStringLiteral(node) || ts.isTemplateExpression(node) || ts.isJsxText(node);
		if (isLiteral && exempt(node)) return;
		const result = uiTextOf(node);
		if (result.text !== null) found.push(result.text);
		if (!result.leaf) ts.forEachChild(node, visit);
	};
	visit(source);
	return found;
}

describe("console pages use the translation catalogs", () => {
	const files = [...new Set(UI_DIRS.flatMap((dir) => tsxFiles(join(SRC, dir))))]
		.map((path) => relative(SRC, path).split("\\").join("/"))
		.sort();

	it("covers every page", () => {
		expect(files).toContain("ui/pages/ApprovalsPage.tsx");
		expect(files).toContain("ui/AppLayout.tsx");
	});

	it("renders no literal English UI text outside the catalog", () => {
		const offenders: Record<string, string[]> = {};
		for (const file of files) {
			const literals = literalUiText(join(SRC, file));
			if (literals.length > 0) offenders[file] = literals;
		}
		expect(offenders).toEqual({});
	});

	it("catches the heuristic's targets", () => {
		// Guard the guard: a synthetic page with each kind of literal is flagged.
		const probe = join(SRC, "__tests__", "fixtures", "i18n-literal-probe.tsx.txt");
		const found = literalUiText(probe);
		expect(found).toHaveLength(4);
		expect(found).toEqual(
			expect.arrayContaining([
				"Approval signing key rotated.",
				"Pending approvals",
				"Search agents",
				expect.stringContaining("Showing the newest requests"),
			]),
		);
	});
});
