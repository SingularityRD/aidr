// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	placeholderRegex,
	RESTORED_BOX_WIDTH_EM,
	readRestored,
	SPAN_STYLE,
	visibleText,
} from "../content/unmask";
import type { FileDecision } from "../types";
import { EMAIL, FakeDataTransfer, type Harness, setupGuard } from "./content-helpers";

let h: Harness | undefined;
const scope = window as unknown as Record<string, unknown>;

beforeEach(() => {
	scope.DataTransfer = FakeDataTransfer;
});

afterEach(() => {
	h?.guard.stop();
	h = undefined;
	document.body.innerHTML = "";
	delete scope.DataTransfer;
});

function start(options: Parameters<typeof setupGuard>[0] = {}): Harness {
	h = setupGuard(options);
	return h;
}

/** Puts `value` into the vault (as a paste or file would) and returns its placeholder. */
function remember(g: Harness, value: string): string {
	const text = `x ${value}`;
	const result = g.vault.mask(text, [
		{ type: "EMAIL", start: 2, end: text.length, score: 1, source: "rule" },
	]);
	return result.placeholders[0] as string;
}

/** A send carrying `placeholders` left the page (what the guard reports on every send). */
function send(g: Harness, ...placeholders: string[]): void {
	g.guard.unmasker.noteSent(placeholders);
}

/** A new assistant (or user) message container, inserted now. */
function respond(content: string, role: "assistant" | "user" = "assistant"): HTMLElement {
	const el = document.createElement("div");
	el.setAttribute("data-role", role);
	el.innerHTML = content;
	document.body.append(el);
	return el;
}

/** The fixture's assistant container, which exists before any send. */
const oldAnswer = () => document.getElementById("answer") as HTMLElement;
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));
async function flush(g: Harness): Promise<void> {
	await settle();
	g.guard.unmasker.flush();
}

/** Captures the closed shadow roots the unmasker creates. */
function captureShadows(): { roots: ShadowRoot[]; restore(): void } {
	const roots: ShadowRoot[] = [];
	const attach = Element.prototype.attachShadow;
	Element.prototype.attachShadow = function (this: Element, init: ShadowRootInit) {
		const root = attach.call(this, init);
		roots.push(root);
		return root;
	};
	return {
		roots,
		restore: () => {
			Element.prototype.attachShadow = attach;
		},
	};
}

/** Every CSS rule text applied inside a shadow root (adopted sheets or <style>). */
function shadowCss(root: ShadowRoot): string {
	const adopted = (root.adoptedStyleSheets ?? []).flatMap((sheet) =>
		[...sheet.cssRules].map((r) => r.cssText),
	);
	const inline = [...root.querySelectorAll("style")].map((s) => s.textContent ?? "");
	return [...adopted, ...inline].join("\n");
}

describe("content guard: local unmasking", () => {
	it("restores sent placeholders in responses inside text nodes only", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		send(g, placeholder);
		const answer = respond(`<p>Reply to <b>${placeholder}</b> soon.</p>`);
		await flush(g);

		const span = answer.querySelector<HTMLElement>("span.aidr-restored");
		expect(span).not.toBeNull();
		expect(span?.title).toBe("Restored locally by AIDR");
		expect(readRestored(span as HTMLElement)).toBe(EMAIL);
		expect(visibleText(answer)).toBe(`Reply to ${EMAIL} soon.`);
		// The page's own scripts still read the placeholder (original only in the closed shadow root).
		expect(answer.textContent).toBe(`Reply to ${placeholder} soon.`);
		expect(answer.innerHTML).not.toContain(EMAIL);
		// Markup is untouched: the <b> still wraps the restored value.
		expect(span?.parentElement?.tagName).toBe("B");
	});

	it("renders the value as generated content in a reset, fixed-width box (no page-observable text)", async () => {
		const shadows = captureShadows();
		try {
			const g = start();
			const placeholder = remember(g, EMAIL);
			send(g, placeholder);
			const answer = respond(`Reply to ${placeholder}.`);
			await flush(g);
			const span = answer.querySelector("span.aidr-restored");
			const root = shadows.roots.find((s) => s.host === span);
			expect(root?.mode).toBe("closed");
			// Without a <slot>, Chromium's innerText skips the unrendered light DOM and a
			// page's copy/edit action would read "" where the placeholder was.
			const wrapper = root?.querySelector(".ph");
			expect(wrapper?.getAttribute("aria-hidden")).toBe("true");
			expect(wrapper?.querySelector("slot")).not.toBeNull();
			// The value is never a text node (window.find / find-in-page search shadow text):
			// it is the generated content of .v, taken from an attribute inside the closed root.
			const walker = document.createTreeWalker(root as ShadowRoot, NodeFilter.SHOW_TEXT);
			const texts: string[] = [];
			for (let n = walker.nextNode(); n; n = walker.nextNode()) texts.push(n.textContent ?? "");
			expect(texts.join("")).not.toContain(EMAIL);
			expect(root?.querySelector(".v")?.getAttribute("data-v")).toBe(EMAIL);
			expect(span?.textContent).toBe(placeholder);
			const css = shadowCss(root as ShadowRoot).replace(/\s+/g, "");
			expect(css).toMatch(/\.ph\{[^}]*clip-path:inset\(50%\)/);
			expect(css).toMatch(/content:attr\(data-v\)/);
		} finally {
			shadows.restore();
		}
	});

	it("the restored-value styles reset inheritance, use generic fonts only and a fixed width", () => {
		const rule = (selector: string) =>
			new RegExp(`(?:^|\\})${selector.replace(".", "\\.")}\\{([^}]*)\\}`).exec(SPAN_STYLE)?.[1] ??
			"";
		const host = rule(":host");
		const value = rule(".v");
		for (const block of [host, value]) expect(block).toMatch(/^all:initial!important;/);
		// Page @font-face rules can shadow any NAMED family; generic keywords only.
		const families = /font-family:([^;!]+)/.exec(value)?.[1]?.split(",") ?? [];
		expect(families).toEqual(["system-ui", "sans-serif"]);
		expect(SPAN_STYLE).not.toMatch(/font-family:inherit/);
		expect(value).toContain(`width:${RESTORED_BOX_WIDTH_EM}em!important`);
		expect(value).toContain("overflow:hidden!important");
		expect(value).toContain("text-overflow:ellipsis!important");
		// Only value-independent properties are inherited back from the page.
		const inherited = [...SPAN_STYLE.matchAll(/([a-z-]+):inherit/g)].map((m) => m[1]);
		expect(new Set(inherited)).toEqual(new Set(["font-size", "line-height", "color"]));
	});

	it("handles several placeholders in one text node and ignores unknown ones", async () => {
		const g = start();
		const a = remember(g, "a@example.com");
		const b = remember(g, "b@example.com");
		send(g, a, b);
		const answer = respond(`${a} and ${b} but not [EMAIL_99].`);
		await flush(g);
		expect(visibleText(answer)).toBe("a@example.com and b@example.com but not [EMAIL_99].");
		expect(answer.querySelectorAll("span.aidr-restored")).toHaveLength(2);
	});

	it("follows streaming updates to the same text node", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		send(g, placeholder);
		const answer = respond("");
		const text = document.createTextNode("Writing to");
		answer.append(text);
		await flush(g);
		expect(answer.querySelector("span.aidr-restored")).toBeNull();

		text.data = `Writing to ${placeholder}`;
		await flush(g);
		expect(visibleText(answer)).toBe(`Writing to ${EMAIL}`);

		text.data = `Writing to ${placeholder} now, cc ${placeholder}`;
		await flush(g);
		expect(visibleText(answer)).toBe(`Writing to ${EMAIL} now, cc ${EMAIL}`);
		expect(answer.querySelectorAll("span.aidr-restored")).toHaveLength(2);
	});

	it("toggles visibility with SET_RESTORE_VISIBLE and respects policy.restoreResponses", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		send(g, placeholder);
		const answer = respond(`hi ${placeholder}`);
		await flush(g);
		expect(visibleText(answer)).toBe(`hi ${EMAIL}`);

		g.guard.setRestoreVisible(false);
		expect(visibleText(answer)).toBe(`hi ${placeholder}`);
		g.guard.setRestoreVisible(true);
		expect(visibleText(answer)).toBe(`hi ${EMAIL}`);

		g.policy = { ...(g.policy as NonNullable<Harness["policy"]>), restoreResponses: false };
		g.guard.policyChanged();
		expect(visibleText(answer)).toBe(`hi ${placeholder}`);
	});

	it("does nothing when the policy disables restoring", async () => {
		const g = start({ policy: { restoreResponses: false } });
		const placeholder = remember(g, EMAIL);
		send(g, placeholder);
		const answer = respond(`hi ${placeholder}`);
		await flush(g);
		expect(answer.querySelector("span.aidr-restored")).toBeNull();
	});

	it("never unmasks inside the editor or other editable regions", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		send(g, placeholder);
		const answer = respond("");
		const editable = document.createElement("div");
		editable.setAttribute("contenteditable", "true");
		editable.textContent = `draft ${placeholder}`;
		answer.append(editable);
		g.editor.value = `prompt ${placeholder}`;
		await flush(g);
		expect(editable.querySelector("span.aidr-restored")).toBeNull();
		expect(editable.textContent).toBe(`draft ${placeholder}`);
		expect(g.editor.value).toBe(`prompt ${placeholder}`);
	});

	it("ignores placeholders outside response / user-message containers", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		send(g, placeholder);
		const outside = document.createElement("div");
		outside.textContent = placeholder;
		document.body.append(outside);
		await flush(g);
		expect(outside.querySelector("span.aidr-restored")).toBeNull();
	});

	it("never restores never-restore types", async () => {
		const g = start();
		const text = "key sk-live-123456";
		const masked = g.vault.mask(text, [
			{ type: "SECRET", start: 4, end: text.length, score: 1, source: "rule" },
		]);
		send(g, ...masked.placeholders);
		const answer = respond(masked.masked);
		await flush(g);
		expect(answer.querySelector("span.aidr-restored")).toBeNull();
		expect(answer.textContent).toBe(masked.masked);
	});

	it("restores the page's original text when stopped", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		send(g, placeholder);
		const answer = respond(`hi ${placeholder}!`);
		await flush(g);
		g.guard.stop();
		h = undefined;
		expect(answer.querySelector("span.aidr-restored")).toBeNull();
		expect(answer.textContent).toBe(`hi ${placeholder}!`);
	});

	it("unmasks the user's own sent messages", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		send(g, placeholder);
		const mine = respond(`send to ${placeholder}`, "user");
		await flush(g);
		expect(visibleText(mine)).toBe(`send to ${EMAIL}`);
	});
});

describe("content guard: restoration is limited to what this tab sent (oracle mitigation)", () => {
	it("never restores a vault placeholder that was not sent (e.g. a deleted paste)", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		// A hostile page injects the vault's placeholder into a brand-new response.
		const answer = respond(`leak ${placeholder}`);
		await flush(g);
		expect(answer.querySelector("span.aidr-restored")).toBeNull();
		expect(visibleText(answer)).toBe(`leak ${placeholder}`);
	});

	it("never restores inside a container that existed before the send", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		send(g, placeholder);
		oldAnswer().textContent = `rewritten ${placeholder}`;
		const extra = document.createTextNode(` appended ${placeholder}`);
		oldAnswer().append(extra);
		await flush(g);
		expect(oldAnswer().querySelector("span.aidr-restored")).toBeNull();
		expect(visibleText(oldAnswer())).toBe(`rewritten ${placeholder} appended ${placeholder}`);
	});

	it("treats content inserted before the send as old even if its mutations are still queued", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		// Inserted and sent in the same task: the MutationObserver has not delivered yet.
		const early = respond(`early ${placeholder}`);
		send(g, placeholder);
		const late = respond(`late ${placeholder}`);
		await flush(g);
		expect(early.querySelector("span.aidr-restored")).toBeNull();
		expect(visibleText(late)).toBe(`late ${EMAIL}`);
	});

	it("restores a placeholder only in content that appeared after the send that carried it", async () => {
		const g = start();
		const a = remember(g, "a@example.com");
		const b = remember(g, "b@example.com");
		send(g, a);
		const first = respond(`${a} ${b}`);
		send(g, b);
		const second = respond(`${a} ${b}`);
		await flush(g);
		expect(visibleText(first)).toBe(`a@example.com ${b}`);
		expect(visibleText(second)).toBe("a@example.com b@example.com");
	});

	it("content inserted inside a newer ancestor counts as new", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		send(g, placeholder);
		const wrapper = document.createElement("section");
		const inner = document.createElement("div");
		inner.setAttribute("data-role", "assistant");
		inner.textContent = `ok ${placeholder}`;
		wrapper.append(inner);
		document.body.append(wrapper);
		await flush(g);
		expect(visibleText(inner)).toBe(`ok ${EMAIL}`);
	});

	it("a real masked send makes its placeholders restorable in the reply", async () => {
		const g = start();
		g.editor.value = `Please email ${EMAIL} today`;
		g.enter();
		await expect.poll(() => g.sent).toEqual(["Please email [EMAIL_1] today"]);
		const reply = respond("I will email [EMAIL_1] and [EMAIL_2].");
		await flush(g);
		expect(visibleText(reply)).toBe(`I will email ${EMAIL} and [EMAIL_2].`);
	});

	it("placeholders pasted into the prompt become restorable once the prompt is sent", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL); // the paste masked it into the editor
		const before = respond(`${placeholder}`);
		g.editor.value = `note ${placeholder}`;
		g.enter();
		await expect.poll(() => g.sent).toEqual([`note ${placeholder}`]);
		const after = respond(`${placeholder}`);
		await flush(g);
		expect(before.querySelector("span.aidr-restored")).toBeNull();
		expect(visibleText(after)).toBe(EMAIL);
	});

	it("placeholders of a masked file become restorable with the next send", async () => {
		const g = start({
			sanitizeFile: async (file, deps): Promise<FileDecision> => {
				const text = `row ${EMAIL}`;
				const masked = deps.vault.mask(text, [
					{ type: "EMAIL", start: 4, end: text.length, score: 1, source: "rule" },
				]);
				return {
					action: "mask",
					masked: {
						name: file.name,
						type: "text/plain",
						bytes: new TextEncoder().encode(masked.masked),
					},
					counts: masked.counts,
					reasons: ["SENSITIVE_DATA"],
				};
			},
		});
		const event = new Event("paste", { bubbles: true, cancelable: true });
		const data = new FakeDataTransfer();
		data.items.add(new File([`row ${EMAIL}`], "rows.txt", { type: "text/plain" }));
		Object.defineProperty(event, "clipboardData", { value: data });
		g.editor.dispatchEvent(event);
		await expect.poll(() => g.vault.size()).toBe(1);
		const placeholder = "[EMAIL_1]";
		expect(g.vault.lookup(placeholder)).toBe(EMAIL);
		const beforeSend = respond(`${placeholder}`);
		g.editor.value = "summarise the attached file";
		g.enter();
		await expect.poll(() => g.sent).toEqual(["summarise the attached file"]);
		const reply = respond(`${placeholder}`);
		await flush(g);
		expect(beforeSend.querySelector("span.aidr-restored")).toBeNull();
		expect(visibleText(reply)).toBe(EMAIL);
	});
});

describe("placeholderRegex", () => {
	it("matches every placeholder shape the vault produces", () => {
		const text = "[EMAIL_1] [TCKN_2] [TAX_ID_12] [PRIVATE_KEY_3] [NOPE_1] EMAIL_1";
		expect([...text.matchAll(placeholderRegex())].map((m) => m[0])).toEqual([
			"[EMAIL_1]",
			"[TCKN_2]",
			"[TAX_ID_12]",
			"[PRIVATE_KEY_3]",
		]);
	});
});
