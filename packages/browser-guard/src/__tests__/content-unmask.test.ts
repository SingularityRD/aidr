// @vitest-environment jsdom
import { afterEach, describe, expect, it } from "vitest";
import { placeholderRegex, readRestored, visibleText } from "../content/unmask";
import { EMAIL, type Harness, setupGuard } from "./content-helpers";

let h: Harness | undefined;

afterEach(() => {
	h?.guard.stop();
	h = undefined;
	document.body.innerHTML = "";
});

function start(options: Parameters<typeof setupGuard>[0] = {}): Harness {
	h = setupGuard(options);
	return h;
}

/** Puts `value` into the vault and returns its placeholder. */
function remember(g: Harness, value: string): string {
	const text = `x ${value}`;
	const result = g.vault.mask(text, [
		{ type: "EMAIL", start: 2, end: text.length, score: 1, source: "rule" },
	]);
	return result.placeholders[0] as string;
}

const answer = () => document.getElementById("answer") as HTMLElement;
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("content guard: local unmasking", () => {
	it("restores placeholders in responses inside text nodes only", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		answer().innerHTML = `<p>Reply to <b>${placeholder}</b> soon.</p>`;
		await settle();
		g.guard.unmasker.flush();

		const span = answer().querySelector<HTMLElement>("span.aidr-restored");
		expect(span).not.toBeNull();
		expect(span?.title).toBe("Restored locally by AIDR");
		expect(readRestored(span as HTMLElement)).toBe(EMAIL);
		expect(visibleText(answer())).toBe(`Reply to ${EMAIL} soon.`);
		// The page's own scripts still read the placeholder (original only in the closed shadow root).
		expect(answer().textContent).toBe(`Reply to ${placeholder} soon.`);
		expect(answer().innerHTML).not.toContain(EMAIL);
		// Markup is untouched: the <b> still wraps the restored value.
		expect(span?.parentElement?.tagName).toBe("B");
	});

	it("handles several placeholders in one text node and ignores unknown ones", async () => {
		const g = start();
		const a = remember(g, "a@example.com");
		const b = remember(g, "b@example.com");
		answer().textContent = `${a} and ${b} but not [EMAIL_99].`;
		await settle();
		g.guard.unmasker.flush();
		expect(visibleText(answer())).toBe("a@example.com and b@example.com but not [EMAIL_99].");
		expect(answer().querySelectorAll("span.aidr-restored")).toHaveLength(2);
	});

	it("follows streaming updates to the same text node", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		const text = document.createTextNode("Writing to");
		answer().append(text);
		await settle();
		g.guard.unmasker.flush();
		expect(answer().querySelector("span.aidr-restored")).toBeNull();

		text.data = `Writing to ${placeholder}`;
		await settle();
		g.guard.unmasker.flush();
		expect(visibleText(answer())).toBe(`Writing to ${EMAIL}`);

		text.data = `Writing to ${placeholder} now, cc ${placeholder}`;
		await settle();
		g.guard.unmasker.flush();
		expect(visibleText(answer())).toBe(`Writing to ${EMAIL} now, cc ${EMAIL}`);
		expect(answer().querySelectorAll("span.aidr-restored")).toHaveLength(2);
	});

	it("toggles visibility with SET_RESTORE_VISIBLE and respects policy.restoreResponses", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		answer().textContent = `hi ${placeholder}`;
		await settle();
		g.guard.unmasker.flush();
		expect(visibleText(answer())).toBe(`hi ${EMAIL}`);

		g.guard.setRestoreVisible(false);
		expect(visibleText(answer())).toBe(`hi ${placeholder}`);
		g.guard.setRestoreVisible(true);
		expect(visibleText(answer())).toBe(`hi ${EMAIL}`);

		g.policy = { ...(g.policy as NonNullable<Harness["policy"]>), restoreResponses: false };
		g.guard.policyChanged();
		expect(visibleText(answer())).toBe(`hi ${placeholder}`);
	});

	it("does nothing when the policy disables restoring", async () => {
		const g = start({ policy: { restoreResponses: false } });
		const placeholder = remember(g, EMAIL);
		answer().textContent = `hi ${placeholder}`;
		await settle();
		g.guard.unmasker.flush();
		expect(answer().querySelector("span.aidr-restored")).toBeNull();
	});

	it("never unmasks inside the editor or other editable regions", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		const editable = document.createElement("div");
		editable.setAttribute("contenteditable", "true");
		editable.textContent = `draft ${placeholder}`;
		answer().append(editable);
		g.editor.value = `prompt ${placeholder}`;
		await settle();
		g.guard.unmasker.flush();
		expect(editable.querySelector("span.aidr-restored")).toBeNull();
		expect(editable.textContent).toBe(`draft ${placeholder}`);
		expect(g.editor.value).toBe(`prompt ${placeholder}`);
	});

	it("ignores placeholders outside response / user-message containers", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		const outside = document.getElementById("drop-zone") as HTMLElement;
		outside.textContent = placeholder;
		await settle();
		g.guard.unmasker.flush();
		expect(outside.querySelector("span.aidr-restored")).toBeNull();
	});

	it("never restores never-restore types", async () => {
		const g = start();
		const text = "key sk-live-123456";
		const masked = g.vault.mask(text, [
			{ type: "SECRET", start: 4, end: text.length, score: 1, source: "rule" },
		]);
		answer().textContent = masked.masked;
		await settle();
		g.guard.unmasker.flush();
		expect(answer().querySelector("span.aidr-restored")).toBeNull();
		expect(answer().textContent).toBe(masked.masked);
	});

	it("restores the page's original text when stopped", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		answer().textContent = `hi ${placeholder}!`;
		await settle();
		g.guard.unmasker.flush();
		g.guard.stop();
		h = undefined;
		expect(answer().querySelector("span.aidr-restored")).toBeNull();
		expect(answer().textContent).toBe(`hi ${placeholder}!`);
	});

	it("unmasks the user's own sent messages", async () => {
		const g = start();
		const placeholder = remember(g, EMAIL);
		const mine = document.createElement("div");
		mine.setAttribute("data-role", "user");
		mine.textContent = `send to ${placeholder}`;
		document.body.append(mine);
		await settle();
		g.guard.unmasker.flush();
		expect(visibleText(mine)).toBe(`send to ${EMAIL}`);
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
