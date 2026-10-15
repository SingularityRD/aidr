import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { Featurizer, type ModelVocab, norm, shapeOf } from "../engine/ner/featurize.js";

// Written by ml/pii-tiny/tools/parity_fixture.py from the Python featurizer (train_b.py).
const fixture = JSON.parse(
	readFileSync(new URL("./fixtures/ner-featurize-parity.json", import.meta.url), "utf8"),
) as { vocab: ModelVocab; cases: Array<{ text: string; sha256: string }> };

describe("local NER featurizer", () => {
	it("matches the Python training featurizer on every fixture prompt", () => {
		const featurizer = new Featurizer(fixture.vocab);
		const max = fixture.vocab.maxChars;
		const mismatches: string[] = [];
		for (const { text, sha256 } of fixture.cases) {
			const f = featurizer.encode(text);
			const payload = {
				tokens: f.tokens.map(([a, b]) => [a, b]),
				words: [...f.words],
				chars: [...f.chars],
				shape: [...f.shape],
			};
			expect(f.chars.length).toBe(f.tokens.length * max);
			const got = createHash("sha256").update(JSON.stringify(payload)).digest("hex");
			if (got !== sha256) mismatches.push(text.slice(0, 80));
		}
		expect(mismatches).toEqual([]);
		expect(fixture.cases.length).toBeGreaterThan(200);
	});

	it("folds Turkish dotted and dotless I like the training code", () => {
		expect(norm("IŞIK")).toBe("ışık");
		expect(norm("İzmir")).toBe("izmir");
	});

	it("computes shape features from code points", () => {
		expect(shapeOf("Ayşe", "", "'")).toEqual([1, 0, 0, 0, 1, 1, 0, 0]);
		expect(shapeOf("😀", "x", "")).toEqual([0, 0, 0, 1, 0, 0, 0, 1]);
	});
});
