import { describe, expect, it } from "vitest";
import { MAX_BEHAVIORAL_CORPUS_ENTRIES } from "../behavioral-corpus.js";
import { generateEmbedding } from "../ml/embedder.js";
import { LocalEmbeddingModel } from "../ml-model.js";

const fixtureText = "SYNTHETIC TEST ONLY: corpus import fixture";
const fixture = () => ({
	threatId: "synthetic-import-fixture",
	embedding: Array.from(generateEmbedding(fixtureText)),
	metadata: {
		category: "test-fixture",
		severity: "test",
		description: "Synthetic test, not efficacy evidence",
	},
});

const model = () => new LocalEmbeddingModel(LocalEmbeddingModel.createDefaultConfig());

describe("bounded local corpus import", () => {
	it("does not invent a database when the embedder loads", async () => {
		const local = model();
		await local.load();
		expect(await local.getStats()).toMatchObject({ isLoaded: true, threatCount: 0 });
	});

	it("copies validated data and matches the exact synthetic fixture", async () => {
		const local = model();
		const entry = fixture();
		await local.importThreatCorpus([entry]);
		entry.embedding.fill(0);
		entry.metadata.description = "caller changed";
		await local.load();
		const matches = await local.findSimilarThreats(fixtureText);
		expect(matches[0]?.threatId).toBe("synthetic-import-fixture");
		expect(matches[0]?.metadata.description).toBe("Synthetic test, not efficacy evidence");
	});

	it.each([
		["empty", () => []],
		["duplicate IDs", () => [fixture(), fixture()]],
		["wrong dimension", () => [{ ...fixture(), embedding: [1] }]],
		["zero vector", () => [{ ...fixture(), embedding: new Array(100).fill(0) }]],
		["non-finite vector", () => [{ ...fixture(), embedding: new Array(100).fill(Number.NaN) }]],
		["out-of-range vector", () => [{ ...fixture(), embedding: new Array(100).fill(2) }]],
		[
			"too many entries",
			() =>
				Array.from({ length: MAX_BEHAVIORAL_CORPUS_ENTRIES + 1 }, (_, i) => ({
					...fixture(),
					threatId: `fixture-${i}`,
				})),
		],
	] as const)("refuses %s without replacing the active database", async (_name, invalid) => {
		const local = model();
		await local.importThreatCorpus([fixture()]);
		await expect(local.importThreatCorpus(invalid())).rejects.toThrow();
		expect(await local.getThreatCount()).toBe(1);
		await local.load();
		expect((await local.findSimilarThreats(fixtureText))[0]?.threatId).toBe(
			"synthetic-import-fixture",
		);
	});

	it("accepts exactly the documented maximum entry count", async () => {
		const local = model();
		const entry = fixture();
		await local.importThreatCorpus(
			Array.from({ length: MAX_BEHAVIORAL_CORPUS_ENTRIES }, (_, index) => ({
				...entry,
				threatId: `fixture-${index}`,
			})),
		);
		expect(await local.getThreatCount()).toBe(1024);
	});

	it("refuses import into an incompatible configured embedder", async () => {
		const local = new LocalEmbeddingModel({
			...LocalEmbeddingModel.createDefaultConfig(),
			vectorSize: 64,
		});
		await expect(local.importThreatCorpus([fixture()])).rejects.toThrow("incompatible");
		expect(await local.getThreatCount()).toBe(0);
	});
});
