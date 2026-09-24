import { describe, expect, it } from "vitest";
import { ContentClassifier } from "../../dlp/content-classifier.js";

describe("ContentClassifier binary sampling", () => {
	it("keeps Unicode business text as text", () => {
		const result = new ContentClassifier().classify("müşteri.txt", "Gizli müşteri bilgisi: İstanbul");
		expect(result.category).toBe("documentation");
	});

	it("does not hide a credential classification behind Unicode", () => {
		const result = new ContentClassifier().classify("müşteri.txt", "İstanbul\nDB_PASSWORD=synthetic-only");
		expect(result.category).toBe("credentials");
		expect(result.sensitivity).toBe("restricted");
	});

	it("identifies non-NUL binary control characters", () => {
		const result = new ContentClassifier().classify("payload.txt", "header\x01body");
		expect(result.category).toBe("binary");
	});
});
