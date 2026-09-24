import { describe, expect, it } from "vitest";
import { ContentClassifier } from "../../dlp/content-classifier.js";

describe("ContentClassifier", () => {
	it("should classify source code by extension", () => {
		const classifier = new ContentClassifier();
		const result = classifier.classify("src/index.ts");
		expect(result.category).toBe("source_code");
		expect(result.sensitivity).toBe("internal");
		expect(result.confidence).toBeGreaterThanOrEqual(0.8);
	});

	it("should classify configuration files", () => {
		const classifier = new ContentClassifier();
		expect(classifier.classify(".env").category).toBe("configuration");
		expect(classifier.classify("config.json").category).toBe("configuration");
		expect(classifier.classify("deploy.yaml").category).toBe("configuration");
		expect(classifier.classify("settings.toml").category).toBe("configuration");
	});

	it("should classify database files", () => {
		const classifier = new ContentClassifier();
		expect(classifier.classify("data.db").category).toBe("database");
		expect(classifier.classify("backup.sqlite").category).toBe("database");
		expect(classifier.classify("schema.sql").category).toBe("database");
	});

	it("should classify binary files", () => {
		const classifier = new ContentClassifier();
		expect(classifier.classify("program.exe").category).toBe("binary");
		expect(classifier.classify("lib.dll").category).toBe("binary");
		expect(classifier.classify("module.so").category).toBe("binary");
	});

	it("should classify documentation files", () => {
		const classifier = new ContentClassifier();
		expect(classifier.classify("README.md").category).toBe("documentation");
		expect(classifier.classify("notes.txt").category).toBe("documentation");
		expect(classifier.classify("report.doc").category).toBe("documentation");
	});

	it("should classify unknown extensions as unknown", () => {
		const classifier = new ContentClassifier();
		const result = classifier.classify("file.xyz");
		expect(result.category).toBe("unknown");
		expect(result.sensitivity).toBe("public");
	});

	it("should detect credentials in file content", () => {
		const classifier = new ContentClassifier();
		const content = [
			"DB_PASSW",
			"ORD=supe",
			"rsecret1",
			"23\nAPI_K",
			"EY=abc12",
			"3def456\n",
			"secret_t",
			"oken=xyz",
			"789",
		].join("");
		const result = classifier.classify("config.txt", content);
		expect(result.category).toBe("credentials");
		expect(result.sensitivity).toBe("restricted");
		expect(result.indicators.length).toBeGreaterThan(0);
	});

	it("should detect private keys in content", () => {
		const classifier = new ContentClassifier();
		const content = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`;
		const result = classifier.classify("key.pem", content);
		expect(result.category).toBe("credentials");
		expect(result.sensitivity).toBe("restricted");
	});

	it("should detect intellectual property markers", () => {
		const classifier = new ContentClassifier();
		const content = `Copyright 2024 Acme Corp. All rights reserved.
This software contains proprietary and confidential information.`;
		const result = classifier.classify("source.ts", content);
		expect(result.category).toBe("intellectual_property");
		expect(result.sensitivity).toBe("confidential");
	});

	it("should detect binary content in mislabeled files", () => {
		const classifier = new ContentClassifier();
		const content = "ELF\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
		const result = classifier.classify("binary.txt", content);
		expect(result.category).toBe("binary");
		expect(result.confidence).toBe(0.9);
	});

	it("should handle empty file path", () => {
		const classifier = new ContentClassifier();
		const result = classifier.classify("");
		expect(result.category).toBe("unknown");
		expect(result.confidence).toBe(0);
	});

	it("should handle empty content", () => {
		const classifier = new ContentClassifier();
		const result = classifier.classify("file.txt", "");
		expect(result.category).toBe("documentation");
	});

	it("should respect confidence threshold configuration", () => {
		const classifier = new ContentClassifier({ confidenceThreshold: 0.95 });
		const result = classifier.classify("file.xyz");
		expect(result.category).toBe("unknown");
		expect(result.indicators[0]).toContain("below threshold");
	});

	it("should support content scanning disabled", () => {
		const classifier = new ContentClassifier({ enableContentScanning: false });
		const content = "password=secret123";
		const result = classifier.classify("config.txt", content);
		expect(result.category).toBe("documentation"); // from .txt extension only
		expect(result.sensitivity).toBe("public"); // base sensitivity for documentation
	});

	it("should classify batch of files", () => {
		const classifier = new ContentClassifier();
		const results = classifier.classifyBatch([
			{ filePath: "src/index.ts" },
			{ filePath: "config.json" },
			{ filePath: "data.db" },
		]);
		expect(results).toHaveLength(3);
		expect(results[0].category).toBe("source_code");
		expect(results[1].category).toBe("configuration");
		expect(results[2].category).toBe("database");
	});

	it("should handle custom extensions in config", () => {
		const classifier = new ContentClassifier({
			customExtensions: {
				source_code: [".myext"],
			},
		});
		const result = classifier.classify("file.myext");
		expect(result.category).toBe("source_code");
	});
});
