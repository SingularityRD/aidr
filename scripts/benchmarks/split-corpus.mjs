#!/usr/bin/env node
import { createHash, createHmac } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { canonicalJson, validateCorpusStructure } from "./evaluate.mjs";

function fail(message) { throw new Error(message); }
function sha(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function options(argv) {
	const out = {};
	for (let i = 0; i < argv.length; i += 1) {
		if (argv[i] === "--force") { out.force = true; continue; }
		if (!["--corpus", "--key", "--holdout-percent", "--output", "--split-manifest"].includes(argv[i]) || !argv[i + 1]) fail("usage: split-corpus.mjs --corpus PATH --key KEY --holdout-percent N --output PATH --split-manifest PATH [--force]");
		out[argv[i].slice(2)] = argv[++i];
	}
	for (const key of ["corpus", "key", "holdout-percent", "output", "split-manifest"]) if (!out[key]) fail(`missing --${key}`);
	return out;
}

try {
	const args = options(process.argv.slice(2));
	const outputPath = resolve(args.output);
	const manifestPath = resolve(args["split-manifest"]);
	if (outputPath === manifestPath) fail("--output and --split-manifest must be distinct paths");
	const corpus = JSON.parse(readFileSync(resolve(args.corpus), "utf8"));
	validateCorpusStructure(corpus);
	const percent = Number(args["holdout-percent"]);
	if (!Number.isFinite(percent) || percent <= 0 || percent >= 100) fail("--holdout-percent must be greater than 0 and less than 100");
	const threshold = Math.round((percent / 100) * 256);
	const partitionless = { ...corpus, cases: corpus.cases.map(({ partition: _partition, ...entry }) => entry) };
	const assignmentByDigest = new Map();
	for (const entry of partitionless.cases) {
		const contentSha = entry.content_sha256.toLowerCase();
		const byte = createHmac("sha256", args.key).update(contentSha).digest()[0];
		assignmentByDigest.set(contentSha, { content_sha256: contentSha, partition: byte < threshold ? "holdout" : "development" });
	}
	const assignments = [...assignmentByDigest.values()].sort((a, b) => a.content_sha256.localeCompare(b.content_sha256));
	const byDigest = new Map(assignments.map((entry) => [entry.content_sha256, entry.partition]));
	const splitCorpus = { ...corpus, cases: corpus.cases.map((entry) => ({ ...entry, partition: byDigest.get(entry.content_sha256.toLowerCase()) })) };
	for (const partition of ["development", "holdout"]) for (const oracle of ["malicious", "benign"])
		if (!splitCorpus.cases.some((entry) => entry.partition === partition && entry.oracle === oracle)) fail(`digest-keyed split produced no ${oracle} case in ${partition}; use a different key`);
	const manifest = {
		schema_version: 1,
		kind: "aidr-content-digest-split-manifest",
		algorithm: "HMAC-SHA256-content-digest-v1",
		holdout_percent: percent,
		source_corpus_sha256: sha(Buffer.from(canonicalJson(partitionless), "utf8")),
		assignments,
	};
	const flag = args.force ? "w" : "wx";
	writeFileSync(outputPath, `${JSON.stringify(splitCorpus, null, 2)}\n`, { flag });
	writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { flag });
} catch (error) {
	process.stderr.write(`corpus split failed: ${error.message}\n`);
	process.exitCode = 1;
}
