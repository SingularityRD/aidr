#!/usr/bin/env node
import { createHash, createHmac } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { canonicalJson, validateSoldScope } from "./evaluate.mjs";

function fail(message) { throw new Error(message); }
function options(argv) {
	const out = {};
	for (let i = 0; i < argv.length; i += 1) {
		if (argv[i] === "--force") { out.force = true; continue; }
		if (!["--spec", "--scope-file", "--output"].includes(argv[i]) || !argv[i + 1]) fail("usage: generate-corpus.mjs --spec PATH --scope-file PATH --output PATH [--force]");
		out[argv[i].slice(2)] = argv[++i];
	}
	for (const key of ["spec", "scope-file", "output"]) if (!out[key]) fail(`missing --${key}`);
	return out;
}
function digest(value) { return createHash("sha256").update(value).digest("hex"); }
function counterPrng(key) {
	let counter = 0n;
	return () => {
		const bytes = Buffer.alloc(8);
		bytes.writeBigUInt64BE(counter++);
		return createHmac("sha256", key).update(bytes).digest();
	};
}

try {
	const args = options(process.argv.slice(2));
	const spec = JSON.parse(readFileSync(resolve(args.spec), "utf8"));
	if (spec.schema_version !== 1 || spec.provenance !== "synthetic_open") fail("generator only accepts schema_version 1 synthetic_open specs");
	const sold = validateSoldScope(JSON.parse(readFileSync(resolve(args["scope-file"]), "utf8")));
	const random = counterPrng(spec.hmac_key);
	const cases = [];
	let index = 0;
	const minimum = (dimension, id, oracle) => sold.overrides[`${dimension}:${id}`]?.[`minimum_${oracle === "malicious" ? "malicious_cases" : "benign_twins"}`] ?? sold.minimums[oracle];
	const add = (oracle, family, connector = sold.requiredConnectors[index % sold.requiredConnectors.length], surface = sold.requiredSurfaces[index % sold.requiredSurfaces.length]) => {
		const token = random().toString("hex").slice(0, 24);
		const content = (oracle === "malicious" ? spec.malicious_template : spec.benign_template).replace("{token}", token);
		const splitByte = createHmac("sha256", spec.partition_key).update(digest(content)).digest()[0];
		cases.push({ case_id: `syn-${String(index + 1).padStart(4, "0")}-${token.slice(0, 8)}`, partition: splitByte < Math.round((spec.holdout_percent / 100) * 256) ? "holdout" : "development", oracle, family, connector, surface, content, content_sha256: digest(content) });
		index += 1;
	};
	for (const family of sold.requiredAttackFamilies) for (const oracle of ["malicious", "benign"])
		while (cases.filter((entry) => entry.family === family && entry.oracle === oracle).length < minimum("attack_family", family, oracle)) add(oracle, family);
	for (const connector of sold.requiredConnectors) for (const oracle of ["malicious", "benign"])
		while (cases.filter((entry) => entry.connector === connector && entry.oracle === oracle).length < minimum("connector", connector, oracle)) add(oracle, sold.requiredAttackFamilies[index % sold.requiredAttackFamilies.length], connector);
	for (const surface of sold.requiredSurfaces) for (const oracle of ["malicious", "benign"])
		while (cases.filter((entry) => entry.surface === surface && entry.oracle === oracle).length < minimum("surface", surface, oracle)) add(oracle, sold.requiredAttackFamilies[index % sold.requiredAttackFamilies.length], undefined, surface);
	// Deterministically ensure each partition contains both oracle classes without changing content.
	for (const oracle of ["malicious", "benign"]) {
		const classCases = cases.filter((entry) => entry.oracle === oracle);
		if (!classCases.some((entry) => entry.partition === "holdout")) classCases[0].partition = "holdout";
		if (!classCases.some((entry) => entry.partition === "development")) classCases.at(-1).partition = "development";
	}
	const corpus = {
		schema_version: 1, corpus_id: spec.corpus_id, version: spec.version, provenance: "synthetic_open",
		rule_author_id: spec.rule_author_id, oracle_reviewer_id: spec.oracle_reviewer_id,
		scope: { required_attack_families: sold.requiredAttackFamilies, required_connectors: sold.requiredConnectors, required_surfaces: sold.requiredSurfaces },
		cases,
		generation: { algorithm: "HMAC-SHA256-counter", spec_sha256: digest(Buffer.from(canonicalJson(spec), "utf8")), customer_gate_eligible: false },
	};
	writeFileSync(resolve(args.output), `${JSON.stringify(corpus, null, 2)}\n`, { flag: args.force ? "w" : "wx" });
} catch (error) {
	process.stderr.write(`corpus generation failed: ${error.message}\n`);
	process.exitCode = 1;
}
