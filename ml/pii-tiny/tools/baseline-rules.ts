// Rules-only baseline: run Browser Guard's shipped detection over gold JSONL and emit the
// PERSON/ADDRESS/LOCATION spans it finds, in eval.py's format.
//   esbuild tools/baseline-rules.ts --bundle --platform=node --format=esm --outfile=out/baseline.mjs
//   node out/baseline.mjs out/eval.jsonl out/pred-rules.jsonl
import { readFileSync, writeFileSync } from "node:fs";
import { DEFAULT_POLICY } from "../../../packages/browser-guard/src/background/policy.js";
import { createDetectionEngine } from "../../../packages/browser-guard/src/engine/detect.js";

const [input, output] = process.argv.slice(2);
const engine = createDetectionEngine({
	enabledEntities: [...DEFAULT_POLICY.enabledEntities, "LOCATION"],
	literals: [],
	exactData: [],
	detectSignals: false,
	maxInputChars: 200_000,
	maxScanMs: 5_000,
});
const keep = new Set(["PERSON", "ADDRESS", "LOCATION"]);
const lines: string[] = [];
for (const line of readFileSync(input, "utf8").split("\n")) {
	if (!line.trim()) continue;
	const { text } = JSON.parse(line);
	const result = await engine.scan(text);
	const spans = result.findings
		.filter((f) => keep.has(f.type))
		.map((f) => ({ start: f.start, end: f.end, label: f.type }));
	lines.push(JSON.stringify({ text, spans }));
}
writeFileSync(output, `${lines.join("\n")}\n`);
