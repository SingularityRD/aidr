#!/usr/bin/env node
import { readFileSync } from "node:fs";

const promptPath = "docs/production-readiness/next-agent-execution-prompt-v8.md";
const prompt = readFileSync(promptPath, "utf8");
const features = JSON.parse(readFileSync("FEATURE_INVENTORY.json", "utf8"));
const gaps = JSON.parse(readFileSync("PRODUCTION_SALES_GAPS.json", "utf8"));
const backlog = JSON.parse(readFileSync("READINESS_BACKLOG.json", "utf8"));
const failures = [];

function requireText(value, label = value) {
	if (!prompt.includes(value)) failures.push(`missing ${label}`);
}

for (const feature of features.features.filter((row) => row.status !== "wired")) requireText(`**${feature.id} —`, `feature ${feature.id}`);
for (const task of gaps.engineering_and_operations) requireText(`#### ${task.id} —`, `task ${task.id}`);
for (const gate of gaps.commercial_and_external) requireText(`#### ${gate.id} —`, `external gate ${gate.id}`);
for (const finding of backlog.findings.filter((row) => row.status !== "VERIFIED_CLOSED")) requireText(`**${finding.id} —`, `backlog ${finding.id}`);

for (const command of [
	"git diff --check",
	"node scripts/generate-feature-inventory.mjs",
	"node scripts/generate-production-sales-gap-audit.mjs",
	"pnpm check",
	"pnpm quality:static",
	"pnpm audit:prod",
	"pnpm supabase:check",
	"pnpm verify:enforcement",
	"pnpm verify:codex",
	"pnpm test:ci",
	"pnpm test:coverage",
	"pnpm build:release",
	"pnpm verify:native-host",
	"pnpm test:e2e",
	"node docs/scripts/claim-check.mjs --mode=inventory --json",
]) requireText(command, `verification command ${command}`);

for (const invariant of [
	"Dış kanıt uydurma",
	"Fail-closed davranışı koru",
	"git reset --hard",
	"publisher_authenticated=false",
	"AIDR_E2E_RC_DIGEST",
	"BIL-03",
	"MKT-01",
	"LOCAL_ENGINEERING_READY",
]) requireText(invariant, `invariant ${invariant}`);

requireText(`${features.features.length} özellik`, "feature count");
requireText(`${gaps.engineering_and_operations.length} iş`, "technical task count");
requireText(`${gaps.commercial_and_external.length} kapı`, "external gate count");

if (failures.length) {
	console.error(`Next-agent prompt verification failed:\n- ${failures.join("\n- ")}`);
	process.exit(1);
}

console.log(JSON.stringify({
	passed: true,
	prompt: promptPath,
	bytes: Buffer.byteLength(prompt),
	incomplete_features: features.features.filter((row) => row.status !== "wired").length,
	technical_tasks: gaps.engineering_and_operations.length,
	unresolved_backlog: backlog.findings.filter((row) => row.status !== "VERIFIED_CLOSED").length,
	external_gates: gaps.commercial_and_external.length,
	required_commands: 15,
}));
