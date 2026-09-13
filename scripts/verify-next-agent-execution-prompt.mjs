#!/usr/bin/env node
import { readFileSync } from "node:fs";

const promptPath = process.env.AIDR_NEXT_AGENT_PROMPT ?? "docs/production-readiness/next-agent-execution-prompt-v8.md";
const negativeSelfTest = process.argv.includes("--self-test-negative");
const sourcePrompt = readFileSync(promptPath, "utf8");
const prompt = negativeSelfTest
	? sourcePrompt.replace("## Kanıt defteri ve candidate bağlama", "## intentionally removed evidence section")
	: sourcePrompt;
const features = JSON.parse(readFileSync("FEATURE_INVENTORY.json", "utf8"));
const gaps = JSON.parse(readFileSync("PRODUCTION_SALES_GAPS.json", "utf8"));
const backlog = JSON.parse(readFileSync("READINESS_BACKLOG.json", "utf8"));
const failures = [];

const verificationCommands = [
	"git diff --check",
	"node scripts/generate-feature-inventory.mjs",
	"node scripts/generate-production-sales-gap-audit.mjs",
	"node scripts/verify-next-agent-execution-prompt.mjs",
	"pnpm check",
	"pnpm quality:static",
	"pnpm audit:prod",
	"pnpm supabase:check",
	"pnpm verify:enforcement",
	"pnpm verify:codex",
	"pnpm test:ci",
	"pnpm test:coverage",
	"pnpm build:release",
	"python -m pip install -r services/aig-bridge/requirements-test.txt",
	"python -m pytest services/aig-bridge/tests -q",
	"node scripts/verify-support-bundle.mjs --self-test",
	"node scripts/privacy-verify.mjs",
	"node docs/scripts/claim-check.mjs --mode=inventory --json",
	"pnpm verify:native-host",
	"pnpm test:e2e",
	"pnpm aig:verify",
	"pnpm test:e2e:negative",
	"pnpm verify:fleet:windows",
	"pnpm verify:fleet:unix",
	"pnpm verify:monitoring",
	"pnpm verify:upgrade",
	"pnpm verify:support-bundle",
	"pnpm verify:load",
	"pnpm verify:release-signing",
	"pnpm verify:backup-offsite",
	"pnpm verify:offboarding",
	"pnpm verify:customer-onboarding",
	"pnpm test:customer-demo",
];

const requiredSections = [
	"## Kesin görev ve tamamlanma sözleşmesi",
	"## Otorite ve çalışma kuralları",
	"## Çok ajanlı yürütme",
	"## Zorunlu çalışma ve yeniden doğrulama döngüsü",
	"## Her özellik için Definition of Done",
	"## Desteklenen teslimat profilleri",
	"## Uygulama sırası",
	"### Faz 2 — Feature-level kısmi ve eksik yüzeyleri uzlaştır",
	"### Faz 3 — T01-T46 eksiksiz teknik/operasyon matrisi",
	"### Faz 4 — Açık readiness backlog",
	"### Faz 5 — Ticari ve dış kanıt kapıları",
	"## Zorunlu saldırı, müdahale ve benign-twin matrisi",
	"## Güncel pazar ve ürün farkı denetimi",
	"## Kanıt defteri ve candidate bağlama",
	"## Güvenlik invariantları",
	"## Zorunlu yerel doğrulama",
	"## Kaynak ve kapasite doğrulaması",
	"## Üretilecek teslimatlar",
	"## Bitiş ve raporlama biçimi",
];

function requireText(value, label = value) {
	if (!prompt.includes(value)) failures.push(`missing ${label}`);
}

function literalCount(value) {
	let count = 0;
	let offset = 0;
	while ((offset = prompt.indexOf(value, offset)) !== -1) {
		count += 1;
		offset += value.length;
	}
	return count;
}

function requireExactlyOnce(value, label = value) {
	const count = literalCount(value);
	if (count !== 1) failures.push(`${label} expected once, found ${count}`);
}

function requireUniqueIds(rows, group) {
	const ids = rows.map((row) => row.id);
	const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
	if (duplicates.length) failures.push(`${group} duplicate ids: ${[...new Set(duplicates)].join(", ")}`);
}

requireUniqueIds(features.features, "features");
requireUniqueIds(gaps.engineering_and_operations, "technical tasks");
requireUniqueIds(gaps.commercial_and_external, "external gates");
requireUniqueIds(backlog.findings, "backlog");

let previousSectionOffset = -1;
for (const section of requiredSections) {
	const offset = prompt.indexOf(section);
	if (offset === -1) failures.push(`missing section ${section}`);
	else if (offset <= previousSectionOffset) failures.push(`section out of order ${section}`);
	else previousSectionOffset = offset;
}

const h2Headings = [...prompt.matchAll(/^## .+$/gm)].map((match) => match[0]);
const duplicateH2 = h2Headings.filter((heading, index) => h2Headings.indexOf(heading) !== index);
if (duplicateH2.length) failures.push(`duplicate H2 headings: ${[...new Set(duplicateH2)].join(", ")}`);

for (const feature of features.features.filter((row) => row.status !== "wired")) {
	requireExactlyOnce(`- **${feature.id} — ${feature.name} (${feature.status})**`, `feature ${feature.id}`);
	for (const sourcePath of feature.source_paths) requireText(sourcePath, `feature ${feature.id} source ${sourcePath}`);
}

for (const task of gaps.engineering_and_operations) {
	requireExactlyOnce(`#### ${task.id} — ${task.title} [${task.priority}; ${task.status}]`, `task ${task.id}`);
	requireText(`- Zorunlu kapanış testi: ${task.acceptance}`, `task ${task.id} acceptance`);
	requireText(`- Dış bağımlılık/sınır: ${task.dependencies}`, `task ${task.id} dependency`);
}

for (const gate of gaps.commercial_and_external) {
	requireExactlyOnce(`#### ${gate.id} — ${gate.title} [${gate.status}]`, `external gate ${gate.id}`);
	requireText(`- Sorumlu: ${gate.owner_role}`, `external gate ${gate.id} owner`);
	requireText(`- Otomatik kontrol: ${gate.automated_check}`, `external gate ${gate.id} check`);
}

for (const finding of backlog.findings.filter((row) => row.status !== "VERIFIED_CLOSED")) {
	requireExactlyOnce(`- **${finding.id} — ${finding.feature} [${finding.priority}; ${finding.status}]**: ${finding.acceptanceCriteria}`, `backlog ${finding.id}`);
}

for (const command of verificationCommands) requireText(command, `verification command ${command}`);

for (const invariant of [
	"Dış kanıt uydurma",
	"Fail-closed davranışı koru",
	"git reset --hard",
	"publisher_authenticated=false",
	"AIDR_E2E_RC_DIGEST",
	"BIL-03",
	"MKT-01",
	"LOCAL_ENGINEERING_READY",
	"RELEASE_CANDIDATE_READY",
	"PRODUCTION_SALES_GO",
	"atomik commit",
	"benign-twin",
	"cross-tenant",
	"observable davranış",
	"aynı commit ve aynı candidate digest",
	"Managed cloud control plane + customer endpoints",
	"Customer self-hosted control plane + customer endpoints",
	"source inspection, unit/contract, packaged-consumer, isolated integration, native host, deployed environment, customer-observed ve externally-approved",
	"Bir tur sonunda yerel OPEN/partial/backlog kaldıysa final cevap yazıp görevi bitirme",
]) requireText(invariant, `invariant ${invariant}`);

for (const field of [
	"gate_id", "task_ids", "feature_ids", "status", "command", "exit_code",
	"started_at_utc", "ended_at_utc", "duration_ms", "commit_sha", "candidate_digest",
	"environment", "tool_versions", "test_counts", "observed_effect", "log_sha256",
	"artifact_sha256", "limitations", "owner",
]) requireText(`\`${field}\``, `evidence field ${field}`);

for (let step = 1; step <= 28; step += 1) {
	const expression = new RegExp(`^${step}\\. `, "m");
	if (!expression.test(prompt)) failures.push(`missing verification step ${step}`);
}

requireText(`${features.features.length} özellik`, "feature count");
requireText(`${gaps.engineering_and_operations.length} iş`, "technical task count");
requireText(`${gaps.commercial_and_external.length} kapı`, "external gate count");
requireText(`${backlog.findings.length} bulgudan`, "backlog count");

const bytes = Buffer.byteLength(prompt);
if (bytes < 100_000) failures.push(`prompt unexpectedly small: ${bytes} bytes`);
if (prompt.includes("\r")) failures.push("prompt contains CRLF characters");
if (!prompt.endsWith("\n")) failures.push("prompt must end with one newline");
if (prompt.endsWith("\n\n")) failures.push("prompt has an extra blank line at EOF");

if (negativeSelfTest) {
	const expectedFailure = failures.some((failure) => failure.includes("missing section ## Kanıt defteri ve candidate bağlama"));
	if (!expectedFailure) {
		console.error("Negative self-test failed: validator accepted a prompt with a required section removed.");
		process.exit(1);
	}
	console.log(JSON.stringify({ passed: true, negative_self_test: "required-section-removal-detected", detected_failures: failures.length }));
	process.exit(0);
}

if (failures.length) {
	console.error(`Next-agent prompt verification failed:\n- ${failures.join("\n- ")}`);
	process.exit(1);
}

console.log(JSON.stringify({
	passed: true,
	prompt: promptPath,
	bytes,
	lines: prompt.split("\n").length - 1,
	sections: requiredSections.length,
	incomplete_features: features.features.filter((row) => row.status !== "wired").length,
	technical_tasks: gaps.engineering_and_operations.length,
	unresolved_backlog: backlog.findings.filter((row) => row.status !== "VERIFIED_CLOSED").length,
	external_gates: gaps.commercial_and_external.length,
	required_commands: verificationCommands.length,
	verification_steps: 28,
}));
