/**
 * Tests for the local CI runner (scripts/ci-local.mjs) and its pure planning
 * layer (scripts/lib/ci-local-plan.mjs).
 *
 *   node --test scripts/ci-local.test.mjs
 *
 * The drift tests are the contract that keeps `pnpm ci:local` equivalent to
 * .github/workflows/ci.yml: they fail when ci.yml gains a job or a `run:` step
 * with no local counterpart, when a local reference goes stale, when an
 * explicitly covered CI step starts calling something the local command does
 * not, and when `quality:gate` gains a component.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
	CI_WORKFLOW_PATH,
	GROUPS,
	ONPREM_EXTRA_SUITE_PATTERNS,
	REQUIREMENTS,
	STATUS,
	STEPS,
	TOOL_SOURCES,
	blockingDependency,
	buildReport,
	ciRunTokens,
	computeDrift,
	evaluateRequirements,
	expandScriptChain,
	findCiStep,
	formatDuration,
	formatSummary,
	parseArgs,
	parsePinnedTarball,
	referencedSecrets,
	resolveCiStep,
	selectExtraSuites,
	selectSteps,
	substituteExpressions,
	summarize,
	versionAtLeast,
} from "./lib/ci-local-plan.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { parse } = createRequire(path.join(root, "packages/core/package.json"))("yaml");
const workflow = parse(readFileSync(path.join(root, CI_WORKFLOW_PATH), "utf8"));
const rootPackage = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
const rootScripts = rootPackage.scripts;
const clone = (value) => structuredClone(value);
const ids = (list) => list.map((entry) => entry.id);

// ─── drift against the real ci.yml ────────────────────────────────────────

test("the local plan represents every ci.yml job and run: step (no drift)", () => {
	assert.deepEqual(computeDrift(workflow, STEPS, { rootScripts }), []);
});

test("every literal ci.yml step and cleanup resolves without unsupported expressions", () => {
	for (const entry of STEPS) {
		for (const ref of [entry.ci, entry.cleanup].filter(Boolean)) {
			const resolved = resolveCiStep(workflow, ref, { secrets: {} });
			assert.ok(resolved.run.trim().length > 0, `${entry.id} resolved to an empty command`);
			assert.doesNotMatch(resolved.run, /\$\{\{/u, `${entry.id} left an expression unresolved`);
		}
	}
});

test("drift: a new ci.yml job with no local step is reported", () => {
	const changed = clone(workflow);
	changed.jobs["new-gate"] = { "runs-on": "ubuntu-22.04", steps: [{ name: "New gate", run: "pnpm verify:something-new" }] };
	const problems = computeDrift(changed, STEPS, { rootScripts });
	assert.ok(problems.some((problem) => problem.includes('"new-gate / New gate" has no local step')), problems.join("\n"));
	assert.ok(problems.some((problem) => problem.includes('job "new-gate" has no local counterpart')), problems.join("\n"));
});

test("drift: a new run: step in an existing job is reported", () => {
	const changed = clone(workflow);
	changed.jobs.privacy.steps.push({ name: "Privacy fuzzing", run: "pnpm test:privacy:fuzz" });
	const problems = computeDrift(changed, STEPS, { rootScripts });
	assert.deepEqual(problems, ['ci.yml "privacy / Privacy fuzzing" has no local step (add one to scripts/lib/ci-local-plan.mjs or list it in CI_ONLY_STEPS with a reason)']);
});

test("drift: a ci.yml step listed in CI_ONLY_STEPS with a reason is accepted, a reasonless one is not", () => {
	const changed = clone(workflow);
	changed.jobs.privacy.steps.push({ name: "Hosted-only probe", run: "echo hosted" });
	assert.deepEqual(computeDrift(changed, STEPS, { rootScripts, ciOnly: [{ job: "privacy", step: "Hosted-only probe", reason: "needs the hosted runner" }] }), []);
	const problems = computeDrift(changed, STEPS, { rootScripts, ciOnly: [{ job: "privacy", step: "Hosted-only probe", reason: "" }] });
	assert.ok(problems.some((problem) => problem.includes("needs a reason")), problems.join("\n"));
	const stale = computeDrift(workflow, STEPS, { rootScripts, ciOnly: [{ job: "privacy", step: "Gone", reason: "x" }] });
	assert.ok(stale.some((problem) => problem.includes("stale CI_ONLY_STEPS entry")), stale.join("\n"));
});

test("drift: renaming a referenced ci.yml step reports the stale local reference", () => {
	const changed = clone(workflow);
	findCiStep(changed, "helm", "Lint and render the chart").name = "Lint, render and package the chart";
	const problems = computeDrift(changed, STEPS, { rootScripts });
	assert.ok(problems.some((problem) => problem.startsWith('stale reference: local step "helm" points at ci.yml "helm / Lint and render the chart"')), problems.join("\n"));
	assert.ok(problems.some((problem) => problem.includes('"helm / Lint, render and package the chart" has no local step')), problems.join("\n"));
});

test("drift: an explicitly covered ci.yml step that starts calling a new script or file is reported", () => {
	const changed = clone(workflow);
	const helm = findCiStep(changed, "helm", "Lint and render the chart");
	helm.run = "pnpm verify:helm && pnpm verify:helm-package && node --test deploy/helm/package.test.mjs";
	const problems = computeDrift(changed, STEPS, { rootScripts });
	assert.ok(problems.some((problem) => problem.includes('runs "pnpm verify:helm-package"')), problems.join("\n"));
	assert.ok(problems.some((problem) => problem.includes('runs "deploy/helm/package.test.mjs"')), problems.join("\n"));
});

test("drift: a literal (ci:) step picks up ci.yml changes by construction", () => {
	const changed = clone(workflow);
	findCiStep(changed, "privacy", "Build and test packages/privacy").run = "pnpm test:privacy && pnpm test:privacy:extra";
	assert.deepEqual(computeDrift(changed, STEPS, { rootScripts }), []);
	const entry = STEPS.find((candidate) => candidate.id === "privacy");
	assert.equal(resolveCiStep(changed, entry.ci).run, "pnpm test:privacy && pnpm test:privacy:extra");
});

test("drift: a new quality:gate / quality:static component must be run by a local step", () => {
	const problems = computeDrift(workflow, STEPS, { rootScripts: { ...rootScripts, "quality:static": `${rootScripts["quality:static"]} && node scripts/new-static-gate.mjs` } });
	assert.deepEqual(problems, ['"quality:gate" component "node scripts/new-static-gate.mjs" is not run by any local step']);
	const gate = computeDrift(workflow, STEPS, { rootScripts: { ...rootScripts, "quality:gate": `${rootScripts["quality:gate"]} && pnpm verify:sbom` } });
	assert.deepEqual(gate, ['"quality:gate" component "pnpm verify:sbom" is not run by any local step']);
});

test("drift: the decomposed quality-gate step must stay exactly `pnpm quality:gate`", () => {
	const changed = clone(workflow);
	findCiStep(changed, "quality-gate", "Type, lint, audit, tests, coverage and release build").run = "pnpm quality:gate && pnpm verify:extra";
	const problems = computeDrift(changed, STEPS, { rootScripts });
	assert.ok(problems.some((problem) => problem.includes('must stay exactly "pnpm quality:gate"')), problems.join("\n"));
});

test("expandScriptChain flattens quality:* chains and rejects missing scripts", () => {
	const leaves = expandScriptChain("quality:gate", rootScripts);
	assert.ok(leaves.includes("pnpm lint") && leaves.includes("pnpm build:release") && leaves.includes("node scripts/demo-preflight.mjs --static"));
	assert.ok(!leaves.includes("pnpm quality:static"), "nested quality chains are expanded");
	assert.throws(() => expandScriptChain("quality:missing", rootScripts), /no script/u);
});

test("ciRunTokens extracts root scripts and repo files but not pnpm flags or dlx", () => {
	assert.deepEqual(ciRunTokens("pnpm verify:helm\npnpm --filter x test\npnpm dlx supabase@2 start\nnode --test scripts/a.test.mjs deploy/b/c.test.mjs\npnpm -C packages/dashboard build\npnpm run test:privacy"), [
		"deploy/b/c.test.mjs",
		"pnpm test:privacy",
		"pnpm verify:helm",
		"scripts/a.test.mjs",
	]);
});

// ─── catalog integrity ────────────────────────────────────────────────────

test("the step catalog is well formed", () => {
	const seen = new Set();
	const groups = new Set(GROUPS.map(([name]) => name));
	for (const entry of STEPS) {
		assert.ok(!seen.has(entry.id), `duplicate step id ${entry.id}`);
		seen.add(entry.id);
		assert.ok(groups.has(entry.group), `${entry.id} has unknown group ${entry.group}`);
		const kinds = [entry.run, entry.ci, entry.internal, entry.expand].filter(Boolean);
		assert.equal(kinds.length, 1, `${entry.id} needs exactly one of run / ci / internal / expand`);
		assert.ok(entry.timeoutMs > 0, `${entry.id} needs a timeout`);
		for (const requirement of entry.requires) assert.ok(REQUIREMENTS[requirement], `${entry.id} requires unknown ${requirement}`);
		if (entry.requires.includes("release-candidate")) assert.ok(entry.requiresFile, `${entry.id} must name the file it needs`);
		if (entry.phase) assert.equal(entry.group, "guards", `${entry.id}: only guards have a phase`);
	}
	for (const group of groups) assert.ok(STEPS.some((entry) => entry.group === group), `group ${group} has no steps`);
	assert.ok(STEPS.every((entry) => entry.optIn === undefined || entry.group === "real-host-e2e"), "only the real-host group is opt-in");
});

test("the task-level gates are all represented", () => {
	const commands = STEPS.map((entry) => entry.run ?? "").join("\n");
	for (const expected of ["pnpm install --frozen-lockfile", "pnpm build", "pnpm check", "pnpm lint", "pnpm test", "pnpm verify:helm", "pnpm verify:secrets:current", "scripts/validate-backlog.mjs", "scripts/verify-feature-acceptance.mjs", "scripts/check-generator-determinism.mjs", "scripts/brochure-facts.test.mjs", "scripts/render-feature-guide.test.mjs", "pnpm verify:repo-hygiene"]) {
		assert.ok(commands.includes(expected), `no local step runs ${expected}`);
	}
	const literal = new Set(STEPS.filter((entry) => entry.ci).map((entry) => entry.ci.join(" / ")));
	for (const ref of ["privacy / Build and test packages/privacy", "privacy-rules-drift / Verify privacy rules have not drifted", "workflow-lint / Parse every workflow and enforce the CI contract", "quality-gate / Supabase migration contract", "browser-guard / Real-browser E2E (hermetic fixtures)", "onprem-deploy / Bootstrap, upgrade, backup, restore-drill and config-reference gates"]) {
		assert.ok(literal.has(ref), `ci.yml ${ref} is not executed literally`);
	}
});

test("pnpm ci:local and ci:local:quick point at the runner and .ci-local is gitignored", () => {
	assert.equal(rootScripts["ci:local"], "node scripts/ci-local.mjs");
	assert.equal(rootScripts["ci:local:quick"], "node scripts/ci-local.mjs --quick");
	assert.match(readFileSync(path.join(root, ".gitignore"), "utf8"), /^\.ci-local\/$/mu);
});

// ─── selection ────────────────────────────────────────────────────────────

test("default selection runs everything except opt-in steps, guards first and last", () => {
	const { selected, notSelected } = selectSteps(STEPS);
	assert.equal(selected[0].id, "guard-home-record");
	assert.deepEqual(ids(selected.slice(-2)), ["guard-home-verify", "guard-tree-unchanged"]);
	assert.ok(!selected.some((entry) => entry.optIn));
	assert.deepEqual(notSelected.map((entry) => entry.id).sort(), ["real-e2e", "real-e2e-deps", "real-e2e-evidence"]);
	assert.ok(notSelected.every((entry) => entry.reason.startsWith("opt-in")));
	assert.equal(selected.length + notSelected.length, STEPS.length);
});

test("--only restricts to groups or ids (and selects opt-in groups), guards are added", () => {
	const { selected } = selectSteps(STEPS, { only: ["helm", "lint"] });
	assert.deepEqual(ids(selected), ["guard-home-record", "lint", "knip", "duplicates", "helm", "guard-home-verify", "guard-tree-unchanged"]);
	const optIn = selectSteps(STEPS, { only: ["real-host-e2e"], skip: ["guards"] });
	assert.deepEqual(ids(optIn.selected), ["real-e2e-deps", "real-e2e", "real-e2e-evidence"]);
});

test("--skip removes groups and ids; skipping guards removes them", () => {
	const { selected, notSelected } = selectSteps(STEPS, { skip: ["coverage", "bg-e2e", "guards"] });
	for (const id of ["coverage", "coverage-core", "bg-e2e", "guard-home-record", "guard-tree-unchanged"]) {
		assert.ok(!ids(selected).includes(id), `${id} should be skipped`);
		assert.equal(notSelected.find((entry) => entry.id === id)?.reason, "--skip");
	}
});

test("--quick keeps quick steps only, unless a step is named in --only", () => {
	const { selected } = selectSteps(STEPS, { quick: true });
	assert.ok(selected.every((entry) => entry.quick));
	for (const heavy of ["build", "vitest", "coverage", "bg-e2e", "supabase-postgres"]) assert.ok(!ids(selected).includes(heavy));
	for (const fast of ["lint", "check", "ci-local-drift", "validate-backlog", "privacy-rules"]) assert.ok(ids(selected).includes(fast));
	assert.ok(ids(selectSteps(STEPS, { quick: true, only: ["build"] }).selected).includes("build"));
});

test("unknown names fail selection instead of silently selecting nothing", () => {
	assert.throws(() => selectSteps(STEPS, { only: ["lnit"] }), /unknown group or step id: lnit/u);
	assert.throws(() => selectSteps(STEPS, { skip: ["nope"] }), /unknown group or step id: nope/u);
});

// ─── prerequisites ────────────────────────────────────────────────────────

test("a missing prerequisite yields the exact requirement and its fix", () => {
	const helm = STEPS.find((entry) => entry.id === "helm");
	const missing = evaluateRequirements(helm, { available: {}, detail: { helm: "helm not on PATH" } });
	assert.equal(missing.ok, false);
	assert.equal(missing.requirement, "helm");
	assert.match(missing.reason, /^Helm 3 \(ci\.yml pins v3\.19\.0\) not available \(helm not on PATH\)$/u);
	assert.match(missing.fix, /--fetch-tools/u);
	assert.deepEqual(evaluateRequirements(helm, { available: { helm: true } }), { ok: true });

	const postgres = STEPS.find((entry) => entry.id === "supabase-postgres");
	assert.equal(evaluateRequirements(postgres, { available: { network: true } }).requirement, "docker-daemon");

	const real = STEPS.find((entry) => entry.id === "real-e2e");
	const secrets = evaluateRequirements(real, { available: {}, detail: { "ci-secrets:real-e2e": "unset: ANTHROPIC_API_KEY" } });
	assert.match(secrets.reason, /unset: ANTHROPIC_API_KEY/u);
	assert.deepEqual(evaluateRequirements(real, { available: { "ci-secrets:real-e2e": true } }), { ok: true });
});

test("the Node 24 matrix leg is the only core leg that needs Node 24", () => {
	const legs = STEPS.filter((entry) => entry.group === "core-matrix");
	assert.deepEqual(legs.map((entry) => [entry.id, entry.nodeLeg, entry.requires]), [
		["core-node22", "current", []],
		["core-node24", "24", ["node24"]],
	]);
	assert.equal(evaluateRequirements(legs[0], { available: {} }).ok, true);
	assert.equal(evaluateRequirements(legs[1], { available: { node24: false }, detail: {} }).requirement, "node24");
});

// ─── ci.yml resolution ────────────────────────────────────────────────────

test("substituteExpressions honours env, matrix and secrets and rejects the rest", () => {
	assert.equal(substituteExpressions("v${{ matrix.node }} ${{ env.A }} [${{ secrets.S }}]", { env: { A: "a" }, matrix: { node: "24" }, secrets: {} }), "v24 a []");
	assert.throws(() => substituteExpressions("${{ github.run_id }}"), /unsupported expression/u);
	assert.throws(() => substituteExpressions("${{ env.MISSING }}"), /unresolved expression/u);
});

test("resolveCiStep layers workflow, job and step env and keeps working-directory", () => {
	const bridge = resolveCiStep(workflow, ["aig-bridge", "Audit and test bridge"]);
	assert.equal(bridge.workingDirectory, "services/aig-bridge");
	assert.equal(bridge.env.NODE_VERSION, workflow.env.NODE_VERSION);
	const e2e = resolveCiStep(workflow, ["real-host-e2e", "Run positive and negative connector suites"], { secrets: { ANTHROPIC_API_KEY: "k" } });
	assert.equal(e2e.env.ANTHROPIC_API_KEY, "k");
	assert.equal(e2e.env.CURSOR_API_KEY, "");
	assert.deepEqual(referencedSecrets(findCiStep(workflow, "real-host-e2e", "Run positive and negative connector suites")), ["AIDR_AGENT_PATH", "ANTHROPIC_API_KEY", "CURSOR_API_KEY", "OPENCLAW_GATEWAY_TOKEN"]);
	assert.throws(() => resolveCiStep(workflow, ["helm", "Setup Node.js (pinned)"]), /no run: block/u);
});

test("--fetch-tools reads every tool pin (url, sha256, archive member) from ci.yml", () => {
	for (const [name, ref] of Object.entries(TOOL_SOURCES)) {
		const pin = parsePinnedTarball(findCiStep(workflow, ...ref).run);
		assert.match(pin.url, /^https:\/\/github\.com\/.+\.tar\.gz$/u, name);
		assert.match(pin.sha256, /^[0-9a-f]{64}$/u, name);
		assert.ok(pin.member.endsWith(name), `${name} member ${pin.member}`);
	}
	assert.equal(parsePinnedTarball(findCiStep(workflow, ...TOOL_SOURCES.promtool).run).strip, 1);
	assert.throws(() => parsePinnedTarball("curl https://example.com/x"), /no longer has/u);
});

// ─── results ──────────────────────────────────────────────────────────────

const result = (id, status, extra = {}) => ({ id, group: "g", name: id, status, required: true, durationMs: 1200, ...extra });

test("exit code: 0 when everything passes or is skipped, 1 on a required failure only", () => {
	assert.equal(summarize([result("a", STATUS.PASS), result("b", STATUS.SKIPPED)]).exitCode, 0);
	assert.equal(summarize([result("a", STATUS.PASS), result("b", STATUS.FAIL)]).exitCode, 1);
	assert.equal(summarize([result("a", STATUS.FAIL, { required: false })]).exitCode, 0);
	assert.equal(summarize([result("a", STATUS.SKIPPED)], { strict: true }).exitCode, 1);
	assert.equal(summarize([result("a", STATUS.PASS)], { interrupted: true }).exitCode, 130);
	assert.deepEqual(summarize([result("a", STATUS.PASS), result("b", STATUS.FAIL), result("c", STATUS.NOT_RUN)]).counts, { PASS: 1, FAIL: 1, SKIPPED: 0, "NOT RUN": 1 });
});

test("the summary table lists SKIPPED steps with the missing prerequisite and fix", () => {
	const text = formatSummary(
		[
			result("lint", STATUS.PASS),
			result("helm", STATUS.SKIPPED, { reason: "Helm 3 not available (helm not on PATH)", fix: "rerun with --fetch-tools", durationMs: 0 }),
			result("vitest", STATUS.FAIL, { note: "exit 1", log: ".ci-local/logs/03-vitest.log" }),
			result("claims", STATUS.FAIL, { required: false, note: "exit 1" }),
			result("route-smoke", STATUS.NOT_RUN),
		],
		{ notSelected: [{ id: "real-e2e", reason: "opt-in, as in CI (select with --only real-host-e2e)" }] },
	);
	assert.match(text, /^STATUS\s+DURATION\s+GROUP\s+STEP\s+DETAIL$/mu);
	assert.match(text, /^SKIPPED\s+-\s+g\s+helm\s+Helm 3 not available \(helm not on PATH\)$/mu);
	assert.match(text, /^FAIL \(advisory\)\s+1\.2s\s+g\s+claims/mu);
	assert.match(text, /SKIPPED \(1\) - these CI gates did NOT run here/u);
	assert.match(text, /fix: rerun with --fetch-tools/u);
	assert.match(text, /FAILED \(1 required, 1 advisory\):\n {2}- vitest: exit 1 \(log: \.ci-local\/logs\/03-vitest\.log\)/u);
	assert.match(text, /NOT RUN \(1\) after the first required failure/u);
	assert.match(text, /opt-in, as in CI \(select with --only real-host-e2e\): real-e2e/u);
	assert.match(text, /RESULT: FAIL \(exit 1\)$/u);
	assert.match(formatSummary([result("a", STATUS.PASS)]), /RESULT: PASS \(exit 0\)$/u);
});

test("every step dependency names an earlier step, and the release consumers wait for build-release", () => {
	const order = STEPS.map((entry) => entry.id);
	for (const entry of STEPS) {
		for (const id of entry.after ?? []) {
			assert.ok(order.includes(id), `${entry.id} depends on unknown step ${id}`);
			assert.ok(order.indexOf(id) < order.indexOf(entry.id), `${entry.id} must run after ${id}`);
		}
	}
	for (const id of ["package-install", "route-smoke"]) {
		assert.deepEqual(STEPS.find((entry) => entry.id === id).after, ["build-release"]);
	}
});

test("a failed or not-run dependency blocks its consumers; an unselected or skipped one does not", () => {
	const consumer = { id: "route-smoke", after: ["build-release"] };
	assert.equal(blockingDependency(consumer, [result("build-release", STATUS.FAIL)]), "build-release");
	assert.equal(blockingDependency(consumer, [result("build-release", STATUS.NOT_RUN)]), "build-release");
	assert.equal(blockingDependency(consumer, [result("build-release", STATUS.PASS)]), null);
	assert.equal(blockingDependency(consumer, [result("build-release", STATUS.SKIPPED)]), null);
	assert.equal(blockingDependency(consumer, []), null);
	assert.equal(blockingDependency({ id: "lint" }, [result("build-release", STATUS.FAIL)]), null);
});

test("the summary names steps blocked by a dependency separately from a stop", () => {
	const text = formatSummary([
		result("build-release", STATUS.FAIL, { note: "exit 1" }),
		result("route-smoke", STATUS.NOT_RUN, { note: "blocked: build-release did not complete", blockedBy: "build-release" }),
	]);
	assert.match(text, /NOT RUN \(1\) because a step they consume did not complete in this run:\n {2}- route-smoke: needs build-release/u);
	assert.doesNotMatch(text, /after the first required failure/u);
	assert.match(text, /RESULT: FAIL \(exit 1\)$/u);
});

test("the JSON report carries per-step status, duration, reason and exit code", () => {
	const report = buildReport([result("helm", STATUS.SKIPPED, { reason: "r", fix: "f" }), result("lint", STATUS.PASS, { command: "pnpm lint", exitCode: 0 })], {
		startedAt: "2026-01-01T00:00:00.000Z",
		finishedAt: "2026-01-01T00:01:00.000Z",
		options: {},
		environment: {},
	});
	assert.equal(report.schema, "aidr.ci-local.report/v1");
	assert.equal(report.durationMs, 60_000);
	assert.equal(report.exitCode, 0);
	assert.deepEqual(report.counts, { PASS: 1, FAIL: 0, SKIPPED: 1, "NOT RUN": 0 });
	assert.deepEqual([report.steps[0].status, report.steps[0].reason, report.steps[0].fix], ["SKIPPED", "r", "f"]);
	assert.deepEqual([report.steps[1].command, report.steps[1].exitCode], ["pnpm lint", 0]);
});

test("formatDuration and versionAtLeast", () => {
	assert.equal(formatDuration(0), "-");
	assert.equal(formatDuration(1234), "1.2s");
	assert.equal(formatDuration(65_000), "1m05s");
	assert.ok(versionAtLeast("22.22.2", "22.16.0"));
	assert.ok(versionAtLeast("v24.0.0", "22.16.0"));
	assert.ok(!versionAtLeast("22.12.0", "22.16.0"));
	assert.ok(versionAtLeast("22.16.0", "22.16.0"));
});

// ─── arguments and extra suites ───────────────────────────────────────────

test("parseArgs understands every documented flag", () => {
	assert.deepEqual(parseArgs(["--only", "lint,check", "--only=helm", "--skip", "coverage", "--keep-going", "--quick", "--fetch-tools", "--allow-dirty", "--strict", "--list", "--json", "out.json"]), {
		help: false,
		list: true,
		only: ["lint", "check", "helm"],
		skip: ["coverage"],
		quick: true,
		keepGoing: true,
		fetchTools: true,
		allowDirty: true,
		strict: true,
		json: "out.json",
	});
	assert.equal(parseArgs(["--json"]).json, ".ci-local/report.json");
	assert.equal(parseArgs(["--json", "--keep-going"]).json, ".ci-local/report.json");
	assert.equal(parseArgs(["--", "--keep-going"]).keepGoing, true);
	assert.throws(() => parseArgs(["--only"]), /needs a group or step id/u);
	assert.throws(() => parseArgs(["--bogus"]), /unknown option: --bogus/u);
});

test("selectExtraSuites adds uncovered on-prem suites and never Postgres or duplicates", () => {
	const files = ["deployment-doctor.test.mjs", "deployment-smoke.test.mjs", "license.test.mjs", "onprem-licensed-bootstrap-postgres.test.mjs", "onprem-aig-compose.test.mjs", "deployment-doctor.mjs", "unrelated.test.mjs"];
	assert.deepEqual(selectExtraSuites(files, ONPREM_EXTRA_SUITE_PATTERNS, "node --test scripts/deployment-doctor.test.mjs"), [
		"scripts/deployment-smoke.test.mjs",
		"scripts/license.test.mjs",
		"scripts/onprem-aig-compose.test.mjs",
	]);
});

// ─── CLI smoke ────────────────────────────────────────────────────────────

test("the CLI lists every step and rejects unknown selections with exit 2", () => {
	const listed = spawnSync(process.execPath, [path.join(root, "scripts/ci-local.mjs"), "--list"], { cwd: root, encoding: "utf8" });
	assert.equal(listed.status, 0, listed.stderr);
	for (const entry of STEPS) assert.ok(listed.stdout.includes(`  ${entry.id}  `), `--list is missing ${entry.id}`);
	const bad = spawnSync(process.execPath, [path.join(root, "scripts/ci-local.mjs"), "--only", "no-such-group"], { cwd: root, encoding: "utf8" });
	assert.equal(bad.status, 2);
	assert.match(bad.stderr, /unknown group or step id: no-such-group/u);
});
