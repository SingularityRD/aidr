/**
 * Structural contract for .github/workflows.
 *
 * Parses every workflow as YAML (so a syntax error fails before GitHub sees it)
 * and pins the CI/release decisions that are easy to lose in review: immutable
 * action pins, the Node version lines, the on-prem/Helm/privacy/Browser Guard
 * gates, the real-HOME guard, privacy in the RC artifact set and the Browser
 * Guard release boundary.
 */

import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workflowDir = path.join(root, ".github", "workflows");
const { parseDocument } = createRequire(path.join(root, "packages/core/package.json"))("yaml");

// Root scripts owned by parallel workstreams (Helm chart, privacy rule sync,
// Browser Guard packaging, on-prem config reference). CI references them by
// their agreed names; until each lands, its absence is reported, not failed.
const PLANNED_ROOT_SCRIPTS = new Set([
	"build:browser-guard",
	"package:browser-guard",
	"verify:privacy-rules",
	"verify:onprem-config-reference",
	"verify:helm",
]);

const workflowFiles = readdirSync(workflowDir).filter((name) => /\.ya?ml$/u.test(name)).sort();
const raw = (name) => readFileSync(path.join(workflowDir, name), "utf8");
const parsed = new Map(
	workflowFiles.map((name) => {
		const document = parseDocument(raw(name), { prettyErrors: true, uniqueKeys: true });
		return [name, document];
	}),
);
const workflow = (name) => parsed.get(name).toJS();
const rootPackage = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));

function steps(job) {
	return (job.steps ?? []).map((step) => ({ ...step, text: `${step.name ?? ""}\n${step.run ?? ""}` }));
}

function stepNamed(job, name) {
	const found = (job.steps ?? []).find((step) => step.name === name);
	assert.ok(found, `step is missing: ${name}`);
	return found;
}

function runText(job) {
	return steps(job).map((step) => step.run ?? "").join("\n");
}

function pnpmScripts(text) {
	const names = new Set();
	for (const match of text.matchAll(/(?:^|[\s;&|(])pnpm (?!-|exec\b|install\b|dlx\b|--filter\b)([a-z][\w:-]*)/gmu)) names.add(match[1]);
	return names;
}

test("every workflow parses as a well-formed GitHub Actions document", () => {
	assert.ok(workflowFiles.length > 0);
	for (const [name, document] of parsed) {
		assert.deepEqual(document.errors.map(String), [], `${name} has YAML errors`);
		const data = document.toJS();
		assert.equal(typeof data.name, "string", `${name} needs a name`);
		assert.ok(data.on && typeof data.on === "object", `${name} needs triggers`);
		assert.ok(data.jobs && Object.keys(data.jobs).length > 0, `${name} needs jobs`);
		for (const [jobId, job] of Object.entries(data.jobs)) {
			assert.ok(job["runs-on"] || job.uses, `${name}:${jobId} needs runs-on`);
			for (const step of job.steps ?? []) {
				assert.ok(Boolean(step.uses) !== Boolean(step.run), `${name}:${jobId}:${step.name} needs exactly one of uses/run`);
			}
		}
	}
});

test("every action is pinned to one immutable commit with a version label", () => {
	const pins = new Map();
	for (const name of workflowFiles) {
		for (const line of raw(name).split(/\r?\n/u)) {
			const match = /^\s*(?:-\s+)?uses:\s*(\S+)(.*)$/u.exec(line);
			if (!match || match[1].startsWith("./")) continue;
			const pinned = /^([^@]+)@([0-9a-f]{40})$/u.exec(match[1]);
			assert.ok(pinned, `${name}: ${match[1]} must be pinned to a full commit SHA`);
			assert.match(match[2], /^ # v\d+(?:\.\d+){0,2}\b/u, `${name}: ${match[1]} needs a "# vX.Y.Z" label`);
			const action = pinned[1].split("/").slice(0, 2).join("/");
			const previous = pins.get(action);
			assert.ok(!previous || previous.sha === pinned[2], `${action} is pinned to ${previous?.sha} in ${previous?.file} and ${pinned[2]} in ${name}`);
			pins.set(action, { sha: pinned[2], file: name });
		}
	}
});

test("Node lines: minimum engine, Node 24 matrix leg and privacy floor stay consistent", () => {
	const ci = workflow("ci.yml");
	const { NODE_VERSION, NODE_24_VERSION, PRIVACY_NODE_VERSION } = ci.env;
	assert.equal(rootPackage.engines.node, `>=${NODE_VERSION}`, "CI minimum must equal the root engines floor");
	assert.match(String(NODE_24_VERSION), /^24\.\d+\.\d+$/u);
	const privacyEngines = JSON.parse(readFileSync(path.join(root, "packages/privacy/package.json"), "utf8")).engines.node;
	assert.equal(privacyEngines, `>=${PRIVACY_NODE_VERSION}`, "privacy CI must run at the privacy engines floor");
	assert.match(readFileSync(path.join(root, "services/../deploy/dashboard/Dockerfile"), "utf8"), new RegExp(`^FROM node:${NODE_24_VERSION.replaceAll(".", "\\.")}-`, "mu"));

	const matrix = ci.jobs["core-node-matrix"];
	assert.deepEqual(matrix.strategy.matrix.node, [NODE_VERSION, NODE_24_VERSION]);
	assert.equal(stepNamed(matrix, "Setup Node.js (pinned)").with["node-version"], "${{ matrix.node }}");
	assert.match(runText(matrix), /pnpm --filter @singularityrd\/aidr-core run build/u);
	assert.match(runText(matrix), /vitest run --config packages\/core\/vitest\.config\.ts/u);

	assert.equal(ci.jobs["quality-gate"].steps.find((step) => step.uses?.startsWith("actions/setup-node@")).with["node-version"], "${{ env.NODE_VERSION }}");
	assert.equal(stepNamed(ci.jobs["onprem-deploy"], "Setup Node.js 24 (pinned)").with["node-version"], "${{ env.NODE_24_VERSION }}");
	for (const jobId of ["privacy", "privacy-rules-drift"]) {
		const setup = ci.jobs[jobId].steps.find((step) => step.uses?.startsWith("actions/setup-node@"));
		assert.equal(setup.with["node-version"], "${{ env.PRIVACY_NODE_VERSION }}", `${jobId} must run at the privacy floor`);
	}
	const docs = readFileSync(path.join(root, "docs/development.md"), "utf8");
	for (const version of [NODE_VERSION, NODE_24_VERSION, PRIVACY_NODE_VERSION]) assert.ok(docs.includes(version), `docs/development.md must document Node ${version}`);
});

test("test jobs prove the runner's real HOME is untouched", () => {
	const ci = workflow("ci.yml");
	for (const [jobId, trigger] of [["quality-gate", "pnpm quality:gate"], ["core-node-matrix", "vitest run"]]) {
		const names = ci.jobs[jobId].steps.map((step) => step.run ?? "");
		const record = names.findIndex((text) => text.includes("verify-real-home-untouched.mjs --record"));
		const run = names.findIndex((text) => text.includes(trigger));
		const verify = names.findIndex((text) => text.includes("verify-real-home-untouched.mjs --verify"));
		assert.ok(record >= 0 && record < run && run < verify, `${jobId} must record HOME, run tests, then verify HOME`);
		assert.equal(ci.jobs[jobId].steps[verify].if, "success() || failure()");
	}
	for (const file of ["packages/extension/src/__tests__/cursor-hook-installer.test.ts", "packages/extension/src/__tests__/vscode-hook-installer.test.ts"]) {
		const source = readFileSync(path.join(root, file), "utf8");
		assert.match(source, /vi\.stubEnv\("HOME", home\)/u, `${file} must fake HOME`);
		assert.match(source, /vi\.stubEnv\("USERPROFILE", home\)/u, `${file} must fake USERPROFILE`);
		assert.match(source, /expect\(os\.homedir\(\)\)\.toBe\(home\)/u, `${file} must assert the fake home is in effect`);
	}
});

test("on-prem, Helm, privacy and Browser Guard gates run what they claim", () => {
	const ci = workflow("ci.yml");
	const onprem = runText(ci.jobs["onprem-deploy"]);
	for (const file of [
		"scripts/deployment-prepare.test.mjs",
		"scripts/deployment-doctor.test.mjs",
		"scripts/airgap-images.test.mjs",
		"scripts/customer-kit-verify.test.mjs",
		"scripts/deployment-tls-renew.test.mjs",
		"deploy/dashboard/server.test.mjs",
		"deploy/ingress/device-start.test.mjs",
		"deploy/monitoring/monitoring.test.mjs",
	]) {
		assert.ok(onprem.includes(file), `onprem-deploy must run ${file}`);
		assert.ok(existsSync(path.join(root, file)), `${file} must exist`);
	}
	for (const gate of ["pnpm verify:bootstrap", "pnpm verify:upgrade", "pnpm verify:backup-offsite", "pnpm verify:onprem-config-reference"]) {
		assert.ok(onprem.includes(gate), `onprem-deploy must run ${gate}`);
	}
	assert.match(onprem, /docker compose -f docker-compose\.posture-scanner\.yml --env-file \.env\.posture-scanner\.example config --quiet/u);
	assert.match(onprem, /docker build --pull --tag aidr-dashboard:ci "\$\{output\}\/dashboard"/u);
	assert.match(onprem, /docker build --pull --tag aidr-aig-bridge:ci services\/aig-bridge/u);
	assert.ok(onprem.indexOf("scripts/deployment-prepare.mjs --output") < onprem.indexOf("docker build --pull --tag aidr-dashboard:ci"));

	const helm = stepNamed(ci.jobs.helm, "Install Helm 3.19.0 (pinned, signature and checksum verified)");
	assert.equal(helm.env.HELM_VERSION, "v3.19.0");
	assert.match(helm.env.HELM_SIGNER_FINGERPRINT, /^[0-9A-F]{40}$/u);
	assert.match(helm.run, /verify_signature "\$\{work\}\/\$\{archive\}\.asc" "\$\{work\}\/\$\{archive\}"/u);
	assert.match(helm.run, /sha256sum --check --strict/u);
	assert.ok(helm.run.indexOf("sha256sum --check") < helm.run.indexOf("tar -xzf"), "Helm must be verified before it is unpacked");
	assert.match(runText(ci.jobs.helm), /pnpm verify:helm/u);

	assert.match(runText(ci.jobs.privacy), /pnpm test:privacy/u);
	assert.match(runText(ci.jobs["privacy-rules-drift"]), /pnpm verify:privacy-rules/u);

	const browser = runText(ci.jobs["browser-guard"]);
	for (const command of ["pnpm build:browser-guard", "vitest run --config vitest.browser-guard.config.ts", "pnpm test:e2e:browser-guard", "pnpm package:browser-guard"]) {
		assert.ok(browser.includes(command), `browser-guard job must run ${command}`);
	}
	assert.match(browser, /playwright-core\/cli\.js install --with-deps --no-shell chromium/u);
	assert.ok(browser.indexOf("pnpm test:e2e:browser-guard") < browser.indexOf("pnpm package:browser-guard"), "the dev E2E build must not overwrite the packaged zips");

	const actionlint = stepNamed(ci.jobs["workflow-lint"], "actionlint 1.7.7 (pinned)").run;
	assert.match(actionlint, /[0-9a-f]{64} {2}\$\{archive\}" \| sha256sum --check --strict/u);
	assert.match(runText(ci.jobs["workflow-lint"]), /node --test scripts\/ci-workflows\.test\.mjs/u);
});

test("every pnpm script a workflow calls exists at the root", (t) => {
	for (const name of workflowFiles) {
		const data = workflow(name);
		for (const job of Object.values(data.jobs)) {
			for (const script of pnpmScripts(runText(job))) {
				if (rootPackage.scripts[script]) continue;
				if (PLANNED_ROOT_SCRIPTS.has(script)) {
					t.diagnostic(`${name}: root script "${script}" is not present yet (planned workstream)`);
					continue;
				}
				assert.fail(`${name} calls "pnpm ${script}", which is not a root package.json script`);
			}
		}
	}
});

test("release-rc packages, signs and verifies the same dist set the manifests cover, including privacy", () => {
	const manifestScript = readFileSync(path.join(root, "scripts/release-artifact-manifests.mjs"), "utf8");
	const manifestDirs = [...manifestScript.matchAll(/dir: "(packages\/[a-z-]+\/dist)"/gu)].map((match) => match[1]).sort();
	assert.ok(manifestDirs.includes("packages/privacy/dist"));
	const rc = workflow("release-rc.yml");
	const checked = [
		["build-rc", "Archive unsigned release inputs"],
		["package-signing", "Sign package manifests only"],
		["package-signing", "Archive signed package inputs"],
		["assemble-e2e", "Reverify signed packages across runner boundary"],
		["acceptance-e2e", "Reverify signed packages on acceptance runner"],
	];
	for (const [jobId, stepName] of checked) {
		const text = stepNamed(rc.jobs[jobId], stepName).run;
		const listed = [...new Set([...text.matchAll(/packages\/[a-z-]+\/dist\b/gu)].map((match) => match[0]))].sort();
		assert.deepEqual(listed, manifestDirs, `${jobId} / ${stepName} must cover exactly the manifest dist set`);
	}
	const archive = stepNamed(rc.jobs["build-rc"], "Archive unsigned release inputs").run;
	assert.equal((archive.match(/packages\/privacy\/dist/gu) ?? []).length, 2, "privacy dist must be both .env-scanned and archived");

	const bundle = readFileSync(path.join(root, ".github/scripts/build-release-bundle.mjs"), "utf8");
	assert.match(bundle, /aidr-privacy-dist-\$\{privacyVersion\}\.tar\.gz/u);
	assert.match(bundle, /evidenceFiles\.map\(\(name\) => `packages\/privacy\/dist\/\$\{name\}`\)/u);
	assert.match(bundle, /const archiveOnlyDirs = \["packages\/privacy"\]/u);
});

test("release-images: signed RC tag first, every image pushed, scanned, signed and attested by digest", () => {
	const release = workflow("release-images.yml");
	assert.deepEqual(release.permissions, { contents: "read" });
	const build = release.jobs["build-sign"];
	assert.deepEqual(build.permissions, { contents: "read", packages: "write", "id-token": "write" });
	const names = build.steps.map((step) => step.name);
	const firstTool = build.steps.findIndex((step) => /(?:^|[\s;&|(])(?:pnpm|node|go|docker|helm|cosign|trivy|curl)\s/mu.test(step.run ?? ""));
	const identity = names.indexOf("Resolve and verify immutable release identity");
	assert.ok(identity >= 0 && identity < firstTool, "the signed-tag identity check must run before any tag code or tool");
	assert.match(stepNamed(build, "Resolve and verify immutable release identity").run, /verify-tag --raw/u);

	const components = release.env.IMAGE_COMPONENTS.split(",");
	const buildImages = readFileSync(path.join(root, "deploy/helm/build-images.mjs"), "utf8");
	const declared = JSON.parse(/export const COMPONENTS = (\[[^\]]+\])/u.exec(buildImages)[1]);
	assert.deepEqual([...components].sort(), [...declared].sort(), "release-images must build every build-images.mjs component");

	const push = stepNamed(build, "Build and push images under the immutable candidate tag").run;
	assert.match(push, /build-images\.mjs [^\n]*--only "\$\{IMAGE_COMPONENTS\}"/u);
	assert.match(push, /--build --push/u);
	assert.match(push, /release-images\.mjs digests/u);
	assert.doesNotMatch(raw("release-images.yml"), /:latest\b/u);
	assert.match(stepNamed(build, "Scan every pushed digest (fixable CRITICAL fails)").run, /release-images\.mjs gate --summary/u);
	const sign = stepNamed(build, "SBOM, keyless signature and SBOM attestation for every digest").run;
	assert.ok(sign.includes("@sha256:[0-9a-f]{64}$"), "signing must refuse non-digest refs");
	for (const command of [/cosign sign --yes "\$\{ref\}"/u, /cosign attest --yes --type cyclonedx/u, /cosign verify --certificate-identity/u]) assert.match(sign, command);
	const chart = stepNamed(build, "Package, push and sign the digest-pinned Helm chart").run;
	assert.ok(chart.indexOf("release-images.mjs pin-chart") < chart.indexOf("helm package"), "the packaged chart must carry the digest pins");
	assert.match(chart, /cosign sign --yes "\$\{REGISTRY\}\/charts\/aidr@\$\{chart_digest\}"/u);
	assert.equal(stepNamed(build, "Install Helm 3.19.0 (pinned, signature and checksum verified)").env.HELM_VERSION, "v3.19.0");
	const tools = stepNamed(build, "Install pinned Trivy and cosign").run;
	assert.ok(tools.indexOf("sha256sum --check --strict") < tools.indexOf("tar -xzf"), "Trivy must be verified before it is unpacked");

	const provenance = release.jobs.provenance;
	assert.equal(provenance.permissions.attestations, "write");
	assert.equal(provenance.strategy.matrix.subject, "${{ fromJSON(needs.build-sign.outputs.subjects) }}");
	const attest = stepNamed(provenance, "Attest build provenance for the pushed digest (pinned)");
	assert.deepEqual(attest.with, { "subject-name": "${{ matrix.subject.name }}", "subject-digest": "${{ matrix.subject.digest }}", "push-to-registry": true });
});

test("posture scanner supply-chain job audits, govulnchecks and Trivy-scans the vendored tree", () => {
	const job = workflow("ci.yml").jobs["posture-scanner-supply-chain"];
	assert.match(stepNamed(job, "Vendored frontend audit, Go toolchain and image base pin contract").run, /pnpm audit:vendored\n\s*node --test scripts\/audit-vendored-aig\.test\.mjs/u);
	const govuln = stepNamed(job, "govulncheck the vendored Go module (pinned)");
	assert.equal(govuln["working-directory"], "vendor/ai-infra-guard");
	assert.match(govuln.run, /go run "golang\.org\/x\/vuln\/cmd\/govulncheck@\$\{GOVULNCHECK_VERSION\}" \.\/\.\.\./u);
	assert.match(job.env.GOVULNCHECK_VERSION, /^v\d+\.\d+\.\d+$/u);
	const goMod = readFileSync(path.join(root, "vendor/ai-infra-guard/go.mod"), "utf8");
	assert.ok(goMod.split(/\r?\n/u).includes(`toolchain ${job.env.GO_TOOLCHAIN}`), "CI must vet with the go.mod toolchain");
	const trivy = stepNamed(job, "Trivy scan and SBOM of the vendored tree (pinned)").run;
	assert.match(job.env.TRIVY_SHA256, /^[0-9a-f]{64}$/u);
	assert.ok(trivy.indexOf("sha256sum --check --strict") < trivy.indexOf("tar -xzf"), "Trivy must be verified before it is unpacked");
	assert.match(trivy, /--exit-code 1 vendor\/ai-infra-guard/u);
	assert.match(trivy, /--format cyclonedx/u);
});

test("Browser Guard release: protected signed tag, least privilege, attested zips, no store credentials", () => {
	const release = workflow("release-browser-guard.yml");
	assert.deepEqual(release.on, { push: { tags: ["browser-guard-v*"] } });
	assert.deepEqual(release.permissions, { contents: "read" });
	assert.equal(release.jobs.build.permissions, undefined, "the build job inherits read-only permissions");
	assert.deepEqual(release.jobs["attest-publish"].permissions, { contents: "write", attestations: "write", "id-token": "write" });
	assert.deepEqual(release.jobs["attest-publish"].needs, "build");

	const identity = stepNamed(release.jobs.build, "Resolve and verify immutable release identity").run;
	for (const guard of ["GITHUB_REF_PROTECTED", "git verify-tag --raw", "git cat-file -t", "packages/browser-guard/package.json"]) {
		assert.ok(identity.includes(guard), `release identity must check ${guard}`);
	}
	const build = runText(release.jobs.build);
	assert.ok(build.indexOf("pnpm test:e2e:browser-guard") < build.indexOf("pnpm package:browser-guard"));
	assert.match(build, /not reproducible across two builds/u);
	assert.match(build, /sha256sum --check --strict SHA256SUMS/u);

	const publish = release.jobs["attest-publish"].steps;
	const names = publish.map((step) => step.name);
	assert.ok(names.indexOf("Recheck bundle across the runner boundary") < names.indexOf("Attest the Browser Guard zips (pinned)"));
	assert.ok(names.indexOf("Attest the Browser Guard zips (pinned)") < names.indexOf("Publish draft release (pinned)"));
	assert.equal(stepNamed(release.jobs["attest-publish"], "Publish draft release (pinned)").with.draft, true);

	const secrets = new Set([...raw("release-browser-guard.yml").matchAll(/secrets\.([A-Z0-9_]+)/gu)].map((match) => match[1]));
	assert.deepEqual([...secrets].sort(), ["GITHUB_TOKEN", "RELEASE_TAG_PGP_FINGERPRINT", "RELEASE_TAG_PGP_PUBLIC_KEY"]);
	assert.doesNotMatch(raw("release-browser-guard.yml"), /chrome-webstore|webstore|AMO_|addons\.mozilla|EDGE_/iu);
});

// ─── production GO gate (audit item 14) ──────────────────────────────────

const GO_SCRIPT = "node .trusted-release-verifier/scripts/verify-production-go.mjs";
const STAGE_STEP = "Stage signature-verified artifact roots for the claim gate";

/** A step that publishes, deploys, retags or persists promotion state for production. */
function isProductionMutation(step) {
	const run = step.run ?? "";
	if (/softprops\/action-gh-release@/u.test(step.uses ?? "")) return step.with?.draft !== true;
	if (/actions\/upload-artifact@/u.test(step.uses ?? "")) return /anti-rollback-state|aidr-promotion-/u.test(String(step.with?.name ?? ""));
	// Deploy/rollback/yank hooks are POSTed with curl; npm mutations are named.
	return /\bnpm publish\b(?![^\n]*--dry-run)|\bnpm dist-tag\b|\bnpm deprecate\b|\bcurl\b[^\n]*-X POST/u.test(run);
}

function goStepIndex(job, mode) {
	const indices = (job.steps ?? []).flatMap((step, index) => ((step.run ?? "").includes(GO_SCRIPT) && (mode === "rollback") === /--rollback\b/u.test(step.run) ? [index] : []));
	assert.equal(indices.length, 1, `exactly one ${mode} production GO step is required`);
	return indices[0];
}

test("release-promote: the candidate-bound production GO gate precedes every production publish, deploy and state persist", () => {
	const promote = workflow("release-promote.yml").jobs.promote;
	const go = goStepIndex(promote, "promote");
	const gate = promote.steps[go];
	assert.equal(gate.if, undefined, "the GO gate must not be conditional");
	assert.equal(gate["continue-on-error"], undefined, "the GO gate must block");
	for (const flag of ["--root .trusted-release-verifier", "--bundle release-output", '--candidate-digest "${VERIFIED_CANDIDATE_DIGEST}"', "--profile production-ga", "--record"]) {
		assert.ok(gate.run.includes(flag), `GO gate must pass ${flag}`);
	}
	assert.equal(gate.env.VERIFIED_CANDIDATE_DIGEST, "${{ steps.verify.outputs.candidate_digest }}");
	const verify = promote.steps.findIndex((step) => step.id === "verify");
	assert.ok(verify >= 0 && verify < go, "the GO gate consumes the signature-verified candidate digest");
	assert.match(promote.steps[verify].run, /candidate_digest=\$\(sha256sum release-output\/release-inventory\.json/u);
	const staged = promote.steps.findIndex((step) => step.name === STAGE_STEP);
	assert.ok(staged > verify && staged < go, "claim-check needs the candidate artifact roots staged before the gate");

	const mutations = promote.steps.flatMap((step, index) => (isProductionMutation(step) ? [{ index, name: step.name }] : []));
	const names = mutations.map((step) => step.name);
	for (const expected of [
		"Persist anti-rollback state and verification receipt (pinned)",
		"Publish verified npm packages under rc dist-tag",
		"Promote the exact dashboard commit and run remote smoke",
		"Move npm dist-tags to latest only after deployed smoke",
		"Publish final GitHub release from the same bundle (pinned)",
	]) {
		assert.ok(names.includes(expected), `${expected} must be recognised as a production mutation`);
	}
	for (const mutation of mutations) assert.ok(mutation.index > go, `${mutation.name} runs before the production GO gate`);
	const persisted = promote.steps.find((step) => step.name === "Persist anti-rollback state and verification receipt (pinned)");
	assert.match(persisted.with.path, /production-go-ledger\.json/u, "the GO ledger must persist with the protected promotion state");
});

test("release-promote: rollback requires a recorded production GO for the exact candidate before retagging", () => {
	const rollback = workflow("release-promote.yml").jobs.rollback;
	const go = goStepIndex(rollback, "rollback");
	const gate = rollback.steps[go];
	assert.equal(gate.if, undefined);
	assert.equal(gate["continue-on-error"], undefined);
	for (const flag of ["--bundle release-output", "--ledger", '--expected-version "${VERSION}"', '--expected-sha "${VERIFIED_SHA}"']) assert.ok(gate.run.includes(flag), `rollback GO must pass ${flag}`);
	const names = rollback.steps.map((step) => step.name);
	assert.ok(names.indexOf("Restore protected promotion state (pinned)") < go, "the ledger must be restored before the rollback gate");
	assert.ok(names.indexOf("Verify rollback RC signature and identity") < go);
	const mutations = rollback.steps.flatMap((step, index) => (isProductionMutation(step) ? [index] : []));
	assert.ok(mutations.length > 0);
	for (const index of mutations) assert.ok(index > go, `${rollback.steps[index].name} runs before the rollback GO gate`);
});

test("no other release workflow mutates production without a production GO gate", () => {
	for (const name of workflowFiles) {
		for (const [jobId, job] of Object.entries(workflow(name).jobs)) {
			if (name === "release-promote.yml" && ["promote", "rollback", "yank"].includes(jobId)) continue;
			const mutations = (job.steps ?? []).filter(isProductionMutation).map((step) => step.name);
			assert.deepEqual(mutations, [], `${name}:${jobId} publishes to production without the candidate-bound GO gate`);
		}
	}
	// The RC and Browser Guard workflows only ever create draft GitHub releases:
	// the GO record names a candidate digest that does not exist until the RC is
	// built, and Browser Guard store submission is a separate manual step.
	for (const [name, jobId] of [["release-rc.yml", "final-sign-publish"], ["release-browser-guard.yml", "attest-publish"]]) {
		const releases = workflow(name).jobs[jobId].steps.filter((step) => /softprops\/action-gh-release@/u.test(step.uses ?? ""));
		assert.ok(releases.length > 0, `${name} must still publish its draft release`);
		for (const step of releases) assert.equal(step.with.draft, true, `${name}: ${step.name} must stay a draft (non-production) release`);
	}
});

// ─── no release-candidate code next to production credentials ────────────

/** Commands that would build, install or execute code from the RC tag checkout. */
const TAG_CODE = [
	[/(?:^|[\s;&|(`])pnpm\s/mu, "pnpm"],
	[/\bnpm\s+(?:run|run-script|exec|install|i|ci|test|rebuild|start)\b/u, "npm run/exec/install"],
	[/(?:^|[\s;&|(`])(?:npx|yarn|corepack|make)\s/mu, "npx/yarn/corepack/make"],
	[/\b(?:build:release|build-workspace)\b/u, "a release build"],
	[/(?:^|[\s;&|(`])(?:bash|sh|source|\.)\s+(?:\.\/)?(?:scripts|packages|\.github)\//mu, "a checked-out shell script"],
	[/(?:^|[\s;&|(`])\.\/[\w./-]+/mu, "a checked-out executable"],
];

function nodeScriptTargets(run) {
	return [...run.matchAll(/(?:^|[\s;&|(`])node\s+(?!-)("?[^\s"]+"?)/gmu)].map((match) => match[1].replaceAll('"', ""));
}

const isTrustedScript = (target) => /^(?:\$\{GITHUB_WORKSPACE\}\/)?\.trusted-release-verifier\/(?:scripts|docs\/scripts)\/[\w.-]+\.mjs$/u.test(target);

test("release-promote: no job holding publish/deploy credentials builds or runs release-candidate code", () => {
	const promote = workflow("release-promote.yml");
	for (const [jobId, job] of Object.entries(promote.jobs)) {
		for (const step of job.steps ?? []) {
			const label = `release-promote.yml:${jobId}:${step.name}`;
			assert.doesNotMatch(step.uses ?? "", /^pnpm\/action-setup@/u, `${label}: pnpm is not needed when nothing is built`);
			if (/^actions\/setup-node@/u.test(step.uses ?? "")) assert.equal(step.with?.cache, undefined, `${label}: no dependency cache restore/save in a production job`);
			if (/^actions\/checkout@/u.test(step.uses ?? "")) {
				assert.equal(step.with?.submodules, undefined, `${label}: no submodules from the RC tag`);
				assert.equal(step.with?.["persist-credentials"], false, `${label}: checkout must not persist credentials`);
			}
			const run = step.run ?? "";
			for (const [pattern, what] of TAG_CODE) assert.doesNotMatch(run, pattern, `${label} runs ${what} from the RC checkout`);
			for (const target of nodeScriptTargets(run)) assert.ok(isTrustedScript(target), `${label}: node ${target} is not a trusted verifier script`);
			// npm reads a project .npmrc (with \${ENV} expansion) from its working
			// directory; inside the RC checkout that file is tag-controlled.
			const firstNpm = run.search(/\bnpm\s+(?:config|publish|dist-tag|pack|deprecate|view)\b|plan-npm-release-publication/u);
			if (firstNpm >= 0) {
				const isolate = run.indexOf('npm_cwd="$(mktemp -d "${RUNNER_TEMP}/aidr-npm-cwd.XXXXXX")"');
				const enter = run.indexOf('cd "${npm_cwd}"');
				assert.ok(isolate >= 0 && isolate < enter && enter < firstNpm, `${label}: npm must run from an isolated empty directory, not the RC checkout`);
				assert.doesNotMatch(run.slice(enter), /(?:^|[\s"=])release-output\//mu, `${label}: after leaving the checkout, bundle paths must be absolute`);
			}
		}
	}
});

test("release-promote: the GO gate precedes everything except checkout, verification and verified staging", () => {
	const promote = workflow("release-promote.yml").jobs.promote;
	const go = goStepIndex(promote, "promote");
	const allowedBeforeGo = [
		"Validate promotion inputs",
		"Checkout the exact RC tag (pinned)",
		"Checkout immutable trusted verifier (pinned)",
		"Setup Node.js (pinned)",
		"Install pinned GitHub CLI for attestation verification",
		"Resolve latest protected anti-rollback state",
		"Restore protected anti-rollback state (pinned)",
		"Download the signed RC bundle (pinned)",
		"Verify GitHub build attestations for every release file",
		"Prepare trusted release-signer policy",
		"Verify RC identity, manifest, SBOM and signatures",
		STAGE_STEP,
	];
	assert.deepEqual(promote.steps.slice(0, go).map((step) => step.name), allowedBeforeGo);
	for (const step of promote.steps.slice(0, go)) {
		if (step.uses) assert.match(step.uses, /^actions\/(?:checkout|setup-node|download-artifact)@/u, `${step.name} is not a checkout/setup/download step`);
	}

	// The claim-gate roots come from the verified tarballs, never from a build.
	const stage = promote.steps[go - 1];
	assert.equal(stage.name, STAGE_STEP);
	assert.equal(stage.env.VERIFIED_CANDIDATE_DIGEST, "${{ steps.verify.outputs.candidate_digest }}");
	for (const flag of ["node .trusted-release-verifier/scripts/stage-verified-artifact-roots.mjs", "--root .trusted-release-verifier", "--bundle release-output", '--candidate-digest "${VERIFIED_CANDIDATE_DIGEST}"']) {
		assert.ok(stage.run.includes(flag), `artifact-root staging must pass ${flag}`);
	}
	assert.doesNotMatch(stage.run, /\bcp\b|\btar\s+-x|build/u, "staging extracts verified archives in the trusted script only");
	const names = promote.steps.map((step) => step.name);
	assert.ok(names.indexOf("Verify GitHub build attestations for every release file") < go - 1);
	const stager = readFileSync(path.join(root, "scripts/stage-verified-artifact-roots.mjs"), "utf8");
	for (const guard of ["createTarBoundaryValidator", "inspectReleaseArchive", "does not match its signed inventory digest", "is not the verified candidate", 'flag: "wx"']) {
		assert.ok(stager.includes(guard), `stage-verified-artifact-roots.mjs must keep ${guard}`);
	}

	// Route smoke after deployment: trusted script, RC sources as data, verified dist.
	const smoke = stepNamed(promote, "Promote the exact dashboard commit and run remote smoke").run;
	assert.match(smoke, /node \.trusted-release-verifier\/scripts\/dashboard-route-smoke\.mjs/u);
	assert.match(smoke, /--source-root "\$\{GITHUB_WORKSPACE\}"/u);
	assert.match(smoke, /--dist \.trusted-release-verifier\/packages\/dashboard\/dist/u);
	assert.doesNotMatch(smoke, /test:route-smoke/u);
});

test("release-rc: tag code runs only after the signed-tag identity check and never holds production credentials", () => {
	const rc = workflow("release-rc.yml");
	const text = raw("release-rc.yml");
	// The RC workflow is defined by the tag itself, so its protection is the
	// environment boundary: it must never see production publish/deploy access.
	assert.doesNotMatch(text, /environment:\s*production\b/u);
	assert.doesNotMatch(text, /secrets\.(?:DASHBOARD_|MARKETPLACE_|NPM_TOKEN|NODE_AUTH_TOKEN)/u);
	assert.doesNotMatch(text, /packages:\s*write/u);
	assert.doesNotMatch(text, /NODE_AUTH_TOKEN/u);

	const build = rc.jobs["build-rc"];
	const identity = build.steps.findIndex((step) => step.name === "Resolve and verify immutable RC identity");
	assert.ok(identity >= 0);
	assert.match(build.steps[identity].run, /git verify-tag --raw/u);
	const firstTagCode = build.steps.findIndex((step) => /(?:^|[\s;&|(])(?:pnpm|npm|npx)\s|(?:^|[\s;&|(])node\s+(?:scripts|packages|\.github)\//mu.test(step.run ?? ""));
	assert.ok(firstTagCode > identity, "no RC code may run before the signed, protected tag is verified");

	const needsBuild = (jobId, seen = new Set()) => {
		if (jobId === "build-rc") return true;
		if (seen.has(jobId)) return false;
		seen.add(jobId);
		const needs = [rc.jobs[jobId].needs ?? []].flat();
		return needs.some((need) => needsBuild(need, seen));
	};
	for (const [jobId, job] of Object.entries(rc.jobs)) {
		if (jobId === "build-rc") continue;
		assert.ok(needsBuild(jobId), `${jobId} must depend on the verified build-rc identity`);
		for (const step of job.steps ?? []) {
			if (/^actions\/checkout@/u.test(step.uses ?? "")) {
				assert.equal(step.with?.ref, "${{ needs.build-rc.outputs.sha }}", `${jobId}: ${step.name} must check out the verified commit`);
			}
		}
	}
});
