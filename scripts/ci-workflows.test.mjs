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
	assert.match(onprem, /docker compose -f docker-compose\.aig\.yml --env-file \.env\.aig\.example config --quiet/u);
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
