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
import { FINAL_TAG_PATTERN, FINAL_TAG_SHELL_PATTERN, finalTagFor, parseReleaseTag, RC_TAG_PATTERN, RC_TAG_SHELL_PATTERN } from "./lib/rc-tag.mjs";

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

test("Browser Guard release: protected signed tag, least privilege, attested and store-validated packages", () => {
	const release = workflow("release-browser-guard.yml");
	assert.deepEqual(release.on, { push: { tags: ["browser-guard-v*"] } });
	assert.deepEqual(release.permissions, { contents: "read" });
	assert.equal(release.jobs.build.permissions, undefined, "the build job inherits read-only permissions");
	assert.deepEqual(release.jobs["attest-publish"].permissions, { contents: "write", attestations: "write", "id-token": "write" });
	assert.deepEqual(release.jobs["attest-publish"].needs, ["build", "self-hosted-feed"]);
	assert.match(
		release.jobs["attest-publish"].if,
		/needs\.build\.result == 'success' && \(needs\.self-hosted-feed\.result == 'success' \|\| needs\.self-hosted-feed\.result == 'skipped'\)/u,
		"attest-publish runs after a successful or skipped (unconfigured) feed job, never after a failed one",
	);

	const identity = stepNamed(release.jobs.build, "Resolve and verify immutable release identity").run;
	for (const guard of ["GITHUB_REF_PROTECTED", "git verify-tag --raw", "git cat-file -t", "packages/browser-guard/package.json"]) {
		assert.ok(identity.includes(guard), `release identity must check ${guard}`);
	}
	const build = runText(release.jobs.build);
	assert.ok(build.indexOf("pnpm test:e2e:browser-guard") < build.indexOf("pnpm package:browser-guard"));
	assert.match(build, /not reproducible across two builds/u);
	assert.match(build, /sha256sum --check --strict SHA256SUMS/u);
	// The store packages: Chrome/Edge zip, Firefox zip and the AMO source zip, validated offline.
	assert.match(build, /for target in chrome firefox source; do/u);
	const buildNames = release.jobs.build.steps.map((step) => step.name);
	const validate = stepNamed(release.jobs.build, "Offline store validation of the staged packages");
	assert.match(validate.run, /node packages\/browser-guard\/scripts\/validate-store\.mjs --dist release-output-browser-guard/u);
	assert.equal(validate.if, undefined, "store validation must not be conditional");
	assert.equal(validate["continue-on-error"], undefined, "store validation must block");
	assert.ok(buildNames.indexOf("Release build, zips and reproducibility check") < buildNames.indexOf(validate.name));
	assert.ok(
		buildNames.indexOf(validate.name) < buildNames.indexOf("Upload Browser Guard release bundle (pinned)"),
		"only validated packages leave the build job",
	);
	const packageScripts = JSON.parse(readFileSync(path.join(root, "packages/browser-guard/package.json"), "utf8")).scripts;
	assert.match(packageScripts["build:release"], /scripts\/source-archive\.mjs && node scripts\/validate-store\.mjs$/u);

	const publish = release.jobs["attest-publish"].steps;
	const names = publish.map((step) => step.name);
	assert.ok(names.indexOf("Recheck bundle across the runner boundary") < names.indexOf("Attest the Browser Guard zips (pinned)"));
	assert.ok(names.indexOf("Attest the Browser Guard zips (pinned)") < names.indexOf("Publish draft release (pinned)"));
	assert.equal(stepNamed(release.jobs["attest-publish"], "Publish draft release (pinned)").with.draft, true);
	assert.match(stepNamed(release.jobs["attest-publish"], "Recheck bundle across the runner boundary").run, /aidr-browser-guard-source-\$\{VERSION\}\.zip/u);
});

test("Browser Guard self-hosted channel: selfhosted zips validated, CRX signed only with the pinned owner key, fail closed", () => {
	const release = workflow("release-browser-guard.yml");
	const build = release.jobs.build;
	const channel = stepNamed(build, "Resolve the self-hosted update channel");
	assert.equal(channel.id, "channel");
	assert.equal(channel.env.UPDATE_BASE_URL, "${{ vars.BROWSER_GUARD_UPDATE_BASE_URL }}");
	assert.match(channel.run, /\^https:\/\//u, "the update base URL must be https");
	assert.equal(build.outputs.self_hosted, "${{ steps.channel.outputs.self_hosted }}");
	const names = build.steps.map((step) => step.name);
	assert.ok(names.indexOf(channel.name) < names.indexOf("Release build, zips and reproducibility check"));
	const pack = stepNamed(build, "Release build, zips and reproducibility check");
	assert.equal(pack.env.BROWSER_GUARD_UPDATE_BASE_URL, "${{ steps.channel.outputs.update_base_url }}");
	assert.match(pack.run, /for target in chrome-selfhosted firefox-selfhosted; do/u);
	const validate = stepNamed(build, "Offline store validation of the staged packages");
	assert.equal(validate.env.BROWSER_GUARD_UPDATE_BASE_URL, "${{ steps.channel.outputs.update_base_url }}", "the validator requires the selfhosted zips when the channel is on");

	const feed = release.jobs["self-hosted-feed"];
	assert.ok(feed, "the self-hosted-feed job is missing");
	assert.equal(feed.needs, "build");
	assert.equal(feed.if, "needs.build.outputs.self_hosted == 'true'");
	assert.equal(feed.environment, "browser-guard-self-hosted");
	assert.deepEqual(feed.permissions, { contents: "read" }, "the signing job cannot write releases or mint tokens");
	const checkout = feed.steps.find((step) => /actions\/checkout@/u.test(step.uses ?? ""));
	assert.equal(checkout.with.ref, "${{ needs.build.outputs.sha }}", "the signer runs the verified tag commit");
	assert.equal(checkout.with["persist-credentials"], false);
	for (const step of feed.steps) {
		assert.doesNotMatch(String(step.uses ?? ""), /pnpm\/action-setup@/u, "no package manager next to the key");
		assert.doesNotMatch(step.run ?? "", /(?:^|[\s;&|(`])(?:pnpm|npm|npx|yarn)\s/mu, `${step.name} runs a package manager`);
		if (/actions\/setup-node@/u.test(step.uses ?? "")) assert.equal(step.with?.cache, undefined, "no dependency cache next to the key");
		assert.equal(step["continue-on-error"], undefined, `${step.name} must not hide a failure`);
	}
	const sign = stepNamed(feed, "Sign the CRX3 and build the update feed (fails closed without the key)");
	assert.equal(sign.env.BROWSER_GUARD_CRX_KEY_PEM, "${{ secrets.BROWSER_GUARD_CRX_KEY_PEM }}");
	assert.equal(sign.env.EXTENSION_ID, "${{ vars.BROWSER_GUARD_CRX_EXTENSION_ID }}");
	assert.equal(sign.if, undefined);
	assert.match(sign.run, /\[\[ -n "\$\{BROWSER_GUARD_CRX_KEY_PEM\}" \]\] \|\| \{[\s\S]*?exit 1/u, "a missing key fails the release");
	assert.match(sign.run, /\[\[ "\$\{EXTENSION_ID\}" =~ \^\[a-p\]\{32\}\$ \]\] \|\| \{[\s\S]*?exit 1/u, "an unpinned ID fails the release");
	assert.deepEqual([...new Set(nodeScriptTargets(sign.run))], ["packages/browser-guard/scripts/update-feed.mjs"], "the signer runs only the feed builder");
	assert.match(sign.run, /--extension-id "\$\{EXTENSION_ID\}"/u);
	assert.doesNotMatch(sign.run, /--crx-key-file|BROWSER_GUARD_CRX_KEY_PEM\}"? *>/u, "the key never reaches argv or disk");
	const feedNames = feed.steps.map((step) => step.name);
	assert.ok(feedNames.indexOf("Recheck the bundle before signing") < feedNames.indexOf(sign.name));
	// The CRX key is visible to the signing step only.
	for (const [jobId, job] of Object.entries(release.jobs)) {
		for (const step of job.steps ?? []) {
			if (jobId === "self-hosted-feed" && step.name === sign.name) continue;
			assert.ok(!secretsIn(step).has("BROWSER_GUARD_CRX_KEY_PEM"), `${jobId}:${step.name} must not see the CRX key`);
		}
		if (jobId !== "self-hosted-feed") assert.ok(!secretsIn(job.env).has("BROWSER_GUARD_CRX_KEY_PEM"));
	}

	const recheck = stepNamed(release.jobs["attest-publish"], "Recheck bundle across the runner boundary").run;
	assert.match(recheck, /aidr-browser-guard-chrome-selfhosted-\$\{VERSION\}\.zip/u);
	assert.match(recheck, /\(cd \.\.\/update-feed && sha256sum --check --strict SHA256SUMS\)/u);
	const amo = stepNamed(release.jobs["store-drafts"], "addons.mozilla.org - submit unlisted version for signing (never listed)").run;
	assert.match(amo, /aidr-browser-guard-firefox-selfhosted-\$\{VERSION\}\.zip/u, "AMO signs the package that carries the feed URL");
});

const STORE_SECRETS = {
	cws: ["CWS_CLIENT_ID", "CWS_CLIENT_SECRET", "CWS_REFRESH_TOKEN", "CWS_EXTENSION_ID", "CWS_PUBLISHER_ID"],
	edge: ["EDGE_ADDONS_CLIENT_ID", "EDGE_ADDONS_API_KEY", "EDGE_ADDONS_PRODUCT_ID"],
	amo: ["AMO_JWT_ISSUER", "AMO_JWT_SECRET"],
};
const STORE_STEPS = {
	cws: "Chrome Web Store - upload package as a draft (never published)",
	edge: "Edge Add-ons - upload package to the draft submission (never submitted)",
	amo: "addons.mozilla.org - submit unlisted version for signing (never listed)",
};
const secretsIn = (value) => new Set([...JSON.stringify(value ?? {}).matchAll(/secrets\.([A-Z0-9_]+)/gu)].map((match) => match[1]));

test("Browser Guard store drafts: secrets only in the store job, attested bytes only, skipped without secrets", () => {
	const release = workflow("release-browser-guard.yml");
	const job = release.jobs["store-drafts"];
	assert.ok(job, "the store-drafts job is missing");
	assert.deepEqual(job.needs, ["build", "attest-publish"], "stores receive only what the draft GitHub release already carries");
	assert.equal(job.environment, "browser-guard-store");
	assert.deepEqual(job.permissions, { contents: "read" });

	// Store secrets appear in the store job only, and each upload step sees only its own.
	const all = Object.values(STORE_SECRETS).flat();
	for (const [jobId, other] of Object.entries(release.jobs)) {
		if (jobId === "store-drafts") continue;
		for (const name of secretsIn(other)) assert.ok(!all.includes(name), `${jobId} must not see store secret ${name}`);
	}
	assert.deepEqual([...secretsIn(job)].sort(), [...all].sort());
	for (const [store, step] of Object.entries(STORE_STEPS)) {
		assert.deepEqual([...secretsIn(stepNamed(job, step))].sort(), [...STORE_SECRETS[store]].sort(), `${step} sees exactly its own secrets`);
	}
	const workflowSecrets = new Set([...raw("release-browser-guard.yml").matchAll(/secrets\.([A-Z0-9_]+)/gu)].map((match) => match[1]));
	assert.deepEqual([...workflowSecrets].sort(), ["BROWSER_GUARD_CRX_KEY_PEM", "GITHUB_TOKEN", "RELEASE_TAG_PGP_FINGERPRINT", "RELEASE_TAG_PGP_PUBLIC_KEY", ...all].sort());

	// No repository code next to the credentials: no checkout, no package manager, no script files.
	for (const step of job.steps) {
		assert.doesNotMatch(String(step.uses ?? ""), /actions\/checkout@/u, "the store job must not check out the tag");
		const run = step.run ?? "";
		assert.doesNotMatch(run, /(?:^|[\s;&|(`])(?:pnpm|npm|npx|yarn)\s/mu, `${step.name} runs a package manager`);
		assert.deepEqual(nodeScriptTargets(run), [], `${step.name} runs a checked-out node script`);
	}
	const names = job.steps.map((step) => step.name);
	assert.equal(names[0], "Download Browser Guard release bundle (pinned)");
	assert.match(stepNamed(job, "Recheck the attested bundle before any upload").run, /sha256sum --check --strict SHA256SUMS/u);
	const recheck = names.indexOf("Recheck the attested bundle before any upload");
	for (const step of Object.values(STORE_STEPS)) assert.ok(names.indexOf(step) > recheck, `${step} runs before the recheck`);

	// Missing secrets skip that store (notice; the draft GitHub release keeps every package);
	// a partly configured store fails the job loudly instead of silently not uploading.
	const detect = stepNamed(job, "Detect configured store credentials");
	assert.equal(detect.id, "stores");
	assert.match(detect.run, /=skipped" >> "\$\{GITHUB_OUTPUT\}"/u);
	assert.match(detect.run, /::notice title=\$\{store\}::No \$\{store\} credentials configured/u);
	assert.match(detect.run, /::error title=\$\{store\}::Incomplete/u);
	for (const [store, secrets] of Object.entries(STORE_SECRETS)) {
		assert.ok(detect.run.includes(`detect ${store} ${secrets.join(" ")}`), `${store} detection must cover ${secrets.join(", ")}`);
		assert.equal(stepNamed(job, STORE_STEPS[store]).if, `steps.stores.outputs.${store} == 'configured'`);
	}
	assert.equal(stepNamed(job, "Fail on incomplete store credentials").if, "steps.stores.outputs.incomplete == '1'");
	assert.equal(stepNamed(job, "Upload store draft receipts (pinned)").if, "always()");
	for (const step of job.steps) assert.equal(step["continue-on-error"], undefined, `${step.name} must not hide a failure`);
});

test("Browser Guard store drafts never publish: upload/draft endpoints only, AMO unlisted channel", () => {
	const job = workflow("release-browser-guard.yml").jobs["store-drafts"];
	const cws = stepNamed(job, STORE_STEPS.cws).run;
	assert.match(cws, /\/upload\/v2\/\$\{item\}:upload/u);
	assert.doesNotMatch(cws, /:publish|\/publish\b|publishTarget|deployPercentage/u, "the Chrome Web Store step must never publish");
	const edge = stepNamed(job, STORE_STEPS.edge).run;
	assert.match(edge, /\/submissions\/draft\/package"/u);
	assert.equal([...edge.matchAll(/-X POST/gu)].length, 1, "Edge: exactly one POST, the draft package upload");
	assert.doesNotMatch(edge.replace(/\/submissions\/draft\/package/gu, ""), /\/submissions["/]/u, "Edge: never POST /submissions (publish)");
	const amo = stepNamed(job, STORE_STEPS.amo).run;
	assert.match(amo, /-F "channel=unlisted"/u);
	assert.doesNotMatch(amo, /channel=listed/u, "AMO: never the listed channel");
	assert.match(amo, /-F "source=@\$\{source\}"/u, "AMO gets the reviewer source archive");
	assert.match(amo, /\.channel' store-receipts\/addons-mozilla-org\.json\)" == "unlisted"/u, "AMO: the created version is verified to be unlisted");
	// Credentials never reach the process list: header files and stdin only.
	for (const run of [cws, edge, amo]) {
		assert.doesNotMatch(run, /curl[^\n]*(?:-H|--header) "Authorization/u);
		assert.doesNotMatch(run, /curl[^\n]*\$\{(?:CWS|EDGE_ADDONS|AMO)_[A-Z_]*(?:SECRET|TOKEN|KEY)\}/u);
	}
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
			// Store drafts are not a publication: the job only reaches draft/unlisted store
			// endpoints, which the "never publish" test pins.
			if (name === "release-browser-guard.yml" && jobId === "store-drafts") continue;
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
		"Rebuild anti-rollback floor from signed GitHub releases",
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

// ─── RC numbering and durable anti-rollback state (OPS-8, OPS-11) ────────

test("every RC tag check in the release workflows uses the shared rc.N grammar", () => {
	const checks = [];
	for (const name of ["release-rc.yml", "release-promote.yml"]) {
		for (const match of raw(name).matchAll(/\[\[ "\$\{(?:tag|RELEASE_TAG)\}" =~ (\S+) /gu)) checks.push({ name, pattern: match[1] });
	}
	assert.ok(checks.length >= 4, `expected the RC build, promote, dry-run and rollback checks, saw ${checks.length}`);
	for (const { name, pattern } of checks) assert.equal(pattern, RC_TAG_SHELL_PATTERN, `${name} must use RC_TAG_SHELL_PATTERN`);
	// The shell (POSIX ERE) and JS spellings accept and reject the same tags.
	const shell = new RegExp(RC_TAG_SHELL_PATTERN, "u");
	for (const tag of ["v1.0.0-rc.0", "v1.0.0-rc.3", "v2.10.0-rc.42", "v1.0.0-rc.01", "v1.0.0-rc.", "v1.0.0", "v1.0.0-rc.10000"]) {
		assert.equal(shell.test(tag), RC_TAG_PATTERN.test(tag), tag);
	}
	assert.doesNotMatch(raw("release-rc.yml"), /Only vX\.Y\.Z-rc\.0 is supported/u);
	assert.doesNotMatch(raw("release-promote.yml"), /-rc\.0"/u, "rollback must accept the promoted rc.N tag");
});

test("release-promote: the anti-rollback floor survives a lost artifact and a missing state fails closed", () => {
	const promote = workflow("release-promote.yml").jobs.promote;
	const names = promote.steps.map((step) => step.name);
	const rebuild = promote.steps[names.indexOf("Rebuild anti-rollback floor from signed GitHub releases")];
	assert.ok(rebuild, "the promote job must rebuild the floor from signed releases");
	for (const flag of ["node .trusted-release-verifier/scripts/restore-promotion-state.mjs", '--policy "${AIDR_RELEASE_SIGNER_POLICY_PATH}"', '--state "${RUNNER_TEMP}/aidr-promotion-state/anti-rollback-state.json"', '--expected-tag "${RELEASE_TAG}"']) {
		assert.ok(rebuild.run.includes(flag), `floor rebuild must pass ${flag}`);
	}
	assert.ok(names.indexOf("Restore protected anti-rollback state (pinned)") < names.indexOf(rebuild.name), "the artifact state is merged, not overwritten");
	assert.ok(names.indexOf("Prepare trusted release-signer policy") < names.indexOf(rebuild.name));
	const verify = promote.steps.find((step) => step.id === "verify");
	assert.ok(names.indexOf(rebuild.name) < promote.steps.indexOf(verify));
	assert.match(verify.run, /--record \\\n\s+\$\{GENESIS:\+--genesis\}/u, "genesis is only ever passed from the explicit input");
	assert.equal(verify.env.GENESIS, "${{ inputs.genesis }}");
	const validate = promote.steps[names.indexOf("Validate promotion inputs")];
	assert.match(validate.run, /\[\[ -z "\$\{GENESIS\}" \|\| "\$\{GENESIS\}" == "FIRST_PROMOTION" \]\]/u);
	assert.match(raw("release-promote.yml"), /genesis:\n\s+description: "Type FIRST_PROMOTION only/u);
	// Dry-run and rollback verify without --record and must never pass --genesis.
	for (const jobId of ["dry-run", "rollback"]) {
		const text = workflow("release-promote.yml").jobs[jobId].steps.map((step) => step.run ?? "").join("\n");
		assert.doesNotMatch(text, /--genesis|--record\b/u, `${jobId} must not record or claim genesis`);
	}
});

test("release-promote: installers reach the download portal only verified and signed, after the final release", () => {
	const promote = workflow("release-promote.yml").jobs.promote;
	const names = promote.steps.map((step) => step.name);
	const publish = stepNamed(promote, "Publish installers to the download portal");
	assert.ok(names.indexOf("Publish final GitHub release from the same bundle (pinned)") < names.indexOf(publish.name));
	assert.ok(publish.run.includes("node .trusted-release-verifier/scripts/publish-installers.mjs"), "runs the trusted verifier copy");
	assert.ok(publish.run.includes('--policy "${AIDR_RELEASE_SIGNER_POLICY_PATH}"'), "verifies the bundle with the signer policy");
	assert.match(publish.run, /exit 0/u, "an unconfigured portal is skipped with a notice");
	assert.match(publish.run, /-ne 4 \]\][\s\S]{0,400}exit 1/u, "a partly configured portal fails the promotion");
	assert.doesNotMatch(publish.run, /--allow-downgrade/u, "promotion never moves latest.json backwards");
	assert.deepEqual([...secretsIn(publish.env)].sort(), [
		"AIDR_DOWNLOADS_SERVICE_ROLE_KEY",
		"AIDR_DOWNLOADS_SUPABASE_URL",
		"AIDR_INSTALLER_MANIFEST_SIGNING_KEY_PEM",
	]);
});

// ─── per-customer installers (docs/operations/customer-builds.md) ─────────

test("customer-installer: a verified packet and the promoted release's attested, signed bundles only", () => {
	const wf = workflow("customer-installer.yml");
	const text = raw("customer-installer.yml");
	// Manual only, with exactly the documented inputs.
	assert.deepEqual(Object.keys(wf.on), ["workflow_dispatch"]);
	assert.deepEqual(Object.keys(wf.on.workflow_dispatch.inputs).sort(), ["build_exe", "customer_id", "packet_b64", "packet_run_id", "packet_source", "release_tag"]);
	assert.deepEqual(wf.on.workflow_dispatch.inputs.packet_source.options, ["secret", "artifact", "input"]);
	assert.deepEqual(wf.permissions, { contents: "read" });
	assert.doesNotMatch(text, /environment:\s*production\b/u, "customer builds never hold production credentials");
	assert.deepEqual(Object.keys(wf.jobs).sort(), ["linux-build", "linux-sign", "prepare", "windows"]);
	// Inputs reach scripts only through env, never interpolated into a script.
	for (const [jobId, job] of Object.entries(wf.jobs)) {
		for (const step of job.steps ?? []) assert.doesNotMatch(step.run ?? "", /\$\{\{\s*inputs\./u, `${jobId}:${step.name} interpolates an input`);
	}

	// Nothing is built or installed from source; the tooling is the protected default branch.
	for (const [jobId, job] of Object.entries(wf.jobs)) {
		assert.doesNotMatch(runText(job), /(?:^|[\s;&|(])(?:pnpm|npm|npx|yarn)\s/mu, `${jobId} must not install or build`);
		for (const step of job.steps ?? []) {
			if (/^actions\/checkout@/u.test(step.uses ?? "")) {
				assert.equal(step.with.ref, "${{ github.workflow_sha }}", `${jobId}: ${step.name}`);
				assert.equal(step.with["persist-credentials"], false, `${jobId}: ${step.name}`);
			}
		}
	}

	const prepare = wf.jobs.prepare;
	const validate = stepNamed(prepare, "Validate customer build inputs").run;
	assert.match(validate, /refs\/heads\/\$\{DEFAULT_BRANCH\}/u, "runs from the protected default branch only");
	assert.ok(validate.includes(`[[ "\${RELEASE_TAG}" =~ ${RC_TAG_SHELL_PATTERN} ]]`), "the shared rc.N tag grammar");
	assert.ok(validate.includes(`[[ "\${RELEASE_TAG}" =~ ${FINAL_TAG_SHELL_PATTERN} ]]`), "or the final vX.Y.Z tag promotion publishes");
	assert.ok(validate.includes('[[ "${CUSTOMER_ID}" =~ ^[a-z0-9][a-z0-9-]{1,31}$ ]]'), "the contract's customer id grammar");
	assert.match(validate, /stem=SingularityAIDR-\$\{label\}-\$\{version\}-x64/u);

	const bundles = stepNamed(prepare, "Verify the promoted release and its signed SEA bundles").run;
	assert.match(bundles, /isDraft,isPrerelease[\s\S]*"false false"/u, "only a promoted (final, non-draft) release");
	assert.match(bundles, /gh attestation verify "\$\{archive\}"[\s\S]*--signer-workflow "\$\{GITHUB_REPOSITORY\}\/\.github\/workflows\/release-rc\.yml"[\s\S]*--source-ref "refs\/tags\/\$\{source_tag\}"[\s\S]*--source-digest "\$\{tag_sha\}"/u);
	// A final tag: exactly one promoted RC of that version, at the same commit, is the attested source.
	assert.match(bundles, /source_tag="\$\{RELEASE_TAG\}"/u, "an RC tag is its own attestation source");
	assert.ok(bundles.includes(`if [[ "\${RELEASE_TAG}" =~ ${FINAL_TAG_SHELL_PATTERN} ]]; then`));
	assert.match(bundles, /select\(\.draft == false and \.prerelease == false\)/u, "only a promoted RC release");
	assert.match(bundles, /\[\[ "\$\{#promoted\[@\]\}" -eq 1 \]\]/u, "exactly one promoted RC per version");
	assert.match(bundles, /\[\[ "\$\{rc_sha\}" == "\$\{tag_sha\}" \]\]/u, "the final tag points at the RC's commit");
	assert.ok(bundles.indexOf('source_tag="${promoted[0]}"') < bundles.indexOf("gh attestation verify"));
	assert.match(bundles, /build-sea\.mjs --verify "\$\{dir\}" --public-key/u, "Ed25519 release-key signatures and the release flavour");
	assert.match(bundles, /grep -q "sha256:\$\{fingerprint#sha256:\}"/u, "the release key matches its pinned fingerprint");

	// The packet is verified, for this customer, before anything is embedded.
	const packet = stepNamed(prepare, "Verify the customer packet before it is embedded");
	assert.match(packet.run, /node scripts\/customer-packet-verify\.mjs \\\n\s+--packet-file "\$\{packet\}" \\\n\s+--public-keys deploy\/onprem\/license-public-keys\.json \\\n\s+--expect-customer-id "\$\{CUSTOMER_ID\}"/u);
	assert.match(packet.run, /set -euo pipefail/u, "a refused packet (non-zero exit) stops the build");
	assert.match(packet.run, /document_sha256 !== sha256/u, "the verified bytes are the embedded bytes");
	assert.equal(packet.env.PACKET_B64, "${{ inputs.packet_source == 'secret' && secrets[steps.inputs.outputs.secret_name] || '' }}");
	// The admin panel's inline packet is decoded only for packet_source=input, then verified like the others.
	assert.equal(packet.env.PACKET_INPUT_B64, "${{ inputs.packet_source == 'input' && inputs.packet_b64 || '' }}");
	assert.ok(packet.run.indexOf('base64 --decode > "${packet}"') < packet.run.indexOf("customer-packet-verify.mjs"));
	const names = prepare.steps.map((step) => step.name);
	assert.ok(names.indexOf(packet.name) < names.indexOf("Hand the verified packet to the build jobs (pinned)"));
	// prepare reads public keys and the packet only, never a private key.
	assert.deepEqual([...secretsIn(Object.assign({}, ...prepare.steps.map((step) => step.env ?? {})))].sort(), ["AIDR_SIGNING_PUBLIC_KEY_FINGERPRINT", "AIDR_SIGNING_PUBLIC_KEY_PEM"]);

	// Every build job starts from prepare and rechecks the hashes it bound.
	for (const jobId of ["linux-build", "linux-sign", "windows"]) assert.ok([wf.jobs[jobId].needs].flat().includes("prepare"), `${jobId} needs prepare`);
	const linux = stepNamed(wf.jobs["linux-build"], "Build the customer's Linux packages from the verified bundle").run;
	assert.match(linux, /EXPECTED_PACKET_SHA256[^\n]*sha256sum --check --strict/u);
	assert.match(linux, /EXPECTED_SEA_SHA256[^\n]*sha256sum --check --strict/u);
	assert.match(linux, /build-linux-packages\.mjs[\s\S]*--customer-packet "\$\{packet\}" \\\n\s+--customer-id "\$\{CUSTOMER_ID\}"/u);
	assert.deepEqual(secretsIn(Object.assign({}, ...wf.jobs["linux-build"].steps.map((step) => step.env ?? {}))).has("AIDR_LINUX_PACKAGE_GPG_PRIVATE_KEY"), false, "the build job holds no signing key");
	assert.match(runText(wf.jobs["linux-build"]), /node --test deploy\/installers\/installers\.test\.mjs/u);
	const gpg = stepNamed(wf.jobs["linux-sign"], "Sign Linux packages with ephemeral GPG custody").run;
	assert.match(gpg, /no unsigned package is delivered/u);
	assert.match(gpg, /rpmkeys --dbpath "\$\{rpmdb\}" --checksig/u);
	assert.match(gpg, /gpg --batch --verify "\$\{file\}\.asc" "\$\{file\}"/u);

	const windows = stepNamed(wf.jobs.windows, "Build and Authenticode-sign with ephemeral runner certificate custody").run;
	assert.equal(wf.jobs.windows["runs-on"], "windows-2022");
	assert.equal(wf.jobs.windows.environment, "release-candidate");
	assert.ok(windows.indexOf("Verified customer packet hash mismatch") < windows.indexOf("Import-PfxCertificate"));
	assert.ok(windows.indexOf("Signed SEA archive hash mismatch") < windows.indexOf("Import-PfxCertificate"));
	assert.match(windows, /build-msi\.ps1 [^\n]*-SignThumbprint \$thumbprint[^\n]*-CustomerPacket \$packet -CustomerId \$env:CUSTOMER_ID @bundleArgs/u);
	assert.doesNotMatch(windows, /-Unsigned\b/u, "no unsigned installer is delivered");
	assert.match(windows, /finally \{[\s\S]*Remove-Item -LiteralPath \$certificatePath -DeleteKey -Force/u);
	assert.match(text, /wix extension add -g \$extension/u);
	assert.match(text, /"WixToolset\.Bal\.wixext\/5\.0\.2"/u);

	// Delivered artifacts: SingularityAIDR-<CUSTOMER>-<version>-<arch>.<ext>, attested.
	const uploads = Object.values(wf.jobs).flatMap((job) => job.steps.filter((step) => /^actions\/upload-artifact@/u.test(step.uses ?? "")).map((step) => step.with.name));
	for (const ext of ["deb", "rpm", "tar.gz", "msi", "exe"]) assert.ok(uploads.includes(`\${{ needs.prepare.outputs.stem }}.${ext}`), `.${ext} is delivered under the customer name`);
	for (const jobId of ["linux-sign", "windows"]) {
		assert.ok(wf.jobs[jobId].steps.some((step) => /^actions\/attest-build-provenance@/u.test(step.uses ?? "")), `${jobId} attests what it delivers`);
	}
	// The release publishes and attests the signed SEA bundles this workflow consumes.
	const publish = workflow("release-rc.yml").jobs["final-sign-publish"];
	assert.match(stepNamed(publish, "Attest the desktop installers (pinned)").with["subject-path"], /installers\/sea\/\*\.tgz/u);
	assert.match(stepNamed(publish, "Publish draft prerelease evidence (pinned)").with.files, /installers\/sea\/\*\.tgz/u);
	assert.match(stepNamed(publish, "Recheck signed SEA bundles across runner boundary").run, /aidr-sea-windows-signed\.tgz" \| sha256sum --check --strict/u);
	// The builders the workflow calls accept the per-customer flags.
	assert.match(readFileSync(path.join(root, "deploy/installers/linux/build-linux-packages.mjs"), "utf8"), /"customer-packet",\n\s+"customer-id",/u);
	assert.match(readFileSync(path.join(root, "deploy/installers/windows/build-msi.ps1"), "utf8"), /\[string\]\$CustomerPacket = ''[\s\S]*\[switch\]\$Bundle/u);
});

// ─── final release tags (B1) ──────────────────────────────────────────────

test("final vX.Y.Z tags: one grammar, accepted next to rc.N, never built", () => {
	const shell = new RegExp(FINAL_TAG_SHELL_PATTERN, "u");
	for (const tag of ["v1.0.0", "v2.10.3", "v1.0.0-rc.1", "v1.0", "1.0.0", "v1.0.0-beta", "v1.0.0 ", "v1.0.0-sprint3"]) {
		assert.equal(shell.test(tag), FINAL_TAG_PATTERN.test(tag), tag);
	}
	assert.deepEqual(parseReleaseTag("v1.0.0"), { version: "1.0.0", rc: null, final: true });
	assert.deepEqual(parseReleaseTag("v1.0.0-rc.3"), { version: "1.0.0", rc: 3, final: false });
	assert.throws(() => parseReleaseTag("v1.0.0-sprint3"), /neither/u);
	assert.equal(finalTagFor("v1.4.2-rc.7"), "v1.4.2");
	// release-rc.yml and release-images.yml still build only RC tags: a final tag carries the promoted RC's bytes.
	assert.deepEqual(workflow("release-rc.yml").on.push.tags, ["v*.*.*-rc.*"]);
	assert.deepEqual(workflow("release-images.yml").on.push.tags, ["v*.*.*-rc.*"]);
});

test("release-promote: the final vX.Y.Z release republishes the promoted RC's signed files at its commit, after the GO gate", () => {
	const promote = workflow("release-promote.yml").jobs.promote;
	const names = promote.steps.map((step) => step.name);
	const go = goStepIndex(promote, "promote");
	const resolve = stepNamed(promote, "Resolve the final release tag for this RC");
	assert.equal(resolve.id, "final_tag");
	const resolveAt = names.indexOf(resolve.name);
	assert.ok(resolveAt > go, "resolved after the GO gate");
	const firstMutation = promote.steps.findIndex(isProductionMutation);
	assert.ok(resolveAt < firstMutation, "a conflicting final tag stops promotion before anything is published");
	assert.match(resolve.run, /final_tag="\$\{RELEASE_TAG%-rc\.\*\}"/u);
	assert.ok(resolve.run.includes(`[[ "\${final_tag}" =~ ${FINAL_TAG_SHELL_PATTERN} ]]`));
	assert.match(resolve.run, /\[\[ "\$\{final_sha\}" == "\$\{rc_sha\}" \]\][\s\S]*nothing was promoted/u, "an existing final tag elsewhere refuses promotion");
	const final = stepNamed(promote, "Publish the final vX.Y.Z release from the same bundle (pinned)");
	assert.ok(names.indexOf(final.name) > names.indexOf("Publish final GitHub release from the same bundle (pinned)"), "after the RC release itself is final");
	assert.ok(names.indexOf(final.name) < names.indexOf("Publish installers to the download portal"));
	assert.ok(isProductionMutation(final), "the final release is a production mutation behind the GO gate");
	assert.equal(final.with.tag_name, "${{ steps.final_tag.outputs.tag }}");
	assert.equal(final.with.target_commitish, "${{ steps.final_tag.outputs.sha }}");
	assert.equal(final.with.files, "release-output/*", "the same verified bundle, nothing rebuilt");
	assert.equal(final.with.prerelease, false);
	assert.equal(final.with.draft, false);
	assert.equal(final.with.make_latest, true);
});

// ─── Windows Authenticode signer backends (B3) ─────────────────────────────

const WINDOWS_SIGNING_STEPS = [
	["release-rc.yml", "windows-authenticode", "Authenticode sign with ephemeral runner certificate custody", /& \.\/scripts\/sign-windows-response-payload\.ps1 [^\n]*-ExpectedThumbprint \$thumbprint[^\n]*-Signer \$signer/u],
	["release-rc.yml", "installers-windows", "Build and Authenticode-sign the MSI with ephemeral runner certificate custody", /build-msi\.ps1 [^\n]*-SignThumbprint \$thumbprint -Signer \$signer/u],
	["customer-installer.yml", "windows", "Build and Authenticode-sign with ephemeral runner certificate custody", /build-msi\.ps1 [^\n]*-SignThumbprint \$thumbprint -Signer \$signer/u],
];

test("Windows Authenticode: every signing job selects pfx, azure-key-vault or jsign by repository variable, with one pinned identity", () => {
	for (const [file, jobId, stepName, call] of WINDOWS_SIGNING_STEPS) {
		const job = workflow(file).jobs[jobId];
		const step = stepNamed(job, stepName);
		const label = `${file}:${jobId}`;
		assert.equal(step.env.AIDR_WINDOWS_SIGNER, "${{ vars.AIDR_WINDOWS_SIGNER || 'pfx' }}", `${label}: the backend is a repository/environment variable, PFX by default`);
		// Backend secrets reach only the backend that uses them.
		assert.equal(step.env.WINDOWS_CODE_SIGNING_PFX_B64, "${{ (vars.AIDR_WINDOWS_SIGNER || 'pfx') == 'pfx' && secrets.AIDR_WINDOWS_CODE_SIGNING_PFX_B64 || '' }}", label);
		assert.equal(step.env.WINDOWS_CODE_SIGNING_PFX_PASSWORD, "${{ (vars.AIDR_WINDOWS_SIGNER || 'pfx') == 'pfx' && secrets.AIDR_WINDOWS_CODE_SIGNING_PFX_PASSWORD || '' }}", label);
		assert.equal(step.env.AIDR_JSIGN_STOREPASS, "${{ (vars.AIDR_WINDOWS_SIGNER || 'pfx') == 'jsign' && secrets.AIDR_JSIGN_STOREPASS || '' }}", label);
		for (const name of ["AIDR_AZURE_KEY_VAULT_URL", "AIDR_AZURE_KEY_VAULT_CERTIFICATE", "AIDR_AZURE_TENANT_ID", "AIDR_AZURE_CLIENT_ID", "AIDR_JSIGN_STORETYPE", "AIDR_JSIGN_KEYSTORE", "AIDR_JSIGN_ALIAS"]) {
			assert.equal(step.env[name], `\${{ vars.${name} }}`, `${label}: ${name} is a non-secret variable`);
		}
		assert.deepEqual([...secretsIn(Object.fromEntries(Object.entries(step.env).filter(([key]) => /AZURE/u.test(key))))], [], `${label}: the Azure signer holds no client secret (OIDC federation)`);
		assert.equal(job.permissions["id-token"], "write", `${label}: the azure-key-vault signer exchanges a GitHub OIDC token`);
		const run = step.run;
		assert.ok(run.indexOf(". ./scripts/windows-authenticode-signer.ps1") < run.indexOf("Resolve-AidrAuthenticodeSigner $env:AIDR_WINDOWS_SIGNER"), label);
		// The pinned thumbprint is required for every backend; the PFX only for pfx.
		assert.match(run, /if \(\$thumbprint -cnotmatch '\^\[0-9A-F\]\{40\}\$'\) \{ throw /u, `${label}: every backend is checked against the pinned thumbprint`);
		assert.match(run, /if \(\$signer -eq 'pfx' -and \(\[string\]::IsNullOrWhiteSpace\(\$env:WINDOWS_CODE_SIGNING_PFX_B64\)/u, label);
		assert.match(run, /if \(\$signer -eq 'pfx'\) \{\n\s+if \(\$env:GITHUB_ACTIONS -ne 'true' -or \$env:RUNNER_ENVIRONMENT -ne 'github-hosted'\) \{ throw "PFX import requires an ephemeral GitHub-hosted runner" \}/u, `${label}: PFX custody stays on ephemeral runners`);
		const pfxBlock = run.search(/if \(\$signer -eq 'pfx'\) \{\n\s+New-Item -ItemType Directory -Path \$privateDirectory/u);
		assert.ok(pfxBlock > 0 && pfxBlock < run.indexOf("Import-PfxCertificate"), `${label}: the PFX is imported only for the pfx backend`);
		assert.match(run, call, `${label}: the signer reaches the signing script`);
		assert.match(run, /finally \{[\s\S]*Remove-Item -LiteralPath \$certificatePath -DeleteKey -Force/u, `${label}: PFX cleanup unchanged`);
		assert.doesNotMatch(run, /-Unsigned\b/u, `${label}: no unsigned build`);
	}
});

test("Windows Authenticode signer library: pinned tools, secrets by reference, pinned identity verified after every backend", () => {
	const lib = readFileSync(path.join(root, "scripts/windows-authenticode-signer.ps1"), "utf8");
	assert.match(lib, /\$script:AidrSignerBackends = @\('pfx', 'azure-key-vault', 'jsign'\)/u);
	assert.match(lib, /\$script:AidrJsignSha256 = '[0-9a-f]{64}'/u);
	assert.match(lib, /\$script:AidrAzureSignToolSha256 = '[0-9a-f]{64}'/u);
	assert.match(lib, /\$script:AidrJsignUrl = 'https:\/\/github\.com\/ebourg\/jsign\/releases\/download\/7\.4\/jsign-7\.4\.jar'/u);
	assert.match(lib, /\$script:AidrAzureSignToolUrl = 'https:\/\/api\.nuget\.org\/v3-flatcontainer\/azuresigntool\/7\.0\.1\/azuresigntool\.7\.0\.1\.nupkg'/u);
	assert.match(lib, /pinned_tool_hash_mismatch/u, "a downloaded tool whose hash differs is deleted and refused");
	assert.match(lib, /<packageSources><clear \/>/u, "AzureSignTool installs only from the hash-checked local package");
	for (const storeType of ["AZUREKEYVAULT", "TRUSTEDSIGNING", "GOOGLECLOUD", "AWS", "DIGICERTONE", "ESIGNER", "PKCS11", "CRYPTOCERTUM", "ETOKEN", "YUBIKEY"]) {
		assert.match(lib, new RegExp(`'${storeType}'`, "u"), `jsign store type ${storeType}`);
	}
	// jsign reads the store password from the environment by name; the secret is never an argument.
	assert.match(lib, /'--storepass', 'env:AIDR_JSIGN_STOREPASS'/u);
	assert.match(lib, /'--tsmode', 'RFC3161'/u);
	assert.match(lib, /'-fd', 'sha256', '-tr', \$TimestampServer, '-td', 'sha256'/u);
	assert.match(lib, /'sign', '\/fd', 'SHA256', '\/tr', \$TimestampServer, '\/td', 'SHA256', '\/sha1', \$Thumbprint/u);
	assert.match(lib, /api:\/\/AzureADTokenExchange/u, "Azure access through GitHub OIDC federation");
	assert.doesNotMatch(lib, /client_secret|-kvs\b/u, "no Azure client secret path");
	// Verification after signing, for every backend.
	const invoke = lib.slice(lib.indexOf("function Invoke-AidrAuthenticodeSign"));
	assert.match(invoke, /Invoke-AidrSignerProcess[\s\S]*Assert-AidrAuthenticodeSigned -Files \$Files -Thumbprint \$pinned\s*\}\s*$/u);
	const verify = lib.slice(lib.indexOf("function Assert-AidrAuthenticodeSigned"), lib.indexOf("function Invoke-AidrAuthenticodeSign"));
	for (const guard of ["invalid_authenticode_signature", "unexpected_signing_certificate", "1.3.6.1.5.5.7.3.3", "missing_authenticode_timestamp"]) {
		assert.ok(verify.includes(guard), `verification keeps ${guard}`);
	}
	assert.doesNotMatch(lib, /^Set-StrictMode/mu, "a dot-sourced library must not change the caller's strict mode");
});

test("Windows Authenticode: MSI, Burn engine and setup EXE all sign through the selected backend", () => {
	const ps1 = readFileSync(path.join(root, "deploy/installers/windows/build-msi.ps1"), "utf8");
	assert.match(ps1, /\[string\]\$Signer = ''/u);
	assert.match(ps1, /\. \(Join-Path \$repo 'scripts\\windows-authenticode-signer\.ps1'\)/u);
	assert.match(ps1, /if \(\$signing -eq 'signed'\) \{ \$Signer = Resolve-AidrAuthenticodeSigner \$Signer \}/u);
	assert.doesNotMatch(ps1, /'sign', '\/sha1'/u, "no signing call bypasses the backend");
	assert.equal((ps1.match(/Invoke-AidrAuthenticodeSign -Signer \$Signer /gu) ?? []).length, 4, "bundle executables, the per-user cleanup script, the MSI and the Invoke-AuthenticodeSign helper (Burn engine + EXE)");
	assert.match(ps1, /function Invoke-AuthenticodeSign\([^)]*\) \{\n\s+Invoke-AidrAuthenticodeSign -Signer \$Signer -Files \$Files -Thumbprint \$SignThumbprint/u);
	const payload = readFileSync(path.join(root, "scripts/sign-windows-response-payload.ps1"), "utf8");
	assert.match(payload, /\[ValidateSet\('pfx', 'azure-key-vault', 'jsign'\)\]\[string\]\$Signer = 'pfx'/u);
	assert.match(payload, /\. \(Join-Path \$PSScriptRoot 'windows-authenticode-signer\.ps1'\)/u);
	const hsm = payload.slice(payload.indexOf("# The key stays in the HSM/token"));
	assert.match(hsm, /signing_preimage_mismatch[\s\S]*Invoke-AidrAuthenticodeSign -Signer \$Signer[\s\S]*expired_signing_certificate/u, "preimages checked first, certificate validity checked after");
	// The receipt and the per-file signature checks are shared by every backend.
	assert.ok(payload.indexOf("Assert-AidrSigningSignature $file.absolute $thumbprint", payload.indexOf("$outputs = @()")) > 0);
});

// ─── vendor-signed air-gap image bundle (C6) ─────────────────────────────

test("release-images: the air-gap bundle is built from the verified tag, Ed25519- and cosign-signed, and carries no credentials", () => {
	const release = workflow("release-images.yml");
	const build = release.jobs["build-sign"];
	assert.equal(build.outputs.sha, "${{ steps.identity.outputs.sha }}");
	assert.equal(build.outputs.tag, "${{ steps.identity.outputs.tag }}");
	const job = release.jobs["airgap-bundle"];
	assert.ok(job, "the airgap-bundle job is missing");
	assert.deepEqual([job.needs].flat(), ["build-sign"], "only after the signed-tag identity check and the image scan gate");
	assert.equal(job.environment, "release-images");
	assert.deepEqual(job.permissions, { contents: "read", "id-token": "write", attestations: "write" });
	const names = job.steps.map((step) => step.name);
	const checkout = stepNamed(job, "Checkout protected tag (pinned)");
	assert.equal(checkout.with.ref, "${{ needs.build-sign.outputs.tag }}");
	assert.equal(checkout.with["persist-credentials"], false);
	const confirm = names.indexOf("Confirm the checkout is the verified release commit");
	const firstTool = job.steps.findIndex((step) => /(?:^|[\s;&|(])(?:pnpm|node|go|docker|cosign)\s/mu.test(step.run ?? ""));
	assert.ok(confirm >= 0 && confirm < firstTool, "the commit is checked against build-sign's verified SHA before any tag code runs");
	assert.match(stepNamed(job, names[confirm]).run, /"\$\(git rev-parse HEAD\)" == "\$\{EXPECTED_SHA\}"/u);

	const save = stepNamed(job, "Save every image of the default self-hosted stack (throwaway stack, credentials discarded)").run;
	assert.match(save, /trap 'rm -rf "\$\{stack\}" "\$\{scratch\}"' EXIT/u, "the throwaway stack and its generated credentials are deleted on the runner");
	assert.ok(save.indexOf("node scripts/deployment-prepare.mjs --mode self-hosted --output \"${stack}\"") < save.indexOf("docker compose --project-directory \"${stack}\" -f \"${stack}/compose.yml\" build"));
	assert.match(save, /build-airgap-images\.mjs --compose "\$\{stack\}\/compose\.yml" --output "\$\{RUNNER_TEMP\}\/aidr-airgap"/u);
	assert.match(save, /build-airgap-images\.mjs --verify --compose "\$\{stack\}\/compose\.yml"/u, "the bundle is checked complete against the stack");

	// AIDR-079: the first-party dashboard image in the bundle has no CRITICAL/HIGH finding, no ignores.
	const gate = stepNamed(job, "Gate the bundled dashboard image (no CRITICAL or HIGH, no ignores)").run;
	assert.ok(gate.indexOf("sha256sum --check --strict") < gate.indexOf("tar -xzf"), "Trivy is verified before it is unpacked");
	assert.match(gate, /--severity CRITICAL,HIGH --exit-code 1/u);
	assert.match(gate, /--ignorefile "\$\{empty\}\/empty\.trivyignore"/u);
	assert.doesNotMatch(gate, /--ignore-unfixed|--vex|--skip-files/u);
	const savedAt = names.indexOf("Save every image of the default self-hosted stack (throwaway stack, credentials discarded)");
	assert.ok(savedAt < names.indexOf("Gate the bundled dashboard image (no CRITICAL or HIGH, no ignores)") && names.indexOf("Gate the bundled dashboard image (no CRITICAL or HIGH, no ignores)") < names.indexOf("Sign the transfer bundle (Ed25519 offline signature and cosign keyless)"), "nothing is signed before the gate passes");

	const sign = stepNamed(job, "Sign the transfer bundle (Ed25519 offline signature and cosign keyless)");
	assert.deepEqual([...secretsIn(sign.env)], ["AIDR_OFFLINE_BUNDLE_SIGNING_KEY_PEM"]);
	assert.deepEqual([...secretsIn(Object.assign({}, ...job.steps.map((step) => step.env ?? {})))], ["AIDR_OFFLINE_BUNDLE_SIGNING_KEY_PEM"], "the job holds no other secret");
	assert.match(sign.run, /no unsigned air-gap bundle is produced/u);
	assert.match(sign.run, /trap 'rm -rf "\$\{key_dir\}"' EXIT/u);
	const order = [
		"node scripts/onprem-offline-bundle.mjs build",
		"--signing-key \"${key_dir}/signing.pem\"",
		"node scripts/onprem-offline-bundle.mjs verify --bundle",
		"cosign sign-blob --yes --bundle",
		"cosign verify-blob --bundle",
		"--certificate-oidc-issuer https://token.actions.githubusercontent.com",
	].map((needle) => sign.run.indexOf(needle));
	assert.ok(order.every((at) => at >= 0), order.join(","));
	assert.deepEqual([...order].sort((a, b) => a - b), order, "sign, verify offline, cosign sign, cosign verify");
	assert.match(stepNamed(job, "Attest the air-gap bundle (pinned)").with["subject-path"], /airgap-release\/\$\{\{ steps\.bundle\.outputs\.name \}\}\.tar$/u);
	const upload = stepNamed(job, "Upload the signed air-gap bundle (pinned)");
	assert.equal(upload.with["if-no-files-found"], "error");
	assert.deepEqual(job.steps.filter(isProductionMutation).map((step) => step.name), [], "the bundle is an artifact, not a publication");
});

// ─── Windows real-host evidence (D5) ───────────────────────────────────────

test("windows-real-host-e2e: opt-in, secret-free Windows runs of the real hosts and the VS Code extension host", async () => {
	const wf = workflow("windows-real-host-e2e.yml");
	const text = raw("windows-real-host-e2e.yml");
	assert.deepEqual(Object.keys(wf.on), ["workflow_dispatch"], "opt-in only: never on push or schedule");
	assert.deepEqual(wf.permissions, { contents: "read" });
	assert.doesNotMatch(text, /secrets\./u, "the scripted mock model needs no API key or credential");
	assert.doesNotMatch(text, /environment:/u);
	for (const job of Object.values(wf.jobs)) {
		assert.equal(job["runs-on"], "windows-latest");
		assert.deepEqual(job.steps.filter(isProductionMutation).map((step) => step.name), []);
		for (const step of job.steps) {
			if (/^actions\/checkout@/u.test(step.uses ?? "")) assert.equal(step.with["persist-credentials"], false);
		}
	}
	const realHost = wf.jobs["real-host"];
	assert.deepEqual(realHost.strategy.matrix.host, ["claude-code", "codex"]);
	assert.equal(realHost.strategy["fail-fast"], false);
	const { HOST_PINS } = await import("./real-host-e2e/hosts.mjs");
	assert.equal(wf.env.CLAUDE_CODE_VERSION, HOST_PINS["claude-code"].version, "the Claude Code pin is the harness pin");
	const scenarios = stepNamed(realHost, "Run the real-host scenarios").run;
	assert.match(scenarios, /node scripts\/real-host-e2e\/run\.mjs --host \$env:HOST_ID --install/u);
	assert.match(scenarios, /--evidence-dir docs\/evidence\/real-host\/windows/u, "Windows records never overwrite the Linux ones");
	assert.match(scenarios, /if \(\$LASTEXITCODE -ne 0\) \{ throw/u, "a failing scenario fails the job");
	assert.match(stepNamed(realHost, "Frozen install and development build").run, /node --test scripts\/real-host-e2e\/mock-llm-server\.test\.mjs scripts\/real-host-e2e\/hosts\.test\.mjs/u);
	assert.equal(stepNamed(realHost, "Upload the Windows evidence record (pinned)").if, "success() || failure()");
	const vscode = wf.jobs.vscode;
	assert.equal(vscode.if, "inputs.run_vscode");
	assert.match(stepNamed(vscode, "Download pinned VS Code").run, /downloadAndUnzipVSCode\(process\.env\.VSCODE_VERSION\)/u);
	assert.match(stepNamed(vscode, "Download pinned VS Code").run, /VSCODE_EXECUTABLE_PATH=\$code/u);
	assert.equal(stepNamed(vscode, "Run the VS Code extension E2E").env.AIDR_E2E_ENABLE_IDE_HOST, "1");
	// What is not automated is written down.
	const readme = readFileSync(path.join(root, "docs/evidence/real-host/README.md"), "utf8");
	for (const needle of ["## Windows", "What still needs a human on Windows", "Cursor", "A real model", "A person reviews them"]) assert.ok(readme.includes(needle), needle);
});
