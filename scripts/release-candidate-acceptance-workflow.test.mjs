import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

const workflow = readFileSync(fileURLToPath(new URL("../.github/workflows/release-rc.yml", import.meta.url)), "utf8");

function job(name, next) {
	const start = workflow.indexOf(`  ${name}:\n`);
	const end = next ? workflow.indexOf(`  ${next}:\n`, start + 1) : workflow.length;
	assert.ok(start >= 0 && end > start, `${name} job must exist before ${next ?? "end"}`);
	return workflow.slice(start, end);
}

test("exact RC requires packaged native Claude acceptance on Windows before signing", () => {
	const native = job("acceptance-windows-native", "acceptance-e2e");
	assert.match(native, /needs: \[build-rc, assemble-e2e\]/);
	assert.match(native, /runs-on: windows-2022/);
	assert.match(native, /name: aidr-exact-candidate-/);
	assert.match(native, /verify-claude-native-candidate\.mjs --candidate release-output --expected-candidate-digest \$env:EXPECTED_CANDIDATE_DIGEST --public-key/);
	assert.match(native, /if \(\$LASTEXITCODE -ne 0\) \{ throw "Claude native candidate acceptance failed" \}/);
	assert.match(native, /Upload Windows native package receipt/);
	assert.match(native, /sign-windows-response-payload\.ps1 -CheckOnly[\s\S]*-ExpectedThumbprint \$env:WINDOWS_CODE_SIGNING_THUMBPRINT/);
	assert.ok(native.indexOf("Final packaged Authenticode verification failed") < native.indexOf("Verify packaged native AMSI and hook decisions on Windows"));
	assert.doesNotMatch(native, /continue-on-error:/);
	assert.match(job("final-sign-publish"), /needs: \[build-rc, assemble-e2e, acceptance-e2e, acceptance-windows-native\]/);
});

test("protected acceptance runner requires the installed loopback control plane and binds its smoke to the exact RC", () => {
	const acceptance = job("acceptance-e2e", "final-sign-publish");
	assert.match(acceptance, /AIDR_ACCEPTANCE_DEPLOYMENT_DIR must name an isolated, installed loopback control plane/);
	assert.match(acceptance, /node scripts\/deployment-smoke\.mjs "\$\{AIDR_ACCEPTANCE_DEPLOYMENT_DIR\}" --candidate-inventory release-output\/release-inventory\.json/);
	assert.match(acceptance, /smoke-evidence-\$\{\{ needs\.assemble-e2e\.outputs\.candidate_digest \}\}\.json/);
	assert.ok(acceptance.indexOf("Recheck exact candidate identity across runner boundary") < acceptance.indexOf("Candidate-bound isolated control-plane acceptance"));
	assert.ok(acceptance.indexOf("Candidate-bound isolated control-plane acceptance") < acceptance.indexOf("Real-host connector E2E gate"));
	assert.doesNotMatch(acceptance, /continue-on-error:/);
	assert.doesNotMatch(job("build-rc", "windows-authenticode"), /deployment-smoke\.mjs|verify-claude-native-candidate\.mjs/);
});

test("every external E2E receipt requires a detached signature from the protected acceptance workflow", () => {
	const acceptance = job("acceptance-e2e", "final-sign-publish");
	const manifest = JSON.parse(readFileSync(fileURLToPath(new URL("./e2e-release-manifest.json", import.meta.url)), "utf8"));
	const externalSuites = manifest.suites.filter((suite) => suite.kind === "external");
	assert.ok(externalSuites.length > 0);
	for (const suite of externalSuites) {
		assert.ok(suite.externalEvidenceSignatureEnv, `${suite.id} must declare a signature environment`);
		assert.ok(suite.externalEvidencePublicKeyEnv, `${suite.id} must declare a public key environment`);
		assert.ok(suite.requiredEnv.includes(suite.externalEvidenceSignatureEnv), `${suite.id} signature must be required`);
		assert.ok(suite.requiredEnv.includes(suite.externalEvidencePublicKeyEnv), `${suite.id} signer key must be required`);
	}
	for (const receipt of ["aig-live-control-plane", "supabase-live-control-plane", "dashboard-browser"]) {
		assert.match(acceptance, new RegExp(`\\$\\{evidence_input_dir\\}/${receipt}\\.json\\.sig`));
	}
	assert.match(acceptance, /AIDR_EXTERNAL_E2E_EVIDENCE_PUBLIC_KEY: \$\{\{ secrets\.AIDR_EXTERNAL_E2E_EVIDENCE_PUBLIC_KEY_PEM \}\}/);
	assert.match(acceptance, /AIDR_EXTERNAL_E2E_EVIDENCE_PUBLIC_KEY_PATH=.*external-e2e-public\.pem/);
});
