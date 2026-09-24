// The extracted customer kit is a deliberately small, offline-capable delivery.
// Keep this contract in the kit so its verifier and the assembler agree on the
// acceptance tooling that must travel with every candidate.

export const CUSTOMER_KIT_BENCHMARK_FILES = Object.freeze([
	"scripts/benchmarks/README.md",
	"scripts/benchmarks/attest.mjs",
	"scripts/benchmarks/benchmark-contracts.test.mjs",
	"scripts/benchmarks/comparison-spec.json",
	"scripts/benchmarks/corpus-spec.json",
	"scripts/benchmarks/corpus.template.json",
	"scripts/benchmarks/evaluate.mjs",
	"scripts/benchmarks/evaluate.test.mjs",
	"scripts/benchmarks/generate-corpus.mjs",
	"scripts/benchmarks/schemas/attestation.schema.json",
	"scripts/benchmarks/schemas/corpus.schema.json",
	"scripts/benchmarks/schemas/observations.schema.json",
	"scripts/benchmarks/schemas/report.schema.json",
	"scripts/benchmarks/sold-scope.json",
	"scripts/benchmarks/split-corpus.mjs",
	"scripts/benchmarks/trusted-keys.json",
]);

export const CUSTOMER_KIT_DELIVERY_FILES = Object.freeze({
	region_manifest: "deploy/regions.manifest.json",
	ingress_readme: "deploy/ingress/README.md",
	device_start_script: "deploy/ingress/device-start.mjs",
	device_start_test: "deploy/ingress/device-start.test.mjs",
	device_start_nginx: "deploy/ingress/nginx.device-start.reference.conf",
	device_start_service: "deploy/ingress/aidr-device-start.service.reference",
	tls_service: "deploy/ingress/aidr-tls-renew.service",
	tls_timer: "deploy/ingress/aidr-tls-renew.timer",
	tls_script: "scripts/deployment-tls-renew.mjs",
	provenance_script: "scripts/generate-provenance.mjs",
	airgap_script: "scripts/build-airgap-images.mjs",
	provenance_test: "scripts/provenance.test.mjs",
	airgap_test: "scripts/airgap-images.test.mjs",
	tls_test: "scripts/deployment-tls-renew.test.mjs",
	release_evidence: "RELEASE-EVIDENCE.md",
});

// These are the files a customer must have to repeat the offline checks. The
// SHA inventory remains the authority for the complete set and catches any
// unlisted extra file; this list catches an assembler that silently omits a
// newly required delivery artifact.
export const CUSTOMER_KIT_REQUIRED_FILES = Object.freeze([
	"START-HERE.md",
	"INSTALLATION.md",
	"FEATURE_INVENTORY.md",
	"scripts/customer-kit-contract.mjs",
	"scripts/customer-kit-verify.mjs",
	"scripts/verify-customer-kit.mjs",
	"scripts/deployment-prepare.mjs",
	"scripts/deployment-bootstrap.mjs",
	"scripts/license-verify.mjs",
	"scripts/import-offline-pack.mjs",
	"deploy/onprem/license-public-keys.json",
	"scripts/deployment-doctor.mjs",
	"scripts/release-signing-lib.mjs",
	"scripts/release-verify.mjs",
	"scripts/deployment-restore-drill.mjs",
	"scripts/archive-boundary.mjs",
	"scripts/deployment-backup.mjs",
	"scripts/deployment-backup-offsite.mjs",
	"scripts/lib/migration-contract.mjs",
	"scripts/lib/migration-hash-compat.mjs",
	"scripts/lib/atomic-write.mjs",
	"scripts/readiness-evidence-worker.mjs",
	"deploy/maintenance/aidr-siem-delivery.service",
	"deploy/maintenance/aidr-siem-delivery.timer",
	"deploy/maintenance/install-systemd.sh",
	"deploy/onprem/README.md",
	"deploy/onprem/compose.onprem.overlay.yml",
	"deploy/onprem/resource-profile.json",
	"packages/dashboard/package.json",
	"RESTORE-DRILL.md",
	"scripts/verify-native-host-matrix-v6.mjs",
	"NATIVE-HOST-ACCEPTANCE.md",
	"SUPPORT-RUNBOOK.md",
	"SECRETS-RUNBOOK.md",
	"LICENSING.md",
	"THREAT-SYNC.md",
	"FIRST-CUSTOMER-SALES-PACKET.md",
	"CANDIDATE-STATUS.md",
	"supabase/config.toml",
	...Object.values(CUSTOMER_KIT_DELIVERY_FILES),
	...CUSTOMER_KIT_BENCHMARK_FILES,
]);

// Top-level guides are renamed in the portable kit. Keep their local links
// inside the extracted directory and avoid implying source-only paths ship.
const docRewrites = {
	"START-HERE.md": [
		["[deployment kılavuzuna](README.md)", "[deployment kılavuzuna](INSTALLATION.md)"],
		["[Supabase dağıtım rehberine](../supabase/README.md)", "[bulut hazırlığına](INSTALLATION.md)"],
		[
			"Private GitHub\nPackages erişimi, sürüm doğrulama ve OpenClaw/OpenCode/Codex kurulum adımları\n[paket kurulum kılavuzunda](../docs/package-installation.md) yer alır.",
			"Bu kitteki uç cihaz kurulum sınırı [kurulum kılavuzunda](INSTALLATION.md) açıklanır. OpenClaw/OpenCode/Codex için ayrıca onaylı imzalı paket ve müşteriye açık dağıtım erişimi gerekir; kitin varlığı bunları sağlamaz.",
		],
	],
	"INSTALLATION.md": [
		["[first-customer guide](FIRST_CUSTOMER.md)", "[first-customer guide](START-HERE.md)"],
		["[on-prem guide](onprem/README.md)", "[on-prem guide](deploy/onprem/README.md)"],
		["[on-prem sizing and AIG guide](onprem/README.md)", "[on-prem sizing and AIG guide](deploy/onprem/README.md)"],
		["For a limited Cloudflare Free pilot, see [the Cloudflare deployment path](cloudflare/README.md).", "The Cloudflare Free pilot requires a separate reviewed source release; it is not deployable from this extracted customer kit."],
		["[FEATURE_INVENTORY.md](../FEATURE_INVENTORY.md)", "[FEATURE_INVENTORY.md](FEATURE_INVENTORY.md)"],
		["[secret management](../docs/runbooks/secrets-management.md)", "[secret management](SECRETS-RUNBOOK.md)"],
		["[licensing](../docs/operations/licensing.md)", "[licensing](LICENSING.md)"],
		["[air-gapped updates](../docs/operations/threat-sync.md#air-gapped-updates)", "[air-gapped updates](THREAT-SYNC.md#air-gapped-updates)"],
		["[licensing](../docs/operations/licensing.md)", "[licensing](LICENSING.md)"],
		["Commercial/customer approvals remain in the existing\n[evidence registry](../docs/production-readiness/commercial-go-evidence-registry.json).", "Commercial/customer approvals remain open in the [candidate status](CANDIDATE-STATUS.md)."],
	],
};

export function renderCustomerKitDoc(name, source) {
	let rendered = source.replaceAll("\r\n", "\n");
	for (const [before, after] of docRewrites[name] ?? []) {
		if (!rendered.includes(before)) throw new Error(`Customer kit guide link changed: ${name}`);
		rendered = rendered.replace(before, after);
	}
	return rendered;
}

export function isMcpGatewayReleaseArtifact(path) {
	return /(?:^|[\/_-])mcp-gateway(?:[\/_-]|\.|$)/i.test(path);
}

// A release bundle is allowed to carry additional explicitly inventoried
// artifacts, but a provenance statement is mandatory for a current customer
// candidate. It is unsigned evidence; publisher authentication remains an
// independent outer-envelope concern.
export const CUSTOMER_KIT_REQUIRED_RELEASE_ARTIFACTS = Object.freeze([
	"aidr-provenance.intoto.json",
]);
