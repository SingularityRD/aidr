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
	"scripts/customer-kit-contract.mjs",
	"scripts/customer-kit-verify.mjs",
	"scripts/verify-customer-kit.mjs",
	"scripts/release-signing-lib.mjs",
	"scripts/release-verify.mjs",
	"scripts/deployment-restore-drill.mjs",
	"RESTORE-DRILL.md",
	"scripts/verify-native-host-matrix-v6.mjs",
	"NATIVE-HOST-ACCEPTANCE.md",
	"SUPPORT-RUNBOOK.md",
	"FIRST-CUSTOMER-SALES-PACKET.md",
	"CANDIDATE-STATUS.md",
	"supabase/config.toml",
	...Object.values(CUSTOMER_KIT_DELIVERY_FILES),
	...CUSTOMER_KIT_BENCHMARK_FILES,
]);

// A release bundle is allowed to carry additional explicitly inventoried
// artifacts, but a provenance statement is mandatory for a current customer
// candidate. It is unsigned evidence; publisher authentication remains an
// independent outer-envelope concern.
export const CUSTOMER_KIT_REQUIRED_RELEASE_ARTIFACTS = Object.freeze([
	"aidr-provenance.intoto.json",
]);
