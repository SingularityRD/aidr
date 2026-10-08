// Shared contract for the optional AIDR privacy gateway (aidr-privacy-service)
// component. scripts/deployment-prepare.mjs (Compose), deploy/helm/build-images.mjs
// (Kubernetes image) and the customer kit all use this module so the image
// context, the container layout and the refusal rules cannot drift apart.
//
// What the gateway is: an explicit egress API (POST /v1/egress over mutual TLS)
// that applies the privacy policy before it sends text to ONE configured provider
// with credentials only the gateway holds. What it is not: a transparent proxy.
// It does not intercept traffic that is not addressed to it; clients must be
// configured to call it, and direct provider access must be removed by network
// policy, an egress firewall or MDM.
import { X509Certificate, createPrivateKey } from "node:crypto";
import { copyFileSync, existsSync, lstatSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join, posix } from "node:path";

export const PRIVACY_GATEWAY_SERVICE = "privacy-gateway";
export const PRIVACY_GATEWAY_PROFILE = "privacy-gateway";
export const PRIVACY_GATEWAY_UID = 10001;

// Fixed container layout. packages/privacy/deployment/container-service-config.mjs
// enforces the same paths inside the image.
export const PRIVACY_GATEWAY_LAYOUT = Object.freeze({
	config: "/etc/aidr-privacy/config/service.json",
	trust: "/etc/aidr-privacy/trust",
	tls: "/etc/aidr-privacy/tls",
	tlsCert: "/etc/aidr-privacy/tls/server.pem",
	tlsClientCa: "/etc/aidr-privacy/tls/client-ca.pem",
	tlsKeyRef: "aidr-privacy-tls-key",
	secrets: "/run/secrets/aidr-privacy",
	models: "/opt/aidr-models",
	state: "/var/lib/aidr-privacy",
	database: "/var/lib/aidr-privacy/control.sqlite",
	nerPython: "/opt/aidr-ner/bin/python3",
	port: 8443,
});
const L = PRIVACY_GATEWAY_LAYOUT;

const PRIVACY_GATEWAY_PROVIDERS = Object.freeze({
	"openai-responses": "https://api.openai.com",
	"gemini-generate-content": "https://generativelanguage.googleapis.com",
});

// Files of packages/privacy the image needs, relative to that package. dist/ is
// added by privacyGatewayPackageEntries (compiled JavaScript only).
const PACKAGE_FILES = Object.freeze([
	"package.json",
	"LICENSE",
	"NOTICE.md",
	"ner/ner_worker.py",
	"ner/artifacts.py",
	"ner/bioes.py",
	"ner/requirements.linux-py311.lock.txt",
	"deployment/container-service-config.mjs",
]);
export const PRIVACY_GATEWAY_REQUIRED_RUNTIME = Object.freeze([
	...PACKAGE_FILES,
	"dist/platform/serve.js",
	"dist/platform/service.js",
	"dist/platform/index.js",
]);
// Image definition files under deploy/privacy-gateway that every delivery carries.
export const PRIVACY_GATEWAY_DEFINITION_FILES = Object.freeze([
	"deploy/privacy-gateway/Dockerfile",
	"deploy/privacy-gateway/healthcheck.mjs",
	"deploy/privacy-gateway/privacy-gateway.mjs",
	"deploy/privacy-gateway/README.md",
]);

const fail = (message) => { throw new Error(message); };

/** Relative paths (POSIX) under packages/privacy that make up the gateway runtime. */
export function privacyGatewayPackageEntries(root) {
	const pkg = join(root, "packages/privacy");
	const missing = PRIVACY_GATEWAY_REQUIRED_RUNTIME.filter((path) => !existsSync(join(pkg, path)));
	if (missing.length) fail(`Privacy gateway runtime is missing (${missing.join(", ")}); build it first with: pnpm --filter @singularityrd/aidr-privacy build`);
	const walk = (dir, prefix) => readdirSync(dir).sort().flatMap((name) => {
		const full = join(dir, name);
		const relative = `${prefix}/${name}`;
		const info = lstatSync(full);
		if (info.isSymbolicLink()) fail(`Privacy gateway runtime cannot contain symbolic links: ${relative}`);
		if (info.isDirectory()) return walk(full, relative);
		return /\.js$/.test(name) ? [relative] : [];
	});
	return [...PACKAGE_FILES, ...walk(join(pkg, "dist"), "dist")];
}

/** Stage the Docker build context (Dockerfile, health probe, runtime package). */
export function stagePrivacyGatewayImage(root, destination) {
	const entries = privacyGatewayPackageEntries(root);
	mkdirSync(destination, { recursive: true });
	for (const name of ["Dockerfile", "healthcheck.mjs"]) copyFileSync(join(root, "deploy/privacy-gateway", name), join(destination, name));
	for (const relative of entries) {
		const target = join(destination, "package", relative);
		mkdirSync(dirname(target), { recursive: true });
		copyFileSync(join(root, "packages/privacy", relative), target);
	}
	mkdirSync(join(destination, "wheelhouse"), { recursive: true });
	writeFileSync(join(destination, "wheelhouse/README.txt"), "Optional: place the hash-pinned wheels for package/ner/requirements.linux-py311.lock.txt here for an offline (--no-index) build.\n", { flag: "wx" });
	writeFileSync(join(destination, ".dockerignore"), "**/*.map\n**/*.d.ts\n", { flag: "wx" });
	return entries.map((relative) => `package/${relative}`);
}

/**
 * Validate the gateway's mutual-TLS material. The service refuses to start
 * without it; preparation refuses earlier, with a reason, and also refuses
 * material the service would accept but that is weak.
 */
export function validatePrivacyGatewayTls({ cert, key, clientCa }, now = Date.now()) {
	let server;
	let ca;
	let privateKey;
	try { server = new X509Certificate(cert); } catch { fail("Privacy gateway server certificate must be a PEM X.509 certificate"); }
	try { ca = new X509Certificate(clientCa); } catch { fail("Privacy gateway client CA must be a PEM X.509 certificate (mutual TLS is mandatory)"); }
	try { privateKey = createPrivateKey(key); } catch { fail("Privacy gateway server key must be an unencrypted PEM private key"); }
	const current = (certificate) => now >= Date.parse(certificate.validFrom) && now < Date.parse(certificate.validTo);
	if (!current(server)) fail("Privacy gateway server certificate is expired or not yet valid");
	if (server.ca) fail("Privacy gateway server certificate must be a leaf certificate, not a CA");
	if (!server.checkPrivateKey(privateKey)) fail("Privacy gateway server key does not match the server certificate");
	const details = privateKey.asymmetricKeyDetails ?? {};
	const strong = privateKey.asymmetricKeyType === "rsa" ? (details.modulusLength ?? 0) >= 2048
		: privateKey.asymmetricKeyType === "ec" ? ["prime256v1", "secp384r1", "secp521r1"].includes(details.namedCurve)
		: ["ed25519", "ed448"].includes(privateKey.asymmetricKeyType);
	if (!strong) fail("Privacy gateway server key is weak; use RSA 2048+ , ECDSA P-256/P-384/P-521 or Ed25519");
	if (!ca.ca) fail("Privacy gateway client CA must be a CA certificate (basicConstraints CA:TRUE)");
	if (!current(ca)) fail("Privacy gateway client CA is expired or not yet valid");
	if (ca.fingerprint256 === server.fingerprint256) fail("Privacy gateway client CA must not be the server certificate");
	return { serverFingerprint256: server.fingerprint256, clientCaFingerprint256: ca.fingerprint256, serverNotAfter: new Date(server.validTo).toISOString() };
}

const REF = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const OWNED_KEYS = ["tls", "host", "port", "secretStore", "databasePath", "documents"];
const isObject = (value) => !!value && typeof value === "object" && !Array.isArray(value);

function httpsOrigin(value, name) {
	let url;
	try { url = new URL(value); } catch { url = null; }
	if (!url || url.protocol !== "https:" || url.username || url.password || url.search || url.hash) fail(`Privacy gateway ${name} must be an https:// URL without credentials`);
}

/**
 * Validate the administrator service JSON (examples/platform/service-config.example.json
 * shape) and return the container configuration plus the secret references and
 * trust files it needs. Listener, TLS, secret store, state path and NER runtime are
 * owned by the deployment and refused when supplied.
 */
export function normalizePrivacyGatewayConfig(config) {
	if (!isObject(config)) fail("Privacy gateway service configuration must be a JSON object");
	const owned = OWNED_KEYS.filter((key) => Object.hasOwn(config, key));
	if (owned.length) fail(`Privacy gateway service configuration must not set ${owned.join(", ")}: the deployment owns the listener, mutual TLS, secret store and state path${owned.includes("documents") ? " (document parsing is not packaged in the gateway image)" : ""}`);
	if (JSON.stringify(config).includes("REPLACE")) fail("Privacy gateway service configuration still holds a REPLACE placeholder");
	if (typeof config.tenantId !== "string" || !REF.test(config.tenantId)) fail("Privacy gateway tenantId must be a short identifier");
	const destination = config.destination;
	if (!isObject(destination) || PRIVACY_GATEWAY_PROVIDERS[destination.kind] === undefined || destination.origin !== PRIVACY_GATEWAY_PROVIDERS[destination.kind]) {
		fail(`Privacy gateway destination must be one of ${Object.entries(PRIVACY_GATEWAY_PROVIDERS).map(([kind, origin]) => `${kind} (${origin})`).join(", ")}`);
	}
	if (typeof destination.model !== "string" || !destination.model.trim() || typeof destination.id !== "string" || !REF.test(destination.id)) fail("Privacy gateway destination needs an id and an approved model");
	if (!isObject(config.oidc) || !isObject(config.broker)) fail("Privacy gateway service configuration needs oidc and broker sections");
	httpsOrigin(config.oidc.issuer, "oidc.issuer");
	httpsOrigin(config.broker.issuer, "broker.issuer");
	const ner = config.ner;
	if (!isObject(ner) || Object.hasOwn(ner, "python")) fail("Privacy gateway ner must set manifest and manifestSha256 only (the image owns the Python runtime)");
	if (typeof ner.manifest !== "string" || !ner.manifest.startsWith(`${L.models}/`) || posix.normalize(ner.manifest) !== ner.manifest) fail(`Privacy gateway ner.manifest must be a path under ${L.models}`);
	if (!/^[a-f0-9]{64}$/.test(ner.manifestSha256 ?? "")) fail("Privacy gateway ner.manifestSha256 must be the independently approved 64-hex digest");
	const encryptionKeys = config.encryption?.keys;
	if (!Array.isArray(encryptionKeys) || !encryptionKeys.length || !encryptionKeys.some((entry) => entry?.id === config.encryption.active)) fail("Privacy gateway encryption must list keys including the active key");
	const refs = [
		config.oidc.clientSecretRef, config.broker.keyRef, destination.secretRef, config.audit?.secretRef,
		...encryptionKeys.map((entry) => entry?.secretRef),
		...(config.dataPolicy ? [config.dataPolicy.secretRef] : []),
	];
	for (const ref of refs) {
		if (typeof ref !== "string" || !REF.test(ref)) fail("Privacy gateway secret references must be short file names");
		if (ref === L.tlsKeyRef) fail(`Privacy gateway secret reference ${L.tlsKeyRef} is reserved for the TLS key`);
	}
	if (!Array.isArray(config.policy?.keys) || !config.policy.keys.length) fail("Privacy gateway policy needs signedPath and verification keys");
	const trust = [config.oidc.caPath, config.broker.caPath, config.broker.certPath, config.policy.signedPath, ...config.policy.keys.map((entry) => entry?.path)];
	for (const path of trust) {
		if (typeof path !== "string" || !path.startsWith(`${L.trust}/`) || posix.normalize(path) !== path) fail(`Privacy gateway trust files must be paths under ${L.trust}`);
	}
	return {
		config: {
			...config,
			secretStore: "mounted-files",
			host: "0.0.0.0",
			port: L.port,
			databasePath: L.database,
			ner: { ...ner, python: L.nerPython },
			tls: { certPath: L.tlsCert, clientCaPath: L.tlsClientCa, keyRef: L.tlsKeyRef },
		},
		secretRefs: [...new Set(refs)].sort(),
		trustFiles: [...new Set(trust.map((path) => path.slice(L.trust.length + 1)))].sort(),
		modelManifest: ner.manifest.slice(L.models.length + 1),
	};
}

const ipv4 = (value) => {
	const parts = value.split(".");
	if (parts.length !== 4 || parts.some((part) => !/^(0|[1-9]\d{0,2})$/.test(part) || Number(part) > 255)) return null;
	return parts.reduce((acc, part) => (acc * 256) + Number(part), 0);
};

/**
 * Parse an IPv4 CIDR list for the gateway egress allow-list. Default routes,
 * prefixes shorter than /8, loopback, link-local (cloud metadata), "this network"
 * and multicast ranges are refused: an allow-list must name destinations.
 */
export function parsePrivacyGatewayCidrs(value, name, { required = true } = {}) {
	const list = String(value ?? "").split(",").map((entry) => entry.trim()).filter(Boolean);
	if (!list.length) {
		if (required) fail(`${name} is required: list the provider, identity provider and broker IPv4 CIDRs the gateway may reach`);
		return [];
	}
	return [...new Set(list.map((cidr) => {
		const match = /^([0-9.]+)\/(\d{1,2})$/.exec(cidr);
		const address = match ? ipv4(match[1]) : null;
		const prefix = match ? Number(match[2]) : -1;
		if (address === null || prefix < 0 || prefix > 32) fail(`${name}: ${cidr} is not an IPv4 CIDR`);
		if (prefix < 8) fail(`${name}: ${cidr} is too broad; an egress allow-list must name destinations (prefix /8 or longer)`);
		const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
		if (((address & mask) >>> 0) !== address) fail(`${name}: ${cidr} has host bits set; use the network address`);
		const first = address >>> 24;
		if (first === 0 || first === 127 || first >= 224 || (address >>> 16) === ((169 << 8) | 254)) fail(`${name}: ${cidr} is a loopback, link-local, multicast or reserved range`);
		return cidr;
	}))];
}

/** Validate the dedicated Compose network subnet for the gateway. */
export function parsePrivacyGatewaySubnet(value) {
	const match = /^([0-9.]+)\/(\d{1,2})$/.exec(value ?? "");
	const address = match ? ipv4(match[1]) : null;
	const prefix = match ? Number(match[2]) : -1;
	const mask = prefix > 0 ? (0xffffffff << (32 - prefix)) >>> 0 : 0;
	const privateRange = address !== null && ((address >>> 24) === 10 || (address >>> 20) === ((172 << 4) | 1) || (address >>> 16) === ((192 << 8) | 168));
	if (address === null || prefix < 16 || prefix > 29 || ((address & mask) >>> 0) !== address || !privateRange) {
		fail("--privacy-gateway-subnet must be a private IPv4 network between /16 and /29 (default 172.31.253.0/28)");
	}
	return value;
}

// Chains the firewall alternates between, plus the single-chain name earlier
// releases used (migrated away from on the next run).
export const PRIVACY_GATEWAY_FIREWALL_CHAINS = Object.freeze(["AIDR-PRIVACY-GW-A", "AIDR-PRIVACY-GW-B"]);
export const PRIVACY_GATEWAY_LEGACY_FIREWALL_CHAIN = "AIDR-PRIVACY-GATEWAY";

/**
 * Render the host egress firewall for the Compose gateway network. Docker adds
 * no egress filtering of its own; these DOCKER-USER rules are what restricts the
 * gateway to the approved destinations. They are prepared, not applied.
 *
 * Re-running the script never flushes the chain that DOCKER-USER currently jumps
 * to: the rules are built in the other of two alternating chains (A/B), that
 * chain is completed (ending in REJECT) before anything jumps to it, the new jump
 * is inserted at the top of DOCKER-USER, and only then is the old jump removed
 * and the old chain flushed and deleted. At every instant the gateway subnet is
 * filtered by a complete chain. A failure before the swap removes only the
 * half-built chain and leaves the active one in place. The gateway network is
 * IPv4-only (parsePrivacyGatewaySubnet), so there are no ip6tables rules.
 */
export function renderPrivacyGatewayFirewall({ subnet, egressCidrs, dnsCidrs }) {
	const [chainA, chainB] = PRIVACY_GATEWAY_FIREWALL_CHAINS;
	const lines = [
		"#!/usr/bin/env bash",
		"# AIDR privacy gateway egress firewall (generated by scripts/deployment-prepare.mjs).",
		"#",
		"# Docker does not filter container egress. Until these rules are applied the",
		"# gateway container can reach any destination. Review, then run as root AFTER",
		"# Docker starts (and again after every Docker or host firewall restart):",
		"#   bash privacy-gateway/egress-firewall.sh",
		"# The rules only touch traffic FROM the dedicated gateway network; replies to",
		"# clients of the published mTLS port are allowed as established connections.",
		"# Re-running is safe: the active chain is replaced by a fully built one and is",
		"# never flushed while DOCKER-USER still jumps to it.",
		"set -euo pipefail",
		`SUBNET='${subnet}'`,
		`CHAINS=(${chainA} ${chainB})`,
		`LEGACY_CHAIN=${PRIVACY_GATEWAY_LEGACY_FIREWALL_CHAIN}`,
		"",
		"docker_user_rules() { iptables -w -S DOCKER-USER; }",
		"if ! RULES=$(docker_user_rules); then",
		"\techo \"DOCKER-USER chain is missing: start Docker first, then re-run this script\" >&2",
		"\texit 1",
		"fi",
		"# A chain is in use while any DOCKER-USER rule jumps to it.",
		"referenced() { grep -Eq -- \"-j $1( |\\$)\" <<<\"$RULES\"; }",
		"chain_exists() { iptables -w -S \"$1\" >/dev/null 2>&1; }",
		"",
		"NEW=",
		"for candidate in \"${CHAINS[@]}\"; do",
		"\tif ! referenced \"$candidate\"; then NEW=$candidate; break; fi",
		"done",
		"if [ -z \"$NEW\" ]; then",
		"\techo \"Both ${CHAINS[*]} are referenced from DOCKER-USER; refusing to replace a chain in use. Remove the stale DOCKER-USER jump by hand, then re-run.\" >&2",
		"\texit 1",
		"fi",
		"",
		"SWAPPED=0",
		"cleanup() {",
		"\tlocal status=$?",
		"\tif [ \"$status\" -ne 0 ] && [ \"$SWAPPED\" -eq 0 ]; then",
		"\t\t# Nothing jumps to the half-built chain yet; drop it and keep the active one.",
		"\t\tif ! iptables -w -C DOCKER-USER -s \"$SUBNET\" -j \"$NEW\" 2>/dev/null; then",
		"\t\t\tiptables -w -F \"$NEW\" 2>/dev/null || true",
		"\t\t\tiptables -w -X \"$NEW\" 2>/dev/null || true",
		"\t\tfi",
		"\t\techo \"AIDR privacy gateway egress firewall NOT updated; the previous rules are unchanged\" >&2",
		"\tfi",
		"\treturn \"$status\"",
		"}",
		"trap cleanup EXIT",
		"",
		"# 1. Build the complete rule set in the unused chain (a leftover from an",
		"#    interrupted run is not referenced, so clearing it is safe).",
		"if chain_exists \"$NEW\"; then iptables -w -F \"$NEW\"; else iptables -w -N \"$NEW\"; fi",
		"iptables -w -A \"$NEW\" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
		...egressCidrs.map((cidr) => `iptables -w -A "$NEW" -d '${cidr}' -p tcp --dport 443 -j RETURN`),
		...dnsCidrs.flatMap((cidr) => ["udp", "tcp"].map((protocol) => `iptables -w -A "$NEW" -d '${cidr}' -p ${protocol} --dport 53 -j RETURN`)),
		"iptables -w -A \"$NEW\" -j REJECT",
		"",
		"# 2. Swap: jump to the complete new chain first, then drop the old jumps.",
		"iptables -w -I DOCKER-USER 1 -s \"$SUBNET\" -j \"$NEW\"",
		"SWAPPED=1",
		"for old in \"${CHAINS[@]}\" \"$LEGACY_CHAIN\"; do",
		"\t[ \"$old\" != \"$NEW\" ] || continue",
		"\twhile iptables -w -C DOCKER-USER -s \"$SUBNET\" -j \"$old\" 2>/dev/null; do",
		"\t\tiptables -w -D DOCKER-USER -s \"$SUBNET\" -j \"$old\"",
		"\tdone",
		"done",
		"",
		"# 3. Retire old chains that nothing jumps to any more.",
		"RULES=$(docker_user_rules)",
		"for old in \"${CHAINS[@]}\" \"$LEGACY_CHAIN\"; do",
		"\t[ \"$old\" != \"$NEW\" ] || continue",
		"\tif chain_exists \"$old\" && ! referenced \"$old\"; then",
		"\t\tiptables -w -F \"$old\"",
		"\t\tiptables -w -X \"$old\"",
		"\tfi",
		"done",
		"echo \"AIDR privacy gateway egress restricted for $SUBNET (chain $NEW)\"",
		"",
	];
	return lines.join("\n");
}
