// Unit tests for scripts/lib/onprem-sso.mjs (deployment-prepare SSO options).
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createPrivateKey, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
	applySsoCompose,
	generateSamlSigningKey,
	IDP_CA_TARGET,
	normalizeInternalIdpHosts,
	validateIdpCaBundle,
} from "./onprem-sso.mjs";

const openssl = process.env.AIDR_OPENSSL ?? "openssl";
const opensslSkip = spawnSync(openssl, ["version"], { encoding: "utf8" }).status === 0 ? false : "openssl is required to mint throwaway test certificates (set AIDR_OPENSSL)";

// Throwaway, locally generated test certificates; nothing here is a real credential.
function certificate(name, { days = 30, ca = true } = {}) {
	const directory = mkdtempSync(join(tmpdir(), "aidr-onprem-sso-"));
	try {
		execFileSync(openssl, ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
			"-keyout", join(directory, "key.pem"), "-out", join(directory, "cert.pem"), "-days", String(days),
			"-subj", `/CN=${name}.aidr-test.invalid`, "-addext", `basicConstraints=critical,CA:${ca ? "TRUE" : "FALSE"}`], { stdio: "ignore" });
		return { cert: readFileSync(join(directory, "cert.pem"), "utf8"), key: readFileSync(join(directory, "key.pem"), "utf8") };
	} finally {
		rmSync(directory, { recursive: true, force: true });
	}
}

test("a CA bundle is accepted, normalised and summarised", { skip: opensslSkip }, () => {
	const root = certificate("corp-root");
	const issuing = certificate("corp-issuing");
	const { pem, summary } = validateIdpCaBundle(`# corporate roots\r\n${root.cert}\n\n${issuing.cert}`);
	assert.equal(pem.match(/BEGIN CERTIFICATE/g)?.length, 2);
	assert.doesNotMatch(pem, /corporate roots/);
	assert.match(summary.sha256, /^[0-9a-f]{64}$/);
	assert.deepEqual(summary.certificates.map((entry) => [entry.subject, entry.ca]), [
		["CN=corp-root.aidr-test.invalid", true],
		["CN=corp-issuing.aidr-test.invalid", true],
	]);
});

test("a CA bundle refuses keys, other PEM blocks, junk and expired certificates", { skip: opensslSkip }, () => {
	const root = certificate("corp-root");
	const expired = certificate("expired", { days: 1 });
	const later = new Date(Date.now() + 3 * 86_400_000);
	const cases = [
		["", /PEM file/],
		["not a certificate", /only PEM CERTIFICATE blocks/],
		[`${root.cert}\n${root.key}`, /private key/],
		[`${root.cert}\n${generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" })}`, /only PEM CERTIFICATE blocks/],
		["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", /cannot be parsed/],
		["x".repeat(300 * 1024), /at most 256 KiB/],
	];
	for (const [text, pattern] of cases) assert.throws(() => validateIdpCaBundle(text), pattern);
	assert.throws(() => validateIdpCaBundle(expired.cert, later), /has expired/);
});

test("internal IdP hosts are canonicalised with the Edge function's grammar", () => {
	assert.equal(normalizeInternalIdpHosts(undefined), "");
	assert.equal(normalizeInternalIdpHosts(" Keycloak.Corp.example:8443, adfs.corp.local:443 adfs.corp.local "), "keycloak.corp.example:8443,adfs.corp.local");
	for (const value of ["10.0.0.5", "[fd00::1]", "keycloak", "*.corp.example", "sso.localhost", "metadata.google.internal", "a.corp.example:0", "a.corp.example:65536", "https://a.corp.example",
		Array.from({ length: 17 }, (_, index) => `h${index}.corp.example`).join(",")]) {
		assert.throws(() => normalizeInternalIdpHosts(value), /--oidc-internal-idp-hosts/, value);
	}
});

test("the SAML signing key is an RSA-2048 PKCS#1 DER key in base64, fresh each time", () => {
	const first = generateSamlSigningKey();
	assert.notEqual(first, generateSamlSigningKey());
	const key = createPrivateKey({ key: Buffer.from(first, "base64"), format: "der", type: "pkcs1" });
	assert.equal(key.asymmetricKeyType, "rsa");
	assert.equal(key.asymmetricKeyDetails?.modulusLength, 2048);
});

test("Compose wiring: dashboard SSO switches, GoTrue SAML from .env, CA mounted read-only next to public roots", () => {
	const compose = () => ({
		services: {
			dashboard: { environment: { NODE_ENV: "production" } },
			auth: { environment: { GOTRUE_SITE_URL: "x" } },
			functions: { environment: { VERIFY_JWT: "false" }, volumes: ["./volumes/functions:/home/deno/functions:Z"] },
		},
	});
	const plain = applySsoCompose(compose());
	assert.equal(plain.services.dashboard.environment.AIDR_OIDC_SSO, "${AIDR_OIDC_SSO:-false}");
	assert.equal(plain.services.dashboard.environment.AIDR_SAML_PROVIDERS, "${AIDR_SAML_PROVIDERS:-}");
	assert.equal(plain.services.auth.environment.GOTRUE_SAML_ENABLED, "${GOTRUE_SAML_ENABLED:-false}");
	assert.equal(plain.services.functions.environment.SSL_CERT_FILE, undefined, "no CA option, no trust change");
	assert.deepEqual(plain.services.functions.volumes, ["./volumes/functions:/home/deno/functions:Z"]);

	const withCa = applySsoCompose(compose(), { idpCa: true });
	assert.equal(withCa.services.functions.environment.DENO_TLS_CA_STORE, "mozilla,system", "public roots stay trusted");
	assert.equal(withCa.services.functions.environment.SSL_CERT_FILE, IDP_CA_TARGET);
	assert.deepEqual(withCa.services.functions.volumes.at(-1), { type: "bind", source: "./functions-trust/idp-ca.pem", target: IDP_CA_TARGET, read_only: true });
	assert.equal(withCa.services.functions.environment.VERIFY_JWT, "false");

	assert.throws(() => applySsoCompose({ services: { dashboard: {} } }, { idpCa: true }), /self-hosted functions service/);
	const cloud = applySsoCompose({ services: { dashboard: { environment: {} } } });
	assert.equal(cloud.services.auth, undefined);
});
