// On-prem single sign-on preparation (scripts/deployment-prepare.mjs).
//
// Three opt-in pieces for customers whose identity provider (Keycloak, ADFS,
// self-hosted GoTrue SAML) lives on their internal network:
//
//   --idp-ca-file <pem>            Trust an internal CA in the Edge Functions
//                                  runtime so the oidc-sso function can fetch an
//                                  internal IdP's discovery document, JWKS and
//                                  token endpoint over TLS. The pinned
//                                  supabase/edge-runtime honours only
//                                  DENO_TLS_CA_STORE=mozilla,system; "system"
//                                  loads the PEM file named by SSL_CERT_FILE, so
//                                  public CAs (mozilla) stay trusted and the
//                                  customer CA is added, never substituted.
//   --oidc-internal-idp-hosts <h>  Exact host[:port] list allowed to resolve to
//                                  private addresses (AIDR_OIDC_INTERNAL_IDP_HOSTS,
//                                  enforced by supabase/functions/_shared/safe-fetch.ts).
//   --with-saml                    Turn on SAML in the self-hosted GoTrue and
//                                  generate its signing key on this host.
//
// Nothing here weakens the default: without these options the stack is
// prepared exactly as before.

import { generateKeyPairSync, X509Certificate, createHash } from "node:crypto";
import { isIP } from "node:net";

export const IDP_CA_TARGET = "/etc/aidr/idp-ca.pem";
export const IDP_CA_RELATIVE = "functions-trust/idp-ca.pem";
const MAX_CA_BYTES = 256 * 1024;
const MAX_CERTIFICATES = 20;
const MAX_INTERNAL_HOSTS = 16;
const DNS_NAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
const NEVER_INTERNAL = /(^|\.)localhost$|^localhost\.localdomain$|^ip6-(localhost|loopback)$|^metadata\.google\.(internal|com)$|^instance-data\.ec2\.internal$/;

/**
 * Validate a PEM bundle of CA certificates. Returns the normalised bundle and a
 * summary for deployment.json. Refuses private keys, non-certificate PEM
 * blocks, unparsable or expired certificates and oversized input.
 */
export function validateIdpCaBundle(text, now = new Date()) {
	if (typeof text !== "string" || text.length === 0 || Buffer.byteLength(text) > MAX_CA_BYTES)
		throw new Error("--idp-ca-file must be a PEM file of at most 256 KiB");
	if (/PRIVATE KEY/.test(text)) throw new Error("--idp-ca-file contains a private key; supply CA certificates only");
	const blocks = [...text.matchAll(/-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g)];
	if (blocks.length === 0 || blocks.some((block) => block[1] !== "CERTIFICATE"))
		throw new Error("--idp-ca-file must contain only PEM CERTIFICATE blocks");
	if (blocks.length > MAX_CERTIFICATES) throw new Error(`--idp-ca-file may contain at most ${MAX_CERTIFICATES} certificates`);
	const certificates = blocks.map((block) => {
		let certificate;
		try {
			certificate = new X509Certificate(block[0]);
		} catch {
			throw new Error("--idp-ca-file contains a certificate that cannot be parsed");
		}
		if (Date.parse(certificate.validTo) <= now.getTime())
			throw new Error(`--idp-ca-file certificate "${certificate.subject.replaceAll("\n", ", ")}" has expired`);
		return certificate;
	});
	const pem = `${blocks.map((block) => block[0].trim()).join("\n")}\n`;
	return {
		pem,
		summary: {
			sha256: createHash("sha256").update(pem).digest("hex"),
			certificates: certificates.map((certificate) => ({
				subject: certificate.subject.replaceAll("\n", ", "),
				ca: certificate.ca,
				not_after: new Date(certificate.validTo).toISOString(),
				fingerprint256: certificate.fingerprint256,
			})),
		},
	};
}

/**
 * Same grammar as parseInternalHosts in supabase/functions/_shared/safe-fetch.ts
 * (parity-tested): comma/space separated FQDN[:port], no IP literals, no
 * wildcards, never loopback or metadata names, at most 16 entries. Returns the
 * canonical value written to AIDR_OIDC_INTERNAL_IDP_HOSTS.
 */
export function normalizeInternalIdpHosts(value) {
	const entries = String(value ?? "").split(/[\s,]+/).filter(Boolean);
	if (entries.length > MAX_INTERNAL_HOSTS) throw new Error(`--oidc-internal-idp-hosts accepts at most ${MAX_INTERNAL_HOSTS} hosts`);
	const canonical = [];
	for (const entry of entries) {
		const match = /^([^:]+)(?::(\d{1,5}))?$/.exec(entry.toLowerCase());
		const host = match?.[1]?.replace(/\.$/, "") ?? "";
		const port = match?.[2] === undefined ? 443 : Number(match[2]);
		if (!match || !DNS_NAME.test(host) || isIP(host) !== 0 || NEVER_INTERNAL.test(host) || port < 1 || port > 65_535)
			throw new Error(`--oidc-internal-idp-hosts entry "${entry}" must be a fully qualified host name with an optional port`);
		const item = port === 443 ? host : `${host}:${port}`;
		if (!canonical.includes(item)) canonical.push(item);
	}
	return canonical.join(",");
}

/** RSA-2048 PKCS#1 DER, base64: the format GoTrue reads from GOTRUE_SAML_PRIVATE_KEY. */
export function generateSamlSigningKey() {
	const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
	return privateKey.export({ type: "pkcs1", format: "der" }).toString("base64");
}

/**
 * Wire the SSO options into the generated self-hosted Compose model:
 *  - the dashboard learns whether to show OIDC / SAML sign-in from .env;
 *  - GoTrue SAML settings come from .env (off unless --with-saml);
 *  - with a CA bundle, the functions container mounts it read-only and adds it
 *    to the runtime trust store next to the public roots.
 */
export function applySsoCompose(compose, { idpCa = false } = {}) {
	const dashboard = compose.services.dashboard;
	if (dashboard) {
		dashboard.environment ??= {};
		Object.assign(dashboard.environment, {
			AIDR_OIDC_SSO: "${AIDR_OIDC_SSO:-false}",
			AIDR_SAML_PROVIDERS: "${AIDR_SAML_PROVIDERS:-}",
			AIDR_SAML_PROVIDER_ID: "${AIDR_SAML_PROVIDER_ID:-}",
			AIDR_SAML_DOMAIN: "${AIDR_SAML_DOMAIN:-}",
		});
	}
	const auth = compose.services.auth;
	if (auth) {
		auth.environment ??= {};
		Object.assign(auth.environment, {
			GOTRUE_SAML_ENABLED: "${GOTRUE_SAML_ENABLED:-false}",
			GOTRUE_SAML_PRIVATE_KEY: "${GOTRUE_SAML_PRIVATE_KEY:-}",
		});
	}
	const functions = compose.services.functions;
	if (idpCa) {
		if (!functions) throw new Error("--idp-ca-file needs the self-hosted functions service");
		functions.environment ??= {};
		Object.assign(functions.environment, { DENO_TLS_CA_STORE: "mozilla,system", SSL_CERT_FILE: IDP_CA_TARGET });
		functions.volumes = [
			...(functions.volumes ?? []),
			{ type: "bind", source: `./${IDP_CA_RELATIVE}`, target: IDP_CA_TARGET, read_only: true },
		];
	}
	return compose;
}
