#!/usr/bin/env node
/**
 * Public TLS renewal hook for the ingress host.
 *
 * The systemd unit `deploy/ingress/aidr-tls-renew.service` runs this script on a
 * timer. It drives the ACME client, then refuses to reload the ingress unless the
 * served chain file is a complete, currently valid chain for the requested
 * hostname. Every attempt writes a renewal receipt beside the certificate chain,
 * so an operator can see what happened without trusting a console message.
 *
 * Nothing here proves a real certificate was issued for a real domain: the ACME
 * client talks to a certificate authority that this repository cannot reach in
 * tests. A runner is injected by `deployment-tls-renew.test.mjs` so the control
 * flow is exercised with fixture files instead of a live challenge.
 */
import { spawnSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const CERTIFICATE_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_DETAIL = 400;

/** Run one command and return its raw result; tests inject a replacement. */
function defaultRunner(command, args) {
	const result = spawnSync(command, args, { encoding: "utf8", timeout: 120_000, windowsHide: true });
	return {
		status: result.status,
		stdout: result.stdout ?? "",
		stderr: result.stderr ?? "",
		error: result.error ?? null,
	};
}

function excerpt(value) {
	const text = String(value ?? "").trim().replace(/\s+/g, " ");
	return text.length > MAX_DETAIL ? `${text.slice(0, MAX_DETAIL)}...` : text;
}

function failureReason(result) {
	if (result?.error?.code) return String(result.error.code);
	const detail = excerpt(result?.stderr || result?.stdout);
	return detail || `exit ${result?.status ?? "unknown"}`;
}

/** Certificate names a TLS client would accept for this leaf certificate. */
function certificateNames(leaf) {
	const names = [];
	if (typeof leaf.subjectAltName === "string") {
		for (const part of leaf.subjectAltName.split(",")) {
			const value = part.trim();
			if (value.toUpperCase().startsWith("DNS:")) names.push(value.slice(4).toLowerCase());
		}
	}
	const commonName = /(?:^|,\s*)CN=([^,]+)/.exec(leaf.subject ?? "");
	if (commonName) names.push(commonName[1].trim().toLowerCase());
	return names;
}

function nameMatches(name, hostname) {
	if (name === hostname) return true;
	return name.startsWith("*.") && hostname.endsWith(name.slice(1)) && hostname.split(".").length === name.split(".").length;
}

/**
 * Parse the served chain file and describe the leaf certificate.
 *
 * A one-certificate file, an unparseable file, or a file whose first certificate
 * was not issued by the second one is refused here: presenting such a file would
 * make the ingress serve an untrusted or incomplete chain. `now` is injectable so
 * the validity window can be exercised without waiting for a real clock.
 */
function inspectChain(chainPath, hostname, now) {
	if (!existsSync(chainPath)) throw new Error(`certificate chain ${chainPath} is missing after the ACME client reported success`);
	const blocks = readFileSync(chainPath, "utf8").match(CERTIFICATE_BLOCK) ?? [];
	if (blocks.length < 2) {
		throw new Error(`certificate chain ${chainPath} carries ${blocks.length} certificate(s); a leaf certificate and its issuer are required`);
	}
	let chain;
	try {
		chain = blocks.map((block) => new X509Certificate(block));
	} catch {
		throw new Error(`certificate chain ${chainPath} is not parseable PEM`);
	}
	const [leaf, issuer] = chain;
	if (!leaf.checkIssued(issuer) || !leaf.verify(issuer.publicKey)) {
		throw new Error(`certificate chain ${chainPath} does not link its leaf certificate to the declared issuer`);
	}
	if (!certificateNames(leaf).some((name) => nameMatches(name, hostname))) {
		throw new Error(`certificate chain ${chainPath} does not cover the requested hostname ${hostname}`);
	}
	const notBefore = Date.parse(leaf.validFrom);
	const notAfter = Date.parse(leaf.validTo);
	if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter)) {
		throw new Error(`certificate chain ${chainPath} has an unreadable validity window`);
	}
	if (notBefore > now) throw new Error(`certificate chain ${chainPath} is not valid before ${new Date(notBefore).toISOString()}`);
	if (notAfter <= now) throw new Error(`certificate chain ${chainPath} expired at ${new Date(notAfter).toISOString()}`);
	return {
		certificates: chain.length,
		fingerprint: createHash("sha256").update(leaf.raw).digest("hex"),
		expiresAt: new Date(notAfter).toISOString(),
	};
}

/**
 * Attempt one renewal and return its receipt.
 *
 * Order is deliberate: validate the request, prove the ACME client exists, run the
 * challenge, inspect the served chain, and only then test and reload the ingress.
 * Any refusal or failure writes a receipt with `outcome` `refused` or `failed`,
 * leaves `reloaded` false and throws. The ingress is never reloaded on a failed
 * challenge, and a missing ACME client is a refusal rather than a silent success.
 */
export function renewCertificate(options = {}, dependencies = {}) {
	const run = dependencies.run ?? defaultRunner;
	const clock = dependencies.now ?? (() => Date.now());
	const hostname = String(options.hostname ?? process.env.AIDR_TLS_HOSTNAME ?? "").trim().toLowerCase();
	const email = String(options.email ?? process.env.AIDR_TLS_EMAIL ?? "").trim();
	const tlsDir = resolve(String(options.tlsDir ?? process.env.AIDR_TLS_DIR ?? "/etc/aidr/tls"));
	const receiptPath = resolve(String(options.receipt ?? process.env.AIDR_TLS_RECEIPT ?? join(tlsDir, "renewal-receipt.json")));
	const acmeClient = String(options.acmeClient ?? process.env.AIDR_ACME_CLIENT ?? "certbot");
	const webroot = resolve(String(options.webroot ?? process.env.AIDR_TLS_WEBROOT ?? "/var/www/aidr-acme"));
	const nginx = String(options.nginx ?? process.env.AIDR_NGINX ?? "nginx");
	const chainPath = join(tlsDir, "fullchain.pem");
	const startedAt = new Date(clock()).toISOString();
	const receipt = {
		schema_version: 1,
		action: "renew-public-tls-certificate",
		started_at: startedAt,
		completed_at: null,
		hostname: hostname || null,
		acme_client: acmeClient,
		certificate_chain: chainPath,
		receipt_path: receiptPath,
		certificate_fingerprint_sha256: null,
		certificate_expires_at: null,
		challenge_succeeded: false,
		reloaded: false,
		outcome: "refused",
		detail: null,
		scope: "Local renewal attempt record. It states that the ACME client ran and that the served chain file was inspected; it is not proof that a public hostname, DNS record or real TLS client served this certificate.",
	};
	const write = (patch) => {
		Object.assign(receipt, patch, { completed_at: new Date(clock()).toISOString() });
		mkdirSync(dirname(receiptPath), { recursive: true, mode: 0o700 });
		writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
		return receipt;
	};
	const refuse = (detail) => {
		const error = new Error(detail);
		error.receipt = write({ outcome: "refused", detail });
		throw error;
	};
	const fail = (detail) => {
		const error = new Error(detail);
		error.receipt = write({ outcome: "failed", detail });
		throw error;
	};

	const missing = [];
	if (!HOSTNAME.test(hostname)) missing.push("--hostname with a fully qualified domain name");
	if (!EMAIL.test(email)) missing.push("--email with an ACME account contact");
	if (missing.length) refuse(`TLS renewal requires ${missing.join(" and ")}; refusing to run without an explicit hostname and email`);

	const probe = run(acmeClient, ["--version"]);
	if (!probe || probe.status !== 0) {
		refuse(`ACME client "${acmeClient}" is not available (${failureReason(probe)}); install it or pass --acme-client <path>`);
	}

	let previousFingerprint = null;
	try {
		previousFingerprint = inspectChain(chainPath, hostname, clock()).fingerprint;
	} catch {
		previousFingerprint = null;
	}

	const challenge = run(acmeClient, [
		"certonly", "--non-interactive", "--agree-tos", "--keep-until-expiring",
		"--webroot", "-w", webroot, "-d", hostname, "-m", email,
	]);
	if (!challenge || challenge.status !== 0) {
		fail(`ACME challenge for ${hostname} failed (${failureReason(challenge)}); the ingress was not reloaded`);
	}
	receipt.challenge_succeeded = true;

	let chain;
	try {
		chain = inspectChain(chainPath, hostname, clock());
	} catch (error) {
		fail(`ACME challenge for ${hostname} reported success but ${error.message}; the ingress was not reloaded`);
	}
	receipt.certificate_fingerprint_sha256 = chain.fingerprint;
	receipt.certificate_expires_at = chain.expiresAt;

	const unchanged = previousFingerprint !== null && previousFingerprint === chain.fingerprint;
	if (!unchanged) {
		const tested = run(nginx, ["-t"]);
		if (!tested || tested.status !== 0) {
			fail(`ingress configuration test failed (${failureReason(tested)}); the renewed certificate is not served and nginx was not reloaded`);
		}
		const reload = run(nginx, ["-s", "reload"]);
		if (!reload || reload.status !== 0) {
			fail(`ingress reload failed (${failureReason(reload)}); the renewed certificate is not served`);
		}
		receipt.reloaded = true;
	}
	return write({
		outcome: unchanged ? "unchanged" : "renewed",
		detail: unchanged
			? `the ACME client reported no change for ${hostname}; the ingress was not reloaded`
			: `renewed ${hostname} from a complete chain and reloaded the ingress after a successful challenge`,
	});
}

const invoked = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invoked) {
	const { values } = parseArgs({
		options: {
			hostname: { type: "string" }, email: { type: "string" }, "tls-dir": { type: "string" },
			receipt: { type: "string" }, "acme-client": { type: "string" }, webroot: { type: "string" }, nginx: { type: "string" },
		},
	});
	try {
		const receipt = renewCertificate(values);
		console.log(JSON.stringify({
			outcome: receipt.outcome,
			hostname: receipt.hostname,
			certificate_fingerprint_sha256: receipt.certificate_fingerprint_sha256,
			certificate_expires_at: receipt.certificate_expires_at,
			reloaded: receipt.reloaded,
			receipt: receipt.receipt_path,
		}));
	} catch (error) {
		console.error(`AIDR TLS renewal did not complete: ${error.message}`);
		process.exitCode = 1;
	}
}
