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
 *
 * `--mode static` serves on-prem and air-gapped ingresses that cannot reach an
 * ACME CA: it validates an operator-supplied chain and key (completeness,
 * hostname, validity margin, key match), installs them atomically and reloads the
 * ingress only after `nginx -t` passes. See `installStaticCertificate`.
 */
import { spawnSync } from "node:child_process";
import { createHash, createPrivateKey, X509Certificate } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
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
	const tlsDir = resolve(String(options.tlsDir ?? process.env.AIDR_TLS_DIR ?? "/etc/letsencrypt"));
	const receiptPath = resolve(String(options.receipt ?? process.env.AIDR_TLS_RECEIPT ?? "/var/lib/aidr/tls-renewal-receipt.json"));
	const acmeClient = String(options.acmeClient ?? process.env.AIDR_ACME_CLIENT ?? "certbot");
	const webroot = resolve(String(options.webroot ?? process.env.AIDR_TLS_WEBROOT ?? "/var/www/aidr-acme"));
	const nginx = String(options.nginx ?? process.env.AIDR_NGINX ?? "nginx");
	const chainPath = join(tlsDir, "live", hostname, "fullchain.pem");
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
		"--config-dir", tlsDir, "--cert-name", hostname, "--webroot", "-w", webroot, "-d", hostname, "-m", email,
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

function readRegularFile(path, label) {
	let stats;
	try {
		stats = lstatSync(path);
	} catch {
		throw new Error(`${label} ${path} does not exist`);
	}
	if (stats.isSymbolicLink() || !stats.isFile()) throw new Error(`${label} ${path} must be a regular, non-symlink file`);
	return { bytes: readFileSync(path), mode: stats.mode };
}

function writeAtomically(path, bytes, mode) {
	const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
	try {
		writeFileSync(temporary, bytes, { mode, flag: "wx" });
		chmodSync(temporary, mode);
		renameSync(temporary, path);
	} catch (error) {
		rmSync(temporary, { force: true });
		throw error;
	}
}

/**
 * Install a customer-supplied (BYO / internal CA) certificate for an on-prem or
 * air-gapped ingress where ACME cannot run.
 *
 * The operator's chain and key are validated before anything is written: the
 * chain must be complete (leaf plus issuer), cover the hostname, be currently
 * valid with at least `minDays` remaining, and the private key must be the leaf's
 * key and owner-only on POSIX. The files are then installed atomically under
 * `<tlsDir>/live/<hostname>/{fullchain,privkey}.pem`, the ingress configuration is
 * tested and only then reloaded. A failed test or reload restores the previously
 * installed files, so the files on disk keep matching what the ingress serves.
 */
export function installStaticCertificate(options = {}, dependencies = {}) {
	const run = dependencies.run ?? defaultRunner;
	const clock = dependencies.now ?? (() => Date.now());
	const hostname = String(options.hostname ?? process.env.AIDR_TLS_HOSTNAME ?? "").trim().toLowerCase();
	const tlsDir = resolve(String(options.tlsDir ?? process.env.AIDR_TLS_DIR ?? "/etc/aidr/tls"));
	const receiptPath = resolve(String(options.receipt ?? process.env.AIDR_TLS_RECEIPT ?? "/var/lib/aidr/tls-renewal-receipt.json"));
	const nginx = String(options.nginx ?? process.env.AIDR_NGINX ?? "nginx");
	const certFile = options.certFile ?? process.env.AIDR_TLS_CERT_FILE;
	const keyFile = options.keyFile ?? process.env.AIDR_TLS_KEY_FILE;
	const minDays = Number(options.minDays ?? process.env.AIDR_TLS_MIN_DAYS ?? 14);
	const liveDir = join(tlsDir, "live", hostname || "invalid");
	const chainPath = join(liveDir, "fullchain.pem");
	const keyPath = join(liveDir, "privkey.pem");
	const receipt = {
		schema_version: 1,
		action: "install-static-tls-certificate",
		mode: "static",
		started_at: new Date(clock()).toISOString(),
		completed_at: null,
		hostname: hostname || null,
		certificate_chain: chainPath,
		receipt_path: receiptPath,
		certificate_fingerprint_sha256: null,
		certificate_expires_at: null,
		key_matches_certificate: false,
		reloaded: false,
		outcome: "refused",
		detail: null,
		scope: "Local installation record for an operator-supplied certificate. It states that the chain and key were validated and installed; it is not proof that a TLS client trusts the issuing CA or that DNS points at this ingress.",
	};
	const write = (patch) => {
		Object.assign(receipt, patch, { completed_at: new Date(clock()).toISOString() });
		mkdirSync(dirname(receiptPath), { recursive: true, mode: 0o700 });
		writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
		return receipt;
	};
	const stop = (outcome, detail) => {
		const error = new Error(detail);
		error.receipt = write({ outcome, detail });
		throw error;
	};

	const missing = [];
	if (!HOSTNAME.test(hostname)) missing.push("--hostname with a fully qualified domain name");
	if (!certFile) missing.push("--cert-file with the full certificate chain");
	if (!keyFile) missing.push("--key-file with the private key");
	if (!Number.isInteger(minDays) || minDays < 0 || minDays > 365) missing.push("--min-days between 0 and 365");
	if (missing.length) stop("refused", `static TLS installation requires ${missing.join(" and ")}`);

	let chain;
	let chainBytes;
	let keyBytes;
	try {
		const source = readRegularFile(resolve(certFile), "certificate chain");
		chainBytes = source.bytes;
		const key = readRegularFile(resolve(keyFile), "private key");
		if (process.platform !== "win32" && (key.mode & 0o077) !== 0) throw new Error(`private key ${resolve(keyFile)} must be owner-only (mode 0600)`);
		keyBytes = key.bytes;
		chain = inspectChain(resolve(certFile), hostname, clock());
	} catch (error) {
		stop("refused", `${error.message}; nothing was installed`);
	}
	let privateKey;
	try {
		privateKey = createPrivateKey(keyBytes);
	} catch {
		stop("refused", "the private key is not a readable unencrypted PEM key; nothing was installed");
	}
	const leaf = new X509Certificate(chainBytes.toString("utf8").match(CERTIFICATE_BLOCK)[0]);
	if (!leaf.checkPrivateKey(privateKey)) stop("refused", "the private key does not belong to the leaf certificate; nothing was installed");
	receipt.key_matches_certificate = true;
	receipt.certificate_fingerprint_sha256 = chain.fingerprint;
	receipt.certificate_expires_at = chain.expiresAt;
	const remainingDays = (Date.parse(chain.expiresAt) - clock()) / 86_400_000;
	if (remainingDays < minDays) {
		stop("refused", `the certificate expires at ${chain.expiresAt}, within the required ${minDays}-day validity margin; nothing was installed`);
	}

	const previous = {
		chain: existsSync(chainPath) ? readFileSync(chainPath) : null,
		key: existsSync(keyPath) ? readFileSync(keyPath) : null,
	};
	if (previous.chain?.equals(chainBytes) && previous.key?.equals(keyBytes)) {
		return write({ outcome: "unchanged", detail: `the supplied certificate for ${hostname} is already installed; the ingress was not reloaded` });
	}
	const restore = () => {
		for (const [path, bytes, mode] of [[chainPath, previous.chain, 0o644], [keyPath, previous.key, 0o600]]) {
			if (bytes) writeAtomically(path, bytes, mode);
			else rmSync(path, { force: true });
		}
	};
	try {
		mkdirSync(liveDir, { recursive: true, mode: 0o700 });
		writeAtomically(keyPath, keyBytes, 0o600);
		writeAtomically(chainPath, chainBytes, 0o644);
	} catch (error) {
		restore();
		stop("failed", `installing the certificate failed (${error.message}); previous files were restored and nginx was not reloaded`);
	}
	const tested = run(nginx, ["-t"]);
	if (!tested || tested.status !== 0) {
		restore();
		stop("failed", `ingress configuration test failed (${failureReason(tested)}); previous files were restored and nginx was not reloaded`);
	}
	const reload = run(nginx, ["-s", "reload"]);
	if (!reload || reload.status !== 0) {
		restore();
		stop("failed", `ingress reload failed (${failureReason(reload)}); previous files were restored`);
	}
	receipt.reloaded = true;
	return write({ outcome: "installed", detail: `installed the supplied certificate for ${hostname} and reloaded the ingress after a successful configuration test` });
}

const invoked = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invoked) {
	const { values } = parseArgs({
		options: {
			mode: { type: "string" },
			hostname: { type: "string" }, email: { type: "string" }, "tls-dir": { type: "string" },
			receipt: { type: "string" }, "acme-client": { type: "string" }, webroot: { type: "string" }, nginx: { type: "string" },
			"cert-file": { type: "string" }, "key-file": { type: "string" }, "min-days": { type: "string" },
		},
	});
	try {
		const mode = values.mode ?? process.env.AIDR_TLS_MODE ?? "acme";
		if (!["acme", "static"].includes(mode)) throw new Error("--mode must be acme or static");
		const options = {
			hostname: values.hostname, email: values.email, tlsDir: values["tls-dir"], receipt: values.receipt,
			acmeClient: values["acme-client"], webroot: values.webroot, nginx: values.nginx,
			certFile: values["cert-file"], keyFile: values["key-file"], minDays: values["min-days"],
		};
		const receipt = mode === "static" ? installStaticCertificate(options) : renewCertificate(options);
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
