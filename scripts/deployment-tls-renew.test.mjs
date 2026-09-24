import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { renewCertificate } from "./deployment-tls-renew.mjs";

// Public test certificates only. The leaf and its issuer were generated for this
// test file with a local throwaway key that is not stored anywhere; no
// certificate authority was contacted, no domain is owned by this repository and
// the chain covers only the reserved test hostname below. Validity is pinned to
// 2020-01-01..2056-01-01 so the assertions do not depend on the wall clock.
const LEAF = `-----BEGIN CERTIFICATE-----
MIIB6DCCAY6gAwIBAgIUC4Vqf+ES3n714zEmhZQL+X5FBA0wCgYIKoZIzj0EAwIw
IzEhMB8GA1UEAwwYQUlEUiBUTFMgcmVuZXdhbCB0ZXN0IENBMCAXDTIwMDEwMTAw
MDAwMFoYDzIwNTYwMTAxMDAwMDAwWjAkMSIwIAYDVQQDDBlhcGkuYWlkci5jdXN0
b21lci5leGFtcGxlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEclhk3MBXiog
wfNe3oPe1XtTIL4XryOkjATlVUuUyJQZnYwhwbgpGCEG/6mm74bLYmmZ3FLkJzwE
Ft5YiZ/6z6OBnDCBmTAkBgNVHREEHTAbghlhcGkuYWlkci5jdXN0b21lci5leGFt
cGxlMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsG
AQUFBwMBMB0GA1UdDgQWBBSaG012SWySgYQ2EWUlZkJM4689cDAfBgNVHSMEGDAW
gBTik6M1jXxOcSwR3o0oROjVpCxmEDAKBggqhkjOPQQDAgNIADBFAiA7V2pFH1J0
/5nt5v34Uz2ziKJTFfwqh2SxeUnM5r1iJQIhAJHxUmQYwggTfe++uZIi2Aw9AeS+
VTegNJrs8orbCQem
-----END CERTIFICATE-----`;
const ISSUER = `-----BEGIN CERTIFICATE-----
MIIBnjCCAUOgAwIBAgIUS34Im9J39qoTmkEnHysyexDCHsgwCgYIKoZIzj0EAwIw
IzEhMB8GA1UEAwwYQUlEUiBUTFMgcmVuZXdhbCB0ZXN0IENBMCAXDTIwMDEwMTAw
MDAwMFoYDzIwNTYwMTAxMDAwMDAwWjAjMSEwHwYDVQQDDBhBSURSIFRMUyByZW5l
d2FsIHRlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR1aKe1W7zPCWN/
5AMSMmEXZaRtZhxti2OpneFgeLYLzOPfeX/QMB1mh6UkjqeHTTxH0BkbXYJ+7EKq
1yjVfCaao1MwUTAdBgNVHQ4EFgQU4pOjNY18TnEsEd6NKETo1aQsZhAwHwYDVR0j
BBgwFoAU4pOjNY18TnEsEd6NKETo1aQsZhAwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAgNJADBGAiEAo2F9ZdwYLVm2FtSJl7g8U93b0IPTvzCIbTLLF4g9Rq4C
IQDV7ZcmrXg2Izcj7YHcsLbObYT+JatstjbaD9BFDcS+9A==
-----END CERTIFICATE-----`;
const COMPLETE_CHAIN = `${LEAF}\n${ISSUER}\n`;
const HOSTNAME = "api.aidr.customer.example";
const EMAIL = "tls-owner@customer.example";
// SHA-256 of the leaf DER and its notAfter, recorded independently of the
// implementation under test.
const FINGERPRINT = "b93de8221d17888325f375becc66feda472d5d81ee7610fbcac617ed6881afe6";
const EXPIRES_AT = "2056-01-01T00:00:00.000Z";
const ACME = "certbot";
const NGINX = "nginx";
const CLOCK = Date.parse("2026-09-14T08:00:00Z");

function workdir(t) {
	const directory = mkdtempSync(join(tmpdir(), "aidr-tls-renew-"));
	t.after(() => rmSync(directory, { recursive: true, force: true }));
	return directory;
}

function succeeded(stdout = "") {
	return { status: 0, stdout, stderr: "", error: null };
}

function failed(stderr, status = 1) {
	return { status, stdout: "", stderr, error: null };
}

/** A complete, well-formed renewal request pointing at a throwaway directory. */
function request(tlsDir, overrides = {}) {
	return { hostname: HOSTNAME, email: EMAIL, tlsDir, receipt: join(tlsDir, "renewal-receipt.json"), acmeClient: ACME, webroot: join(tlsDir, "acme"), nginx: NGINX, ...overrides };
}

function chainFile(tlsDir, hostname = HOSTNAME) {
	const directory = join(tlsDir, "live", hostname);
	mkdirSync(directory, { recursive: true });
	return join(directory, "fullchain.pem");
}

function recorded(tlsDir) {
	return JSON.parse(readFileSync(join(tlsDir, "renewal-receipt.json"), "utf8"));
}

test("reference ingress serves the HTTP-01 webroot and renews the same certificate Nginx serves", () => {
	const ingress = resolve(import.meta.dirname, "../deploy/ingress");
	const nginx = readFileSync(join(ingress, "nginx.device-start.reference.conf"), "utf8");
	const service = readFileSync(join(ingress, "aidr-tls-renew.service"), "utf8");
	assert.match(nginx, /location \^~ \/\.well-known\/acme-challenge\/\s*\{\s*root \/var\/www\/aidr-acme;\s*try_files \$uri =404;/);
	assert.match(nginx, /ssl_certificate \/etc\/letsencrypt\/live\/api\.aidr\.customer\.example\/fullchain\.pem;/);
	assert.match(nginx, /ssl_certificate_key \/etc\/letsencrypt\/live\/api\.aidr\.customer\.example\/privkey\.pem;/);
	assert.match(service, /ExecStart=\/usr\/bin\/node \/srv\/aidr\/ingress\/deployment-tls-renew\.mjs/);
	for (const path of ["/etc/letsencrypt", "/var/lib/letsencrypt", "/var/log/letsencrypt", "/var/www/aidr-acme"]) assert.ok(service.includes(path), `${path} must be writable to certbot`);
});

test("refuses to install without an explicit hostname and email", (t) => {
	const tlsDir = workdir(t);
	const calls = [];
	const run = (command, args) => {
		calls.push({ command, args });
		return succeeded();
	};
	assert.throws(
		() => renewCertificate({ tlsDir, receipt: join(tlsDir, "renewal-receipt.json"), acmeClient: ACME }, { run }),
		(error) => {
			assert.match(error.message, /--hostname/);
			assert.match(error.message, /--email/);
			return true;
		},
	);
	assert.deepEqual(calls, [], "no command may run without an explicit hostname and email");
	const receipt = recorded(tlsDir);
	assert.equal(receipt.outcome, "refused");
	assert.equal(receipt.challenge_succeeded, false);
	assert.equal(receipt.reloaded, false);
	assert.equal(receipt.certificate_fingerprint_sha256, null);
	assert.equal(receipt.certificate_expires_at, null);
	assert.equal(receipt.hostname, null);
});

test("writes a renewal receipt and reloads only after a successful challenge", (t) => {
	const tlsDir = workdir(t);
	const calls = [];
	const run = (command, args) => {
		calls.push({ command, args });
		if (command === ACME && args[0] === "--version") return succeeded("certbot 2.11.0");
		if (command === ACME && args[0] === "certonly") {
			writeFileSync(chainFile(tlsDir), COMPLETE_CHAIN, { mode: 0o600 });
			return succeeded("Successfully received certificate");
		}
		if (command === NGINX) return succeeded();
		return failed("unexpected command", 127);
	};
	const receipt = renewCertificate(request(tlsDir), { run, now: () => CLOCK });
	assert.equal(receipt.outcome, "renewed");
	assert.equal(receipt.hostname, HOSTNAME);
	assert.equal(receipt.challenge_succeeded, true);
	assert.equal(receipt.reloaded, true);
	assert.equal(receipt.certificate_fingerprint_sha256, FINGERPRINT);
	assert.equal(receipt.certificate_expires_at, EXPIRES_AT);
	assert.equal(receipt.started_at, "2026-09-14T08:00:00.000Z");
	assert.equal(receipt.completed_at, "2026-09-14T08:00:00.000Z");
	const challenge = calls.findIndex((call) => call.args[0] === "certonly");
	const tested = calls.findIndex((call) => call.args[0] === "-t");
	const reload = calls.findIndex((call) => call.args[0] === "-s" && call.args[1] === "reload");
	assert.ok(challenge >= 0, "the ACME challenge must run");
	assert.ok(tested > challenge, "the ingress configuration is tested after the challenge");
	assert.ok(reload > tested, "the ingress is reloaded only after a successful configuration test");
	const challengeArgs = calls[challenge].args;
	assert.equal(challengeArgs[challengeArgs.indexOf("--config-dir") + 1], tlsDir);
	assert.equal(challengeArgs[challengeArgs.indexOf("--cert-name") + 1], HOSTNAME);
	assert.equal(challengeArgs[challengeArgs.indexOf("-d") + 1], HOSTNAME);
	assert.equal(challengeArgs[challengeArgs.indexOf("-m") + 1], EMAIL);
	const written = recorded(tlsDir);
	assert.equal(written.outcome, "renewed");
	assert.equal(written.certificate_fingerprint_sha256, FINGERPRINT);
	assert.equal(written.certificate_expires_at, EXPIRES_AT);
	assert.equal(written.reloaded, true);
});

test("fails closed when the certificate chain is incomplete", (t) => {
	const tlsDir = workdir(t);
	const calls = [];
	const run = (command, args) => {
		calls.push({ command, args });
		if (command === ACME && args[0] === "--version") return succeeded("certbot 2.11.0");
		if (command === ACME && args[0] === "certonly") {
			writeFileSync(chainFile(tlsDir), `${LEAF}\n`, { mode: 0o600 });
			return succeeded("Successfully received certificate");
		}
		if (command === NGINX) return succeeded();
		return failed("unexpected command", 127);
	};
	assert.throws(
		() => renewCertificate(request(tlsDir), { run, now: () => CLOCK }),
		/a leaf certificate and its issuer are required/,
	);
	assert.ok(!calls.some((call) => call.command === NGINX), "nginx must not run for an incomplete chain");
	const receipt = recorded(tlsDir);
	assert.equal(receipt.outcome, "failed");
	assert.equal(receipt.challenge_succeeded, true);
	assert.equal(receipt.reloaded, false);
	assert.equal(receipt.certificate_fingerprint_sha256, null);
	assert.equal(receipt.certificate_expires_at, null);
});

test("no ingress reload happens when the challenge fails", (t) => {
	const tlsDir = workdir(t);
	const calls = [];
	const run = (command, args) => {
		calls.push({ command, args });
		if (command === ACME && args[0] === "--version") return succeeded("certbot 2.11.0");
		if (command === ACME && args[0] === "certonly") {
			return failed("urn:ietf:params:acme:error:dns :: DNS problem: NXDOMAIN looking up A for api.aidr.customer.example");
		}
		if (command === NGINX) return succeeded();
		return failed("unexpected command", 127);
	};
	assert.throws(
		() => renewCertificate(request(tlsDir), { run, now: () => CLOCK }),
		/ACME challenge for api\.aidr\.customer\.example failed \(urn:ietf:params:acme:error:dns/,
	);
	assert.ok(!calls.some((call) => call.command === NGINX), "nginx must not run when the challenge fails");
	const receipt = recorded(tlsDir);
	assert.equal(receipt.outcome, "failed");
	assert.equal(receipt.challenge_succeeded, false);
	assert.equal(receipt.reloaded, false);
	assert.equal(receipt.certificate_fingerprint_sha256, null);
	assert.equal(receipt.certificate_expires_at, null);
});

test("fails closed when the ACME client is not installed", (t) => {
	const tlsDir = workdir(t);
	const calls = [];
	const run = (command, args) => {
		calls.push({ command, args });
		return { status: null, stdout: "", stderr: "", error: Object.assign(new Error("spawn certbot ENOENT"), { code: "ENOENT" }) };
	};
	assert.throws(
		() => renewCertificate(request(tlsDir), { run, now: () => CLOCK }),
		/is not available \(ENOENT\); install it or pass --acme-client/,
	);
	assert.equal(calls.length, 1, "only the ACME client probe may run");
	assert.ok(!calls.some((call) => call.args.includes("certonly")), "no challenge may run without an ACME client");
	const receipt = recorded(tlsDir);
	assert.equal(receipt.outcome, "refused");
	assert.equal(receipt.reloaded, false);
	assert.equal(receipt.challenge_succeeded, false);
});

test("refuses a chain that does not cover the requested hostname", (t) => {
	const tlsDir = workdir(t);
	const calls = [];
	const run = (command, args) => {
		calls.push({ command, args });
		if (command === ACME && args[0] === "--version") return succeeded("certbot 2.11.0");
		if (command === ACME && args[0] === "certonly") {
			writeFileSync(chainFile(tlsDir, "console.customer.example"), COMPLETE_CHAIN, { mode: 0o600 });
			return succeeded("Successfully received certificate");
		}
		if (command === NGINX) return succeeded();
		return failed("unexpected command", 127);
	};
	assert.throws(
		() => renewCertificate(request(tlsDir, { hostname: "console.customer.example" }), { run, now: () => CLOCK }),
		/does not cover the requested hostname console\.customer\.example/,
	);
	assert.ok(!calls.some((call) => call.command === NGINX), "nginx must not run for a chain for another hostname");
	assert.equal(recorded(tlsDir).reloaded, false);
});

test("does not reload when the ACME client reports no change", (t) => {
	const tlsDir = workdir(t);
	writeFileSync(chainFile(tlsDir), COMPLETE_CHAIN, { mode: 0o600 });
	const calls = [];
	const run = (command, args) => {
		calls.push({ command, args });
		if (command === ACME && args[0] === "--version") return succeeded("certbot 2.11.0");
		if (command === ACME && args[0] === "certonly") return succeeded("Certificate not yet due for renewal");
		if (command === NGINX) return succeeded();
		return failed("unexpected command", 127);
	};
	const receipt = renewCertificate(request(tlsDir), { run, now: () => CLOCK });
	assert.equal(receipt.outcome, "unchanged");
	assert.equal(receipt.challenge_succeeded, true);
	assert.equal(receipt.reloaded, false);
	assert.equal(receipt.certificate_fingerprint_sha256, FINGERPRINT);
	assert.ok(!calls.some((call) => call.command === NGINX), "an unchanged certificate does not require an ingress reload");
});
