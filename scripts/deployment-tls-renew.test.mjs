import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { installStaticCertificate, renewCertificate } from "./deployment-tls-renew.mjs";

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

// ── Static (BYO certificate) mode ──────────────────────────────────────────
// Certificates below are minted in memory per run with throwaway Ed25519 keys:
// no private key is stored in the repository and no CA is contacted.
const der = {
	tlv(tag, content) {
		const length = content.length;
		const header = length < 0x80 ? Buffer.from([tag, length]) : length < 0x100 ? Buffer.from([tag, 0x81, length]) : Buffer.from([tag, 0x82, length >> 8, length & 0xff]);
		return Buffer.concat([header, content]);
	},
	seq: (...items) => der.tlv(0x30, Buffer.concat(items)),
	oid(dotted) {
		const [a, b, ...rest] = dotted.split(".").map(Number);
		const bytes = [40 * a + b];
		for (const arc of rest) {
			const chunk = [arc & 0x7f];
			for (let value = arc >> 7; value > 0; value >>= 7) chunk.unshift((value & 0x7f) | 0x80);
			bytes.push(...chunk);
		}
		return der.tlv(0x06, Buffer.from(bytes));
	},
	name: (cn) => der.seq(der.tlv(0x31, der.seq(der.oid("2.5.4.3"), der.tlv(0x0c, Buffer.from(cn))))),
	time(ms) {
		const iso = new Date(ms).toISOString();
		const digits = iso.slice(0, 19).replace(/[-:T]/g, "");
		return Number(iso.slice(0, 4)) < 2050 ? der.tlv(0x17, Buffer.from(`${digits.slice(2)}Z`)) : der.tlv(0x18, Buffer.from(`${digits}Z`));
	},
};

function mintCertificate({ subject, issuer, subjectKey, issuerKey, notBefore, notAfter, serial, dnsName, ca = false }) {
	const extensions = [];
	if (dnsName) extensions.push(der.seq(der.oid("2.5.29.17"), der.tlv(0x04, der.seq(der.tlv(0x82, Buffer.from(dnsName))))));
	if (ca) extensions.push(der.seq(der.oid("2.5.29.19"), der.tlv(0x01, Buffer.from([0xff])), der.tlv(0x04, der.seq(der.tlv(0x01, Buffer.from([0xff]))))));
	const algorithm = der.seq(der.oid("1.3.101.112"));
	const tbs = der.seq(
		der.tlv(0xa0, der.tlv(0x02, Buffer.from([2]))),
		der.tlv(0x02, Buffer.from([serial])),
		algorithm,
		der.name(issuer),
		der.seq(der.time(notBefore), der.time(notAfter)),
		der.name(subject),
		createPublicKey(subjectKey).export({ type: "spki", format: "der" }),
		der.tlv(0xa3, der.seq(...extensions)),
	);
	const certificate = der.seq(tbs, algorithm, der.tlv(0x03, Buffer.concat([Buffer.from([0]), sign(null, tbs, issuerKey)])));
	return `-----BEGIN CERTIFICATE-----\n${certificate.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
}

const STATIC_HOST = "aidr.customer.example";
const STATIC_NOW = Date.parse("2026-09-24T00:00:00Z");

function staticMaterial(directory, { hostname = STATIC_HOST, notAfter = Date.parse("2027-09-24T00:00:00Z"), keyMode = 0o600, mismatchedKey = false, label = hostname } = {}) {
	const caKey = generateKeyPairSync("ed25519").privateKey;
	const leafKey = generateKeyPairSync("ed25519").privateKey;
	const notBefore = Date.parse("2026-01-01T00:00:00Z");
	const root = mintCertificate({ subject: "AIDR on-prem test CA", issuer: "AIDR on-prem test CA", subjectKey: caKey, issuerKey: caKey, notBefore, notAfter: Date.parse("2036-01-01T00:00:00Z"), serial: 1, ca: true });
	const leaf = mintCertificate({ subject: hostname, issuer: "AIDR on-prem test CA", subjectKey: leafKey, issuerKey: caKey, notBefore, notAfter, serial: 2, dnsName: hostname });
	const certFile = join(directory, `supplied-${label}-fullchain.pem`);
	const keyFile = join(directory, `supplied-${label}-key.pem`);
	writeFileSync(certFile, `${leaf}${root}`);
	const key = mismatchedKey ? generateKeyPairSync("ed25519").privateKey : leafKey;
	writeFileSync(keyFile, key.export({ type: "pkcs8", format: "pem" }), { mode: keyMode });
	chmodSync(keyFile, keyMode);
	return { certFile, keyFile, chain: `${leaf}${root}` };
}

function staticRequest(directory, material, overrides = {}) {
	return { hostname: STATIC_HOST, certFile: material.certFile, keyFile: material.keyFile, tlsDir: join(directory, "tls"), receipt: join(directory, "tls", "receipt.json"), nginx: NGINX, ...overrides };
}

test("static mode validates an operator-supplied chain and key, installs atomically and reloads after nginx -t", (t) => {
	const directory = workdir(t);
	const material = staticMaterial(directory);
	const calls = [];
	const run = (command, args) => {
		calls.push({ command, args });
		return succeeded();
	};
	const receipt = installStaticCertificate(staticRequest(directory, material), { run, now: () => STATIC_NOW });
	assert.equal(receipt.outcome, "installed");
	assert.equal(receipt.mode, "static");
	assert.equal(receipt.key_matches_certificate, true);
	assert.equal(receipt.reloaded, true);
	assert.equal(receipt.certificate_expires_at, "2027-09-24T00:00:00.000Z");
	const live = join(directory, "tls", "live", STATIC_HOST);
	assert.equal(readFileSync(join(live, "fullchain.pem"), "utf8"), material.chain);
	assert.equal(readFileSync(join(live, "privkey.pem"), "utf8"), readFileSync(material.keyFile, "utf8"));
	if (process.platform !== "win32") assert.equal(statSync(join(live, "privkey.pem")).mode & 0o777, 0o600);
	assert.deepEqual(calls.map((call) => call.args.join(" ")), ["-t", "-s reload"]);

	const again = installStaticCertificate(staticRequest(directory, material), { run, now: () => STATIC_NOW });
	assert.equal(again.outcome, "unchanged");
	assert.equal(calls.length, 2, "an identical certificate is not reinstalled or reloaded");
});

test("static mode refuses mismatched keys, wrong hostnames, short validity and readable keys without touching the ingress", (t) => {
	const directory = workdir(t);
	const cases = [
		[staticMaterial(directory, { mismatchedKey: true, label: "mismatch" }), {}, /private key does not belong to the leaf certificate/],
		[staticMaterial(directory, { hostname: "other.customer.example" }), {}, /does not cover the requested hostname aidr\.customer\.example/],
		[staticMaterial(directory, { hostname: "short.customer.example", notAfter: Date.parse("2026-10-01T00:00:00Z") }), { hostname: "short.customer.example" }, /within the required 14-day validity margin/],
		[staticMaterial(directory, { hostname: "expired.customer.example", notAfter: Date.parse("2026-06-01T00:00:00Z") }), { hostname: "expired.customer.example" }, /expired at 2026-06-01/],
	];
	if (process.platform !== "win32") cases.push([staticMaterial(directory, { hostname: "loose.customer.example", keyMode: 0o644 }), { hostname: "loose.customer.example" }, /must be owner-only/]);
	for (const [material, overrides, expected] of cases) {
		const calls = [];
		const run = (command, args) => {
			calls.push({ command, args });
			return succeeded();
		};
		assert.throws(() => installStaticCertificate(staticRequest(directory, material, overrides), { run, now: () => STATIC_NOW }), expected);
		assert.deepEqual(calls, [], "nginx must not run for a refused certificate");
		assert.equal(existsSync(join(directory, "tls", "live", overrides.hostname ?? STATIC_HOST, "fullchain.pem")), false, "nothing is installed");
		const receipt = JSON.parse(readFileSync(join(directory, "tls", "receipt.json"), "utf8"));
		assert.equal(receipt.outcome, "refused");
		assert.equal(receipt.reloaded, false);
	}
	const single = staticMaterial(directory, { hostname: "single.customer.example" });
	writeFileSync(single.certFile, single.chain.slice(0, single.chain.indexOf("-----END CERTIFICATE-----") + 26));
	assert.throws(() => installStaticCertificate(staticRequest(directory, single, { hostname: "single.customer.example" }), { run: () => succeeded(), now: () => STATIC_NOW }), /a leaf certificate and its issuer are required/);
	assert.throws(() => installStaticCertificate({ tlsDir: join(directory, "tls"), receipt: join(directory, "tls", "receipt.json") }, { run: () => succeeded() }), /--hostname.*--cert-file.*--key-file/);
});

test("static mode restores the previous certificate when nginx rejects the new one", (t) => {
	const directory = workdir(t);
	const first = staticMaterial(directory, { label: "first" });
	installStaticCertificate(staticRequest(directory, first), { run: () => succeeded(), now: () => STATIC_NOW });
	const replacement = staticMaterial(directory, { notAfter: Date.parse("2028-01-01T00:00:00Z"), label: "replacement" });
	const calls = [];
	const run = (command, args) => {
		calls.push(args.join(" "));
		return args[0] === "-t" ? failed("nginx: [emerg] cannot load certificate key") : succeeded();
	};
	assert.throws(() => installStaticCertificate(staticRequest(directory, replacement), { run, now: () => STATIC_NOW }), /configuration test failed .*previous files were restored/);
	assert.deepEqual(calls, ["-t"], "no reload after a failed configuration test");
	const live = join(directory, "tls", "live", STATIC_HOST);
	assert.equal(readFileSync(join(live, "fullchain.pem"), "utf8"), first.chain, "the served chain is restored");
	assert.equal(readFileSync(join(live, "privkey.pem"), "utf8"), readFileSync(first.keyFile, "utf8"));
	assert.equal(JSON.parse(readFileSync(join(directory, "tls", "receipt.json"), "utf8")).outcome, "failed");
});

test("on-prem reference ingress serves dashboard and API vhosts with HSTS from the static-mode certificate paths", () => {
	const nginx = readFileSync(resolve(import.meta.dirname, "../deploy/ingress/nginx.onprem.reference.conf"), "utf8");
	for (const host of ["aidr.customer.example", "api.aidr.customer.example"]) {
		const escaped = host.replaceAll(".", "\\.");
		assert.match(nginx, new RegExp(`server_name ${escaped};\\s*if \\(\\$host != "${escaped}"\\) \\{ return 444; \\}`));
		assert.match(nginx, new RegExp(`ssl_certificate /etc/aidr/tls/live/${escaped}/fullchain\\.pem;`));
		assert.match(nginx, new RegExp(`ssl_certificate_key /etc/aidr/tls/live/${escaped}/privkey\\.pem;`));
	}
	assert.equal((nginx.match(/add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;/g) ?? []).length, 2, "HSTS on both vhosts");
	assert.equal((nginx.match(/add_header X-Content-Type-Options "nosniff" always;/g) ?? []).length, 2);
	assert.equal((nginx.match(/ssl_protocols TLSv1\.2 TLSv1\.3;/g) ?? []).length, 2);
	assert.match(nginx, /proxy_pass http:\/\/127\.0\.0\.1:8080;/, "dashboard upstream");
	assert.match(nginx, /proxy_pass http:\/\/127\.0\.0\.1:8000;/, "API gateway upstream");
	assert.match(nginx, /location \^~ \/functions\/v1\/device-start \{[\s\S]*proxy_pass_request_headers off;[\s\S]*X-AIDR-Proxy-Request-ID \$request_id;[\s\S]*X-AIDR-Proxy-Client-IP \$remote_addr;/);
	assert.match(nginx, /location = \/metrics \{\s*return 404;/, "metrics never exposed publicly");
	assert.match(nginx, /listen 443 ssl default_server;[\s\S]*ssl_reject_handshake on;\s*return 444;/, "unknown hosts are dropped");
	assert.match(nginx, /server_tokens off;/);
	assert.doesNotMatch(nginx, /^\s*(real_ip_header|set_real_ip_from)\s/m);
	// add_header inside a location would drop the server-level security headers.
	const directives = nginx.replace(/#.*$/gm, "");
	const locations = directives.match(/location [^{]+\{[^}]*\}/g) ?? [];
	assert.ok(locations.length >= 4);
	for (const block of locations) assert.doesNotMatch(block, /add_header/);
});

test("on-prem reference ingress never proxies Supabase Studio from the API host", () => {
	const ingress = resolve(import.meta.dirname, "../deploy/ingress");
	for (const file of ["nginx.onprem.reference.conf", "nginx.device-start.reference.conf"]) {
		const directives = readFileSync(join(ingress, file), "utf8").replace(/#.*$/gm, "");
		const gatewayLocations = [...directives.matchAll(/location ([^{]+)\{[^}]*proxy_pass http:\/\/127\.0\.0\.1:8000;[^}]*\}/g)].map((match) => match[1].trim());
		assert.equal(gatewayLocations.length, 1, `${file}: exactly one gateway location`);
		const [, pattern] = /^~ (\S+)$/.exec(gatewayLocations[0]) ?? [];
		assert.ok(pattern, `${file}: the gateway location must be an explicit API allowlist, not a catch-all`);
		const allowed = new RegExp(pattern);
		for (const path of ["/auth/v1/token", "/rest/v1/tenants", "/storage/v1/object/x", "/functions/v1/packs-manifest", "/realtime/v1/websocket", "/graphql/v1", "/pg/query", "/.well-known/oauth-authorization-server"]) {
			assert.match(path, allowed, `${file}: ${path} must reach the gateway`);
		}
		for (const path of ["/", "/project/default", "/api/platform/profile", "/api/mcp", "/mcp", "/_next/static/x.js", "/authx/v1/", "/rest/v10/"]) {
			assert.doesNotMatch(path, allowed, `${file}: ${path} must not reach the gateway (Studio)`);
		}
		assert.match(directives, /location \/ \{\s*return 404;\s*\}/, `${file}: everything else is a 404`);
		assert.doesNotMatch(directives, /127\.0\.0\.1:8001/, `${file}: the Studio admin listener is never proxied`);
	}
});
