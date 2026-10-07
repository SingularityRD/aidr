import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const serverFile = join(dirname(fileURLToPath(import.meta.url)), "server.mjs");
const anonKey = "sb_publishable_test_key";

async function startServer(env) {
	const child = spawn(process.execPath, [serverFile], { env, stdio: ["ignore", "pipe", "pipe"] });
	try {
		const port = await new Promise((resolvePort, rejectPort) => {
			let output = "";
			const timeout = setTimeout(() => rejectPort(new Error("Dashboard did not start")), 10_000);
			child.stdout.on("data", (chunk) => {
				output += chunk.toString();
				const match = output.match(/AIDR dashboard listening on (\d+)/);
				if (match) { clearTimeout(timeout); resolvePort(Number(match[1])); }
			});
			child.once("error", (error) => { clearTimeout(timeout); rejectPort(error); });
			child.once("exit", (code) => { clearTimeout(timeout); rejectPort(new Error(`Dashboard exited before readiness: ${code}`)); });
		});
		return { child, port };
	} catch (error) {
		child.kill();
		throw error;
	}
}

test("dashboard rejects a non-loopback HTTP Supabase URL", () => {
	const invalid = spawnSync(process.execPath, [serverFile], {
		env: {
			...process.env,
			VITE_SUPABASE_URL: "http://127.attacker.test",
			VITE_SUPABASE_ANON_KEY: anonKey,
		},
		encoding: "utf8",
		timeout: 10_000,
	});
	assert.notEqual(invalid.status, 0);
	assert.match(invalid.stderr, /must use HTTPS/);
});

test("dashboard exposes configured auth, Sentry origin, metrics, and only the recovery and invite templates", async () => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-dashboard-auth-"));
	writeFileSync(join(directory, "index.html"), "<!doctype html><title>AIDR test</title>");
	const templateDirectory = join(directory, "auth-templates");
	mkdirSync(templateDirectory);
	writeFileSync(join(templateDirectory, "recovery.html"), "<p>{{ .Token }}</p>");
	writeFileSync(join(templateDirectory, "invite.html"), "<a href=\"{{ .SiteURL }}/auth/callback?token_hash={{ .TokenHash }}&type=invite\">Accept</a>");
	writeFileSync(join(templateDirectory, "private.html"), "must not be served");
	const env = {
		...process.env,
		AIDR_STATIC_DIR: directory,
		AIDR_AUTH_TEMPLATE_DIR: templateDirectory,
		VITE_SUPABASE_URL: "https://api.customer.example",
		VITE_SUPABASE_ANON_KEY: anonKey,
		SENTRY_DSN: "https://public-key@o123.ingest.sentry.io/456",
		SENTRY_ENVIRONMENT: "customer-production",
		SENTRY_TRACES_SAMPLE_RATE: "0.25",
		AIDR_AUTH_METHODS: "password,azure,azure",
		AIDR_SIGNUP_MODE: "cloud",
		AIDR_SAML_PROVIDER_ID: "21648a9d-8d5a-4555-a9d1-d6375dc14e92",
		AIDR_SAML_DOMAIN: "",
		AIDR_OIDC_SSO: "true",
		AIDR_METRICS_TOKEN: "test-metrics-token",
		NODE_ENV: "production",
		PORT: "0",
	};
	let child;
	let port;
	try {
		const invalid = spawnSync(process.execPath, [serverFile], { env: { ...env, AIDR_AUTH_METHODS: "password,unapproved" }, encoding: "utf8", timeout: 10_000 });
		assert.notEqual(invalid.status, 0);
		assert.match(invalid.stderr, /Invalid AIDR_AUTH_METHODS/);
		for (const overrides of [{ AIDR_SIGNUP_MODE: "pilot" }, { AIDR_AUTH_METHODS: "magic-link" }]) {
			const invalidSignup = spawnSync(process.execPath, [serverFile], { env: { ...env, ...overrides }, encoding: "utf8", timeout: 10_000 });
			assert.notEqual(invalidSignup.status, 0);
			assert.match(invalidSignup.stderr, /AIDR_SIGNUP_MODE|Cloud signup requires password auth/);
		}
		for (const [overrides, message] of [
			[{ AIDR_SAML_PROVIDER_ID: "invalid" }, /Invalid AIDR_SAML_PROVIDER_ID/],
			[{ AIDR_SAML_DOMAIN: "company.example" }, /Configure only one of AIDR_SAML_PROVIDERS/],
			[{ AIDR_SAML_PROVIDER_ID: "", AIDR_SAML_DOMAIN: "company.example/path" }, /Invalid AIDR_SAML_DOMAIN/],
			[{ AIDR_SAML_PROVIDERS: "not-json", AIDR_SAML_PROVIDER_ID: "" }, /Invalid AIDR_SAML_PROVIDERS/],
			[{ AIDR_OIDC_SSO: "maybe" }, /Invalid AIDR_OIDC_SSO/],
		]) {
			const invalidSaml = spawnSync(process.execPath, [serverFile], { env: { ...env, ...overrides }, encoding: "utf8", timeout: 10_000 });
			assert.notEqual(invalidSaml.status, 0);
			assert.match(invalidSaml.stderr, message);
		}

		({ child, port } = await startServer(env));
		const response = await fetch(`http://127.0.0.1:${port}/runtime-config.js`, { signal: AbortSignal.timeout(5_000) });
		assert.equal(response.status, 200);
		const body = await response.text();
		const config = JSON.parse(body.replace(/^window\.__AIDR_CONFIG__=/, "").replace(/;$/, ""));
		assert.deepEqual(config.authMethods, ["password", "azure"]);
		assert.equal(config.signupMode, "cloud");
		assert.equal(config.samlProviderId, env.AIDR_SAML_PROVIDER_ID);
		assert.equal(config.samlDomain, undefined);
		assert.equal(config.oidcSso, true);
		assert.equal(config.supabaseUrl, "https://api.customer.example");
		assert.equal(config.sentryDsn, "https://public-key@o123.ingest.sentry.io/456");
		assert.equal(config.sentryEnvironment, "customer-production");
		assert.equal(config.sentryTracesSampleRate, 0.25);
		const csp = response.headers.get("content-security-policy") ?? "";
		assert.match(csp, /script-src 'self' https:\/\/challenges\.cloudflare\.com/);
		assert.match(csp, /frame-src https:\/\/challenges\.cloudflare\.com/);
		assert.match(csp, /object-src 'none'/);
		assert.match(csp, /upgrade-insecure-requests/);
		assert.doesNotMatch(csp, /accounts\.google\.com|img-src[^;]*https:/);
		const connectSources = csp.match(/connect-src ([^;]+)/)?.[1] ?? "";
		assert.match(connectSources, /https:\/\/o123\.ingest\.sentry\.io/);
		assert.doesNotMatch(connectSources, /public-key|\/456|wss:/);
		// Every non-connect-src header comes from the shared source of truth.
		const { securityHeaders } = await import("./security-headers.mjs");
		for (const [name, value] of securityHeaders()) {
			if (name === "Content-Security-Policy") {
				assert.equal(csp.replace(/connect-src [^;]+/, ""), value.replace(/connect-src [^;]+/, ""));
			} else {
				assert.equal(response.headers.get(name), value, name);
			}
		}
		assert.match(response.headers.get("strict-transport-security") ?? "", /max-age=63072000/);

		const recoveryTemplate = await fetch(`http://127.0.0.1:${port}/auth-templates/recovery.html`);
		assert.equal(recoveryTemplate.status, 200);
		assert.equal(await recoveryTemplate.text(), "<p>{{ .Token }}</p>");
		const inviteTemplate = await fetch(`http://127.0.0.1:${port}/auth-templates/invite.html`);
		assert.equal(inviteTemplate.status, 200);
		assert.match(await inviteTemplate.text(), /\/auth\/callback\?token_hash=\{\{ \.TokenHash \}\}&type=invite/);
		assert.equal((await fetch(`http://127.0.0.1:${port}/auth-templates/private.html`)).status, 404);

		const anonymousMetrics = await fetch(`http://127.0.0.1:${port}/metrics`);
		assert.equal(anonymousMetrics.status, 401);
		assert.equal(anonymousMetrics.headers.get("www-authenticate"), 'Bearer realm="metrics"');
		const authorizedMetrics = await fetch(`http://127.0.0.1:${port}/metrics`, {
			headers: { Authorization: "Bearer test-metrics-token" },
		});
		assert.equal(authorizedMetrics.status, 200);
		assert.match(await authorizedMetrics.text(), /aidr_readiness/);
	} finally {
		child?.kill();
		assert.equal(dirname(realpathSync(directory)), realpathSync(tmpdir()));
		rmSync(directory, { recursive: true, force: true });
	}
});

test("dashboard runtime config exposes labeled Entra and Okta provider choices", async () => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-dashboard-saml-"));
	writeFileSync(join(directory, "index.html"), "<!doctype html><title>AIDR test</title>");
	let child;
	try {
		const { port, child: server } = await startServer({
			...process.env,
			AIDR_STATIC_DIR: directory,
			VITE_SUPABASE_URL: "https://api.customer.example",
			VITE_SUPABASE_ANON_KEY: anonKey,
			AIDR_AUTH_METHODS: "password",
			AIDR_SIGNUP_MODE: "closed",
			AIDR_SAML_PROVIDER_ID: "",
			AIDR_SAML_DOMAIN: "",
			AIDR_SAML_PROVIDERS: JSON.stringify([
				{ providerId: "21648a9d-8d5a-4555-a9d1-d6375dc14e92", label: "Microsoft Entra ID" },
				{ providerId: "33333333-3333-4333-8333-333333333333", label: "Okta" },
			]),
			PORT: "0",
		});
		child = server;
		const response = await fetch(`http://127.0.0.1:${port}/runtime-config.js`);
		assert.equal(response.status, 200);
		const config = JSON.parse((await response.text()).replace(/^window\.__AIDR_CONFIG__=/, "").replace(/;$/, ""));
		assert.deepEqual(config.samlProviders, [
			{ providerId: "21648a9d-8d5a-4555-a9d1-d6375dc14e92", label: "Microsoft Entra ID" },
			{ providerId: "33333333-3333-4333-8333-333333333333", label: "Okta" },
		]);
	} finally {
		child?.kill();
		assert.equal(dirname(realpathSync(directory)), realpathSync(tmpdir()));
		rmSync(directory, { recursive: true, force: true });
	}
});

test("dashboard omits disabled Sentry and fails closed for invalid DSNs or template configuration", async () => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-dashboard-csp-"));
	writeFileSync(join(directory, "index.html"), "<!doctype html><title>AIDR test</title>");
	const env = {
		...process.env,
		AIDR_STATIC_DIR: directory,
		VITE_SUPABASE_URL: "https://api.customer.example",
		VITE_SUPABASE_ANON_KEY: anonKey,
		SENTRY_DSN: "",
		SENTRY_ENVIRONMENT: "",
		SENTRY_TRACES_SAMPLE_RATE: "",
		AIDR_SAML_PROVIDER_ID: "",
		AIDR_SAML_DOMAIN: "",
		AIDR_SIGNUP_MODE: "",
		NODE_ENV: "production",
		PORT: "0",
	};
	let child;
	try {
		let port;
		({ child, port } = await startServer(env));
		const response = await fetch(`http://127.0.0.1:${port}/runtime-config.js`);
		assert.equal(response.status, 200);
		assert.equal(response.headers.get("content-security-policy")?.includes("sentry.io"), false);
		const config = JSON.parse((await response.text()).replace(/^window\.__AIDR_CONFIG__=/, "").replace(/;$/, ""));
		assert.equal(config.sentryDsn, null);
		assert.equal(config.sentryEnvironment, "production");
		assert.equal(config.sentryTracesSampleRate, 0);
		assert.equal(config.samlProviderId, undefined);
		assert.equal(config.samlDomain, undefined);
		assert.equal(config.signupMode, "closed");
		assert.equal((await fetch(`http://127.0.0.1:${port}/auth-templates/recovery.html`)).status, 404);
	} finally {
		child?.kill();
	}

	for (const dsn of ["not-a-url", "http://public-key@o123.ingest.sentry.io/456", "https://o123.ingest.sentry.io/456"]) {
		const invalid = spawnSync(process.execPath, [serverFile], { env: { ...env, SENTRY_DSN: dsn }, encoding: "utf8", timeout: 10_000 });
		assert.notEqual(invalid.status, 0);
		assert.match(invalid.stderr, /valid HTTPS Sentry DSN/);
	}
	for (const [name, value, message] of [
		["SENTRY_ENVIRONMENT", "invalid environment", /safe Sentry environment name/],
		["SENTRY_TRACES_SAMPLE_RATE", "1.01", /number from 0 to 1/],
	]) {
		const invalid = spawnSync(process.execPath, [serverFile], { env: { ...env, [name]: value }, encoding: "utf8", timeout: 10_000 });
		assert.notEqual(invalid.status, 0);
		assert.match(invalid.stderr, message);
	}
	const missingTemplate = spawnSync(process.execPath, [serverFile], { env: { ...env, AIDR_AUTH_TEMPLATE_DIR: join(directory, "missing") }, encoding: "utf8", timeout: 10_000 });
	assert.notEqual(missingTemplate.status, 0);
	assert.match(missingTemplate.stderr, /ENOENT/);
	assert.equal(dirname(realpathSync(directory)), realpathSync(tmpdir()));
	rmSync(directory, { recursive: true, force: true });
});

function releaseManifest(overrides = {}) {
	return {
		version: "1.2.3",
		publishedAt: "2026-09-01T12:00:00Z",
		artifacts: [
			{
				id: "claude-code",
				version: "1.2.3",
				url: "https://downloads.customer.example/aidr/aidr-claude-plugin-1.2.3.tar.gz",
				sha256: "a".repeat(64),
				signature: "https://downloads.customer.example/aidr/aidr-claude-plugin-1.2.3.tar.gz.sig",
				size: 4096,
				platforms: ["any"],
			},
		],
		...overrides,
	};
}

function readRuntimeConfig(body) {
	return JSON.parse(body.replace(/^window\.__AIDR_CONFIG__=/, "").replace(/;$/, ""));
}

test("dashboard serves a validated release manifest with cache validators and withholds invalid replacements", async () => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-dashboard-release-"));
	writeFileSync(join(directory, "index.html"), "<!doctype html><title>AIDR test</title>");
	const manifestPath = join(directory, "release-manifest.json");
	writeFileSync(manifestPath, JSON.stringify(releaseManifest()));
	let child;
	try {
		let port;
		({ child, port } = await startServer({
			...process.env,
			AIDR_STATIC_DIR: directory,
			VITE_SUPABASE_URL: "https://api.customer.example",
			VITE_SUPABASE_ANON_KEY: anonKey,
			AIDR_RELEASE_MANIFEST_PATH: manifestPath,
			VITE_AIDR_RELEASE_MANIFEST_URL: "",
			AIDR_SAML_PROVIDER_ID: "",
			AIDR_SAML_DOMAIN: "",
			PORT: "0",
		}));
		const base = `http://127.0.0.1:${port}`;
		const config = readRuntimeConfig(await (await fetch(`${base}/runtime-config.js`)).text());
		assert.equal(config.releaseManifestUrl, "/release-manifest.json");

		const response = await fetch(`${base}/release-manifest.json`);
		assert.equal(response.status, 200);
		assert.equal(response.headers.get("content-type"), "application/json; charset=utf-8");
		assert.equal(response.headers.get("cache-control"), "public, max-age=60, must-revalidate");
		assert.equal(response.headers.get("x-content-type-options"), "nosniff");
		const etag = response.headers.get("etag");
		assert.match(etag ?? "", /^"sha256-[A-Za-z0-9_-]{43}"$/);
		assert.deepEqual(await response.json(), releaseManifest());

		const revalidated = await fetch(`${base}/release-manifest.json`, { headers: { "If-None-Match": `W/${etag}` } });
		assert.equal(revalidated.status, 304);
		assert.equal(await revalidated.text(), "");
		const head = await fetch(`${base}/release-manifest.json`, { method: "HEAD" });
		assert.equal(head.status, 200);
		assert.equal(head.headers.get("etag"), etag);

		// A replacement that downgrades a download URL to http: is withheld, not served.
		const insecure = releaseManifest();
		insecure.artifacts[0].url = "http://downloads.customer.example/aidr/plugin.tar.gz";
		writeFileSync(manifestPath, JSON.stringify(insecure));
		const withheld = await fetch(`${base}/release-manifest.json`);
		assert.equal(withheld.status, 503);
		assert.equal(withheld.headers.get("cache-control"), "no-store");

		// A valid update is picked up without a restart and changes the validator.
		writeFileSync(manifestPath, JSON.stringify(releaseManifest({ version: "1.2.4" })));
		const updated = await fetch(`${base}/release-manifest.json`, { headers: { "If-None-Match": etag } });
		assert.equal(updated.status, 200);
		assert.notEqual(updated.headers.get("etag"), etag);
		assert.equal((await updated.json()).version, "1.2.4");
	} finally {
		child?.kill();
		assert.equal(dirname(realpathSync(directory)), realpathSync(tmpdir()));
		rmSync(directory, { recursive: true, force: true });
	}
});

test("dashboard release manifest configuration fails closed and defaults to not configured", async () => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-dashboard-release-config-"));
	writeFileSync(join(directory, "index.html"), "<!doctype html><title>AIDR test</title>");
	const env = {
		...process.env,
		AIDR_STATIC_DIR: directory,
		VITE_SUPABASE_URL: "https://api.customer.example",
		VITE_SUPABASE_ANON_KEY: anonKey,
		AIDR_RELEASE_MANIFEST_PATH: "",
		VITE_AIDR_RELEASE_MANIFEST_URL: "",
		AIDR_SAML_PROVIDER_ID: "",
		AIDR_SAML_DOMAIN: "",
		PORT: "0",
	};
	const artifact = releaseManifest().artifacts[0];
	let child;
	try {
		for (const [overrides, message] of [
			[{ artifacts: [{ ...artifact, url: "http://downloads.customer.example/a.tgz" }] }, /must use https/],
			[{ artifacts: [{ ...artifact, sha256: undefined }] }, /sha256/],
			[{ artifacts: [{ ...artifact, id: "unknown-runtime" }] }, /supported artifact id/],
			[{ publishedAt: "yesterday" }, /publishedAt/],
		]) {
			const manifestPath = join(directory, "invalid.json");
			writeFileSync(manifestPath, JSON.stringify(releaseManifest(overrides)));
			const invalid = spawnSync(process.execPath, [serverFile], { env: { ...env, AIDR_RELEASE_MANIFEST_PATH: manifestPath }, encoding: "utf8", timeout: 10_000 });
			assert.notEqual(invalid.status, 0);
			assert.match(invalid.stderr, message);
		}
		for (const [overrides, message] of [
			[{ AIDR_RELEASE_MANIFEST_PATH: "relative/release-manifest.json" }, /must be an absolute path/],
			[{ AIDR_RELEASE_MANIFEST_PATH: join(directory, "missing.json") }, /ENOENT/],
			[{ AIDR_RELEASE_MANIFEST_PATH: directory }, /regular file/],
			[{ VITE_AIDR_RELEASE_MANIFEST_URL: "http://downloads.customer.example/release-manifest.json" }, /absolute https: URL/],
			[{ VITE_AIDR_RELEASE_MANIFEST_URL: "https://user:pass@downloads.customer.example/m.json" }, /absolute https: URL/],
		]) {
			const invalid = spawnSync(process.execPath, [serverFile], { env: { ...env, ...overrides }, encoding: "utf8", timeout: 10_000 });
			assert.notEqual(invalid.status, 0);
			assert.match(invalid.stderr, message);
		}
		const manifestPath = join(directory, "release-manifest.json");
		writeFileSync(manifestPath, JSON.stringify(releaseManifest()));
		const both = spawnSync(process.execPath, [serverFile], {
			env: { ...env, AIDR_RELEASE_MANIFEST_PATH: manifestPath, VITE_AIDR_RELEASE_MANIFEST_URL: "https://downloads.customer.example/m.json" },
			encoding: "utf8",
			timeout: 10_000,
		});
		assert.notEqual(both.status, 0);
		assert.match(both.stderr, /Configure only one of AIDR_RELEASE_MANIFEST_PATH/);

		let port;
		({ child, port } = await startServer(env));
		const unconfigured = await fetch(`http://127.0.0.1:${port}/runtime-config.js`);
		assert.equal(readRuntimeConfig(await unconfigured.text()).releaseManifestUrl, null);
		assert.equal((await fetch(`http://127.0.0.1:${port}/release-manifest.json`)).status, 404);
		child.kill();
		child = undefined;

		({ child, port } = await startServer({ ...env, VITE_AIDR_RELEASE_MANIFEST_URL: "https://downloads.customer.example/aidr/release-manifest.json" }));
		const external = await fetch(`http://127.0.0.1:${port}/runtime-config.js`);
		assert.equal(readRuntimeConfig(await external.text()).releaseManifestUrl, "https://downloads.customer.example/aidr/release-manifest.json");
		const connectSources = external.headers.get("content-security-policy")?.match(/connect-src ([^;]+)/)?.[1] ?? "";
		assert.match(connectSources, /https:\/\/downloads\.customer\.example(?:\s|$)/);
		assert.equal((await fetch(`http://127.0.0.1:${port}/release-manifest.json`)).status, 404);
	} finally {
		child?.kill();
		assert.equal(dirname(realpathSync(directory)), realpathSync(tmpdir()));
		rmSync(directory, { recursive: true, force: true });
	}
});
