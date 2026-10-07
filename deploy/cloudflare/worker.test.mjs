import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import worker, { handle } from "./worker.mjs";

const site = "https://aidr-pilot.example.workers.dev";
const provider = "https://project.supabase.co";
const secret = "a-device-start-signing-secret-longer-than-32-bytes";
const env = {
	AIDR_PUBLIC_ORIGIN: site,
	AIDR_SUPABASE_ORIGIN: provider,
	AIDR_SUPABASE_ANON_KEY: "sb_publishable_test-only",
	AIDR_DEVICE_START_INGRESS_SECRET: secret,
	ASSETS: { fetch: async () => new Response("static asset", { status: 200 }) },
};

test("serves assets without proxying arbitrary paths", async () => {
	let called = false;
	const response = await handle(new Request(`${site}/incidents`), env, () => { called = true; });
	assert.equal(response.status, 200);
	assert.equal(await response.text(), "static asset");
	assert.equal(called, false);
});

test("health routes never fall through to the SPA and readiness checks live dependencies", async () => {
	let assetCalls = 0;
	const healthEnv = { ...env, ASSETS: { fetch: async (request) => {
		assetCalls++;
		assert.equal(new URL(request.url).pathname, "/index.html");
		return new Response("<html>dashboard</html>", { headers: { "content-type": "text/html" } });
	} } };
	for (const path of ["/livez", "/healthz"]) {
		const response = await handle(new Request(`${site}${path}`), healthEnv);
		assert.equal(response.status, 200);
		assert.match(response.headers.get("content-type"), /application\/json/);
		assert.deepEqual(await response.json(), { status: "alive" });
	}
	const upstreamCalls = [];
	const ready = await handle(new Request(`${site}/readyz`), { ...healthEnv, AIDR_RELEASE_VERSION: "1.2.3", AIDR_RELEASE_SHA: "a".repeat(40) }, async (url, init) => {
		upstreamCalls.push(url);
		assert.equal(init.headers.apikey, env.AIDR_SUPABASE_ANON_KEY);
		assert.equal(init.redirect, "manual");
		assert.ok(init.signal);
		if (url.endsWith("/rest/v1/rpc/aidr_readiness_probe")) return Response.json({ ok: true });
		if (url.endsWith("/functions/v1/packs-manifest")) return Response.json({ error: "missing_api_key" }, { status: 401 });
		return new Response(null, { status: 200 });
	});
	assert.equal(ready.status, 503);
	assert.match(ready.headers.get("content-type"), /application\/json/);
	assert.deepEqual(await ready.json(), { status: "not_ready", component: "cloud-control-plane", checks: {
		auth: "reachable", database: "reachable", storage: "reachable", functions: "reachable",
		signing: "unverified", backup: "unverified", queue: "unverified", certificate: "unverified",
	} });
	assert.equal(assetCalls, 0);
	assert.deepEqual(upstreamCalls.sort(), [
		`${provider}/auth/v1/health`,
		`${provider}/functions/v1/packs-manifest`,
		`${provider}/rest/v1/rpc/aidr_readiness_probe`,
		`${provider}/storage/v1/status`,
	].sort());
});

test("health routes handle HEAD and unsupported methods without returning HTML", async () => {
	const readyEnv = { ...env, ASSETS: { fetch: async () => new Response("<html>dashboard</html>", { headers: { "content-type": "text/html" } }) } };
	for (const path of ["/livez", "/healthz", "/readyz"]) {
		const head = await handle(new Request(`${site}${path}`, { method: "HEAD" }), path === "/readyz" ? readyEnv : env);
		assert.equal(head.status, path === "/readyz" ? 503 : 200);
		assert.equal(await head.text(), "");
		assert.match(head.headers.get("content-type"), /application\/json/);

		const post = await handle(new Request(`${site}${path}`, { method: "POST" }), env);
		assert.equal(post.status, 405);
		assert.equal(post.headers.get("allow"), "GET, HEAD");
		assert.match(post.headers.get("content-type"), /application\/json/);
		assert.doesNotMatch(await post.text(), /<html/i);
	}
});

test("readiness fails closed without release identity and never probes an unconfigured provider", async () => {
	let calls = 0;
	const ready = await handle(new Request(`${site}/readyz`), env, async () => {
		calls++;
		return Response.json({ status: "ok" });
	});
	assert.equal(ready.status, 503);
	assert.deepEqual(await ready.json(), { error: "release_identity_unavailable" });
	assert.equal(calls, 0);
	const wrongHost = await handle(new Request("https://other.example/readyz"), { ...env, AIDR_RELEASE_VERSION: "1.2.3", AIDR_RELEASE_SHA: "a".repeat(40) }, async () => {
		calls++;
		return Response.json({ ok: true });
	});
	assert.equal(wrongHost.status, 403);
	assert.deepEqual(await wrongHost.json(), { error: "wrong_public_origin" });
	assert.equal(calls, 0);
});

test("readiness reports failed provider probes without exposing upstream errors", async () => {
	const releaseEnv = { ...env, AIDR_RELEASE_VERSION: "1.2.3", AIDR_RELEASE_SHA: "a".repeat(40) };
	const response = await handle(new Request(`${site}/readyz`), releaseEnv, async (url) => {
		if (url.endsWith("/auth/v1/health")) throw new Error("private provider detail");
		if (url.endsWith("/rest/v1/rpc/aidr_readiness_probe")) return Response.json({ ok: false });
		if (url.endsWith("/storage/v1/status")) return new Response(null, { status: 302, headers: { location: "https://untrusted.example" } });
		return Response.json({ error: "wrong_reason" }, { status: 401 });
	});
	assert.equal(response.status, 503);
	assert.equal(response.headers.get("cache-control"), "no-store");
	const body = await response.json();
	assert.deepEqual(Object.values(body.checks).slice(0, 4), ["failed", "failed", "failed", "failed"]);
	assert.doesNotMatch(JSON.stringify(body), /private provider detail|untrusted\.example|wrong_reason/);
});

test("readiness rejects oversized or non-JSON database and function responses", async () => {
	const releaseEnv = { ...env, AIDR_RELEASE_VERSION: "1.2.3", AIDR_RELEASE_SHA: "a".repeat(40) };
	const response = await handle(new Request(`${site}/readyz`), releaseEnv, async (url) => {
		if (url.endsWith("/rest/v1/rpc/aidr_readiness_probe")) return Response.json({ ok: true, padding: "x".repeat(512) });
		if (url.endsWith("/functions/v1/packs-manifest")) return new Response("<html>missing_api_key</html>", { status: 401, headers: { "content-type": "text/html" } });
		return new Response(null, { status: 200 });
	});
	const body = await response.json();
	assert.equal(body.checks.database, "failed");
	assert.equal(body.checks.functions, "failed");
});

test("readiness coalesces concurrent probes and briefly caches only the same release", async () => {
	let calls = 0;
	const releaseEnv = { ...env, AIDR_RELEASE_VERSION: "1.2.3", AIDR_RELEASE_SHA: "b".repeat(40) };
	const fetcher = async (url) => {
		calls++;
		await Promise.resolve();
		if (url.endsWith("/rest/v1/rpc/aidr_readiness_probe")) return Response.json({ ok: true });
		if (url.endsWith("/functions/v1/packs-manifest")) return Response.json({ error: "missing_api_key" }, { status: 401 });
		return new Response(null, { status: 200 });
	};
	const request = () => new Request(`${site}/readyz`);
	await Promise.all([handle(request(), releaseEnv, fetcher), handle(request(), releaseEnv, fetcher)]);
	assert.equal(calls, 4);
	await handle(request(), releaseEnv, fetcher);
	assert.equal(calls, 4);
	await handle(request(), { ...releaseEnv, AIDR_RELEASE_SHA: "c".repeat(40) }, fetcher);
	assert.equal(calls, 8);
});

test("metrics is explicitly unsupported instead of returning the SPA shell", async () => {
	let assetCalls = 0;
	const metricsEnv = { ...env, ASSETS: { fetch: async () => { assetCalls++; return new Response("<html>SPA</html>"); } } };
	const response = await handle(new Request(`${site}/metrics`), metricsEnv);
	assert.equal(response.status, 501);
	assert.deepEqual(await response.json(), { error: "metrics_not_supported" });
	const head = await handle(new Request(`${site}/metrics`, { method: "HEAD" }), metricsEnv);
	assert.equal(head.status, 501);
	assert.equal(await head.text(), "");
	assert.equal(assetCalls, 0);
});

test("version endpoint attests the configured release version and exact source commit", async () => {
	const releaseEnv = { ...env, AIDR_RELEASE_VERSION: "1.2.3-rc.4", AIDR_RELEASE_SHA: "a".repeat(40) };
	const response = await handle(new Request(`${site}/version`), releaseEnv);
	assert.equal(response.status, 200);
	assert.deepEqual(await response.json(), { version: "1.2.3-rc.4", git_sha: "a".repeat(40) });
	assert.equal(response.headers.get("cache-control"), "no-store");

	const head = await handle(new Request(`${site}/version`, { method: "HEAD" }), releaseEnv);
	assert.equal(head.status, 200);
	assert.equal(await head.text(), "");
});

test("version endpoint fails closed for invalid identity, host, and methods", async () => {
	for (const invalid of [
		{ ...env, AIDR_RELEASE_VERSION: "latest", AIDR_RELEASE_SHA: "a".repeat(40) },
		{ ...env, AIDR_RELEASE_VERSION: "1.2.3", AIDR_RELEASE_SHA: "not-a-commit" },
	]) {
		const response = await handle(new Request(`${site}/version`), invalid);
		assert.equal(response.status, 503);
		assert.deepEqual(await response.json(), { error: "release_identity_unavailable" });
	}

	const releaseEnv = { ...env, AIDR_RELEASE_VERSION: "1.2.3", AIDR_RELEASE_SHA: "a".repeat(40) };
	const wrongHost = await handle(new Request("https://other.example/version"), releaseEnv);
	assert.equal(wrongHost.status, 403);
	assert.deepEqual(await wrongHost.json(), { error: "wrong_public_origin" });
	const unsupported = await handle(new Request(`${site}/version`, { method: "POST" }), releaseEnv);
	assert.equal(unsupported.status, 405);
	assert.equal(unsupported.headers.get("allow"), "GET, HEAD");
});

test("Wrangler routes health paths to the Worker before static SPA fallback", async () => {
	const config = JSON.parse(await readFile(new URL("./wrangler.jsonc", import.meta.url), "utf8"));
	assert.deepEqual(config.assets.run_worker_first.slice(0, 6), [
		"/runtime-config.js",
		"/livez",
		"/healthz",
		"/readyz",
		"/metrics",
		"/version",
	]);
	assert.equal(config.vars.AIDR_ENABLE_AZURE_AUTH, "false");
	assert.equal(config.vars.AIDR_SIGNUP_MODE, "closed");
	assert.equal(config.env.staging.vars.AIDR_SIGNUP_MODE, "closed");
	assert.deepEqual(config.assets.run_worker_first.slice(6, 8), ["/demo", "/demo/"]);
});

test("retired demo URL redirects at the edge before any SPA shell is served", async () => {
	let assetCalls = 0;
	const redirectEnv = { ...env, ASSETS: { fetch: async () => { assetCalls++; return new Response("<html>demo</html>"); } } };
	for (const path of ["/demo", "/demo/"]) {
		const response = await handle(new Request(`${site}${path}`), redirectEnv);
		assert.equal(response.status, 302);
		assert.equal(response.headers.get("location"), "/login?returnTo=%2Fonboarding");
		assert.equal(response.headers.get("cache-control"), "no-store");
		assert.equal(await response.text(), "");
	}
	assert.equal(assetCalls, 0);
});

test("Worker contract remains blocking in CI and release-candidate workflows", async () => {
	for (const workflow of ["ci.yml", "release-rc.yml"]) {
		const source = await readFile(new URL(`../../.github/workflows/${workflow}`, import.meta.url), "utf8");
		assert.match(source, /- name: Cloudflare Worker contract\r?\n\s+run: node --test deploy\/cloudflare\/worker\.test\.mjs deploy\/cloudflare\/verify-operational\.test\.mjs/);
	}
});

test("auth callback and recovery routes stay on the SPA asset path", async () => {
	const paths = [];
	const assets = { fetch: async (request) => { paths.push(new URL(request.url).pathname); return new Response("spa"); } };
	let proxied = false;
	for (const path of ["/auth/callback", "/auth/recover"]) {
		const response = await handle(new Request(`${site}${path}?code=redacted`, { headers: { "sec-fetch-mode": "navigate" } }), { ...env, ASSETS: assets }, () => { proxied = true; });
		assert.equal(response.status, 200);
	}
	assert.deepEqual(paths, ["/auth/callback", "/auth/recover"]);
	assert.equal(proxied, false);
});

test("fingerprinted dashboard bundles get immutable caching without caching the SPA shell", async () => {
	const headers = await readFile(new URL("../../packages/dashboard/public/_headers", import.meta.url), "utf8");
	assert.match(headers, /\/assets\/\*\s+Cache-Control: public, max-age=31536000, immutable/);
	assert.doesNotMatch(headers, /^\/\*\r?\n\s+Cache-Control: public, max-age=31536000, immutable/m);
});

test("runtime configuration exposes only the public origin and anon key", async () => {
	const response = await handle(new Request(`${site}/runtime-config.js`), env);
	const script = await response.text();
	assert.equal(response.status, 200);
	assert.match(script, /sb_publishable_test-only/);
	assert.match(script, /aidr-pilot\.example\.workers\.dev/);
	assert.match(script, /"magic-link"/);
	assert.match(script, /"signupMode":"closed"/);
	assert.doesNotMatch(script, /a-device-start-signing-secret/);
	assert.doesNotMatch(script, /project\.supabase\.co/);
	assert.equal(response.headers.get("cache-control"), "no-store");
	assert.equal((await handle(new Request(`${site}/runtime-config.js`, { method: "POST" }), env)).status, 405);
});

test("cloud signup hint is exact and defaults closed without enabling provider signup", async () => {
	const configFor = async (workerEnv) => {
		const response = await handle(new Request(`${site}/runtime-config.js`), workerEnv);
		assert.equal(response.status, 200);
		const script = await response.text();
		return JSON.parse(script.slice("window.__AIDR_CONFIG__=".length, -1));
	};
	assert.equal((await configFor(env)).signupMode, "closed");
	assert.equal((await configFor({ ...env, AIDR_SIGNUP_MODE: "cloud" })).signupMode, "cloud");
	assert.equal((await handle(new Request(`${site}/runtime-config.js`), { ...env, AIDR_SIGNUP_MODE: "pilot" })).status, 503);
});

test("Azure sign-in stays hidden unless its exact opt-in flag is enabled", async () => {
	const readMethods = async (workerEnv) => {
		const response = await handle(new Request(`${site}/runtime-config.js`), workerEnv);
		assert.equal(response.status, 200);
		const script = await response.text();
		const payload = JSON.parse(script.slice("window.__AIDR_CONFIG__=".length, -1));
		return payload.authMethods;
	};
	assert.deepEqual(await readMethods(env), ["password", "magic-link"]);
	assert.deepEqual(await readMethods({ ...env, AIDR_ENABLE_AZURE_AUTH: "false" }), ["password", "magic-link"]);
	assert.deepEqual(await readMethods({ ...env, AIDR_ENABLE_AZURE_AUTH: "true" }), ["password", "magic-link", "azure"]);
});

test("SAML discovery is absent by default and exposes only an explicit provider or domain", async () => {
	const readConfig = async (workerEnv) => {
		const response = await handle(new Request(`${site}/runtime-config.js`), workerEnv);
		assert.equal(response.status, 200);
		const script = await response.text();
		return JSON.parse(script.slice("window.__AIDR_CONFIG__=".length, -1));
	};
	const absent = await readConfig(env);
	assert.equal(absent.samlProviderId, undefined);
	assert.equal(absent.samlDomain, undefined);
	const provider = await readConfig({ ...env, AIDR_SAML_PROVIDER_ID: "21648a9d-8d5a-4555-a9d1-d6375dc14e92" });
	assert.equal(provider.samlProviderId, "21648a9d-8d5a-4555-a9d1-d6375dc14e92");
	const providers = await readConfig({ ...env, AIDR_SAML_PROVIDERS: JSON.stringify([
		{ providerId: "21648a9d-8d5a-4555-a9d1-d6375dc14e92", label: "Microsoft Entra ID" },
		{ providerId: "33333333-3333-4333-8333-333333333333", label: "Okta" },
	]) });
	assert.deepEqual(providers.samlProviders, [
		{ providerId: "21648a9d-8d5a-4555-a9d1-d6375dc14e92", label: "Microsoft Entra ID" },
		{ providerId: "33333333-3333-4333-8333-333333333333", label: "Okta" },
	]);
	const domain = await readConfig({ ...env, AIDR_SAML_DOMAIN: "company.example" });
	assert.equal(domain.samlDomain, "company.example");
	assert.equal((await handle(new Request(`${site}/runtime-config.js`), { ...env, AIDR_SAML_DOMAIN: "company.example/path" })).status, 503);
	assert.equal((await handle(new Request(`${site}/runtime-config.js`), { ...env, AIDR_SAML_DOMAIN: "company.example", AIDR_SAML_PROVIDER_ID: provider.samlProviderId })).status, 503);
	assert.equal((await handle(new Request(`${site}/runtime-config.js`), { ...env, AIDR_SAML_PROVIDERS: "not-json" })).status, 503);
	assert.equal((await handle(new Request(`${site}/runtime-config.js`), { ...env, AIDR_SAML_PROVIDERS: JSON.stringify([
		{ providerId: provider.samlProviderId, label: "Entra" },
		{ providerId: provider.samlProviderId.toUpperCase(), label: "Okta" },
	]) })).status, 503);
});

test("fails closed on missing configuration, wrong host, and service-role key", async () => {
	assert.equal((await handle(new Request(`${site}/runtime-config.js`), { ...env, AIDR_DEVICE_START_INGRESS_SECRET: "short" })).status, 503);
	assert.equal((await handle(new Request("https://other.example/runtime-config.js"), env)).status, 403);
	const jwt = `header.${Buffer.from(JSON.stringify({ role: "service_role" })).toString("base64url")}.signature`;
	assert.equal((await handle(new Request(`${site}/runtime-config.js`), { ...env, AIDR_SUPABASE_ANON_KEY: jwt })).status, 503);
});

test("proxies only fixed Supabase namespaces and preserves query and user auth", async () => {
	let received;
	const response = await handle(new Request(`${site}/rest/v1/events?limit=2`, {
		headers: {
			authorization: "Bearer user-token",
			"x-aidr-client-signature": "forged",
			"cf-connecting-ip": "198.51.100.20",
			"cf-ipcountry": "TR",
			"cf-ray": "example-ray",
		},
	}), env, async (url, init) => {
		received = { url, init };
		return Response.json({ ok: true });
	});
	assert.equal(response.status, 200);
	assert.equal(received.url, `${provider}/rest/v1/events?limit=2`);
	assert.equal(received.init.headers.get("authorization"), "Bearer user-token");
	assert.equal(received.init.headers.has("x-aidr-client-signature"), false);
	for (const name of ["cf-connecting-ip", "cf-ipcountry", "cf-ray"]) {
		assert.equal(received.init.headers.has(name), false, `${name} must not be forwarded`);
	}
	assert.equal(response.headers.get("cache-control"), "no-store");
});

test("closed signup mode blocks password signup and OTP requests that may create users", async () => {
	let calls = 0;
	for (const path of ["/auth/v1/signup", "/auth/v1/signup/", "/auth/v1/%73ignup"]) {
		const response = await handle(new Request(`${site}${path}`, {
			method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "new@example.test", password: "secret" }),
		}), env, async () => { calls++; return Response.json({ ok: true }); });
		assert.equal(response.status, 403);
		assert.deepEqual(await response.json(), { error: "signup_closed" });
	}
	for (const payload of [{ email: "new@example.test" }, { email: "new@example.test", create_user: true }]) {
		const response = await handle(new Request(`${site}/auth/v1/otp`, {
			method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
		}), env, async () => { calls++; return Response.json({ ok: true }); });
		assert.equal(response.status, 403);
		assert.deepEqual(await response.json(), { error: "signup_closed" });
	}
	assert.equal(calls, 0);
});

test("closed signup mode preserves existing-user magic-link OTP", async () => {
	const payload = { email: "existing@example.test", create_user: false, gotrue_meta_security: { captcha_token: "test-token" } };
	let forwarded;
	const response = await handle(new Request(`${site}/auth/v1/otp`, {
		method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
	}), env, async (url, init) => {
		forwarded = { url, init, body: await new Response(init.body).text() };
		return Response.json({ ok: true });
	});
	assert.equal(response.status, 200);
	assert.equal(forwarded.url, `${provider}/auth/v1/otp`);
	assert.deepEqual(JSON.parse(forwarded.body), payload);
});

test("cloud signup mode forwards signup and signup-capable OTP to Auth", async () => {
	let paths = [];
	for (const [path, payload] of [
		["/auth/v1/signup", { email: "new@example.test", password: "secret" }],
		["/auth/v1/otp", { email: "new@example.test", create_user: true }],
	]) {
		const response = await handle(new Request(`${site}${path}`, {
			method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
		}), { ...env, AIDR_SIGNUP_MODE: "cloud" }, async (url) => {
			paths.push(url);
			return Response.json({ ok: true });
		});
		assert.equal(response.status, 200);
	}
	assert.deepEqual(paths, [`${provider}/auth/v1/signup`, `${provider}/auth/v1/otp`]);
});

test("deployed entrypoint ignores the Workers execution context when proxying", async (t) => {
	t.mock.method(globalThis, "fetch", async () => Response.json({ healthy: true }));
	const response = await worker.fetch(new Request(`${site}/auth/v1/health`), env, { waitUntil() {} });
	assert.equal(response.status, 200);
	assert.deepEqual(await response.json(), { healthy: true });
});

test("device bootstrap signs the Cloudflare client IP and ignores spoofed AIDR headers", async () => {
	let received;
	const response = await handle(new Request(`${site}/functions/v1/device-start`, {
		method: "POST",
		headers: {
			"cf-connecting-ip": "198.51.100.20",
			"cf-ray": "example-ray",
			"x-aidr-client-ip": "203.0.113.99",
			"x-aidr-client-signature": "forged",
			"x-forwarded-for": "203.0.113.99",
			origin: site,
		},
		body: "{}",
	}), env, async (url, init) => {
		received = { url, init };
		return Response.json({ ok: true }, { headers: { "access-control-allow-origin": site } });
	});
	assert.equal(response.status, 200);
	assert.equal(received.url, `${provider}/functions/v1/device-start`);
	assert.equal(received.init.headers.get("x-aidr-client-ip"), "198.51.100.20");
	assert.equal(received.init.headers.has("cf-connecting-ip"), false);
	assert.equal(received.init.headers.has("cf-ray"), false);
	assert.equal(received.init.headers.has("x-forwarded-for"), false);
	assert.equal(received.init.headers.get("authorization"), `Bearer ${env.AIDR_SUPABASE_ANON_KEY}`);
	const timestamp = received.init.headers.get("x-aidr-client-timestamp");
	const expected = createHmac("sha256", secret).update(`device-start:v1\n${timestamp}\n198.51.100.20`).digest("hex");
	assert.equal(received.init.headers.get("x-aidr-client-signature"), expected);
	assert.equal(response.headers.get("access-control-allow-origin"), site);
});

test("waitlist signup forwards a route-bound signature of the Cloudflare client IP", async () => {
	let received;
	const response = await handle(new Request(`${site}/functions/v1/waitlist-signup`, {
		method: "POST",
		headers: {
			"cf-connecting-ip": "2001:db8::20",
			"x-aidr-client-ip": "203.0.113.99",
			"x-aidr-client-signature": "forged",
			"x-forwarded-for": "203.0.113.99",
			"content-type": "application/json",
		},
		body: JSON.stringify({ email: "person@example.com" }),
	}), env, async (url, init) => {
		received = { url, init };
		return Response.json({ ok: true });
	});
	assert.equal(response.status, 200);
	assert.equal(received.url, `${provider}/functions/v1/waitlist-signup`);
	assert.equal(received.init.headers.get("x-aidr-client-ip"), "2001:db8::20");
	assert.equal(received.init.headers.has("x-forwarded-for"), false);
	const timestamp = received.init.headers.get("x-aidr-client-timestamp");
	const expected = createHmac("sha256", secret).update(`waitlist-signup:v1\n${timestamp}\n2001:db8::20`).digest("hex");
	assert.equal(received.init.headers.get("x-aidr-client-signature"), expected);
	assert.notEqual(expected, createHmac("sha256", secret).update(`device-start:v1\n${timestamp}\n2001:db8::20`).digest("hex"));

	let unsigned;
	await handle(new Request(`${site}/functions/v1/waitlist-signup`, {
		method: "POST",
		headers: { "x-aidr-client-ip": "203.0.113.99", "x-aidr-client-signature": "forged" },
		body: "{}",
	}), env, async (_url, init) => {
		unsigned = init;
		return Response.json({ ok: true });
	});
	assert.equal(unsigned.headers.has("x-aidr-client-ip"), false);
	assert.equal(unsigned.headers.has("x-aidr-client-signature"), false);
});

test("device poll, identity recovery and OIDC SSO get a route-bound client IP proof while keeping user auth", async () => {
	for (const [path, context] of [["device-poll", "device-poll:v1"], ["identity-security", "identity-security:v1"], ["oidc-sso", "oidc-sso:v1"]]) {
		let received;
		const response = await handle(new Request(`${site}/functions/v1/${path}`, {
			method: "POST",
			headers: {
				authorization: "Bearer caller-credential",
				"cf-connecting-ip": "198.51.100.20",
				"x-aidr-client-ip": "203.0.113.99",
				"x-aidr-client-signature": "forged",
			},
			body: "{}",
		}), env, async (url, init) => {
			received = { url, init };
			return Response.json({ ok: true });
		});
		assert.equal(response.status, 200);
		assert.equal(received.init.headers.get("authorization"), "Bearer caller-credential");
		assert.equal(received.init.headers.get("x-aidr-client-ip"), "198.51.100.20");
		assert.equal(received.init.headers.has("cf-connecting-ip"), false);
		const timestamp = received.init.headers.get("x-aidr-client-timestamp");
		const expected = createHmac("sha256", secret).update(`${context}\n${timestamp}\n198.51.100.20`).digest("hex");
		assert.equal(received.init.headers.get("x-aidr-client-signature"), expected);

		// Without an edge IP the call is forwarded unsigned (the function's unsigned aggregate applies).
		const unsigned = await handle(new Request(`${site}/functions/v1/${path}`, {
			method: "POST", headers: { "x-aidr-client-signature": "forged" }, body: "{}",
		}), env, async (url, init) => {
			received = { url, init };
			return Response.json({ ok: true });
		});
		assert.equal(unsigned.status, 200);
		assert.equal(received.init.headers.has("x-aidr-client-signature"), false);
	}
});

test("device bootstrap rejects missing edge IP, oversized body, redirects, and oversized responses", async () => {
	const url = `${site}/functions/v1/device-start`;
	const forbidden = await handle(new Request(url, { method: "POST", body: "{}", headers: { "x-forwarded-for": "198.51.100.20" } }), env);
	assert.equal(forbidden.status, 403);
	const headers = { "cf-connecting-ip": "198.51.100.20" };
	const oversized = await handle(new Request(url, { method: "POST", body: "x".repeat(4097), headers }), env);
	assert.equal(oversized.status, 413);
	const request = () => new Request(url, { method: "POST", body: "{}", headers });
	assert.equal((await handle(request(), env, async () => new Response(null, { status: 302, headers: { location: "https://evil.example" } }))).status, 502);
	assert.equal((await handle(request(), env, async () => new Response("x".repeat(16385)))).status, 502);
});

test("device bootstrap preserves a bodyless CORS preflight", async () => {
	const response = await handle(new Request(`${site}/functions/v1/device-start`, {
		method: "OPTIONS", headers: { "cf-connecting-ip": "2001:db8::1", origin: site },
	}), env, async (_url, init) => {
		assert.equal(init.headers.get("x-aidr-client-ip"), "2001:db8::1");
		return new Response(null, { status: 204, headers: { "access-control-allow-origin": site, "access-control-allow-methods": "POST, OPTIONS" } });
	});
	assert.equal(response.status, 204);
	assert.equal(response.headers.get("access-control-allow-origin"), site);
});
