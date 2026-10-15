import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildRequestBody, obtainAccessToken, resolveProjectUrl, run, sha256Hex } from "./operator-admin.mjs";

const TENANT = "33333333-3333-4333-8333-333333333333";
const OWNER = "22222222-2222-4222-8222-222222222222";
const FACTOR = "44444444-4444-4444-8444-444444444444";
const TOKEN = "aal2-secret-token-value";
const ENV = {
	AIDR_SUPABASE_URL: "https://project.supabase.co",
	SUPABASE_ANON_KEY: "anon-key",
	AIDR_OPERATOR_ACCESS_TOKEN: TOKEN,
};

function jsonResponse(status, body) {
	return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

/** Fake fetch: `routes` maps a URL (without origin) to a response factory. */
function fakeFetch(routes) {
	const calls = [];
	const fetch = async (input, init = {}) => {
		const url = new URL(String(input));
		const key = `${url.pathname}${url.search}`;
		calls.push({ url: String(input), key, init, body: init.body ? JSON.parse(init.body) : undefined });
		const route = routes[key] ?? routes[url.href];
		if (!route) throw new Error(`unexpected fetch ${url.href}`);
		return route(calls.at(-1));
	};
	return { fetch, calls };
}

function capture() {
	const out = [];
	const err = [];
	return { out, err, stdout: (line) => out.push(line), stderr: (line) => err.push(line) };
}

describe("request bodies", () => {
	it("builds every action body with normalized values", async () => {
		assert.deepEqual(await buildRequestBody("mode", ["onprem"], {}), { action: "configure_admission_mode", mode: "onprem" });
		assert.deepEqual(
			await buildRequestBody("grant", [], {
				tenant: TENANT.toUpperCase(),
				plan: "business",
				seats: "30",
				"expires-at": "2027-09-25",
				reference: "PO-1",
				owner: OWNER,
			}),
			{
				action: "grant_license",
				tenant_id: TENANT,
				plan_id: "business",
				seats: 30,
				expires_at: "2027-09-25T00:00:00.000Z",
				reference: "PO-1",
				owner_user_id: OWNER,
			},
		);
		assert.deepEqual(await buildRequestBody("revoke", [], { tenant: TENANT, reason: "ended" }), {
			action: "revoke_license",
			tenant_id: TENANT,
			reason: "ended",
		});
		assert.deepEqual(await buildRequestBody("tenants", [], { limit: "25", after: TENANT }), {
			action: "list_tenants",
			limit: 25,
			after: TENANT,
		});
		assert.deepEqual(await buildRequestBody("usage", [], { tenant: TENANT }), { action: "tenant_usage", tenant_id: TENANT });
	});

	it("computes legal digests from files and rejects a mismatched declaration", async () => {
		const files = { "/docs/terms.pdf": Buffer.from("terms v1"), "/docs/privacy.pdf": Buffer.from("privacy v1") };
		const io = { readFile: async (path) => files[path] ?? Promise.reject(new Error(`missing ${path}`)) };
		const values = {
			"terms-version": "2026.09",
			"terms-url": "https://aidr.example/terms",
			"terms-file": "/docs/terms.pdf",
			"privacy-version": "2026.09",
			"privacy-url": "https://aidr.example/privacy",
			"privacy-sha256": sha256Hex(files["/docs/privacy.pdf"]).toUpperCase(),
			"approval-reference": "LEGAL-42",
		};
		const body = await buildRequestBody("legal", [], values, io);
		assert.equal(body.terms.sha256, sha256Hex(files["/docs/terms.pdf"]));
		assert.equal(body.privacy.sha256, sha256Hex(files["/docs/privacy.pdf"]));

		await assert.rejects(
			buildRequestBody("legal", [], { ...values, "terms-sha256": "0".repeat(64) }, io),
			/does not match --terms-file/,
		);
		await assert.rejects(
			buildRequestBody("legal", [], { ...values, "terms-file": undefined }, io),
			/--terms-sha256 or --terms-file is required/,
		);
	});

	it("rejects invalid input locally", async () => {
		await assert.rejects(buildRequestBody("mode", ["unconfigured"], {}), /cloud, onprem, pilot/);
		await assert.rejects(buildRequestBody("grant", [], { tenant: "x", plan: "team", seats: "1", "expires-at": "2027-01-01", reference: "r" }), /UUID/);
		await assert.rejects(buildRequestBody("grant", [], { tenant: TENANT, plan: "team", seats: "-1", "expires-at": "2027-01-01", reference: "r" }), /positive integer/);
		await assert.rejects(buildRequestBody("grant", [], { tenant: TENANT, plan: "team", seats: "1", "expires-at": "soon", reference: "r" }), /ISO-8601/);
		await assert.rejects(buildRequestBody("revoke", [], { tenant: TENANT }), /--reason is required/);
		await assert.rejects(buildRequestBody("delete", [], {}), /unknown command/);
	});
});

describe("environment", () => {
	it("requires https except on localhost and refuses embedded credentials", () => {
		assert.equal(resolveProjectUrl({ SUPABASE_URL: "https://p.supabase.co/" }).href, "https://p.supabase.co/");
		assert.equal(resolveProjectUrl({ AIDR_SUPABASE_URL: "http://127.0.0.1:54321" }).origin, "http://127.0.0.1:54321");
		assert.throws(() => resolveProjectUrl({ SUPABASE_URL: "http://p.supabase.co" }), /https/);
		assert.throws(() => resolveProjectUrl({ SUPABASE_URL: "https://u:p@p.supabase.co" }), /credentials/);
		assert.throws(() => resolveProjectUrl({}), /required/);
	});

	it("signs in with a password and steps up with the single verified TOTP factor", async () => {
		const { fetch, calls } = fakeFetch({
			"/auth/v1/token?grant_type=password": () => jsonResponse(200, {
				access_token: "aal1",
				user: { factors: [{ id: FACTOR, factor_type: "totp", status: "verified" }, { id: "x", factor_type: "phone", status: "verified" }] },
			}),
			[`/auth/v1/factors/${FACTOR}/challenge`]: () => jsonResponse(200, { id: "challenge-1" }),
			[`/auth/v1/factors/${FACTOR}/verify`]: () => jsonResponse(200, { access_token: TOKEN }),
		});
		const env = {
			SUPABASE_ANON_KEY: "anon-key",
			AIDR_OPERATOR_EMAIL: "ops@aidr.example",
			AIDR_OPERATOR_PASSWORD: "correct horse",
			AIDR_OPERATOR_TOTP_CODE: "123456",
		};
		const token = await obtainAccessToken(env, resolveProjectUrl({ SUPABASE_URL: "https://p.supabase.co" }), fetch);

		assert.equal(token, TOKEN);
		assert.deepEqual(calls[0].body, { email: "ops@aidr.example", password: "correct horse" });
		assert.equal(calls[0].init.headers.apikey, "anon-key");
		assert.equal(calls[1].init.headers.Authorization, "Bearer aal1");
		assert.deepEqual(calls[2].body, { challenge_id: "challenge-1", code: "123456" });
	});

	it("refuses ambiguous or missing MFA before sending the code", async () => {
		const base = resolveProjectUrl({ SUPABASE_URL: "https://p.supabase.co" });
		const env = {
			SUPABASE_ANON_KEY: "anon-key",
			AIDR_OPERATOR_EMAIL: "ops@aidr.example",
			AIDR_OPERATOR_PASSWORD: "pw",
			AIDR_OPERATOR_TOTP_CODE: "123456",
		};
		for (const factors of [[], [
			{ id: FACTOR, factor_type: "totp", status: "verified" },
			{ id: OWNER, factor_type: "totp", status: "verified" },
		]]) {
			const { fetch, calls } = fakeFetch({
				"/auth/v1/token?grant_type=password": () => jsonResponse(200, { access_token: "aal1", user: { factors } }),
			});
			await assert.rejects(obtainAccessToken(env, base, fetch), /TOTP/);
			assert.equal(calls.length, 1);
		}
		await assert.rejects(obtainAccessToken({ ...env, AIDR_OPERATOR_TOTP_CODE: "12" }, base, fakeFetch({}).fetch), /6-digit/);
		await assert.rejects(obtainAccessToken({ SUPABASE_ANON_KEY: "a" }, base, fakeFetch({}).fetch), /AIDR_OPERATOR_ACCESS_TOKEN/);
	});

	it("reports a failed sign-in without echoing credentials", async () => {
		const { fetch } = fakeFetch({
			"/auth/v1/token?grant_type=password": () => jsonResponse(400, { error: "invalid_grant" }),
		});
		const io = capture();
		const code = await run(["usage", "--tenant", TENANT], {
			env: { AIDR_SUPABASE_URL: "https://p.supabase.co", SUPABASE_ANON_KEY: "anon-key", AIDR_OPERATOR_EMAIL: "ops@x", AIDR_OPERATOR_PASSWORD: "hunter2", AIDR_OPERATOR_TOTP_CODE: "123456" },
			fetch,
			...io,
		});
		assert.equal(code, 1);
		assert.match(io.err.join("\n"), /sign-in failed \(HTTP 400\)/);
		assert.doesNotMatch([...io.out, ...io.err].join("\n"), /hunter2|anon-key/);
	});
});

describe("run", () => {
	it("posts to the operator-admin function with the bearer token and prints the result", async () => {
		const { fetch, calls } = fakeFetch({
			"/functions/v1/operator-admin": () => jsonResponse(200, { ok: true, action: "tenant_usage", result: { members: 2 } }),
		});
		const io = capture();
		const code = await run(["usage", "--tenant", TENANT], { env: ENV, fetch, ...io });

		assert.equal(code, 0);
		assert.equal(calls.length, 1);
		assert.equal(calls[0].url, "https://project.supabase.co/functions/v1/operator-admin");
		assert.equal(calls[0].init.method, "POST");
		assert.equal(calls[0].init.headers.Authorization, `Bearer ${TOKEN}`);
		assert.equal(calls[0].init.headers.apikey, "anon-key");
		assert.deepEqual(calls[0].body, { action: "tenant_usage", tenant_id: TENANT });
		assert.deepEqual(JSON.parse(io.out.join("\n")), { ok: true, action: "tenant_usage", result: { members: 2 } });
		assert.doesNotMatch(io.out.join("\n"), new RegExp(TOKEN));
	});

	it("keeps a self-hosted gateway path prefix", async () => {
		const { fetch, calls } = fakeFetch({
			"/supabase/functions/v1/operator-admin": () => jsonResponse(200, { ok: true, action: "list_tenants", result: { tenants: [], next_cursor: null } }),
		});
		const env = { ...ENV, AIDR_SUPABASE_URL: "https://gateway.example/supabase/" };
		assert.equal(await run(["tenants"], { env, fetch, ...capture() }), 0);
		assert.equal(calls[0].url, "https://gateway.example/supabase/functions/v1/operator-admin");
	});

	it("exits 1 and prints the service error when the function refuses", async () => {
		const { fetch } = fakeFetch({ "/functions/v1/operator-admin": () => jsonResponse(403, { error: "mfa_required" }) });
		const io = capture();
		assert.equal(await run(["mode", "cloud"], { env: ENV, fetch, ...io }), 1);
		assert.deepEqual(JSON.parse(io.out.join("\n")), { error: "mfa_required" });
	});

	it("dry-run prints the body without credentials or network access", async () => {
		const io = capture();
		const code = await run(["revoke", "--tenant", TENANT, "--reason", "ended", "--dry-run"], {
			env: {},
			fetch: () => assert.fail("dry-run must not call the network"),
			...io,
		});
		assert.equal(code, 0);
		assert.deepEqual(JSON.parse(io.out.join("\n")), { action: "revoke_license", tenant_id: TENANT, reason: "ended" });
	});

	it("exits 2 on usage errors and unknown flags", async () => {
		for (const argv of [["mode"], ["grant", "--tenant", TENANT], ["usage", "--password", "x"], ["usage", "--tenant", TENANT, "--all"], []]) {
			const io = capture();
			assert.equal(await run(argv, { env: ENV, fetch: () => assert.fail("no network"), ...io }), 2, argv.join(" "));
		}
	});

	it("follows keyset cursors with --all", async () => {
		const second = "55555555-5555-4555-8555-555555555555";
		const { fetch, calls } = fakeFetch({
			"/functions/v1/operator-admin": ({ body }) => jsonResponse(200, body.after
				? { ok: true, action: "list_tenants", result: { tenants: [{ id: second }], next_cursor: null } }
				: { ok: true, action: "list_tenants", result: { tenants: [{ id: TENANT }], next_cursor: TENANT } }),
		});
		const io = capture();
		assert.equal(await run(["tenants", "--all", "--limit", "1"], { env: ENV, fetch, ...io }), 0);
		assert.deepEqual(calls.map((call) => call.body), [
			{ action: "list_tenants", limit: 1 },
			{ action: "list_tenants", limit: 1, after: TENANT },
		]);
		assert.deepEqual(JSON.parse(io.out.join("\n")).result.tenants, [{ id: TENANT }, { id: second }]);
	});

	it("verifies remote legal documents against their declared digests before sending", async () => {
		const terms = Buffer.from("terms body");
		const privacy = Buffer.from("privacy body");
		const argv = [
			"legal", "--verify-remote",
			"--terms-version", "v1", "--terms-url", "https://aidr.example/terms", "--terms-sha256", sha256Hex(terms),
			"--privacy-version", "v1", "--privacy-url", "https://aidr.example/privacy", "--privacy-sha256", sha256Hex(privacy),
			"--approval-reference", "LEGAL-1",
		];
		const ok = fakeFetch({
			"https://aidr.example/terms": () => new Response(terms),
			"https://aidr.example/privacy": () => new Response(privacy),
			"/functions/v1/operator-admin": () => jsonResponse(200, { ok: true, action: "configure_legal_documents", result: { status: "configured" } }),
		});
		assert.equal(await run(argv, { env: ENV, fetch: ok.fetch, ...capture() }), 0);
		assert.equal(ok.calls.at(-1).key, "/functions/v1/operator-admin");

		const tampered = fakeFetch({
			"https://aidr.example/terms": () => new Response("tampered"),
			"https://aidr.example/privacy": () => new Response(privacy),
		});
		const io = capture();
		assert.equal(await run(argv, { env: ENV, fetch: tampered.fetch, ...io }), 2);
		assert.match(io.err.join("\n"), /terms document .* does not match/);
		assert.equal(tampered.calls.some((call) => call.key === "/functions/v1/operator-admin"), false);
	});
});

describe("signed licence commands", () => {
	// DEV test keys only: generated in memory for every run.
	async function fixture(t, terms = {}) {
		const { generateKeyPairSync } = await import("node:crypto");
		const { mkdtempSync, rmSync, writeFileSync } = await import("node:fs");
		const { tmpdir } = await import("node:os");
		const { join } = await import("node:path");
		const { publicKeyEntry, signLicense } = await import("./license-issue.mjs");
		const key = generateKeyPairSync("ed25519").privateKey;
		const dir = mkdtempSync(join(tmpdir(), "aidr-operator-licence-"));
		t.after(() => rmSync(dir, { recursive: true, force: true }));
		const now = Date.now();
		const iso = (offsetDays) =>
			new Date(Math.floor((now + offsetDays * 86_400_000) / 1000) * 1000).toISOString().replace(".000Z", "Z");
		const license = signLicense(
			{
				license_id: "LIC-2026-0042",
				customer: "Example Customer AG",
				plan_id: "enterprise",
				seats: 250,
				features: [],
				deployment: "airgap",
				issued_at: iso(-10),
				not_before: iso(-10),
				expires_at: iso(300),
				grace_days: 14,
				...terms,
			},
			{ privateKey: key, keyId: "dev-1" },
		);
		const registry = {
			format: "aidr-license-public-keys-v1",
			schema_version: 1,
			keys: [publicKeyEntry(key, { keyId: "dev-1", notBefore: "2024-01-01T00:00:00Z" })],
		};
		writeFileSync(join(dir, "license.json"), JSON.stringify(license, null, 2));
		writeFileSync(join(dir, "keys.json"), JSON.stringify(registry));
		return { license, licenseFile: join(dir, "license.json"), keysFile: join(dir, "keys.json") };
	}

	it("license-apply verifies locally and sends the exact signed document", async (t) => {
		const f = await fixture(t);
		const body = await buildRequestBody("license-apply", [], {
			tenant: TENANT,
			"license-file": f.licenseFile,
			"public-keys": f.keysFile,
			import: OWNER,
		});
		assert.deepEqual(body, { action: "apply_license", tenant_id: TENANT, license: f.license, import_id: OWNER });
	});

	it("license-apply refuses a tampered or expired file before any request", async (t) => {
		const f = await fixture(t);
		const { readFileSync, writeFileSync } = await import("node:fs");
		const tampered = JSON.parse(readFileSync(f.licenseFile, "utf8"));
		tampered.payload.seats = 9999;
		writeFileSync(f.licenseFile, JSON.stringify(tampered));
		await assert.rejects(
			buildRequestBody("license-apply", [], { tenant: TENANT, "license-file": f.licenseFile, "public-keys": f.keysFile }),
			/license verification failed: .*signature/,
		);
		const expired = await fixture(t, {
			issued_at: "2025-01-01T00:00:00Z",
			not_before: "2025-01-01T00:00:00Z",
			expires_at: "2025-06-01T00:00:00Z",
		});
		await assert.rejects(
			buildRequestBody("license-apply", [], {
				tenant: TENANT,
				"license-file": expired.licenseFile,
				"public-keys": expired.keysFile,
			}),
			/is expired/,
		);
		await assert.rejects(buildRequestBody("license-apply", [], { tenant: TENANT }), /--license-file is required/);
		const io = capture();
		const fetch = fakeFetch({});
		const code = await run(
			["license-apply", "--tenant", TENANT, "--license-file", f.licenseFile, "--public-keys", f.keysFile],
			{ env: ENV, fetch: fetch.fetch, stdout: io.stdout, stderr: io.stderr },
		);
		assert.equal(code, 2);
		assert.equal(fetch.calls.length, 0);
	});

	it("license-imports lists staged licences", async () => {
		assert.deepEqual(await buildRequestBody("license-imports", [], {}), { action: "list_license_imports" });
		assert.deepEqual(await buildRequestBody("license-imports", [], { limit: "10" }), {
			action: "list_license_imports",
			limit: 10,
		});
	});
});
