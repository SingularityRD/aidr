// Contract suite for the `url-check` Edge Function.
//
// The response contract matters because `@singularityrd/aidr-core` turns it into
// a detection leg (`packages/core/src/clients/url-check.ts`). A URL that the
// tenant's reputation store holds no row for must be reported as an explicit
// unknown/no-coverage state: before this contract, an absent row produced an
// empty `classification.result`, which the client read as `isMalicious: false`
// and reported to the user as "this URL is clean". The URL path is enabled by
// default (`url_check.enabled`), so that was a false-clean on the default path.
//
// The suite follows the handler-factory pattern used by the other Edge contract
// tests: `npm:` imports are mocked, `globalThis.Deno` is stubbed, and the
// service-role client is injected through `UrlCheckDeps.db` - the runtime
// `createClient` must never be reached.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The Edge Function imports Supabase through Deno's `npm:` specifier, which a
// Node test runner cannot resolve. The factory only exists to prove that the
// handler builds its client from validated configuration; the suite always
// injects `deps.db`.
vi.mock("npm:@supabase/supabase-js@2", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through UrlCheckDeps.db");
	},
}));

// The Edge runtime provides `Deno.env` and `Deno.serve`; the test process does
// not. The env stub delegates to `process.env` so `vi.stubEnv` drives the same
// values the production `runtimeEnv` reader would see. `serve` records the
// handler so the suite can prove the runtime entry point is wired to the
// exported factory.
const serveCalls: unknown[] = [];
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: {
		get: (name: string) => process.env[name],
	},
	serve: (handler: unknown) => {
		serveCalls.push(handler);
	},
};

// Imported once, after the Deno stub exists: the module calls `Deno.serve` while
// it is loaded. `vi.mock` above is hoisted, so `createClient` is already
// replaced and the injected database is the only client the handler can build.
const { createUrlCheckHandler } = await import("../url-check/index.ts");

const FUNCTION_URL = "https://project.supabase.co/functions/v1/url-check";
const TENANT = "22222222-2222-4222-8222-222222222222";
const USER = "11111111-1111-4111-8111-111111111111";
const API_KEY = "aidr_contract_api_key";

/** A URL nothing in the tenant's reputation store mentions. */
const UNLISTED = "https://unlisted.example/payload.sh";
/** A URL with a malicious row. */
const MALICIOUS = "https://malware.example/trojan.sh";
/** A URL with a benign row: the feed HAS data and it says "not malicious". */
const BENIGN = "https://benign.example/index.html";

interface UrlRepRow {
	url: string | null;
	domain: string | null;
	is_malicious: boolean | null;
	severity_name: string | null;
	type_name: string | null;
	flags: string[] | null;
}

function urlRow(overrides: Partial<UrlRepRow> = {}): UrlRepRow {
	return {
		url: null,
		domain: null,
		is_malicious: false,
		severity_name: null,
		type_name: null,
		flags: [],
		...overrides,
	};
}

interface QueryResult {
	data: unknown;
	error: unknown;
}

interface DbOptions {
	/** Rows the `.in("url", ...)` read answers with. */
	urlRows?: UrlRepRow[];
	/** Rows the `.in("domain", ...)` read answers with. */
	domainRows?: UrlRepRow[];
}

function database(options: DbOptions = {}) {
	const fromCalls: string[] = [];
	const rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];

	function resultFor(table: string, column: string): QueryResult {
		if (table === "api_keys") {
			return { data: { user_id: USER, tenant_id: TENANT, revoked: false }, error: null };
		}
		if (table === "tenant_members") return { data: { expires_at: null }, error: null };
		if (table === "tenants") return { data: { status: "active" }, error: null };
		if (table === "url_reputation") {
			return {
				data: column === "url" ? (options.urlRows ?? []) : (options.domainRows ?? []),
				error: null,
			};
		}
		return { data: null, error: null };
	}

	// Minimal PostgREST-shaped query builder: chainable plus awaitable, which is
	// how the handler reads `url_reputation` (`.select().eq().in(...)`).
	function from(table: string) {
		fromCalls.push(table);
		let column = "";
		const query = {
			select: () => query,
			eq: () => query,
			in: (name: string) => {
				column = name;
				return query;
			},
			maybeSingle: async () => resultFor(table, column),
			then: (
				onFulfilled: (value: QueryResult) => unknown,
				onRejected?: (reason: unknown) => unknown,
			) => Promise.resolve(resultFor(table, column)).then(onFulfilled, onRejected),
		};
		return query;
	}

	return {
		db: {
			from: vi.fn(from),
			rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
				rpcCalls.push({ name, args });
				if (name === "consume_tenant_rate_limit") {
					return { data: [{ allowed: true, remaining: 599 }], error: null };
				}
				return { data: null, error: null };
			}),
		},
		fromCalls,
		rpcCalls,
	};
}

describe("url-check Edge handler", () => {
	beforeEach(() => {
		vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "service-role-key");
	});

	afterEach(() => {
		vi.unstubAllEnvs();
	});

	async function handlerWith(options: DbOptions = {}) {
		const { db, fromCalls, rpcCalls } = database(options);
		return {
			handle: createUrlCheckHandler({ db: db as never }),
			fromCalls,
			rpcCalls,
		};
	}

	function post(urls: string[]): Request {
		return new Request(FUNCTION_URL, {
			method: "POST",
			headers: {
				Authorization: `Bearer ${API_KEY}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({
				queries: urls.map((url) => ({ key: { "url-like": url } })),
				"client-info": { "product-name": "aidr", "product-version": "0.0.0" },
			}),
		});
	}

	it("is wired to the runtime entry point through the exported factory", () => {
		expect(serveCalls).toHaveLength(1);
		expect(typeof serveCalls[0]).toBe("function");
	});

	it("marks a URL with no reputation row as unknown/no data instead of clean", async () => {
		const { handle } = await handlerWith({ urlRows: [], domainRows: [] });

		const response = await handle(post([UNLISTED]));

		// A genuine lookup still answers 200; the payload - not the status - is
		// what distinguishes "no data" from "clean".
		expect(response.status).toBe(200);
		const body = (await response.json()) as {
			coverage: string;
			answers: Array<Record<string, unknown>>;
		};

		expect(body.coverage).toBe("none");
		expect(body.answers).toHaveLength(1);

		const answer = body.answers[0] as {
			key: string;
			coverage: string;
			result: { success: { classification: { result: Record<string, unknown> }; flags: string[]; coverage: string } };
		};
		expect(answer.key).toBe(UNLISTED);
		// The machine-readable state, at the answer and inside the classification.
		expect(answer.coverage).toBe("no_data");
		expect(answer.result.success.coverage).toBe("no_data");
		expect(answer.result.success.classification.result).toEqual({
			unknown: { reason: "no_reputation_row" },
		});
		// The false-clean shape: an empty classification would mean "checked and
		// found clean", and must not be what an absent row produces.
		expect(answer.result.success.classification.result).not.toEqual({});
		expect(answer.result.success.classification.result).not.toHaveProperty("malicious");
	});

	it("keeps the existing classification contract for a URL that does have a row", async () => {
		const { handle } = await handlerWith({
			urlRows: [
				urlRow({
					url: MALICIOUS,
					is_malicious: true,
					severity_name: "malware",
					type_name: "trojan",
					flags: ["MALWARE"],
				}),
				urlRow({ url: BENIGN, is_malicious: false, flags: ["TRUSTED"] }),
			],
			domainRows: [],
		});

		const response = await handle(post([MALICIOUS, BENIGN]));
		expect(response.status).toBe(200);
		const body = (await response.json()) as {
			coverage: string;
			answers: Array<{
				key: string;
				coverage: string;
				result: { success: { classification: { result: Record<string, unknown> }; flags: string[] } };
			}>;
		};

		expect(body.coverage).toBe("complete");

		const malicious = body.answers.find((answer) => answer.key === MALICIOUS);
		expect(malicious?.coverage).toBe("covered");
		expect(malicious?.result.success.classification.result).toEqual({
			malicious: { findings: [{ "severity-name": "malware", "type-name": "trojan" }] },
		});
		expect(malicious?.result.success.flags).toEqual(["MALWARE"]);

		// A row that says "not malicious" is a real clean answer: the historical
		// empty classification is preserved, and it is NOT reported as no-data.
		const benign = body.answers.find((answer) => answer.key === BENIGN);
		expect(benign?.coverage).toBe("covered");
		expect(benign?.result.success.classification.result).toEqual({});
		expect(benign?.result.success.flags).toEqual(["TRUSTED"]);
	});

	it("reports partial coverage when only some queried URLs have a row", async () => {
		const { handle } = await handlerWith({
			urlRows: [urlRow({ url: MALICIOUS, is_malicious: true })],
			domainRows: [],
		});

		const response = await handle(post([MALICIOUS, UNLISTED]));
		const body = (await response.json()) as {
			coverage: string;
			answers: Array<{ key: string; coverage: string }>;
		};

		expect(body.coverage).toBe("partial");
		expect(body.answers.find((answer) => answer.key === MALICIOUS)?.coverage).toBe("covered");
		expect(body.answers.find((answer) => answer.key === UNLISTED)?.coverage).toBe("no_data");
	});

	it("scopes both reputation reads to the authenticated tenant", async () => {
		const { handle, fromCalls, rpcCalls } = await handlerWith({ urlRows: [], domainRows: [] });

		await handle(post([UNLISTED]));

		expect(fromCalls).toContain("url_reputation");
		expect(rpcCalls.find((call) => call.name === "consume_tenant_rate_limit")?.args).toMatchObject({
			p_tenant_id: TENANT,
			p_subject: USER,
			p_endpoint: "url-check",
		});
	});
});
