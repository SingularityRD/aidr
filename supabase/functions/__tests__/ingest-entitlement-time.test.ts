import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { afterEach, describe, expect, it, vi } from "vitest";

// Deno's npm: imports and Deno.serve prevent importing the Edge entrypoint in
// Vitest. Compile only its real, pure timing declarations and execute them;
// this exercises issuance math without replacing it with a test copy.
const source = readFileSync(
	resolve(dirname(fileURLToPath(import.meta.url)), "../ingest/index.ts"),
	"utf8",
);
const ast = ts.createSourceFile("ingest/index.ts", source, ts.ScriptTarget.ES2022, true);
const timedDeclarations = new Set([
	"ENTITLEMENT_TTL_HOURS_RAW",
	"ENTITLEMENT_GRACE_HOURS_RAW",
	"parseBoundedHours",
	"entitlementTiming",
	"buildEntitlementSnapshot",
]);
const selected = ast.statements.filter((statement) => {
	if (ts.isFunctionDeclaration(statement)) return Boolean(statement.name && timedDeclarations.has(statement.name.text));
	if (!ts.isVariableStatement(statement)) return false;
	return statement.declarationList.declarations.some((declaration) =>
		ts.isIdentifier(declaration.name) && timedDeclarations.has(declaration.name.text));
});
const compiled = ts.transpileModule(
	`${selected.map((statement) => statement.getText(ast)).join("\n")}
export { entitlementTiming, buildEntitlementSnapshot };`,
	{ compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } },
).outputText;

type Timing = { ttlHours: number; graceHours: number } | null;
type Snapshot = {
	issued_at: string;
	expires_at: string;
	grace_until: string;
	pack_keys: Array<{ expires_at: string }>;
};

function issuer(env: Record<string, string>) {
	const exports: Record<string, unknown> = {};
	const evaluate = new Function("exports", "Deno", "crypto", compiled);
	evaluate(
		exports,
		{ env: { get: (name: string) => env[name] ?? null } },
		{ randomUUID },
	);
	return exports as {
		entitlementTiming: () => Timing;
		buildEntitlementSnapshot: (params: {
			tenantId: string;
			includedAgents: number;
			extraAgents: number;
			allowedAgents: number;
			premiumModules: string[];
			tenantPackKey: string | null;
			revocationEpoch: number;
			timing: NonNullable<Timing>;
		}) => Snapshot;
	};
}

afterEach(() => vi.useRealTimers());

describe("ingest signed entitlement timing", () => {
	it("uses one issue time for 7d TTL, then 72h grace and pack-key expiry", () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));
		const functions = issuer({});
		const timing = functions.entitlementTiming();
		expect(timing).toEqual({ ttlHours: 168, graceHours: 72 });
		const snapshot = functions.buildEntitlementSnapshot({
			tenantId: "tenant-1", includedAgents: 1, extraAgents: 1, allowedAgents: 2,
			premiumModules: ["premium_intel"], tenantPackKey: "test-pack-key", revocationEpoch: 1,
			timing: timing!,
		});
		expect(snapshot.issued_at).toBe("2026-01-01T00:00:00.000Z");
		expect(snapshot.expires_at).toBe("2026-01-08T00:00:00.000Z");
		expect(snapshot.grace_until).toBe("2026-01-11T00:00:00.000Z");
		expect(snapshot.pack_keys[0]?.expires_at).toBe(snapshot.grace_until);
	});

	it("accepts zero grace and refuses malformed or out-of-range timing", () => {
		expect(issuer({ AIDR_ENTITLEMENT_TTL_HOURS: "1", AIDR_ENTITLEMENT_GRACE_HOURS: "0" }).entitlementTiming())
			.toEqual({ ttlHours: 1, graceHours: 0 });
		for (const env of [
			{ AIDR_ENTITLEMENT_TTL_HOURS: "0" },
			{ AIDR_ENTITLEMENT_TTL_HOURS: "721" },
			{ AIDR_ENTITLEMENT_GRACE_HOURS: "169" },
			{ AIDR_ENTITLEMENT_GRACE_HOURS: "NaN" },
			{ AIDR_ENTITLEMENT_TTL_HOURS: "1e6" },
		]) expect(issuer(env).entitlementTiming()).toBeNull();
	});

	it("does not expose raw database errors at agent registration", () => {
		expect(source).toContain('error: "agent_registration_unavailable", retryable: true');
		expect(source).not.toContain('detail: String(registrationErr.message');
	});

	it("uses the guarded helper in both success and seat-limit responses", () => {
		expect(source.match(/buildEntitlementSnapshot\(\{/g)).toHaveLength(2);
		expect(source.indexOf("const timing = entitlementTiming();")).toBeLessThan(source.indexOf("const apiKey = getBearerToken(req);"));
	});
});
