import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { verifyEd25519CanonicalJson } from "../managed.js";
import { canonicalPolicyJson } from "../policy-canonical-json.js";
import { governanceOverlaySha256 } from "../policy-signature.js";

interface Vector {
	name: string;
	input_json: string;
	canonical: string;
	sha256: string;
}

/** Shared with supabase/functions/__tests__/policy-signature.test.ts (the signer side). */
const VECTORS = (
	JSON.parse(
		readFileSync(
			join(
				__dirname,
				"..",
				"..",
				"..",
				"..",
				"docs",
				"contracts",
				"policy-canonical-json-vectors.json",
			),
			"utf8",
		),
	) as { vectors: Vector[] }
).vectors;

const sha256 = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");

describe("canonicalPolicyJson cross-implementation vectors", () => {
	it("covers the tricky cases", () => {
		expect(VECTORS.length).toBeGreaterThanOrEqual(10);
	});

	it.each(VECTORS.map((vector) => [vector.name, vector] as const))("%s", (_name, vector) => {
		const canonical = canonicalPolicyJson(JSON.parse(vector.input_json));
		expect(canonical).toBe(vector.canonical);
		expect(sha256(canonical)).toBe(vector.sha256);
	});

	it("is idempotent over its own output", () => {
		for (const vector of VECTORS) {
			expect(canonicalPolicyJson(JSON.parse(vector.canonical))).toBe(vector.canonical);
		}
	});
});

describe("canonicalPolicyJson on values JSON cannot carry", () => {
	it("omits undefined, function and symbol members and writes them as null in arrays", () => {
		expect(
			canonicalPolicyJson({ b: undefined, a: [undefined, () => 1, Symbol("s")], c: () => 1 }),
		).toBe('{"a":[null,null,null]}');
	});

	it("writes non-finite numbers as null and a top-level undefined as null", () => {
		expect(canonicalPolicyJson([Number.NaN, Number.POSITIVE_INFINITY, -0])).toBe("[null,null,0]");
		expect(canonicalPolicyJson(undefined)).toBe("null");
	});

	it("does not depend on insertion order", () => {
		const forward: Record<string, unknown> = {};
		const backward: Record<string, unknown> = {};
		const keys = ["10", "b", "9", "a", "\u{1F600}", "Ａ"];
		for (const key of keys) forward[key] = key;
		for (const key of [...keys].reverse()) backward[key] = key;
		expect(canonicalPolicyJson(forward)).toBe(canonicalPolicyJson(backward));
	});
});

describe("every signing-contract consumer in core uses the shared form", () => {
	it("hashes the governance overlay with integer-like keys exactly as the signer does", () => {
		// The previous hand-rolled serializer emitted "10" before "9" here, so a
		// server digest over the same overlay was rejected as governance_mismatch.
		const governance = { mcp_deny_servers: [], "10": ["x"], "9": ["y"] };
		expect(governanceOverlaySha256({ governance })).toBe(
			sha256('{"9":["y"],"10":["x"],"mcp_deny_servers":[]}'),
		);
	});

	it("verifies an Ed25519 signature over each vector's canonical bytes", () => {
		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
		for (const vector of VECTORS) {
			const sig = sign(null, Buffer.from(vector.canonical, "utf8"), privateKey).toString("base64");
			expect(
				verifyEd25519CanonicalJson({
					value: JSON.parse(vector.input_json),
					sig_b64: sig,
					public_keys_pem: [publicPem],
				}),
				vector.name,
			).toBe(true);
		}
	});
});
