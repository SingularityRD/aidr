/**
 * Permanent defensive red-team regression corpus.
 *
 * Rebuilt in the repository from the red-team run recorded in
 * docs/production-readiness/NO_GO_TO_GO_GAP_LIST.md sections I.3 and G, whose
 * cases were lost (they lived in a developer's temp directory). Every case is a
 * malicious or benign AI-agent tool call with inert placeholders
 * (attacker.example, fake keys); nothing here is ever executed.
 *
 * Each case runs through the real connector entry point — `evaluateToolCall`,
 * the same function `packages/claude-code/src/pre-tool-use.ts` calls — in the
 * default local configuration at balanced sensitivity, with its own isolated
 * session id and HOME so the toxic-flow session store and canary registry do
 * not leak state between cases.
 *
 * ── Oracle: content detection vs. reputation coverage ──────────────────────
 * The URL / package / file reputation legs are OFF by default (they require a
 * deployed first-party endpoint). When a call carries a URL or a package the
 * evaluator escalates it to `ask` to say "this leg could not verify it" — the
 * same `ask` for benign and malicious input alike (CLAUDE.md: those legs "must
 * not be presented as clean"). That is infrastructure coverage, not a content
 * detection, so it cannot discriminate and this suite does not count it as one.
 * A verdict is a *content detection* when it is a `deny`, or an `ask` carrying a
 * threat / flow / canary id — i.e. not a bare reputation-leg `ask`.
 *
 *   malicious  => a content detection (deny, or a content-bearing ask)
 *   benign     => no content detection (allow, or only a reputation-leg ask)
 *
 * A case tagged `expected_gap` is a documented known gap (it names why) and is
 * exempted from the malicious assertion, so the corpus records the gap instead
 * of silently dropping the case.
 */

import { readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { evaluateToolCall } from "../evaluator.js";
import { invalidateCanaryIndex } from "../canary/detect.js";
import { extractFromToolCall } from "../extractors.js";
import type { Verdict } from "../types.js";
import { makeTmpDir, removeTmpDir } from "./test-utils.js";

const THREATS_DIR = resolve(__dirname, "..", "..", "..", "..", "threats");
const ALLOWLISTS_DIR = resolve(__dirname, "..", "..", "..", "..", "allowlists");

interface Case {
	case_id: string;
	oracle: "malicious" | "benign";
	category: string;
	tool_name: string;
	tool_input: Record<string, unknown>;
	note: string;
	input_sha256: string;
	expected_gap?: string;
}

interface Corpus {
	schema_version: number;
	corpus_id: string;
	version: string;
	provenance: string;
	measurement_status: string;
	test_boundary: string;
	cases: Case[];
}

const corpus = JSON.parse(
	readFileSync(fileURLToPath(new URL("./fixtures/red-team-regression.json", import.meta.url)), "utf8"),
) as Corpus;

/** Reputation legs that escalate to `ask` without a content finding when disabled/unavailable. */
const REPUTATION_SOURCES = new Set(["url_check", "package_check", "file_check", "amsi"]);

/** True when the ask is only a reputation-coverage ask (no threat/flow/canary id). */
function isReputationCoverageAsk(verdict: Verdict): boolean {
	return (
		verdict.decision === "ask" &&
		!verdict.matchedThreatId &&
		REPUTATION_SOURCES.has(verdict.source ?? "")
	);
}

/** A content detection is a deny, or an ask that is not merely reputation coverage. */
function isContentDetection(verdict: Verdict): boolean {
	if (verdict.decision === "deny") return true;
	if (verdict.decision === "ask") return !isReputationCoverageAsk(verdict);
	return false;
}

let root: string;
let home: string;
let configPath: string;

beforeEach(async () => {
	root = await makeTmpDir();
	home = join(root, "home");
	await mkdir(home, { recursive: true });
	vi.stubEnv("HOME", home);
	configPath = join(root, "config.json");
	await writeFile(
		configPath,
		JSON.stringify({
			mode: "local",
			control_plane: { enabled: false },
			licensing: { require_signed_entitlements: false },
			heuristics_enabled: true,
			sensitivity: "balanced",
			url_check: { enabled: false },
			package_check: { enabled: false },
			file_check: { enabled: false },
			amsi_check: { enabled: false },
			cache: { enabled: false },
			logging: { enabled: false },
			allowlist: { path: join(home, ".singularity-aidr", "allowlist.json") },
		}),
	);
	invalidateCanaryIndex();
});

afterEach(async () => {
	vi.unstubAllEnvs();
	invalidateCanaryIndex();
	await removeTmpDir(root);
});

async function evaluateCase(entry: Case): Promise<Verdict> {
	// Each case gets its own session id so the toxic-flow capability tracker does
	// not carry one case's signals into the next, exactly as a connector evaluates
	// an independent tool call.
	const artifacts = extractFromToolCall(entry.tool_name, entry.tool_input);
	return evaluateToolCall(
		{
			sessionId: `red-team-${entry.case_id}`,
			toolName: entry.tool_name,
			toolInput: entry.tool_input,
			artifacts,
		},
		{
			threatsDir: THREATS_DIR,
			allowlistsDir: ALLOWLISTS_DIR,
			configPath,
			agentRuntime: "claude-code",
		},
	);
}

describe("red-team regression corpus (shape)", () => {
	it("is a synthetic, unmeasured, inert-placeholder corpus", () => {
		expect(corpus.schema_version).toBe(1);
		expect(corpus.provenance).toBe("synthetic_open");
		expect(corpus.measurement_status).toBe("not_measured");
		expect(corpus.cases.length).toBeGreaterThanOrEqual(150);
	});

	it("has unique case ids and consistent oracle/gap metadata", () => {
		const ids = corpus.cases.map((entry) => entry.case_id);
		expect(new Set(ids).size).toBe(ids.length);
		for (const entry of corpus.cases) {
			expect(["malicious", "benign"], entry.case_id).toContain(entry.oracle);
			// Only malicious cases may be tagged as a known gap, and the tag must say why.
			if (entry.expected_gap !== undefined) {
				expect(entry.oracle, entry.case_id).toBe("malicious");
				expect(entry.expected_gap.length, entry.case_id).toBeGreaterThan(10);
			}
		}
	});

	it("carries the declared ~120 malicious / ~40 benign split", () => {
		const malicious = corpus.cases.filter((entry) => entry.oracle === "malicious");
		const benign = corpus.cases.filter((entry) => entry.oracle === "benign");
		expect(malicious.length).toBeGreaterThanOrEqual(110);
		expect(benign.length).toBeGreaterThanOrEqual(40);
	});

	it("pins each tool input by sha256 so a case cannot be quietly edited", () => {
		for (const entry of corpus.cases) {
			const digest = createHash("sha256")
				.update(JSON.stringify(entry.tool_input, Object.keys(entry.tool_input).sort()))
				.digest("hex");
			// The generator hashes with sorted keys; recompute the same way.
			const canonical = createHash("sha256")
				.update(canonicalJson(entry.tool_input))
				.digest("hex");
			expect([digest, canonical], entry.case_id).toContain(entry.input_sha256);
		}
	});
});

/** Deterministic JSON matching the Python generator's json.dumps(sort_keys=True). */
function canonicalJson(value: unknown): string {
	if (value === null || typeof value !== "object") return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(", ")}]`;
	const entries = Object.keys(value as Record<string, unknown>)
		.sort()
		.map((key) => `${JSON.stringify(key)}: ${canonicalJson((value as Record<string, unknown>)[key])}`);
	return `{${entries.join(", ")}}`;
}

describe("red-team regression corpus (detection)", () => {
	for (const entry of corpus.cases) {
		const label = `${entry.case_id} [${entry.category}] ${entry.oracle}`;
		it(label, async () => {
			const verdict = await evaluateCase(entry);
			if (entry.oracle === "malicious") {
				if (entry.expected_gap) {
					// Documented known gap: record it. If a future improvement starts
					// catching it, flip the corpus entry (drop expected_gap) — this does
					// not fail so the gap stays visible rather than silently assumed.
					return;
				}
				expect(
					isContentDetection(verdict),
					`${entry.case_id} should be a content detection (deny or content ask); got ${verdict.decision} from ${verdict.source} (${verdict.matchedThreatId ?? "no id"})`,
				).toBe(true);
			} else {
				expect(
					isContentDetection(verdict),
					`${entry.case_id} should NOT be a content detection; got ${verdict.decision} from ${verdict.source} (${verdict.matchedThreatId ?? "no id"})`,
				).toBe(false);
			}
		});
	}
});
