/**
 * Regression tests for the vendored posture scanner supply-chain gate
 * (OPS-4) and the first-party image base pins (OPS-5).
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
	BUILT_DOCKERFILES,
	FRONTEND_DIR,
	assessVendoredFrontendAudit,
	checkDockerfile,
	checkGoToolchain,
	offlineChecks,
} from "./audit-vendored-aig.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (file) => readFileSync(path.join(root, file), "utf8");
const DIGEST = `@sha256:${"a".repeat(64)}`;

test("every Dockerfile AIDR builds is digest-pinned and non-root, and the Go toolchain is supported", () => {
	assert.deepEqual(offlineChecks(), []);
	assert.ok(BUILT_DOCKERFILES.includes("deploy/helm/images/migrations.Dockerfile"));
});

test("the migrations image uses a digest-pinned 17.11 client (server is supabase/postgres 17.11)", () => {
	const from = read("deploy/helm/images/migrations.Dockerfile").match(/^FROM (\S+)$/mu)[1];
	assert.match(from, /^postgres:17\.11-alpine[\d.]+@sha256:[0-9a-f]{64}$/u);
	// The pre-fix tag-only base is rejected.
	assert.deepEqual(checkDockerfile("m.Dockerfile", "FROM postgres:17.6-alpine3.22\nUSER 70:70\n"), [
		"m.Dockerfile:1: base postgres:17.6-alpine3.22 is not pinned by @sha256 digest",
	]);
});

test("Dockerfile check: stage aliases and the declared same-run base pass; root or missing USER fails", () => {
	const multi = `FROM golang:1.27.2-alpine${DIGEST} AS builder\nRUN true\nFROM python:3.12-slim${DIGEST}\nCOPY --from=builder /a /a\nUSER app\n`;
	assert.deepEqual(checkDockerfile("ok", multi), []);
	assert.deepEqual(checkDockerfile("stage", `FROM node${DIGEST} AS base\nFROM base\nUSER node\n`), []);
	assert.deepEqual(checkDockerfile("shim", "ARG BASE\nFROM ${BASE}\nUSER agent\n", "${BASE}"), []);
	assert.match(checkDockerfile("shim", "ARG BASE\nFROM ${BASE}\nUSER agent\n").join(), /not pinned/u);
	assert.deepEqual(checkDockerfile("nouser", `FROM node${DIGEST}\nRUN true\n`), ["nouser: final stage has no USER (would run as root)"]);
	assert.deepEqual(checkDockerfile("root", `FROM node${DIGEST}\nUSER node\nUSER root\n`), ["root: final stage runs as root"]);
	// A USER in an earlier stage does not cover the final stage.
	assert.match(checkDockerfile("early", `FROM a${DIGEST} AS b\nUSER x\nFROM c${DIGEST}\n`).join(), /final stage has no USER/u);
});

test("Go toolchain check rejects the pre-fix Go 1.23.2 and mismatched builder images", () => {
	const old = checkGoToolchain("module x\n\ngo 1.23.2\n", { Dockerfile: `FROM golang:1.23.2-alpine${DIGEST} AS builder\n` });
	assert.ok(old.includes("go.mod has no valid `toolchain goX.Y.Z` line"), old.join("\n"));
	assert.ok(old.includes("Go 1.23.2 is below the supported floor 1.26"), old.join("\n"));

	const mismatch = checkGoToolchain("go 1.26.0\n\ntoolchain go1.27.2\n", { Dockerfile: `FROM golang:1.26.9-alpine${DIGEST} AS builder\n` });
	assert.deepEqual(mismatch, ["Dockerfile: golang:1.26.9 does not match go.mod go1.27.2"]);
	assert.deepEqual(checkGoToolchain("go 1.26.0\ntoolchain go1.27.2\n", { Dockerfile: `FROM golang:1.27.2-alpine${DIGEST} AS builder\n` }), []);

	const goMod = read("vendor/ai-infra-guard/go.mod");
	assert.match(goMod, /^toolchain go1\.(?:2[6-9]|[3-9]\d)\.\d+$/mu);
});

test("frontend audit classification fails closed on any advisory and on malformed reports", () => {
	const clean = { advisories: {}, metadata: { dependencies: 700, vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 } } };
	assert.deepEqual(assessVendoredFrontendAudit(clean, { status: 0 }), []);
	const vulnerable = {
		advisories: { 1: { module_name: "jspdf", severity: "critical", github_advisory_id: "GHSA-f8cm-6447-x5h2", patched_versions: ">=4.0.0", findings: [{ version: "3.0.3" }] } },
		metadata: { dependencies: 700, vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 1 } },
	};
	assert.deepEqual(assessVendoredFrontendAudit(vulnerable, { status: 1 }), ["jspdf 3.0.3: critical GHSA-f8cm-6447-x5h2 (patched >=4.0.0)"]);
	assert.ok(assessVendoredFrontendAudit({}, { status: 0 }).length > 0);
});

test("the vendored frontend lockfile resolves the patched versions of the audited packages", () => {
	const lock = read(`${FRONTEND_DIR}/pnpm-lock.yaml`);
	const resolved = (name) => [...lock.matchAll(new RegExp(`^  ${name.replace(/[.*+?^${}()|[\]\\/]/gu, "\\$&")}@(\\d+)\\.(\\d+)\\.(\\d+)(?:\\(|:)`, "gmu"))].map((m) => m.slice(1, 4).map(Number));
	const atLeast = (version, floor) => version[0] > floor[0] || (version[0] === floor[0] && (version[1] > floor[1] || (version[1] === floor[1] && version[2] >= floor[2])));
	const floors = {
		jspdf: [4, 2, 1],
		"js-cookie": [3, 0, 7],
		"js-yaml": [4, 3, 2],
		"react-router": [7, 18, 0],
		"socket.io-parser": [4, 2, 7],
		ws: [8, 21, 0],
		lodash: [4, 18, 0],
		dompurify: [3, 4, 16],
		uuid: [11, 1, 1],
	};
	for (const [name, floor] of Object.entries(floors)) {
		const versions = resolved(name);
		assert.ok(versions.length > 0, `${name} is not in the lockfile`);
		for (const version of versions) assert.ok(atLeast(version, floor), `${name}@${version.join(".")} is below ${floor.join(".")}`);
	}
	const manifest = JSON.parse(read(`${FRONTEND_DIR}/package.json`));
	assert.equal(manifest.dependencies["tailwindcss-animate"], undefined, "Tailwind build plugins are not runtime dependencies");
});

test("Dependabot watches the vendored posture scanner ecosystems and every built image directory", () => {
	const { parse } = createRequire(path.join(root, "packages/core/package.json"))("yaml");
	const updates = parse(read(".github/dependabot.yml")).updates;
	const covered = new Set(updates.flatMap((entry) => (entry.directories ?? [entry.directory]).map((directory) => `${entry["package-ecosystem"]} ${directory}`)));
	for (const expected of [
		"npm /vendor/ai-infra-guard/frontend",
		"gomod /vendor/ai-infra-guard",
		"uv /vendor/ai-infra-guard/agent-scan",
		"uv /vendor/ai-infra-guard/skill-scan",
		"uv /vendor/ai-infra-guard/AIG-PromptSecurity",
		"pip /vendor/ai-infra-guard/mcp-scan",
		"pip /vendor/ai-infra-guard/services/api_checker",
	]) {
		assert.ok(covered.has(expected), `dependabot.yml is missing ${expected}`);
	}
	for (const dockerfile of BUILT_DOCKERFILES) {
		assert.ok(covered.has(`docker /${path.posix.dirname(dockerfile)}`), `dependabot.yml docker entry is missing /${path.posix.dirname(dockerfile)}`);
	}
});
