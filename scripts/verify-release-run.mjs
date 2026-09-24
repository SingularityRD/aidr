#!/usr/bin/env node

import path from "node:path";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { assertTrustedGitHubApiUrl } from "./lib/trusted-github-api-url.mjs";

export function assertReleaseRun(run, expected) {
	if (!run || typeof run !== "object") throw new Error("GitHub workflow run response is invalid");
	if (run.status !== "completed" || run.conclusion !== "success") {
		throw new Error(`RC workflow run must be completed successfully; got ${run.status}/${run.conclusion}`);
	}
	if (normalizeWorkflowPath(run.path) !== expected.workflowPath) {
		throw new Error(`RC workflow mismatch: ${String(run.path)} != ${expected.workflowPath}`);
	}
	if (run.repository?.full_name !== expected.repository) {
		throw new Error(`RC workflow repository mismatch: ${String(run.repository?.full_name)} != ${expected.repository}`);
	}
	if (!new Set(["push", "workflow_dispatch"]).has(run.event)) throw new Error(`RC workflow event is not allowed: ${String(run.event)}`);
	if (run.event === "push") {
		if (String(run.head_sha).toLowerCase() !== expected.sha.toLowerCase()) throw new Error("RC push workflow commit mismatch");
		if (run.head_branch !== expected.tag) throw new Error("RC push workflow tag mismatch");
	}
}

export function assertRunAttestation(provenance, metadata, expected) {
	const parameters = provenance?.predicate?.invocation?.parameters;
	if (String(parameters?.ci_run_id) !== expected.runId) throw new Error("signed release provenance does not bind the RC workflow run ID");
	if (String(parameters?.git_sha).toLowerCase() !== expected.sha.toLowerCase()) {
		throw new Error("signed release evidence does not bind the RC commit");
	}
	if (metadata?.release_tag !== expected.tag || String(metadata?.git_sha).toLowerCase() !== expected.sha.toLowerCase()) {
		throw new Error("signed release metadata does not bind the requested tag and commit");
	}
}

export async function verifyReleaseRun(options, fetchImpl = fetch) {
	assertTrustedGitHubApiUrl(options.apiUrl, options.serverUrl);
	const url = new URL(`repos/${options.repository}/actions/runs/${options.runId}`, `${options.apiUrl.replace(/\/$/, "")}/`);
	const response = await fetchImpl(url, {
		headers: {
			Accept: "application/vnd.github+json",
			Authorization: `Bearer ${options.token}`,
			"X-GitHub-Api-Version": "2022-11-28",
		},
	});
	if (!response.ok) throw new Error(`cannot read RC workflow run ${options.runId}: GitHub API returned ${response.status}`);
	const run = await response.json();
	assertReleaseRun(run, options);
	const evidence = JSON.parse(await readFile(path.join(options.bundle, "aidr-provenance.intoto.json"), "utf8"));
	const metadata = JSON.parse(await readFile(path.join(options.bundle, "release-metadata.json"), "utf8"));
	assertRunAttestation(evidence, metadata, options);
}

function normalizeWorkflowPath(value) {
	return String(value ?? "").split("@")[0];
}

function parseArguments(argv) {
	const values = {};
	for (let index = 0; index < argv.length; index += 2) {
		const flag = argv[index];
		const value = argv[index + 1];
		if (!flag?.startsWith("--") || !value) throw new Error(`unknown or incomplete option: ${String(flag)}`);
		values[flag.slice(2).replaceAll("-", "_")] = value;
	}
	for (const name of ["bundle", "run_id", "expected_tag", "expected_sha", "repository", "api_url", "workflow_path"]) {
		if (!values[name]) throw new Error(`--${name.replaceAll("_", "-")} is required`);
	}
	if (!process.env.GITHUB_SERVER_URL) throw new Error("GITHUB_SERVER_URL is required to bind the API origin");
	const token = process.env.GITHUB_TOKEN;
	if (!token) throw new Error("GITHUB_TOKEN is required");
	if (!/^\d+$/.test(values.run_id)) throw new Error("--run-id is invalid");
	if (!/^[0-9a-f]{40,64}$/i.test(values.expected_sha)) throw new Error("--expected-sha is invalid");
	return {
		bundle: path.resolve(values.bundle),
		runId: values.run_id,
		tag: values.expected_tag,
		sha: values.expected_sha,
		repository: values.repository,
		apiUrl: values.api_url,
		serverUrl: process.env.GITHUB_SERVER_URL,
		workflowPath: values.workflow_path,
		token,
	};
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
	try {
		await verifyReleaseRun(parseArguments(process.argv.slice(2)));
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode = 1;
	}
}
