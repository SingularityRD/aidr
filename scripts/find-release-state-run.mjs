#!/usr/bin/env node

import path from "node:path";
import { pathToFileURL } from "node:url";
import { assertTrustedGitHubApiUrl } from "./lib/trusted-github-api-url.mjs";

export async function findReleaseStateRun(options, fetchImpl = fetch) {
	assertTrustedGitHubApiUrl(options.apiUrl, options.serverUrl);
	const url = new URL(`repos/${options.repository}/actions/artifacts`, `${options.apiUrl.replace(/\/$/, "")}/`);
	url.searchParams.set("name", options.artifactName);
	url.searchParams.set("per_page", "100");
	const response = await githubFetch(fetchImpl, url, options.token);
	const payload = await response.json();
	const artifacts = Array.isArray(payload.artifacts) ? payload.artifacts : [];
	artifacts.sort((left, right) => String(right.created_at).localeCompare(String(left.created_at)));
	for (const artifact of artifacts) {
		if (artifact?.expired || artifact?.name !== options.artifactName || !artifact.workflow_run?.id) continue;
		const runUrl = new URL(`repos/${options.repository}/actions/runs/${artifact.workflow_run.id}`, `${options.apiUrl.replace(/\/$/, "")}/`);
		const run = await (await githubFetch(fetchImpl, runUrl, options.token)).json();
		if (
			normalizeWorkflowPath(run.path) === options.workflowPath &&
			run.status === "completed" &&
			run.event === "workflow_dispatch" &&
			run.repository?.full_name === options.repository &&
			run.head_branch === options.defaultBranch
		) {
			// The promotion workflow persists anti-rollback state immediately after
			// signature and semantic verification, before publishing packages or
			// deploying the dashboard. A later publication failure must not discard
			// that already-verified sequence; the artifact's existence proves the
			// persistence step ran, while a failed run with no artifact is skipped.
			return String(run.id);
		}
	}
	return "";
}

async function githubFetch(fetchImpl, url, token) {
	const response = await fetchImpl(url, {
		headers: {
			Accept: "application/vnd.github+json",
			Authorization: `Bearer ${token}`,
			"X-GitHub-Api-Version": "2022-11-28",
		},
	});
	if (!response.ok) throw new Error(`GitHub API returned ${response.status} for ${url.pathname}`);
	return response;
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
	for (const name of ["artifact_name", "repository", "api_url", "workflow_path", "default_branch"]) {
		if (!values[name]) throw new Error(`--${name.replaceAll("_", "-")} is required`);
	}
	if (!process.env.GITHUB_SERVER_URL) throw new Error("GITHUB_SERVER_URL is required to bind the API origin");
	const token = process.env.GITHUB_TOKEN;
	if (!token) throw new Error("GITHUB_TOKEN is required");
	return {
		artifactName: values.artifact_name,
		repository: values.repository,
		apiUrl: values.api_url,
		serverUrl: process.env.GITHUB_SERVER_URL,
		workflowPath: values.workflow_path,
		defaultBranch: values.default_branch,
		token,
	};
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
	try {
		process.stdout.write(await findReleaseStateRun(parseArguments(process.argv.slice(2))));
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode = 1;
	}
}
