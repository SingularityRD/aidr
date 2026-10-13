#!/usr/bin/env node
/**
 * Rebuild the production anti-rollback floor from the signed release manifests
 * attached to every published GitHub release, and merge it into the state
 * restored from the promotion workflow's artifact.
 *
 * Why: the promotion state used to live only in an Actions artifact, which
 * expires (365 days) and can be deleted by anyone with actions:write. A missing
 * artifact was then read as "first release", so an older signed RC could be
 * promoted again (OPS-8). Every promotion also publishes its signed bundle,
 * including aidr-release.manifest.json and its Ed25519 signature, as a
 * non-draft GitHub release; those signatures are verified here against the
 * trusted signer policy, so the floor survives the artifact. Anything that
 * does not verify is ignored (it can only lower the floor, never raise it).
 *
 * The state file is written only when there is something to record. With no
 * prior state and no signed release, nothing is written and the promotion's
 * --record step fails closed unless the operator supplied the explicit genesis
 * approval.
 *
 * It also refuses a second promotion of an already promoted version from a
 * different RC tag: RCs share the stable package version, so only one RC per
 * version may ever be promoted (OPS-11).
 *
 * Usage (promotion workflow, trusted verifier checkout):
 *   GITHUB_TOKEN=... GITHUB_SERVER_URL=... node scripts/restore-promotion-state.mjs \
 *     --repository <owner/repo> --api-url <url> --policy <json> --state <json> \
 *     --bundle <release-output> --expected-tag vX.Y.Z-rc.N
 */

import { existsSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { parseRcTag } from "./lib/rc-tag.mjs";
import { assertTrustedGitHubApiUrl } from "./lib/trusted-github-api-url.mjs";
import {
	atomicJsonWrite,
	loadRollbackState,
	loadSignerPolicy,
	raiseRollbackFloor,
	RELEASE_MANIFEST_NAME,
	RELEASE_SIGNATURE_NAME,
	verifySignedRollbackEvidence,
} from "./release-signing-lib.mjs";

const MAX_PAGES = 50;

/**
 * Signed manifests of every published (non-draft, non-prerelease) release.
 * @returns {Promise<Array<{tag: string, manifestRaw: Buffer, signatureRaw: Buffer}>>}
 */
export async function fetchPublishedReleaseManifests(options, fetchImpl = fetch) {
	assertTrustedGitHubApiUrl(options.apiUrl, options.serverUrl);
	const base = `${options.apiUrl.replace(/\/$/, "")}/`;
	const releases = [];
	for (let page = 1; page <= MAX_PAGES; page += 1) {
		const url = new URL(`repos/${options.repository}/releases`, base);
		url.searchParams.set("per_page", "100");
		url.searchParams.set("page", String(page));
		const batch = await (await githubFetch(fetchImpl, url, options.token, "application/vnd.github+json")).json();
		if (!Array.isArray(batch)) throw new Error("GitHub releases listing is not an array");
		releases.push(...batch);
		if (batch.length < 100) break;
		if (page === MAX_PAGES) throw new Error(`more than ${MAX_PAGES * 100} releases; refusing a partial rollback floor`);
	}
	const signed = [];
	for (const release of releases) {
		if (release?.draft !== false || release?.prerelease !== false) continue;
		const assets = Array.isArray(release.assets) ? release.assets : [];
		const manifest = assets.find((asset) => asset?.name === RELEASE_MANIFEST_NAME);
		const signature = assets.find((asset) => asset?.name === RELEASE_SIGNATURE_NAME);
		if (!manifest || !signature) continue;
		const download = async (asset) => {
			const assetUrl = new URL(String(asset.url));
			if (assetUrl.origin !== new URL(base).origin) throw new Error(`release asset URL is not on the trusted API origin: ${assetUrl.origin}`);
			return Buffer.from(await (await githubFetch(fetchImpl, assetUrl, options.token, "application/octet-stream")).arrayBuffer());
		};
		signed.push({ tag: String(release.tag_name ?? ""), manifestRaw: await download(manifest), signatureRaw: await download(signature) });
	}
	return signed;
}

/**
 * Merge verified release evidence into the state file.
 * @param {{policy: string, state: string, bundle: string, expectedTag: string}} options
 * @param {Array<{tag: string, manifestRaw: Buffer, signatureRaw: Buffer}>} releases
 */
export async function restorePromotionState(options, releases, { now = new Date(), warn = (line) => console.error(line) } = {}) {
	const { version: expectedVersion } = parseRcTag(options.expectedTag);
	const bundle = path.resolve(options.bundle);
	const policy = await loadSignerPolicy(options.policy, bundle);
	const hadState = existsSync(path.resolve(options.state));
	const state = await loadRollbackState(options.state, bundle);
	const evidence = [];
	const rejected = [];
	for (const release of releases) {
		let item;
		try {
			const signatureEnvelope = JSON.parse(Buffer.from(release.signatureRaw).toString("utf8"));
			item = verifySignedRollbackEvidence(release.manifestRaw, signatureEnvelope, policy);
		} catch (error) {
			const reason = error instanceof Error ? error.message : String(error);
			rejected.push({ tag: release.tag, reason });
			warn(`WARN: ignoring release ${release.tag}: ${reason}`);
			continue;
		}
		if (item.release_version === expectedVersion && item.release_tag !== options.expectedTag) {
			throw new Error(`version ${expectedVersion} was already promoted from ${item.release_tag}; RCs share the stable package version, so ${options.expectedTag} cannot be promoted. Bump the version.`);
		}
		evidence.push(item);
	}
	raiseRollbackFloor(state, evidence, now);
	const records = Object.keys(state.value.records).length;
	const written = hadState || records > 0;
	if (written) await atomicJsonWrite(state.path, state.value, 0o600);
	return { had_state: hadState, verified_releases: evidence.length, rejected, records, written };
}

async function githubFetch(fetchImpl, url, token, accept) {
	const response = await fetchImpl(url, {
		headers: { Accept: accept, Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28" },
	});
	if (!response.ok) throw new Error(`GitHub API returned ${response.status} for ${url.pathname}`);
	return response;
}

function parseArguments(argv) {
	const values = {};
	for (let index = 0; index < argv.length; index += 2) {
		const flag = argv[index];
		const value = argv[index + 1];
		if (!flag?.startsWith("--") || !value) throw new Error(`unknown or incomplete option: ${String(flag)}`);
		values[flag.slice(2).replaceAll("-", "_")] = value;
	}
	for (const name of ["repository", "api_url", "policy", "state", "bundle", "expected_tag"]) {
		if (!values[name]) throw new Error(`--${name.replaceAll("_", "-")} is required`);
	}
	if (!process.env.GITHUB_SERVER_URL) throw new Error("GITHUB_SERVER_URL is required to bind the API origin");
	if (!process.env.GITHUB_TOKEN) throw new Error("GITHUB_TOKEN is required");
	return {
		repository: values.repository,
		apiUrl: values.api_url,
		serverUrl: process.env.GITHUB_SERVER_URL,
		token: process.env.GITHUB_TOKEN,
		policy: values.policy,
		state: values.state,
		bundle: values.bundle,
		expectedTag: values.expected_tag,
	};
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
	try {
		const options = parseArguments(process.argv.slice(2));
		const releases = await fetchPublishedReleaseManifests(options);
		console.log(JSON.stringify(await restorePromotionState(options, releases)));
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode = 1;
	}
}
