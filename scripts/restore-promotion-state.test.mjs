import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { parseRcTag, RC_TAG_PATTERN } from "./lib/rc-tag.mjs";
import {
	enforceRollbackState,
	loadRollbackState,
	loadSignerPolicy,
	RELEASE_MANIFEST_NAME,
	RELEASE_SIGNATURE_NAME,
	signReleaseManifest,
} from "./release-signing-lib.mjs";
import { fetchPublishedReleaseManifests, restorePromotionState } from "./restore-promotion-state.mjs";
import { assertPromotionStatePolicy } from "./verify-release-promotion.mjs";

const PRODUCT = "aidr";
const CHANNEL = "stable";

function signer(keyId) {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const fingerprint = `sha256:${createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex")}`;
	return { keyId, privateKey, publicKey, fingerprint };
}

function workspace(t, trusted) {
	const dir = mkdtempSync(path.join(tmpdir(), "aidr-promotion-state-"));
	t.after(() => rmSync(dir, { recursive: true, force: true }));
	const bundle = path.join(dir, "release-output");
	mkdirSync(bundle);
	const policy = path.join(dir, "policy.json");
	writeFileSync(
		policy,
		JSON.stringify({
			schema_version: 1,
			policy_id: "test-policy",
			product_id: PRODUCT,
			allowed_channels: [CHANNEL],
			minimum_release_sequence: 1,
			maximum_signature_lifetime_seconds: 86400 * 30,
			trusted_signers: trusted.map((key) => ({
				key_id: key.keyId,
				public_key_pem: key.publicKey.export({ type: "spki", format: "pem" }).toString(),
				fingerprint_sha256: key.fingerprint,
				valid_from: "2026-01-01T00:00:00.000Z",
				valid_until: "2027-12-31T00:00:00.000Z",
			})),
			revoked_key_ids: [],
			revoked_fingerprints: [],
		}),
	);
	return { dir, bundle, policy, state: path.join(dir, "state", "anti-rollback-state.json") };
}

/** A published release as the promotion workflow attaches it: signed manifest + signature. */
function release(key, { sequence, version, tag = `v${version}-rc.0` }) {
	const manifest = {
		schema_version: 1,
		type: "aidr-release",
		product_id: PRODUCT,
		channel: CHANNEL,
		release_sequence: sequence,
		release_tag: tag,
		release_version: version,
		git_sha: "a".repeat(40),
		// Long expired on purpose: an old signed release still sets the floor.
		issued_at: "2026-01-02T00:00:00.000Z",
		expires_at: "2026-01-09T00:00:00.000Z",
		signer: { key_id: key.keyId, fingerprint_sha256: key.fingerprint },
		bindings: {},
		artifacts: [],
	};
	const manifestRaw = Buffer.from(`${JSON.stringify(manifest)}\n`);
	const signatureRaw = Buffer.from(JSON.stringify(signReleaseManifest(manifestRaw, key.privateKey, key.keyId)));
	return { tag, manifestRaw, signatureRaw, digest: createHash("sha256").update(manifestRaw).digest("hex") };
}

const quiet = { warn: () => {}, now: new Date("2026-10-13T00:00:00Z") };

test("a lost promotion artifact no longer resets the floor: it is rebuilt from signed releases (OPS-8)", async (t) => {
	const key = signer("release-2026");
	const w = workspace(t, [key]);
	const older = release(key, { sequence: 2, version: "0.9.0" });
	const latest = release(key, { sequence: 3, version: "1.0.0", tag: "v1.0.0-rc.2" });
	const summary = await restorePromotionState({ ...w, expectedTag: "v1.1.0-rc.0" }, [older, latest], quiet);
	assert.deepEqual({ ...summary, rejected: summary.rejected.length }, { had_state: false, verified_releases: 2, rejected: 0, records: 1, written: true });
	const state = JSON.parse(readFileSync(w.state, "utf8"));
	assert.deepEqual(state.records[`${PRODUCT}/${CHANNEL}`], {
		highest_release_sequence: 3,
		manifest_sha256: latest.digest,
		release_version: "1.0.0",
		recorded_at: "2026-10-13T00:00:00.000Z",
	});
	// The rollback attack the floor exists for: re-promoting the older signed RC.
	const loaded = await loadRollbackState(w.state, w.bundle, { requireExisting: true });
	assert.throws(() => enforceRollbackState(loaded, { product_id: PRODUCT, channel: CHANNEL, release_sequence: 2 }, older.digest), /release rollback rejected: sequence 2 is below installed sequence 3/u);
});

test("forged, tampered and untrusted manifests are ignored and never raise or set the floor", async (t) => {
	const key = signer("release-2026");
	const stranger = signer("release-2026");
	const w = workspace(t, [key]);
	const forged = release(stranger, { sequence: 9, version: "9.0.0" });
	const genuine = release(key, { sequence: 4, version: "1.2.0" });
	const tampered = { ...genuine, tag: "v1.3.0-rc.0", manifestRaw: Buffer.from(genuine.manifestRaw.toString().replace('"release_sequence":4', '"release_sequence":8')) };
	const garbage = { tag: "v0.0.1-rc.0", manifestRaw: Buffer.from("not json"), signatureRaw: Buffer.from("{}") };
	const summary = await restorePromotionState({ ...w, expectedTag: "v2.0.0-rc.0" }, [forged, tampered, garbage, genuine], quiet);
	assert.equal(summary.verified_releases, 1);
	assert.deepEqual(summary.rejected.map((entry) => entry.tag).sort(), ["v0.0.1-rc.0", "v1.3.0-rc.0", "v9.0.0-rc.0"]);
	assert.equal(JSON.parse(readFileSync(w.state, "utf8")).records[`${PRODUCT}/${CHANNEL}`].highest_release_sequence, 4);
});

test("the restored artifact state and the signed releases merge to the higher floor; equivocation fails", async (t) => {
	const key = signer("release-2026");
	const w = workspace(t, [key]);
	mkdirSync(path.dirname(w.state), { recursive: true });
	const artifactRecord = { highest_release_sequence: 5, manifest_sha256: "b".repeat(64), release_version: "1.4.0", recorded_at: "2026-10-01T00:00:00.000Z" };
	writeFileSync(w.state, JSON.stringify({ schema_version: 1, records: { [`${PRODUCT}/${CHANNEL}`]: artifactRecord } }));
	await restorePromotionState({ ...w, expectedTag: "v1.5.0-rc.0" }, [release(key, { sequence: 3, version: "1.0.0" })], quiet);
	assert.deepEqual(JSON.parse(readFileSync(w.state, "utf8")).records[`${PRODUCT}/${CHANNEL}`], artifactRecord, "a lower signed release never lowers the floor");
	await assert.rejects(restorePromotionState({ ...w, expectedTag: "v1.5.0-rc.0" }, [release(key, { sequence: 5, version: "1.4.0" })], quiet), /release equivocation: sequence 5/u);
});

test("with no prior state and no signed release nothing is written, so the recording promotion fails closed", async (t) => {
	const key = signer("release-2026");
	const w = workspace(t, [key]);
	const summary = await restorePromotionState({ ...w, expectedTag: "v1.0.0-rc.0" }, [], quiet);
	assert.equal(summary.written, false);
	assert.equal(existsSync(w.state), false);
	await assert.rejects(loadRollbackState(w.state, w.bundle, { requireExisting: true }), /anti-rollback state is missing/u);
	assert.equal((await loadRollbackState(w.state, w.bundle)).value.records.constructor, Object, "endpoint first installs keep the empty default");
});

test("promotion state policy: --record needs a state unless genesis; genesis never overwrites a state", () => {
	assert.throws(() => assertPromotionStatePolicy({ record: true }, false), /anti-rollback state is missing; refusing to treat this promotion as a first release/u);
	assert.equal(assertPromotionStatePolicy({ record: true }, true), true, "an existing state is required to keep existing on the --record call");
	assert.equal(assertPromotionStatePolicy({ record: true, genesis: true }, false), false);
	assert.throws(() => assertPromotionStatePolicy({ record: true, genesis: true }, true), /--genesis refused: an anti-rollback state already exists/u);
	assert.throws(() => assertPromotionStatePolicy({ genesis: true }, false), /--genesis only applies to a recording promotion/u);
	// Dry-run and rollback verification never record, so they keep an empty scratch state.
	assert.equal(assertPromotionStatePolicy({}, false), false);
});

test("one RC per version: a version already promoted from another RC tag cannot be promoted again (OPS-11)", async (t) => {
	const key = signer("release-2026");
	const w = workspace(t, [key]);
	const promoted = release(key, { sequence: 6, version: "1.0.0", tag: "v1.0.0-rc.1" });
	await assert.rejects(restorePromotionState({ ...w, expectedTag: "v1.0.0-rc.2" }, [promoted], quiet), /version 1\.0\.0 was already promoted from v1\.0\.0-rc\.1/u);
	// Re-running the same promotion (e.g. after a later step failed) is allowed.
	const again = await restorePromotionState({ ...w, expectedTag: "v1.0.0-rc.1" }, [promoted], quiet);
	assert.equal(again.verified_releases, 1);
});

test("rc tag grammar accepts rc.N without leading zeros only", () => {
	for (const tag of ["v1.0.0-rc.0", "v1.0.0-rc.1", "v12.3.40-rc.27"]) assert.ok(RC_TAG_PATTERN.test(tag), tag);
	for (const tag of ["v1.0.0-rc.01", "v1.0.0-rc.", "v1.0.0", "1.0.0-rc.1", "v1.0-rc.1", "v1.0.0-rc.1x", "v1.0.0-rc.10000"]) assert.ok(!RC_TAG_PATTERN.test(tag), tag);
	assert.deepEqual(parseRcTag("v2.3.4-rc.5"), { version: "2.3.4", rc: 5 });
});

test("fetchPublishedReleaseManifests reads only published releases, from the trusted API origin", async (t) => {
	const key = signer("release-2026");
	const w = workspace(t, [key]);
	const published = release(key, { sequence: 7, version: "1.6.0" });
	const asset = (name, id) => ({ name, url: `https://api.github.com/repos/o/r/releases/assets/${id}` });
	const bodies = { 1: published.manifestRaw, 2: published.signatureRaw };
	const listing = [
		{ tag_name: "v1.6.0-rc.0", draft: false, prerelease: false, assets: [asset(RELEASE_MANIFEST_NAME, 1), asset(RELEASE_SIGNATURE_NAME, 2)] },
		{ tag_name: "v1.7.0-rc.0", draft: true, prerelease: true, assets: [asset(RELEASE_MANIFEST_NAME, 3), asset(RELEASE_SIGNATURE_NAME, 4)] },
		{ tag_name: "v0.1.0", draft: false, prerelease: false, assets: [] },
	];
	const requests = [];
	const fakeFetch = async (url, init) => {
		requests.push({ url: String(url), accept: init.headers.Accept });
		const id = /assets\/(\d+)$/u.exec(url.pathname)?.[1];
		if (id) return new Response(bodies[id]);
		return new Response(JSON.stringify(listing));
	};
	const options = { repository: "o/r", apiUrl: "https://api.github.com", serverUrl: "https://github.com", token: "test-token" };
	const releases = await fetchPublishedReleaseManifests(options, fakeFetch);
	assert.deepEqual(releases.map((entry) => entry.tag), ["v1.6.0-rc.0"]);
	assert.ok(requests.filter((entry) => /assets/u.test(entry.url)).every((entry) => entry.accept === "application/octet-stream"));
	assert.ok(!requests.some((entry) => /assets\/[34]$/u.test(entry.url)), "draft RC evidence is never read");
	const summary = await restorePromotionState({ ...w, policy: w.policy, expectedTag: "v1.8.0-rc.0" }, releases, quiet);
	assert.equal(summary.records, 1);

	listing[0].assets[0].url = "https://evil.example/asset";
	await assert.rejects(fetchPublishedReleaseManifests(options, fakeFetch), /not on the trusted API origin/u);
	await assert.rejects(fetchPublishedReleaseManifests({ ...options, apiUrl: "https://evil.example" }, fakeFetch), /GitHub API origin does not match/u);
	await assert.doesNotReject(loadSignerPolicy(w.policy, w.bundle));
});
