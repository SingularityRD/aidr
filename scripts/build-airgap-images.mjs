#!/usr/bin/env node
/**
 * Build or verify an air-gapped container-image bundle for a prepared AIDR stack.
 *
 * Build path (requires a reachable registry and a running Docker daemon):
 *   every image referenced by the plan is pulled, written with `docker save`,
 *   hashed, and recorded in a digest manifest. The manifest is written only
 *   after every image was saved and hashed, so a failed run cannot leave a
 *   manifest claiming a bundle that does not exist.
 *
 * Verify path (`--verify`, no network and no Docker daemon required):
 *   the transferred bundle is re-checked against the manifest and, when a plan
 *   is supplied, against the exact image set the stack needs. A missing
 *   tarball, a size or SHA-256 mismatch, an incomplete image set, or an image
 *   the plan does not name all fail closed.
 *
 * Boundary: this proves local file integrity and plan completeness of the
 * transferred media. It is not registry publication, not a publisher identity,
 * and not attestation: the recorded digests mirror whatever the build host
 * pulled. Publisher signing, registry delivery, notarization and MDM remain
 * external.
 *
 * Usage:
 *   node scripts/build-airgap-images.mjs --output <dir> (--plan <json> | --compose <yml> | --images <ref>...)
 *     [--platform <os/arch>] [--skip-pull] [--docker-bin <path>]
 *   node scripts/build-airgap-images.mjs --verify --output <dir> [--manifest <file>]
 *     [--plan <json> | --compose <yml> | --images <ref>...]
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";

const MANIFEST_NAME = "aidr-airgap-images.manifest.json";
const TARBALL_DIR = "tarballs";
const BUNDLE_KIND = "aidr-airgap-image-bundle";
const IMAGE_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._/:@-]*$/;

const repoRoot = path.resolve(process.cwd());
let options;
let outputDir;
let manifestPath;
let dockerBin;

try {
	options = parseArguments(process.argv.slice(2));
	outputDir = path.resolve(repoRoot, options.output ?? ".aidr-airgap");
	manifestPath = options.manifest ? path.resolve(repoRoot, options.manifest) : path.join(outputDir, MANIFEST_NAME);
	dockerBin = options.dockerBin ?? process.env.AIDR_DOCKER_BIN ?? "docker";
	if (options.verify) await verifyBundle();
	else await buildBundle();
} catch (error) {
	console.error(`ERROR: ${formatError(error)}`);
	process.exit(1);
}

async function buildBundle() {
	const plan = resolvePlannedImages();
	if (existsSync(manifestPath)) {
		throw new Error(`output already contains an image manifest (${manifestPath}); choose a new output directory`);
	}
	assertDockerDaemon();

	await mkdir(outputDir, { recursive: true });
	const stagingDir = path.join(outputDir, `.staging-${process.pid}`);
	const tarballDir = path.join(outputDir, TARBALL_DIR);
	const images = [];
	try {
		await rm(stagingDir, { recursive: true, force: true });
		await mkdir(stagingDir, { recursive: true });
		const usedSlugs = new Set();
		for (const planned of plan.images) {
			const ref = planned.ref;
			if (!options.skipPull) {
				runDocker(["pull", ...(plan.platform ? ["--platform", plan.platform] : []), ref], `unable to pull ${ref}`);
			}
			const inspect = inspectImage(ref);
			if (planned.digest && inspect.imageId !== planned.digest && !inspect.repoDigests.some((digest) => digest.endsWith(planned.digest))) {
				throw new Error(
					`image ${ref} does not match the digest pinned in the plan: expected ${planned.digest}, observed ${inspect.imageId}`,
				);
			}
			const slug = uniqueSlug(ref, usedSlugs);
			const stagedPath = path.join(stagingDir, `${slug}.tar`);
			runDocker(["save", "-o", stagedPath, ref], `unable to save ${ref}`);
			const bytes = await readFile(stagedPath);
			images.push({
				ref,
				tarball: `${TARBALL_DIR}/${slug}.tar`,
				sha256: sha256(bytes),
				size: bytes.byteLength,
				image_id: inspect.imageId,
				repo_digest: inspect.repoDigests.find((digest) => planned.digest && digest.endsWith(planned.digest)) ?? inspect.repoDigests[0] ?? null,
				observed_platform: inspect.platform,
			});
			console.log(`Saved ${ref} -> ${TARBALL_DIR}/${slug}.tar (${bytes.byteLength} bytes)`);
		}

		await rm(tarballDir, { recursive: true, force: true });
		await mkdir(tarballDir, { recursive: true });
		for (const image of images) {
			await rename(path.join(stagingDir, path.basename(image.tarball)), path.join(outputDir, image.tarball));
		}
	} finally {
		await rm(stagingDir, { recursive: true, force: true });
	}

	const manifest = {
		schema_version: 1,
		kind: BUNDLE_KIND,
		image_source: "docker save",
		platform: plan.platform ?? null,
		created_at: buildTimestamp(),
		images: images.sort((a, b) => compareStrings(a.ref, b.ref)),
	};
	const temporaryManifest = `${manifestPath}.tmp`;
	await writeFile(temporaryManifest, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
	await rename(temporaryManifest, manifestPath);

	const verified = await verifyBundle({ quiet: true });
	console.log(
		JSON.stringify({
			status: "built",
			manifest: relativeDisplay(manifestPath),
			images: verified.images,
			platform: manifest.platform,
		}),
	);
}

async function verifyBundle({ quiet = false } = {}) {
	if (!existsSync(manifestPath)) throw new Error(`image manifest is missing: ${manifestPath}`);
	if (!statSync(manifestPath).isFile()) throw new Error(`image manifest must be a regular file: ${manifestPath}`);
	let manifest;
	try {
		manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
	} catch (error) {
		throw new Error(`image manifest is not valid JSON: ${formatError(error)}`);
	}
	if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) throw new Error("image manifest must be a JSON object");
	if (manifest.kind !== BUNDLE_KIND) throw new Error(`unexpected image manifest kind: ${String(manifest.kind)}`);
	const entries = Array.isArray(manifest.images) ? manifest.images : null;
	if (!entries || entries.length === 0) throw new Error("image manifest lists no images");

	const seen = new Map();
	for (const entry of entries) {
		if (!entry || typeof entry !== "object") throw new Error("image manifest entry must be an object");
		assertImageRef(entry.ref);
		if (seen.has(entry.ref)) throw new Error(`image manifest lists ${entry.ref} twice`);
		if (typeof entry.tarball !== "string" || !entry.tarball.startsWith(`${TARBALL_DIR}/`) || entry.tarball.includes("..")) {
			throw new Error(`image manifest tarball path is not a ${TARBALL_DIR}/ path: ${String(entry.tarball)}`);
		}
		const tarballPath = path.resolve(outputDir, entry.tarball);
		const relative = path.relative(outputDir, tarballPath);
		if (relative.startsWith("..") || path.isAbsolute(relative)) throw new Error(`image tarball escapes the bundle: ${entry.tarball}`);
		if (!existsSync(tarballPath)) throw new Error(`image tarball is missing from the bundle: ${entry.tarball}`);
		const info = statSync(tarballPath);
		if (!info.isFile()) throw new Error(`image tarball is not a regular file: ${entry.tarball}`);
		const declaredDigest = assertHexDigest(entry.sha256, `image ${entry.ref}`);
		if (typeof entry.size !== "number" || !Number.isInteger(entry.size) || entry.size < 0) {
			throw new Error(`image ${entry.ref} has no valid recorded size`);
		}
		if (info.size !== entry.size) {
			throw new Error(`image tarball size mismatch for ${entry.ref}: manifest records ${entry.size} but the file is ${info.size} bytes`);
		}
		const actualDigest = sha256(readFileSync(tarballPath));
		if (actualDigest !== declaredDigest) {
			throw new Error(`image tarball digest mismatch for ${entry.ref}: manifest records sha256:${declaredDigest} but the file has sha256:${actualDigest}`);
		}
		seen.set(entry.ref, entry);
	}

	const plan = hasPlanSource() ? resolvePlannedImages() : null;
	if (plan) {
		for (const planned of plan.images) {
			const entry = seen.get(planned.ref);
			if (!entry) throw new Error(`air-gapped bundle is incomplete: ${planned.ref} is required by the plan but not present`);
			if (planned.digest && !(typeof entry.repo_digest === "string" && entry.repo_digest.endsWith(planned.digest)) && entry.image_id !== planned.digest) {
				throw new Error(`image ${planned.ref} does not match the digest pinned in the plan: expected ${planned.digest}`);
			}
		}
		for (const ref of seen.keys()) {
			if (!plan.images.some((planned) => planned.ref === ref)) {
				throw new Error(`image manifest contains ${ref}, which the plan does not name`);
			}
		}
	}

	if (!quiet) {
		console.log(
			JSON.stringify({
				status: "verified",
				manifest: relativeDisplay(manifestPath),
				images: seen.size,
				platform: manifest.platform ?? null,
				plan_checked: Boolean(plan),
			}),
		);
	}
	return { images: seen.size };
}

function resolvePlannedImages() {
	const images = new Map();
	let platform = options.platform;

	if (options.plan) {
		const planPath = path.resolve(repoRoot, options.plan);
		if (!existsSync(planPath)) throw new Error(`image plan is missing: ${planPath}`);
		let plan;
		try {
			plan = JSON.parse(readFileSync(planPath, "utf8"));
		} catch (error) {
			throw new Error(`image plan is not valid JSON: ${formatError(error)}`);
		}
		const entries = Array.isArray(plan) ? plan : Array.isArray(plan?.images) ? plan.images : null;
		if (!entries || entries.length === 0) throw new Error("image plan lists no images");
		if (!Array.isArray(plan) && typeof plan.platform === "string" && !platform) platform = plan.platform;
		for (const entry of entries) {
			if (typeof entry === "string") addPlannedImage(images, { ref: entry });
			else if (entry && typeof entry === "object") addPlannedImage(images, { ref: entry.ref, digest: entry.digest });
			else throw new Error("image plan entry must be a ref string or an object with a ref");
		}
	}

	if (options.compose) {
		const composePath = path.resolve(repoRoot, options.compose);
		if (!existsSync(composePath)) throw new Error(`compose file is missing: ${composePath}`);
		for (const ref of parseComposeImages(readFileSync(composePath, "utf8"))) addPlannedImage(images, { ref });
	}

	for (const ref of options.images) addPlannedImage(images, { ref });

	if (images.size === 0) {
		throw new Error("no images were planned; pass --plan <json>, --compose <yml>, or --images <ref>");
	}
	return { platform: platform ?? null, images: [...images.values()].sort((a, b) => compareStrings(a.ref, b.ref)) };
}

function hasPlanSource() {
	return Boolean(options.plan || options.compose || options.images.length > 0);
}

function addPlannedImage(images, { ref, digest }) {
	assertImageRef(ref);
	const embeddedDigest = ref.includes("@") ? ref.slice(ref.indexOf("@") + 1) : null;
	if (embeddedDigest !== null) assertDigest(embeddedDigest, ref);
	if (digest !== undefined && digest !== null) assertDigest(digest, ref);
	if (embeddedDigest && digest && embeddedDigest !== digest) throw new Error(`image ${ref} has conflicting pinned digests`);
	const plannedDigest = digest ?? embeddedDigest;
	const existingDigest = images.get(ref)?.digest;
	if (existingDigest && plannedDigest && existingDigest !== plannedDigest) throw new Error(`image ${ref} has conflicting pinned digests`);
	images.set(ref, { ref, digest: plannedDigest ?? existingDigest ?? null });
}

function parseComposeImages(content) {
	const refs = [];
	for (const line of String(content).split(/\r?\n/)) {
		const match = line.match(/^\s*image:\s*(?:"([^"]+)"|'([^']+)'|([^\s#]+))\s*(?:#.*)?$/);
		if (!match) continue;
		const ref = match[1] ?? match[2] ?? match[3];
		if (!ref) continue;
		if (ref.includes("${")) {
			throw new Error(`compose image reference is not resolved: ${ref}; prepare the stack before building an air-gap bundle`);
		}
		refs.push(ref);
	}
	if (refs.length === 0) throw new Error("compose file declares no image references");
	return refs;
}

function assertImageRef(ref) {
	if (typeof ref !== "string" || ref === "" || /\s/.test(ref) || ref.startsWith("-")) {
		throw new Error(`invalid image reference: ${String(ref)}`);
	}
	if (!IMAGE_REF_RE.test(ref) || ref.includes("${")) {
		throw new Error(`invalid image reference: ${ref}`);
	}
}

function assertDigest(digest, ref) {
	if (typeof digest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(digest)) {
		throw new Error(`image ${ref} must pin a sha256:<64 hex> digest`);
	}
}

function assertDockerDaemon() {
	const probe = spawnSync(dockerBin, ["version", "--format", "{{.Server.Version}}"], { encoding: "utf8", windowsHide: true });
	if (probe.error || probe.status !== 0) {
		const detail = (probe.error?.message ?? String(probe.stderr ?? "").trim()) || `exit status ${probe.status}`;
		throw new Error(
			`Docker daemon is unavailable (${detail}). The air-gap image bundle was not built and no manifest was written; build it on a connected host with Docker, or run --verify against a pre-built manifest.`,
		);
	}
}

function inspectImage(ref) {
	const result = spawnSync(dockerBin, ["image", "inspect", "--format", "{{json .}}", ref], {
		encoding: "utf8",
		windowsHide: true,
		maxBuffer: 16 * 1024 * 1024,
	});
	if (result.error || result.status !== 0) {
		const detail = (result.error?.message ?? String(result.stderr ?? "").trim()) || `exit status ${result.status}`;
		throw new Error(`unable to inspect ${ref}: ${detail}`);
	}
	let info;
	try {
		info = JSON.parse(String(result.stdout).trim());
	} catch (error) {
		throw new Error(`docker image inspect returned invalid JSON for ${ref}: ${formatError(error)}`);
	}
	const repoDigests = Array.isArray(info?.RepoDigests) ? info.RepoDigests.filter((value) => typeof value === "string") : [];
	const platform = info?.Os && info?.Architecture ? `${info.Os}/${info.Architecture}` : null;
	return { imageId: typeof info?.Id === "string" ? info.Id : null, repoDigests, platform };
}

function runDocker(args, label) {
	const result = spawnSync(dockerBin, args, { encoding: "utf8", windowsHide: true, maxBuffer: 64 * 1024 * 1024 });
	if (result.error || result.status !== 0) {
		const detail = (result.error?.message ?? String(result.stderr ?? "").trim()) || `exit status ${result.status}`;
		throw new Error(`${label}: ${detail}`);
	}
}

function uniqueSlug(ref, used) {
	const base = ref.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[.-]+|[.-]+$/g, "") || "image";
	let slug = base;
	let index = 2;
	while (used.has(slug)) slug = `${base}-${index++}`;
	used.add(slug);
	return slug;
}

function assertHexDigest(value, label) {
	if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
		throw new Error(`${label} must record a lowercase sha256 hex digest`);
	}
	return value;
}

function buildTimestamp() {
	const raw = process.env.SOURCE_DATE_EPOCH;
	if (raw !== undefined && raw !== "") {
		const seconds = Number(raw);
		if (Number.isFinite(seconds) && seconds >= 0) return new Date(seconds * 1000).toISOString();
	}
	return new Date().toISOString();
}

function relativeDisplay(absolutePath) {
	const relative = path.relative(repoRoot, absolutePath);
	if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) return toPosix(absolutePath);
	return toPosix(relative);
}

function toPosix(value) {
	return value.replace(/\\/g, "/");
}

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function compareStrings(a, b) {
	return a < b ? -1 : a > b ? 1 : 0;
}

function parseArguments(argv) {
	const parsed = {
		output: undefined,
		plan: undefined,
		compose: undefined,
		images: [],
		platform: undefined,
		manifest: undefined,
		dockerBin: undefined,
		skipPull: false,
		verify: false,
	};
	for (let index = 0; index < argv.length; index += 1) {
		const flag = argv[index];
		if (flag === "--verify") {
			parsed.verify = true;
			continue;
		}
		if (flag === "--skip-pull") {
			parsed.skipPull = true;
			continue;
		}
		if (!["--output", "--plan", "--compose", "--images", "--platform", "--manifest", "--docker-bin"].includes(flag)) {
			throw new Error(`unknown argument: ${flag ?? ""}`);
		}
		const value = argv[index + 1];
		if (!value || value.startsWith("--")) throw new Error(`missing value for ${flag}`);
		index += 1;
		if (flag === "--output") parsed.output = value;
		else if (flag === "--plan") parsed.plan = value;
		else if (flag === "--compose") parsed.compose = value;
		else if (flag === "--images") parsed.images.push(value);
		else if (flag === "--platform") parsed.platform = value;
		else if (flag === "--manifest") parsed.manifest = value;
		else if (flag === "--docker-bin") parsed.dockerBin = value;
	}
	return parsed;
}

function formatError(error) {
	return error instanceof Error ? error.message : String(error);
}
