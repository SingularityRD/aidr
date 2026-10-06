import { spawnSync } from "node:child_process";
import { lstatSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

const NODE_HELPER_BASE_IMAGE = "node:24.21.0-alpine3.24@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1";

// Build only the reviewed public Dockerfile, never the installation or its env.
// A cached pinned base permits an entirely disconnected build. Use the returned
// image ID so a mutable tag cannot change the helper between archive operations.
export function buildNodeHelperImage({ dockerBin = "docker" } = {}) {
	const dockerfile = new URL("./node-helper.Dockerfile", import.meta.url);
	const info = lstatSync(dockerfile);
	if (!info.isFile() || info.isSymbolicLink()) throw new Error("Node helper Dockerfile must be a regular file");
	const recipe = readFileSync(dockerfile, "utf8");
	if (recipe.split(/\r?\n/, 1)[0] !== `FROM ${NODE_HELPER_BASE_IMAGE}`) throw new Error("Node helper base does not match its reviewed pinned image");
	const temporaryRoot = realpathSync(tmpdir());
	const prefix = join(temporaryRoot, "aidr-node-helper-");
	const context = mkdtempSync(prefix);
	const owned = lstatSync(context);
	try {
		writeFileSync(join(context, "Dockerfile"), recipe, { mode: 0o600, flag: "wx" });
		const run = spawnSync(dockerBin, ["build", "--quiet", "--pull=false", "--network=none", "--file", join(context, "Dockerfile"), context], {
			encoding: "utf8", timeout: 180000, maxBuffer: 1024 * 1024, windowsHide: true,
		});
		if (run.status !== 0) throw new Error("Node helper build failed; load the reviewed pinned base image before backup or recovery");
		const imageId = run.stdout.trim();
		if (!/^sha256:[a-f0-9]{64}$/.test(imageId)) throw new Error("Node helper build returned no immutable image ID");
		return imageId;
	} finally {
		const current = lstatSync(context);
		if (dirname(resolve(context)) !== temporaryRoot || !resolve(context).startsWith(prefix)
			|| !current.isDirectory() || current.isSymbolicLink() || current.dev !== owned.dev || current.ino !== owned.ino) {
			throw new Error("Node helper context changed ownership or escaped its temporary directory");
		}
		rmSync(context, { recursive: true, force: true });
	}
}
