import { createHash } from "node:crypto";
import { lstat, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";

const CONTROL_FILES = new Set([
	"release-metadata.json",
	"release-inventory.json",
	"aidr-release.manifest.json",
	"aidr-release.manifest.sig",
	"aidr-artifact.manifest.json",
	"aidr-artifact.manifest.sig",
]);

/** Finalize the exact artifact set after every package, archive and VSIX exists. */
export async function finalizeReleaseBundle(outputDir) {
	const metadataPath = path.join(outputDir, "release-metadata.json");
	const inventoryPath = path.join(outputDir, "release-inventory.json");
	const metadata = JSON.parse(await readFile(metadataPath, "utf8"));
	const files = await listRegularFiles(outputDir);
	const artifacts = [];
	for (const relative of files) {
		const basename = path.posix.basename(relative);
		if (CONTROL_FILES.has(basename)) {
			if (relative !== basename) throw new Error(`release artifact path collides with a control file: ${relative}`);
			continue;
		}
		const bytes = await readFile(path.join(outputDir, ...relative.split("/")));
		artifacts.push({
			path: relative,
			size: bytes.byteLength,
			sha256: createHash("sha256").update(bytes).digest("hex"),
		});
	}
	artifacts.sort((left, right) => compareStrings(left.path, right.path));
	if (artifacts.length === 0) throw new Error("release bundle contains no artifacts");
	await writeFile(metadataPath, `${JSON.stringify({ ...metadata, artifacts }, null, 2)}\n`, "utf8");
	await writeFile(
		inventoryPath,
		`${JSON.stringify(
			{
				schema_version: 1,
				artifacts: artifacts.map((entry) => ({
					source_path: `release-output/${entry.path}`,
					staged_path: entry.path,
					kind: "release-artifact",
					sha256: entry.sha256,
				})),
			},
			null,
			2,
		)}\n`,
		"utf8",
	);
	return artifacts;
}

async function listRegularFiles(root) {
	const files = [];
	const stack = [{ absolute: root, relative: "" }];
	while (stack.length > 0) {
		const current = stack.pop();
		for (const entry of await readdir(current.absolute, { withFileTypes: true })) {
			const absolute = path.join(current.absolute, entry.name);
			const relative = current.relative ? `${current.relative}/${entry.name}` : entry.name;
			const info = await lstat(absolute);
			if (info.isSymbolicLink()) throw new Error(`release bundle contains a symlink: ${relative}`);
			if (info.isDirectory()) stack.push({ absolute, relative });
			else if (info.isFile()) files.push(relative);
			else throw new Error(`release bundle contains an unsupported entry: ${relative}`);
		}
	}
	return files.sort(compareStrings);
}

function compareStrings(left, right) {
	return left < right ? -1 : left > right ? 1 : 0;
}
