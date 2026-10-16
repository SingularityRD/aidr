import { createHash } from "node:crypto";
import {
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, sep } from "node:path";

export function tempDir(prefix: string): string {
	return mkdtempSync(join(tmpdir(), `aidr-desktop-${prefix}-`));
}

function listFiles(root: string, current = root): string[] {
	return readdirSync(current).flatMap((name) => {
		const path = join(current, name);
		return statSync(path).isDirectory()
			? listFiles(root, path)
			: [relative(root, path).split(sep).join("/")];
	});
}

const sha = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");

/**
 * A structurally valid, unsigned standalone bundle (the layout build-sea.mjs
 * writes): bin/aidr(.exe), dist/ files, the runtime manifest and the bundle
 * manifest. The "binary" is not executable; tests that run it inject a runner.
 */
export function fakeBundle(version = "9.9.9"): string {
	const root = tempDir("bundle");
	const binary = process.platform === "win32" ? "bin/aidr.exe" : "bin/aidr";
	const files: Record<string, string> = {
		[binary]: "not really a binary",
		"dist/resources/threats/commands.yaml": "- id: TEST-001\n",
		"dist/resources/allowlists/domains.txt": "example.com\n",
		"dist/response-worker.cjs": "// worker\n",
	};
	for (const [path, content] of Object.entries(files)) {
		mkdirSync(dirname(join(root, path)), { recursive: true });
		writeFileSync(join(root, path), content);
	}
	const dist = join(root, "dist");
	const runtime = {
		schema_version: 1,
		artifact_id: "sea/dist",
		artifact_version: version,
		files: listFiles(dist).map((path) => ({ path, sha256: sha(join(dist, path)) })),
	};
	writeFileSync(join(dist, "aidr-artifact.manifest.json"), `${JSON.stringify(runtime, null, 2)}\n`);
	const bundle = {
		schema_version: 1,
		artifact_id: "claude-code/sea",
		artifact_version: version,
		files: listFiles(root).map((path) => ({ path, sha256: sha(join(root, path)) })),
		sea: { flavor: "development", signed: false },
	};
	writeFileSync(join(root, "aidr-artifact.manifest.json"), `${JSON.stringify(bundle, null, 2)}\n`);
	return root;
}
