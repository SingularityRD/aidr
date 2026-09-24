import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("the development container meets the repository Node floor and preserves onboarding", () => {
	const packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
	const devcontainer = JSON.parse(readFileSync(join(root, ".devcontainer", "devcontainer.json"), "utf8"));
	const minimumNode = packageJson.engines.node.match(/^>=(\d+)\.(\d+)\.(\d+)$/);
	assert.ok(minimumNode, "package.json must declare an exact minimum Node version");
	const imageNode = devcontainer.image.match(/^mcr\.microsoft\.com\/devcontainers\/typescript-node:(\d+)-bookworm$/);
	assert.ok(imageNode, "devcontainer must use the official Debian bookworm TypeScript/Node image");
	assert.ok(Number(imageNode[1]) >= Number(minimumNode[1]), "devcontainer Node major is below the repository minimum");
	assert.equal(devcontainer.postCreateCommand, "pnpm install && pnpm build");
	assert.equal(devcontainer.remoteUser, "node");
});
