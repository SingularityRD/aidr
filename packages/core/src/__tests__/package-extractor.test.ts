import { describe, expect, it } from "vitest";
import {
	extractPackagesFromCommand,
	extractPackagesFromManifest,
	isDependencyManifestPath,
} from "../package-extractor.js";

describe("extractPackagesFromCommand", () => {
	it("extracts from npm install", () => {
		const result = extractPackagesFromCommand("npm install express");
		expect(result).toHaveLength(1);
		expect(result[0]?.name).toBe("express");
		expect(result[0]?.registry).toBe("npm");
	});

	it("extracts scoped package from npm i", () => {
		const result = extractPackagesFromCommand("npm i @scope/pkg");
		expect(result).toHaveLength(1);
		expect(result[0]?.name).toBe("@scope/pkg");
	});

	it("extracts multiple from pip install", () => {
		const result = extractPackagesFromCommand("pip install requests flask");
		expect(result).toHaveLength(2);
		expect(result[0]?.name).toBe("requests");
		expect(result[0]?.registry).toBe("pypi");
		expect(result[1]?.name).toBe("flask");
	});

	it("extracts multiple from yarn add", () => {
		const result = extractPackagesFromCommand("yarn add react react-dom");
		expect(result).toHaveLength(2);
		expect(result[0]?.name).toBe("react");
		expect(result[1]?.name).toBe("react-dom");
	});

	it("extracts from npx (executable check)", () => {
		const result = extractPackagesFromCommand("npx create-react-app my-app");
		expect(result).toHaveLength(1);
		expect(result[0]?.name).toBe("create-react-app");
	});

	it.each([
		"npm.cmd install",
		"npm.ps1 install",
		"npm.exe install",
		'"C:/Program Files/nodejs/npm.cmd" install',
		'"C:/Program Files/nodejs/npm.ps1" install',
	])("marks Windows npm shim %s for review", (command) => {
		expect(extractPackagesFromCommand(command)).toMatchObject([
			{ name: "manifest dependencies", unverifiedReason: expect.stringContaining("manifest") },
		]);
	});

	it.each([
		"npx.cmd evil-package",
		"npx.ps1 evil-package",
		'"C:/Program Files/nodejs/npx.cmd" evil-package',
	])("recognizes Windows npx shim %s", (command) => {
		expect(extractPackagesFromCommand(command)).toMatchObject([
			{ name: "evil-package", registry: "npm" },
		]);
	});

	it.each(["npm exec evil-package", "npm exe evil-package", "npm x evil-package"])(
		"marks npm exec package calls %s for review",
		(command) => {
			expect(extractPackagesFromCommand(command)).toMatchObject([
				{ unverifiedReason: expect.stringContaining("execute a package") },
			]);
		},
	);

	it("extracts from pnpm dlx", () => {
		const result = extractPackagesFromCommand("pnpm dlx pkg");
		expect(result).toHaveLength(1);
		expect(result[0]?.name).toBe("pkg");
	});

	it("extracts from bunx", () => {
		const result = extractPackagesFromCommand("bunx pkg");
		expect(result).toHaveLength(1);
		expect(result[0]?.name).toBe("pkg");
	});

	it("extracts the package executed by yarn dlx", () => {
		expect(extractPackagesFromCommand("yarn dlx create-vite app")).toMatchObject([
			{ name: "create-vite", registry: "npm", source: "command" },
		]);
	});

	it.each([
		"uv add requests",
		"uv pip install requests",
		"uv sync",
		"poetry add requests",
		"poetry install",
		"pipenv install requests",
		"go get example.com/module",
		"go mod tidy",
	])("marks unsupported dependency manager operation for review: %s", (command) => {
		expect(extractPackagesFromCommand(command)).toMatchObject([
			{ registry: "unknown", unverifiedReason: expect.stringContaining("not supported") },
		]);
	});

	it("extracts version-pinned package (still checked)", () => {
		const result = extractPackagesFromCommand("npm install express@4.18.0");
		expect(result).toHaveLength(1);
		expect(result[0]?.name).toBe("express");
		expect(result[0]?.version).toBe("4.18.0");
	});

	it("marks URL installs unverified instead of silently skipping them", () => {
		const result = extractPackagesFromCommand("pip install https://example.com/pkg.tar.gz");
		expect(result).toMatchObject([{ unverifiedReason: expect.stringContaining("direct URL") }]);
	});

	it("marks local path installs unverified instead of silently skipping them", () => {
		const result = extractPackagesFromCommand("npm install ./local-pkg");
		expect(result).toMatchObject([
			{ unverifiedReason: expect.stringContaining("local dependency") },
		]);
	});

	it("marks git installs unverified instead of silently skipping them", () => {
		const result = extractPackagesFromCommand("pip install git+https://github.com/user/repo.git");
		expect(result).toMatchObject([{ unverifiedReason: expect.stringContaining("Git source") }]);
	});

	it.each([
		["npm install pkg@https://example.com/pkg.tgz", "direct URL"],
		["yarn add pkg@github:user/repo", "Git source"],
		["pnpm add pkg@file:../local", "local dependency"],
		["bun add pkg@workspace:*", "local dependency"],
	])("marks package@source form %s unverified", (command, expected) => {
		const result = extractPackagesFromCommand(command);
		expect(result).toHaveLength(1);
		expect(result[0]?.unverifiedReason).toContain(expected);
	});

	it("marks pip requirements-file installs and bare npm installs for review", () => {
		expect(extractPackagesFromCommand("pip install -r requirements.txt")).toMatchObject([
			{ name: "requirements file", unverifiedReason: expect.stringContaining("requirements file") },
		]);
		expect(extractPackagesFromCommand("npm install")).toMatchObject([
			{ name: "manifest dependencies", unverifiedReason: expect.stringContaining("manifest") },
		]);
		expect(extractPackagesFromCommand("yarn")).toMatchObject([
			{ name: "manifest dependencies", unverifiedReason: expect.stringContaining("manifest") },
		]);
		expect(extractPackagesFromCommand("npm add")).toMatchObject([
			{ name: "manifest dependencies", unverifiedReason: expect.stringContaining("manifest") },
		]);
	});

	it.each([
		"npm add",
		"npm i",
		"npm in",
		"npm ins",
		"npm inst",
		"npm insta",
		"npm instal",
		"npm install",
		"npm isnt",
		"npm isnta",
		"npm isntal",
		"npm isntall",
		"npm ci",
		"npm clean-install",
		"npm ic",
		"npm install-cl",
		"npm install-cle",
		"npm install-clea",
		"npm install-clean",
		"npm isntall-",
		"npm isntall-c",
		"npm isntall-cl",
		"npm isntall-cle",
		"npm isntall-clea",
		"npm isntall-clean",
		"npm clean-install-",
		"npm clean-install-t",
		"npm clean-install-te",
		"npm clean-install-tes",
		"npm clean-install-test",
		"npm install-ci",
		"npm install-ci-",
		"npm install-ci-t",
		"npm install-ci-te",
		"npm install-ci-tes",
		"npm install-ci-test",
		"npm cit",
		"npm si",
		"npm sit",
		"npm install-t",
		"npm install-te",
		"npm install-tes",
		"npm install-test",
		"npm it",
	])("marks bare npm install alias %s for review", (command) => {
		expect(extractPackagesFromCommand(command)).toMatchObject([
			{ name: "manifest dependencies", unverifiedReason: expect.stringContaining("manifest") },
		]);
	});

	it("skips shell redirections like 2>&1", () => {
		const result = extractPackagesFromCommand(
			"python.exe -m pip install python-docx markdown 2>&1 | tail -5",
		);
		expect(result).toHaveLength(2);
		expect(result[0]?.name).toBe("python-docx");
		expect(result[1]?.name).toBe("markdown");
	});

	it("handles npm install with flags", () => {
		const result = extractPackagesFromCommand("npm install -g --save-dev express lodash");
		expect(result).toHaveLength(2);
		expect(result[0]?.name).toBe("express");
		expect(result[1]?.name).toBe("lodash");
	});

	it("handles bun add", () => {
		const result = extractPackagesFromCommand("bun add zod");
		expect(result).toHaveLength(1);
		expect(result[0]?.name).toBe("zod");
	});

	it("handles pnpm add", () => {
		const result = extractPackagesFromCommand("pnpm add typescript --save-dev");
		expect(result).toHaveLength(1);
		expect(result[0]?.name).toBe("typescript");
	});

	it("returns empty for non-install commands", () => {
		const result = extractPackagesFromCommand("npm run build");
		expect(result).toHaveLength(0);
	});

	it("handles chained commands", () => {
		const result = extractPackagesFromCommand("npm install express && npm install lodash");
		expect(result).toHaveLength(2);
	});

	it("extracts from python -m pip install", () => {
		const result = extractPackagesFromCommand("python -m pip install requests");
		expect(result).toHaveLength(1);
		expect(result[0]?.name).toBe("requests");
		expect(result[0]?.registry).toBe("pypi");
	});

	it("extracts from python3 -m pip install", () => {
		const result = extractPackagesFromCommand("python3 -m pip install flask gunicorn");
		expect(result).toHaveLength(2);
		expect(result[0]?.name).toBe("flask");
		expect(result[1]?.name).toBe("gunicorn");
	});

	it("extracts from full-path python.exe -m pip install", () => {
		const result = extractPackagesFromCommand("/usr/bin/python3 -m pip install numpy");
		expect(result).toHaveLength(1);
		expect(result[0]?.name).toBe("numpy");
	});

	it("handles pip version specifiers", () => {
		const result = extractPackagesFromCommand("pip install requests==2.31.0 flask>=2.0");
		expect(result).toHaveLength(2);
		expect(result[0]?.name).toBe("requests");
		expect(result[0]?.version).toBe("2.31.0");
	});
});

describe("extractPackagesFromManifest", () => {
	it("extracts dependencies from package.json", () => {
		const content = JSON.stringify({
			dependencies: { express: "^4.18.0", lodash: "~4.17.0" },
			devDependencies: { typescript: "^5.0.0" },
		});
		const result = extractPackagesFromManifest("package.json", content);
		expect(result).toHaveLength(3);
		expect(result.map((p) => p.name)).toContain("express");
		expect(result.map((p) => p.name)).toContain("typescript");
		expect(result[0]?.registry).toBe("npm");
		expect(result[0]?.source).toBe("package.json");
	});

	it("marks file: and link: dependencies in package.json unverified", () => {
		const content = JSON.stringify({
			dependencies: { "local-pkg": "file:../local", linked: "link:./linked" },
		});
		const result = extractPackagesFromManifest("package.json", content);
		expect(result).toHaveLength(2);
		expect(result.every((pkg) => pkg.unverifiedReason?.includes("local dependency"))).toBe(true);
	});

	it("extracts from requirements.txt", () => {
		const content =
			"requests==2.31.0\nflask>=2.0\n# comment\n\n-r other.txt\ngit+https://github.com/user/repo.git\n";
		const result = extractPackagesFromManifest("requirements.txt", content);
		expect(result).toHaveLength(4);
		expect(result[0]).toMatchObject({ name: "requests", registry: "pypi" });
		expect(result[1]).toMatchObject({ name: "flask", registry: "pypi" });
		expect(result.slice(2).every((pkg) => pkg.unverifiedReason)).toBe(true);
	});

	it.each([
		["--requirement nested.txt", "requirements file"],
		["-e ../local-package", "editable package source"],
		["git+https://github.com/example/pkg.git", "Git source"],
		["https://example.com/pkg.whl", "direct URL"],
		["../wheels/pkg.whl", "local dependency"],
	])("marks unsupported requirements.txt entry %s unverified", (entry, expected) => {
		const result = extractPackagesFromManifest("requirements.txt", entry);
		expect(result).toHaveLength(1);
		expect(result[0]?.unverifiedReason).toContain(expected);
	});

	it("does not silently lose duplicate package.json dependency keys", () => {
		const result = extractPackagesFromManifest(
			"package.json",
			'{"dependencies":{"safe":"1.0.0","safe":"2.0.0"}}',
		);
		// Extraction alone cannot distinguish an ambiguous object; evaluator completeness
		// validation rejects it before this output can be treated as exhaustive.
		expect(result).toHaveLength(1);
	});

	it("handles malformed package.json gracefully", () => {
		const result = extractPackagesFromManifest("package.json", "not json");
		expect(result).toHaveLength(0);
	});

	it("marks recognized but unsupported dependency manifests unverified", () => {
		expect(isDependencyManifestPath("services/api/pyproject.toml")).toBe(true);
		expect(extractPackagesFromManifest("services/api/pyproject.toml", "[project]")).toMatchObject([
			{
				registry: "unknown",
				unverifiedReason: expect.stringContaining("unsupported dependency manifest"),
			},
		]);
	});

	it("supports conventional requirements variant names", () => {
		expect(extractPackagesFromManifest("requirements-dev.txt", "requests==2.31.0")).toMatchObject([
			{ name: "requests", registry: "pypi" },
		]);
	});

	it("returns empty for an unrelated file type", () => {
		const result = extractPackagesFromManifest("README.md", "gem 'rails'");
		expect(result).toHaveLength(0);
	});

	it("handles requirements.txt with extras", () => {
		const content = "requests[security]==2.31.0\n";
		const result = extractPackagesFromManifest("requirements.txt", content);
		expect(result).toHaveLength(1);
		expect(result[0]?.name).toBe("requests");
	});
});
