import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";

import { assessHostVersion, detectHostVersion, VERIFIED_HOST_VERSIONS } from "../host-compat.js";

const tempDirs: string[] = [];

describe("host version compatibility (CON-14)", () => {
	it("treats the verified major.minor line as verified and warns outside it", () => {
		expect(VERIFIED_HOST_VERSIONS).toEqual({ cursor: ["3.19.7"], vscode: ["1.137.0"] });
		expect(assessHostVersion("vscode", "1.137.2")).toMatchObject({
			status: "verified",
			warning: undefined,
		});
		expect(assessHostVersion("vscode", "1.140.0")).toMatchObject({ status: "newer" });
		expect(assessHostVersion("vscode", "1.120.1")).toMatchObject({ status: "older" });
		expect(assessHostVersion("cursor", "3.19.0").status).toBe("verified");
		expect(assessHostVersion("cursor", "4.0.0").warning).toContain(
			"Cursor 4.0.0, which is newer than the verified Cursor 3.19.7",
		);
		const unknown = assessHostVersion("cursor", undefined);
		expect(unknown.status).toBe("unknown");
		expect(unknown.warning).toContain("could not determine the Cursor version");
	});

	it("reads Cursor's own version from product.json, never the VS Code API level", async () => {
		const appRoot = await mkdtemp(path.join(os.tmpdir(), "aidr-host-"));
		tempDirs.push(appRoot);
		expect(detectHostVersion("cursor", "1.99.3", appRoot)).toBeUndefined();

		await writeFile(
			path.join(appRoot, "product.json"),
			JSON.stringify({ version: "3.19.7", vscodeVersion: "1.99.3" }),
		);
		expect(detectHostVersion("cursor", "1.99.3", appRoot)).toBe("3.19.7");

		// A plain VS Code product.json has no vscodeVersion: not a Cursor build.
		await writeFile(path.join(appRoot, "product.json"), JSON.stringify({ version: "1.137.0" }));
		expect(detectHostVersion("cursor", "1.137.0", appRoot)).toBeUndefined();
		expect(detectHostVersion("vscode", "1.137.0", appRoot)).toBe("1.137.0");
	});
});

afterAll(async () => {
	await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
});
