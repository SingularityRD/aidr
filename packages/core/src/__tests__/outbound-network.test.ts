import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer, type Server } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { connect as netConnect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
	bypassesProxy,
	configureOutboundNetwork,
	resolveOutboundNetwork,
	trustedCertificates,
} from "../outbound-network.js";

const HOST = "aidr-proxy-test.invalid";
const haveOpenssl = spawnSync("openssl", ["version"], { encoding: "utf8" }).status === 0;

function listen(server: Server): Promise<number> {
	return new Promise((resolve) => {
		server.listen(0, "127.0.0.1", () => {
			const address = server.address();
			resolve(typeof address === "object" && address ? address.port : 0);
		});
	});
}

describe("proxy bypass rules", () => {
	it("follows NO_PROXY suffix, wildcard and port entries and always bypasses loopback", () => {
		expect(bypassesProxy("127.0.0.1", "443", [])).toBe(true);
		expect(bypassesProxy("localhost", "443", [])).toBe(true);
		expect(bypassesProxy("::1", "443", [])).toBe(true);
		expect(bypassesProxy("aidr.corp.example", "443", ["corp.example"])).toBe(true);
		expect(bypassesProxy("aidr.corp.example", "443", [".corp.example"])).toBe(true);
		expect(bypassesProxy("aidr.corp.example", "443", ["*.corp.example"])).toBe(true);
		expect(bypassesProxy("corp.example", "443", ["corp.example"])).toBe(true);
		expect(bypassesProxy("notcorp.example", "443", ["corp.example"])).toBe(false);
		expect(bypassesProxy("aidr.corp.example", "443", ["corp.example:8443"])).toBe(false);
		expect(bypassesProxy("aidr.corp.example", "8443", ["corp.example:8443"])).toBe(true);
		expect(bypassesProxy("anything.example", "443", ["*"])).toBe(true);
	});

	it("takes the configuration over the environment and ignores an unparseable proxy", () => {
		const env = { HTTPS_PROXY: "http://env-proxy:3128", NO_PROXY: "a.example" };
		expect(resolveOutboundNetwork(undefined, env).proxy?.host).toBe("env-proxy:3128");
		const configured = resolveOutboundNetwork(
			{ https_proxy: "http://cfg-proxy:8080", no_proxy: "b.example, c.example" },
			env,
		);
		expect(configured.proxy?.host).toBe("cfg-proxy:8080");
		expect(configured.noProxy).toEqual(["b.example", "c.example"]);
		expect(resolveOutboundNetwork({ https_proxy: "ftp://nope" }, {}).proxy).toBeUndefined();
		expect(resolveOutboundNetwork(undefined, {}).proxy).toBeUndefined();
	});

	it("adds the CA file to the bundled roots and never trusts a file without certificates", () => {
		const warnings: string[] = [];
		const logger = {
			debug() {},
			info() {},
			warn: (message: string) => warnings.push(message),
			error() {},
		};
		expect(trustedCertificates({ useOsTrustStore: false }, logger)).toBeNull();
		const pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
		const withFile = trustedCertificates(
			{ caFile: "/ca.pem", useOsTrustStore: false },
			logger,
			() => pem,
		);
		expect(withFile).toContain(pem);
		expect(withFile?.length).toBeGreaterThan(1);
		const empty = trustedCertificates(
			{ caFile: "/x.pem", useOsTrustStore: false },
			logger,
			() => "junk",
		);
		expect(empty).not.toContain("junk");
		expect(warnings.some((message) => message.includes("no PEM certificate"))).toBe(true);
	});
});

describe.skipIf(!haveOpenssl)("outbound fetch through the configured CA and proxy", () => {
	let dir = "";
	let target: Server;
	let proxy: Server;
	let targetPort = 0;
	let proxyPort = 0;
	const connects: string[] = [];

	beforeAll(async () => {
		dir = mkdtempSync(join(tmpdir(), "aidr-network-"));
		const run = (...args: string[]) => {
			const result = spawnSync("openssl", args, { cwd: dir, encoding: "utf8" });
			if (result.status !== 0) throw new Error(result.stderr);
		};
		run(
			"req",
			"-x509",
			"-newkey",
			"ec",
			"-pkeyopt",
			"ec_paramgen_curve:prime256v1",
			"-nodes",
			"-keyout",
			"ca.key",
			"-out",
			"ca.pem",
			"-days",
			"2",
			"-subj",
			"/CN=AIDR Test Internal CA",
		);
		run(
			"req",
			"-newkey",
			"ec",
			"-pkeyopt",
			"ec_paramgen_curve:prime256v1",
			"-nodes",
			"-keyout",
			"leaf.key",
			"-out",
			"leaf.csr",
			"-subj",
			`/CN=${HOST}`,
		);
		writeFileSync(join(dir, "ext.cnf"), `subjectAltName=DNS:${HOST},IP:127.0.0.1\n`);
		run(
			"x509",
			"-req",
			"-in",
			"leaf.csr",
			"-CA",
			"ca.pem",
			"-CAkey",
			"ca.key",
			"-CAcreateserial",
			"-out",
			"leaf.pem",
			"-days",
			"2",
			"-extfile",
			"ext.cnf",
		);
		target = createHttpsServer(
			{ key: readFileSync(join(dir, "leaf.key")), cert: readFileSync(join(dir, "leaf.pem")) },
			(_req, res) => res.end("internal-ok"),
		);
		targetPort = await listen(target);
		proxy = createHttpServer((_req, res) => res.writeHead(405).end());
		proxy.on("connect", (req, client) => {
			connects.push(req.url ?? "");
			// Every tunnel ends at the local test server, whatever name was asked for.
			const upstream = netConnect(targetPort, "127.0.0.1", () => {
				client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
				upstream.pipe(client);
				client.pipe(upstream);
			});
			upstream.on("error", () => client.destroy());
			client.on("error", () => upstream.destroy());
		});
		proxyPort = await listen(proxy);
	});

	afterEach(async () => {
		await configureOutboundNetwork({}, undefined, {});
	});

	afterAll(() => {
		target?.close();
		proxy?.close();
		if (dir) rmSync(dir, { recursive: true, force: true });
	});

	it("rejects the internal CA by default and accepts it from network.ca_file", async () => {
		await configureOutboundNetwork({}, undefined, {});
		await expect(fetch(`https://127.0.0.1:${targetPort}/`)).rejects.toThrow();
		const applied = await configureOutboundNetwork({ ca_file: join(dir, "ca.pem") }, undefined, {});
		expect(applied).toEqual({ proxy: false, extraCa: true });
		const response = await fetch(`https://127.0.0.1:${targetPort}/`);
		expect(await response.text()).toBe("internal-ok");
	});

	it("tunnels HTTPS through the proxy with CONNECT and still verifies the destination", async () => {
		connects.length = 0;
		await configureOutboundNetwork(
			{ https_proxy: `http://127.0.0.1:${proxyPort}`, ca_file: join(dir, "ca.pem") },
			undefined,
			{},
		);
		const response = await fetch(`https://${HOST}:${targetPort}/`);
		expect(await response.text()).toBe("internal-ok");
		expect(connects).toEqual([`${HOST}:${targetPort}`]);

		// Without the internal CA the tunnelled certificate is refused.
		await configureOutboundNetwork({ https_proxy: `http://127.0.0.1:${proxyPort}` }, undefined, {});
		await expect(fetch(`https://${HOST}:${targetPort}/`)).rejects.toThrow();
	});

	it("takes HTTPS_PROXY from the environment and sends no_proxy hosts direct", async () => {
		connects.length = 0;
		await configureOutboundNetwork({ ca_file: join(dir, "ca.pem"), no_proxy: HOST }, undefined, {
			HTTPS_PROXY: `http://127.0.0.1:${proxyPort}`,
		});
		// Direct: the .invalid name does not resolve, and the proxy never sees it.
		await expect(fetch(`https://${HOST}:${targetPort}/`)).rejects.toThrow();
		expect(connects).toEqual([]);
		await configureOutboundNetwork({ ca_file: join(dir, "ca.pem") }, undefined, {
			HTTPS_PROXY: `http://127.0.0.1:${proxyPort}`,
		});
		const response = await fetch(`https://${HOST}:${targetPort}/`);
		expect(await response.text()).toBe("internal-ok");
		expect(connects).toEqual([`${HOST}:${targetPort}`]);
	});
});
