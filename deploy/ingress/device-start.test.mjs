import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { createServer, request } from "node:http";
import { after, before, test } from "node:test";
import { createDeviceStartIngress } from "./device-start.mjs";

const signingSecret = "signer-test-secret-0123456789-0123456789";
const proxyToken = "proxy-test-secret-0123456789-0123456789";
const path = "/functions/v1/device-start";
let upstream;
let signer;
let upstreamUrl;
let signerPort;
let lastRequest;
let upstreamStatus = 200;

function listen(server) {
	return new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", () => resolve(server.address().port));
	});
}

function close(server) {
	return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function call(headers = {}, options = {}) {
	return new Promise((resolve, reject) => {
		const body = options.body ?? "{}";
		const req = request({
			host: "127.0.0.1", port: signerPort,
			method: options.method ?? "POST", path: options.path ?? path,
			headers: {
				"x-aidr-proxy-token": proxyToken,
				"x-aidr-proxy-client-ip": "203.0.113.7",
				"content-type": "application/json",
				...headers,
			},
		}, (response) => {
			const chunks = [];
			response.on("data", (chunk) => chunks.push(chunk));
			response.on("end", () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString() }));
		});
		req.on("error", reject);
		req.end(body);
	});
}

before(async () => {
	upstream = createServer(async (req, res) => {
		const body = [];
		for await (const chunk of req) body.push(chunk);
		lastRequest = { method: req.method, path: req.url, headers: req.headers, body: Buffer.concat(body).toString() };
		if (upstreamStatus === 302) {
			res.writeHead(302, { location: "https://other.example/" });
			res.end();
			return;
		}
		res.writeHead(200, { "content-type": "application/json", "access-control-allow-origin": req.headers.origin ?? "", "access-control-allow-methods": "POST, OPTIONS" });
		res.end('{"ok":true}');
	});
	upstreamUrl = `http://127.0.0.1:${await listen(upstream)}${path}`;
	signer = createDeviceStartIngress({ signingSecret, proxyToken, upstreamUrl });
	signerPort = await listen(signer);
});

after(async () => { await close(signer); await close(upstream); });

test("overwrites forged signed and forwarded headers with a trusted proxy IP", async () => {
	const result = await call({
		"x-aidr-client-ip": "198.51.100.9",
		"x-aidr-client-timestamp": "1",
		"x-aidr-client-signature": "forged",
		"x-aidr-client-extra": "forged",
		"x-forwarded-for": "198.51.100.10",
		"cf-connecting-ip": "198.51.100.11",
		"x-real-ip": "198.51.100.12",
		origin: "https://dashboard.example",
	});
	assert.equal(result.status, 200);
	assert.equal(lastRequest.path, path);
	assert.equal(lastRequest.headers["x-aidr-client-ip"], "203.0.113.7");
	assert.equal(lastRequest.headers["x-aidr-client-extra"], undefined);
	for (const header of ["x-forwarded-for", "cf-connecting-ip", "x-real-ip", "x-aidr-proxy-client-ip", "x-aidr-proxy-token"]) assert.equal(lastRequest.headers[header], undefined);
	const timestamp = lastRequest.headers["x-aidr-client-timestamp"];
	assert.ok(Math.abs(Number(timestamp) - Math.floor(Date.now() / 1000)) <= 2);
	assert.equal(lastRequest.headers["x-aidr-client-signature"], createHmac("sha256", signingSecret).update(`device-start:v1\n${timestamp}\n203.0.113.7`).digest("hex"));
	assert.equal(result.headers["access-control-allow-origin"], "https://dashboard.example");
});

test("rejects a peer absent from the exact trusted-peer allowlist", async () => {
	const isolated = createDeviceStartIngress({ signingSecret, proxyToken, upstreamUrl, trustedPeers: "::1" });
	const port = await listen(isolated);
	try {
		const result = await new Promise((resolve, reject) => {
			const req = request({ host: "127.0.0.1", port, method: "POST", path, headers: { "x-aidr-proxy-token": proxyToken, "x-aidr-proxy-client-ip": "203.0.113.7" } }, (response) => {
			response.resume(); response.on("end", () => resolve(response.statusCode));
			});
			req.on("error", reject); req.end("{}");
		});
		assert.equal(result, 403);
	} finally { await close(isolated); }
});

test("rejects missing or forged proxy token and duplicated proxy headers", async () => {
	assert.equal((await call({ "x-aidr-proxy-token": "forged" })).status, 403);
	assert.equal((await call({ "x-aidr-proxy-token": "" })).status, 403);
	assert.equal((await call({ "x-aidr-proxy-client-ip": "198.51.100.7, 203.0.113.7" })).status, 403);
	const duplicate = await call({ "x-aidr-proxy-client-ip": ["203.0.113.7", "198.51.100.8"] });
	assert.equal(duplicate.status, 403);
});

test("canonicalizes IPv6 before signing and rejects ambiguous IP notation", async () => {
	assert.equal((await call({ "x-aidr-proxy-client-ip": "2001:0DB8:0:0:0:0:0:1" })).status, 200);
	assert.equal(lastRequest.headers["x-aidr-client-ip"], "2001:db8::1");
	assert.equal((await call({ "x-aidr-proxy-client-ip": "010.0.0.1" })).status, 403);
	assert.equal((await call({ "x-aidr-proxy-client-ip": "::ffff:127.0.0.1" })).status, 403);
});

test("bounds payloads and routes before invoking upstream", async () => {
	const previous = lastRequest;
	assert.equal((await call({}, { body: "x".repeat(4097) })).status, 413);
	assert.equal((await call({ "transfer-encoding": "chunked" }, { body: "x".repeat(4097) })).status, 413);
	assert.equal((await call({}, { path: `${path}?bypass=1` })).status, 404);
	assert.equal((await call({}, { path: "/functions/v1/device-poll" })).status, 404);
	assert.equal((await call({}, { method: "GET", body: "" })).status, 405);
	assert.equal(lastRequest, previous);
});

test("passes bounded browser preflight to the fixed endpoint", async () => {
	const result = await call({ origin: "https://dashboard.example", "access-control-request-headers": "content-type, apikey" }, { method: "OPTIONS", body: "" });
	assert.equal(result.status, 200);
	assert.equal(lastRequest.method, "OPTIONS");
	assert.equal(lastRequest.headers["access-control-request-method"], "POST");
	assert.equal(result.headers["access-control-allow-origin"], "https://dashboard.example");
});

test("does not follow upstream redirects", async () => {
	upstreamStatus = 302;
	try { assert.equal((await call()).status, 502); }
	finally { upstreamStatus = 200; }
});

test("rejects insecure non-loopback upstreams and weak secrets at startup", () => {
	assert.throws(() => createDeviceStartIngress({ signingSecret: "weak", proxyToken, upstreamUrl }), /at least 32/);
	assert.throws(() => createDeviceStartIngress({ signingSecret, proxyToken: "REPLACE_WITH_PRIVATE_32_BYTE_MINIMUM_TOKEN", upstreamUrl }), /configured private secret/);
	assert.throws(() => createDeviceStartIngress({ signingSecret, proxyToken: signingSecret, upstreamUrl }), /must be different/);
	assert.throws(() => createDeviceStartIngress({ signingSecret, proxyToken, upstreamUrl: `http://example.com${path}` }), /numeric loopback/);
	assert.throws(() => createDeviceStartIngress({ signingSecret, proxyToken, upstreamUrl: `${upstreamUrl}?x=1` }), /exactly/);
});
