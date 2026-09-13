#!/usr/bin/env node
import { createHmac, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REQUEST_PATH = "/functions/v1/device-start";
const SIGNING_CONTEXT = "device-start:v1";
const DEFAULT_MAX_BODY_BYTES = 4096;
const MAX_RESPONSE_BYTES = 16384;
const MAX_HEADER_BYTES = 8192;

function canonicalIp(value) {
	if (typeof value !== "string" || value.length > 45 || value !== value.trim()) return null;
	if (isIP(value) === 4) {
		const parts = value.split(".");
		return parts.some((part) => part.length > 1 && part.startsWith("0")) ? null : value;
	}
	if (isIP(value) !== 6 || !/^[0-9a-fA-F:]+$/.test(value)) return null;
	try {
		return new URL(`http://[${value}]/`).hostname.slice(1, -1).toLowerCase();
	} catch {
		return null;
	}
}

function parsePeerList(value) {
	const peers = String(value).split(",").map((entry) => canonicalIp(entry.trim()));
	if (peers.length === 0 || peers.some((entry) => !entry)) throw new Error("AIDR_DEVICE_START_TRUSTED_PEERS must contain exact IP addresses");
	return new Set(peers);
}

function checkedSecret(name, value) {
	if (typeof value !== "string" || Buffer.byteLength(value, "utf8") < 32 || /[\r\n]/.test(value)) {
		throw new Error(`${name} must contain at least 32 UTF-8 bytes and no newlines`);
	}
	if (value.startsWith("REPLACE_")) throw new Error(`${name} must be a configured private secret`);
	return value;
}

function checkedUpstream(value) {
	let url;
	try { url = new URL(value); } catch { throw new Error("AIDR_DEVICE_START_UPSTREAM_URL must be an absolute URL"); }
	if (url.pathname !== REQUEST_PATH || url.search || url.hash || url.username || url.password) {
		throw new Error(`AIDR_DEVICE_START_UPSTREAM_URL must point exactly to ${REQUEST_PATH}`);
	}
	if (url.protocol === "http:" && !["127.0.0.1", "[::1]"].includes(url.hostname)) {
		throw new Error("Plain HTTP upstream must use a numeric loopback address");
	}
	if (!["http:", "https:"].includes(url.protocol)) throw new Error("Upstream must use HTTP loopback or HTTPS");
	return url;
}

function singleHeader(req, name) {
	let count = 0;
	for (let index = 0; index < req.rawHeaders.length; index += 2) {
		if (req.rawHeaders[index].toLowerCase() === name) count++;
	}
	return count === 1 ? req.headers[name] : null;
}

function reply(res, status, error) {
	res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", connection: "close" });
	res.end(JSON.stringify({ error }));
}

function readBounded(req, maxBodyBytes) {
	const length = req.headers["content-length"];
	if (length !== undefined && (!/^(0|[1-9]\d*)$/.test(length) || Number(length) > maxBodyBytes)) {
		return Promise.reject(Object.assign(new Error("request_too_large"), { status: 413 }));
	}
	return new Promise((resolveBody, rejectBody) => {
		let size = 0;
		const chunks = [];
		const cleanup = () => {
			req.off("data", onData); req.off("end", onEnd); req.off("error", onError); req.off("aborted", onAborted);
		};
		const onData = (chunk) => {
			size += chunk.length;
			if (size > maxBodyBytes) {
				req.pause();
				cleanup();
				rejectBody(Object.assign(new Error("request_too_large"), { status: 413 }));
				return;
			}
			chunks.push(chunk);
		};
		const onEnd = () => { cleanup(); resolveBody(Buffer.concat(chunks, size)); };
		const onError = (error) => { cleanup(); rejectBody(error); };
		const onAborted = () => { cleanup(); rejectBody(new Error("request_aborted")); };
		req.on("data", onData); req.on("end", onEnd); req.on("error", onError); req.on("aborted", onAborted);
	});
}

async function readResponseBounded(response) {
	const length = response.headers.get("content-length");
	if (length && Number(length) > MAX_RESPONSE_BYTES) throw new Error("upstream_response_too_large");
	const chunks = [];
	let size = 0;
	for await (const chunk of response.body ?? []) {
		size += chunk.byteLength;
		if (size > MAX_RESPONSE_BYTES) throw new Error("upstream_response_too_large");
		chunks.push(Buffer.from(chunk));
	}
	return Buffer.concat(chunks, size);
}

function safeResponseHeaders(response, origin) {
	const headers = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
	const allowedOrigin = response.headers.get("access-control-allow-origin");
	if (origin && allowedOrigin === origin) {
		headers["access-control-allow-origin"] = origin;
		headers.vary = "Origin";
		for (const name of ["access-control-allow-headers", "access-control-allow-methods"]) {
			const value = response.headers.get(name);
			if (value && !/[\r\n]/.test(value)) headers[name] = value;
		}
	}
	const requestId = response.headers.get("x-request-id");
	if (requestId && /^[a-zA-Z0-9._-]{1,128}$/.test(requestId)) headers["x-request-id"] = requestId;
	return headers;
}

export function createDeviceStartIngress(options) {
	const signingSecret = checkedSecret("AIDR_DEVICE_START_INGRESS_SECRET", options.signingSecret);
	const proxyToken = checkedSecret("AIDR_DEVICE_START_PROXY_TOKEN", options.proxyToken);
	if (signingSecret === proxyToken) throw new Error("Proxy token and ingress signing secret must be different");
	const upstream = checkedUpstream(options.upstreamUrl);
	const trustedPeers = parsePeerList(options.trustedPeers ?? "127.0.0.1,::1");
	const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
	if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 0 || maxBodyBytes > 65536) throw new Error("Invalid request body limit");
	const anonKey = options.anonKey;
	if (anonKey !== undefined && (typeof anonKey !== "string" || !anonKey || /[\r\n]/.test(anonKey))) throw new Error("Invalid anonymous API key");

	const server = createServer({ maxHeaderSize: MAX_HEADER_BYTES }, async (req, res) => {
		const peer = canonicalIp(req.socket.remoteAddress);
		if (!peer || !trustedPeers.has(peer)) return reply(res, 403, "untrusted_proxy_peer");
		if (req.url !== REQUEST_PATH) return reply(res, 404, "not_found");
		if (req.method !== "POST" && req.method !== "OPTIONS") return reply(res, 405, "method_not_allowed");
		const incomingToken = singleHeader(req, "x-aidr-proxy-token");
		if (!incomingToken || typeof incomingToken !== "string") return reply(res, 403, "untrusted_proxy");
		const supplied = Buffer.from(incomingToken, "utf8");
		const expected = Buffer.from(proxyToken, "utf8");
		if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return reply(res, 403, "untrusted_proxy");
		const clientIp = canonicalIp(singleHeader(req, "x-aidr-proxy-client-ip"));
		if (!clientIp) return reply(res, 403, "invalid_proxy_client_ip");
		if (req.headers["transfer-encoding"] && req.headers["content-length"]) return reply(res, 400, "ambiguous_request_length");
		try {
			const body = await readBounded(req, maxBodyBytes);
			if (req.method === "OPTIONS" && body.length !== 0) return reply(res, 400, "preflight_body_not_allowed");
			const timestamp = String(Math.floor(Date.now() / 1000));
			const signature = createHmac("sha256", signingSecret)
				.update(`${SIGNING_CONTEXT}\n${timestamp}\n${clientIp}`, "utf8").digest("hex");
			// Build from a fixed allowlist; every inbound x-aidr-client-* and
			// forwarding/authority header is discarded before the upstream hop.
			const headers = {
				"x-aidr-client-ip": clientIp,
				"x-aidr-client-timestamp": timestamp,
				"x-aidr-client-signature": signature,
				"content-type": "application/json",
				accept: "application/json",
			};
			if (anonKey) {
				headers.apikey = anonKey;
				headers.authorization = `Bearer ${anonKey}`;
			}
			const origin = req.headers.origin;
			if (typeof origin === "string" && origin.length <= 2048 && !/[\r\n]/.test(origin)) headers.origin = origin;
			if (req.method === "OPTIONS") {
				const requestedHeaders = req.headers["access-control-request-headers"];
				if (typeof requestedHeaders === "string" && requestedHeaders.length <= 1024) headers["access-control-request-headers"] = requestedHeaders;
				headers["access-control-request-method"] = "POST";
			}
			const response = await fetch(upstream, {
				method: req.method, headers,
				body: req.method === "POST" ? body : undefined,
				redirect: "manual", cache: "no-store", signal: AbortSignal.timeout(5000),
			});
			if (response.status >= 300 && response.status < 400) return reply(res, 502, "upstream_redirect_rejected");
			const responseBody = await readResponseBounded(response);
			res.writeHead(response.status, safeResponseHeaders(response, origin));
			res.end(responseBody);
		} catch (error) {
			if (!res.headersSent) reply(res, error.status === 413 ? 413 : 502, error.status === 413 ? "request_too_large" : "upstream_unavailable");
		}
	});
	server.requestTimeout = 5000;
	server.headersTimeout = 5000;
	server.keepAliveTimeout = 1000;
	server.maxHeadersCount = 40;
	return server;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
	const host = process.env.AIDR_DEVICE_START_LISTEN_HOST ?? "127.0.0.1";
	if (!["127.0.0.1", "::1"].includes(host)) throw new Error("Ingress signer must listen on numeric loopback only");
	const port = Number(process.env.AIDR_DEVICE_START_LISTEN_PORT ?? "8191");
	if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("Invalid ingress signer listen port");
	const server = createDeviceStartIngress({
		signingSecret: process.env.AIDR_DEVICE_START_INGRESS_SECRET,
		proxyToken: process.env.AIDR_DEVICE_START_PROXY_TOKEN,
		upstreamUrl: process.env.AIDR_DEVICE_START_UPSTREAM_URL ?? `http://127.0.0.1:8000${REQUEST_PATH}`,
		trustedPeers: process.env.AIDR_DEVICE_START_TRUSTED_PEERS ?? "127.0.0.1,::1",
		anonKey: process.env.AIDR_DEVICE_START_ANON_KEY,
	});
	server.listen(port, host, () => process.stdout.write(`device-start signer listening on ${host}:${port}\n`));
}
