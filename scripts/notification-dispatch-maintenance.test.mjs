// Contract for the Compose alert-dispatch timer (deploy/maintenance): the
// runtime posts to the dispatcher with the dedicated token only over HTTPS,
// refuses an absent/weak token, never prints secrets, and the installer only
// enables the timer on request after checking its inputs.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { dispatchTarget, runDispatch } from "../deploy/maintenance/notification-dispatch.mjs";

const TOKEN = "dispatch-token-0123456789abcdef0123456789";
const root = resolve(import.meta.dirname, "..");

function deployment({ url = "https://api.aidr.example.com", development = false, token = TOKEN } = {}) {
	const dir = mkdtempSync(join(tmpdir(), "aidr-notify-"));
	writeFileSync(join(dir, "deployment.json"), JSON.stringify({ supabase_url: url, development }));
	writeFileSync(join(dir, ".env.functions"), `AIDR_PACK_MASTER_KEY_B64=x\n${token === null ? "" : `AIDR_NOTIFICATION_DISPATCH_TOKEN=${token}\n`}`);
	return dir;
}

test("posts to the dispatcher with the dedicated bearer token and returns counts only", async () => {
	const dir = deployment();
	try {
		const calls = [];
		const counts = await runDispatch(dir, {
			fetchImpl: async (url, init) => {
				calls.push({ url: String(url), init });
				return new Response(JSON.stringify({ ok: true, claimed: 3, delivered: 2, retrying: 1, dead: 0, lease_lost: 0, pruned: 4 }), { status: 200 });
			},
		});
		assert.deepEqual(counts, { claimed: 3, delivered: 2, retrying: 1, dead: 0, lease_lost: 0, pruned: 4 });
		assert.equal(calls[0].url, "https://api.aidr.example.com/functions/v1/notification-dispatch");
		assert.equal(calls[0].init.method, "POST");
		assert.equal(calls[0].init.headers.Authorization, `Bearer ${TOKEN}`);
		assert.equal(calls[0].init.redirect, "error");
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("refuses plain HTTP, a missing or weak token, and reports failures without secrets", async () => {
	for (const options of [{ url: "http://api.aidr.example.com" }, { token: null }, { token: "short" }]) {
		const dir = deployment(options);
		try {
			assert.throws(() => dispatchTarget(dir), /HTTPS|AIDR_NOTIFICATION_DISPATCH_TOKEN/);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	}
	const loopback = deployment({ url: "http://127.0.0.1:8000", development: true });
	try {
		assert.equal(dispatchTarget(loopback).url.href, "http://127.0.0.1:8000/functions/v1/notification-dispatch");
		await assert.rejects(
			runDispatch(loopback, { fetchImpl: async () => new Response(JSON.stringify({ error: "invalid_dispatch_token" }), { status: 401 }) }),
			(error) => {
				assert.equal(error.message, "notification dispatch failed (HTTP 401, invalid_dispatch_token)");
				assert.doesNotMatch(error.message, new RegExp(TOKEN));
				return true;
			},
		);
	} finally {
		rmSync(loopback, { recursive: true, force: true });
	}
});

test("units are hardened, minute-cadence and installed only on request after input checks", () => {
	const service = readFileSync(join(root, "deploy/maintenance/aidr-notification-dispatch.service"), "utf8");
	assert.match(service, /^ExecStart=\/usr\/bin\/node \/srv\/aidr\/maintenance\/notification-dispatch\.mjs \/srv\/aidr$/m);
	for (const directive of ["NoNewPrivileges=true", "ProtectSystem=strict", "PrivateTmp=true", "ReadOnlyPaths=/srv/aidr"]) {
		assert.ok(service.includes(directive), directive);
	}
	const timer = readFileSync(join(root, "deploy/maintenance/aidr-notification-dispatch.timer"), "utf8");
	assert.match(timer, /^OnUnitActiveSec=1min$/m);
	assert.match(timer, /^Unit=aidr-notification-dispatch\.service$/m);
	const installer = readFileSync(join(root, "deploy/maintenance/install-systemd.sh"), "utf8");
	assert.match(installer, /--with-notifications\) with_notifications=true/);
	assert.match(installer, /AIDR_NOTIFICATION_DISPATCH_TOKEN=\.\{32,\}/);
	assert.match(installer, /if \[ "\$with_notifications" = true \]; then[\s\S]*systemctl enable --now aidr-notification-dispatch\.timer/);
	// The SIEM timer path is unchanged.
	assert.match(installer, /systemctl enable --now aidr-siem-delivery\.timer/);
});
