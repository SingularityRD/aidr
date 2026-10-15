// (13) The real AIDR Privacy native host (packages/privacy dist/native/host.js), registered
// per user with scripts/native-host.mjs, connected to the extension in the test Chromium.
//
// native-host-connected   opt-in (BG_E2E_NATIVE_HOST=1): it writes a per-user registration
//                         for Chromium (HKCU\Software\Chromium\NativeMessagingHosts on
//                         Windows, ~/.config/chromium/NativeMessagingHosts on Linux), never
//                         for Chrome or Edge, and removes it afterwards. It is skipped when
//                         a Chromium registration already exists (the user's own is never
//                         overwritten). In a managed browser with useNativeHost and the
//                         nativeMessaging grant: the worker reports the host "connected",
//                         a NATIVE_SCAN round trip answers through the host, a prompt sent
//                         on the ChatGPT fixture is masked without the "rules only" notice,
//                         and after unregistering the registration is gone.
//
// The host runs text-only and rules-only (no NER weights ship with the product), so this
// proves the registration, launch, protocol and policy handshake, not NER quality.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
	createDevLauncher,
	nativeHostStatus,
	privacyHostScript,
	registerNativeHost,
	unregisterNativeHost,
} from "../../scripts/native-host.mjs";
import { waitFor } from "../lib/expect.mjs";
import { assertNoLeaks, launch, typePrompt, waitForPrompt } from "../lib/harness.mjs";
import { createManagedDeployment } from "../lib/managed-deployment.mjs";
import { DEMO_ITEMS, DEMO_PROMPT } from "../lib/data.mjs";

const BROWSERS = ["chromium"];
const KEYLESS_ITEMS = DEMO_ITEMS.filter((i) => i.type !== "SECRET");
const PROMPT_WITHOUT_KEYS = KEYLESS_ITEMS.reduce(
	(text, item) => `${text} ${item.type}: ${item.value}.`,
	"Müşteri kaydı, adres: Atatürk Caddesi No 5, Kadıköy.",
);

function skip(h, data) {
	if (process.env.BG_E2E_NATIVE_HOST !== "1") {
		return "opt-in: set BG_E2E_NATIVE_HOST=1 (writes a per-user Chromium native-host registration, removed afterwards)";
	}
	if ((data?.items ?? []).length <= 1) return "the self-test extension has no native bridge";
	if (!["win32", "linux"].includes(process.platform)) return `not wired for ${process.platform}`;
	if (!fs.existsSync(privacyHostScript())) {
		return "packages/privacy is not built (pnpm --filter @singularityrd/aidr-privacy build)";
	}
	if (nativeHostStatus({ browsers: BROWSERS }).browsers[0].registered) {
		return "a Chromium native host registration already exists; not overwriting it";
	}
	return null;
}

/** Text-only host config admitting exactly `extensionId` (packages/privacy/native/config.text-only.example.json). */
function writeHostConfig(dir, extensionId) {
	const file = path.join(dir, "native-config.json");
	fs.writeFileSync(
		file,
		`${JSON.stringify(
			{
				version: 1,
				allowedExtensionIds: [extensionId],
				browserPolicyJSON: "{}",
				text: { profile: "strict", mask: "label", maxInputBytes: 1048576 },
			},
			null,
			2,
		)}\n`,
	);
	return file;
}

/** Launcher for the platform: the dev .cmd on Windows, a shell script elsewhere. */
function writeLauncher(dir, configPath) {
	if (process.platform === "win32") {
		return createDevLauncher({ configPath, outDir: dir }).launcherPath;
	}
	const file = path.join(dir, "aidr-native-host");
	const quote = (s) => `'${s.replaceAll("'", "'\\''")}'`;
	fs.writeFileSync(
		file,
		`#!/bin/sh\nexec ${quote(process.execPath)} ${quote(privacyHostScript())} --config ${quote(configPath)} "$@"\n`,
		{ mode: 0o700 },
	);
	return file;
}

export default [
	{
		id: "native-host-connected",
		title: "real native host registered per user (scripts/native-host.mjs): connected, scans through it, removed again",
		skip,
		async run({ h, checks }) {
			const work = fs.mkdtempSync(path.join(os.tmpdir(), "bg-e2e-native-"));
			const dir = createManagedDeployment(h.extDir, {
				managedPolicy: { policyId: "e2e-native-host", useNativeHost: true },
				grantedOrigins: [],
				grantedPermissions: ["nativeMessaging"],
			});
			let m;
			let registered = false;
			try {
				m = await launch({ extDir: dir });
				const config = writeHostConfig(work, m.extensionId);
				const launcher = writeLauncher(work, config);
				const result = registerNativeHost({
					hostPath: launcher,
					extensionIds: [m.extensionId],
					browsers: BROWSERS,
					manifestDir: work,
				});
				registered = true;
				checks.equal(
					"registered for Chromium only",
					result.registrations.map((r) => r.browser).join(","),
					BROWSERS.join(","),
				);
				checks.check(
					"status reports the registration usable",
					nativeHostStatus({ browsers: BROWSERS }).browsers[0].usable,
					nativeHostStatus({ browsers: BROWSERS }),
				);

				const policy = await m.getPolicy();
				checks.equal("useNativeHost is on (managed)", policy.useNativeHost, true);
				// The worker starts the host on demand (status() from GET_STATS, or the first scan).
				const reply = await m.sendMessage({ type: "NATIVE_SCAN", text: "Adres: Atatürk Caddesi No 5, Kadıköy" });
				checks.check("a NATIVE_SCAN round trip answers", reply.ok && reply.value?.ok, reply);
				const connected = await waitFor(
					async () => ((await m.getStats())?.nativeHost === "connected" ? true : null),
					{ timeout: 15_000, message: "the worker to report the native host connected" },
				).catch(() => false);
				checks.check("the worker reports the native host connected", connected, await m.getStats());
				checks.equal("the NATIVE_SCAN reply comes from the connected host", reply.value?.status, "connected");
				checks.check(
					"the host's findings are returned (array, not null)",
					Array.isArray(reply.value?.findings),
					reply.value,
				);
				const withoutKeys = await m.sendMessage({ type: "NATIVE_SCAN", text: PROMPT_WITHOUT_KEYS });
				checks.check(
					"the host finds the unlabelled street address the in-browser rules cover only by cue words",
					(withoutKeys.value?.findings ?? []).some((f) => f.type === "ADDRESS"),
					withoutKeys.value,
				);
				// Known limitation: the privacy host's own policy blocks text that holds secrets
				// (packages/privacy/src/native/host.ts forces SECRET/PRIVATE_KEY to `block`), so the
				// bridge gets no spans and the page falls back to rules-only and says so, although
				// the host is connected. Masking is unaffected (the rules mask the keys).
				const withKeys = await m.sendMessage({ type: "NATIVE_SCAN", text: DEMO_PROMPT });
				checks.check(
					"text with API keys: the host refuses it (findings null, still connected)",
					withKeys.value?.findings === null && withKeys.value?.status === "connected",
					withKeys.value,
				);

				const page = await m.openSite("chatgpt");
				const baseline = await m.overlays(page, "chatgpt");
				const mark = m.recorder.mark();
				await typePrompt(page, "chatgpt", PROMPT_WITHOUT_KEYS);
				await page.keyboard.press("Enter");
				const sent = await waitForPrompt(m, "chatgpt", mark, 10_000);
				const body = sent.json?.prompt ?? sent.raw;
				for (const item of KEYLESS_ITEMS) {
					checks.excludes(`sent prompt does not contain the ${item.type} value`, body, item.value);
				}
				assertNoLeaks(
					checks,
					m,
					mark,
					KEYLESS_ITEMS.map((i) => i.value),
				);
				await page.waitForTimeout(800);
				const overlays = await m.overlays(page, "chatgpt");
				checks.check(
					'no "built-in rules only" notice: the host answered',
					!overlays.some((o) => !baseline.includes(o) && /built-in rules only/i.test(o)),
					overlays,
				);
				await page.close().catch(() => {});
			} finally {
				await m?.close().catch(() => {});
				if (registered) {
					unregisterNativeHost({ browsers: BROWSERS });
					checks.check(
						"unregistered again: no Chromium registration is left",
						!nativeHostStatus({ browsers: BROWSERS }).browsers[0].registered,
						nativeHostStatus({ browsers: BROWSERS }),
					);
				}
				fs.rmSync(dir, { recursive: true, force: true });
				fs.rmSync(work, { recursive: true, force: true });
			}
		},
	},
];
