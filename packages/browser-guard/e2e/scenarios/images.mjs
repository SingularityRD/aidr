// (14) Uploaded pictures and the AIDR Privacy companion (native host with OCR).
//
// image-uninspected-warn       no companion, no managed policy: the picture is uploaded with a
//                              warning that says how to install and enable the companion.
// image-uninspected-blocked    no companion, under a managed policy (uninspectedImages defaults to
//                              "block"): the picture is not uploaded; the bubble says why and how to
//                              install and enable the companion.
// image-ocr-companion          opt-in (BG_E2E_NATIVE_HOST=1) and needs the companion installed for
//                              this user with OCR (packages/privacy: aidr-privacy-companion install).
//                              Registers a host for Chromium only (removed afterwards) that uses the
//                              installed companion's OCR (Windows built-in recognizer, pinned
//                              manifest) and admits the test extension. A synthetic screenshot with a
//                              TCKN, an IBAN and an e-mail is blocked by its OCR'd text and never
//                              reaches the page; a clean screenshot is uploaded. Timings are recorded.

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
import { staysFalse, waitFor } from "../lib/expect.mjs";
import { assertNoLeaks, launch } from "../lib/harness.mjs";
import { createManagedDeployment } from "../lib/managed-deployment.mjs";
import { SITES } from "../lib/sites.mjs";

const SITE = "chatgpt";
const NO_CODE = /\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b/;
const FIXTURES = path.resolve(import.meta.dirname, "../../../privacy/fixtures/visual");
const SENSITIVE_PNG = () => fs.readFileSync(path.join(FIXTURES, "companion-demo.png"));
const CLEAN_PNG = () => fs.readFileSync(path.join(FIXTURES, "companion-clean.png"));
/** Values rendered (as pixels) in companion-demo.png; they must never appear in any request. */
const PICTURE_VALUES = ["38491572638", "TR410006100000012345678901", "ayse.demo@example.com"];
const INSTALL_HINT = /install-companion/;

const productOnly = (_h, data) =>
	(data?.items ?? []).some((i) => i.type === "TC_KIMLIK")
		? null
		: "product feature (image inspection) not implemented by the self-test extension";

/** Waits for a new overlay containing `needle`; null after the timeout. */
async function newOverlay(h, page, baseline, needle, timeout = 10000) {
	return waitFor(
		async () => (await h.overlays(page, SITE)).find((o) => !baseline.includes(o) && needle.test(o)),
		{ timeout, message: `an overlay matching ${needle}` },
	).catch(() => null);
}

async function noUpload(h, mark, window = 1500) {
	let quiet = true;
	await staysFalse(() => h.recorder.apiSince(mark, { kind: "upload" }).length > 0, {
		window,
		message: "an upload",
	}).catch(() => {
		quiet = false;
	});
	return quiet;
}

/** The installed companion's host config (with OCR), or null. */
function installedCompanion() {
	const dir = path.join(process.env.LOCALAPPDATA ?? "", "SingularityAIDR", "PrivacyCompanion");
	try {
		const config = JSON.parse(fs.readFileSync(path.join(dir, "host-config.json"), "utf8"));
		return config.visual ? { dir, config } : null;
	} catch {
		return null;
	}
}

export default [
	{
		id: "image-uninspected-warn",
		title: "image upload without the companion (unmanaged): uploaded with install guidance",
		settings: { mode: "auto" },
		skip: productOnly,
		async run({ h, checks, open }) {
			const page = await open(SITE);
			const baseline = await h.overlays(page, SITE);
			const mark = h.recorder.mark();
			await page.locator(SITES[SITE].fileInput).setInputFiles({
				name: "ekran.png",
				mimeType: "image/png",
				buffer: CLEAN_PNG(),
			});
			const upload = await waitFor(() => h.recorder.apiSince(mark, { kind: "upload" })[0], {
				timeout: 10000,
				message: "the page to upload the picture",
			}).catch(() => null);
			checks.check("the picture was uploaded (warn)", upload, h.recorder.apiSince(mark));
			const toast = await newOverlay(h, page, baseline, /was not checked/);
			checks.check("a warning says the picture was not checked", toast, await h.overlays(page, SITE));
			checks.contains("the warning says how to install the companion", toast ?? "", INSTALL_HINT);
			checks.contains("the warning names the Options switch", toast ?? "", /Use the AIDR Privacy helper app/);
		},
	},
	{
		id: "image-uninspected-blocked",
		title: "image upload without the companion (managed): not uploaded, with install guidance",
		skip: productOnly,
		async run({ h, checks }) {
			const dir = createManagedDeployment(h.extDir, {
				managedPolicy: { policyId: "e2e-images" },
				grantedOrigins: [],
				grantedPermissions: [],
			});
			let m;
			try {
				m = await launch({ extDir: dir });
				const policy = await m.getPolicy();
				checks.equal("managed default: uninspectedImages is block", policy.uninspectedImages, "block");
				const page = await m.openSite(SITE);
				const baseline = await m.overlays(page, SITE);
				const mark = m.recorder.mark();
				await page.locator(SITES[SITE].fileInput).setInputFiles({
					name: "ekran.png",
					mimeType: "image/png",
					buffer: SENSITIVE_PNG(),
				});
				const bubble = await newOverlay(m, page, baseline, /could not be inspected/);
				checks.check("a bubble says the picture was not uploaded", bubble, await m.overlays(page, SITE));
				checks.contains("it says why", bubble ?? "", /was not uploaded because the picture could not be inspected/);
				checks.contains("it says how to install the companion", bubble ?? "", INSTALL_HINT);
				checks.contains("it names the Options switch", bubble ?? "", /Use the AIDR Privacy helper app/);
				checks.check("no internal reason code is shown", !NO_CODE.test(bubble ?? ""), bubble);
				checks.check("the picture never reached the page", await noUpload(m, mark), m.recorder.apiSince(mark));
				await page.close().catch(() => {});
			} finally {
				await m?.close().catch(() => {});
				fs.rmSync(dir, { recursive: true, force: true });
			}
		},
	},
	{
		id: "image-ocr-companion",
		title: "image upload with the companion (real host, Windows OCR): sensitive screenshot blocked, clean one uploaded",
		skip(h, data) {
			const product = productOnly(h, data);
			if (product) return product;
			if (process.env.BG_E2E_NATIVE_HOST !== "1") {
				return "opt-in: set BG_E2E_NATIVE_HOST=1 (writes a per-user Chromium native-host registration, removed afterwards)";
			}
			if (process.platform !== "win32") return "the companion's OCR backend is Windows-only";
			if (!installedCompanion()) return "no AIDR Privacy companion with OCR installed for this user (aidr-privacy-companion install)";
			if (!fs.existsSync(privacyHostScript())) return "packages/privacy is not built";
			if (nativeHostStatus({ browsers: ["chromium"] }).browsers[0].registered) {
				return "a Chromium native host registration already exists; not overwriting it";
			}
			return null;
		},
		async run({ h, checks }) {
			const companion = installedCompanion();
			const work = fs.mkdtempSync(path.join(os.tmpdir(), "bg-e2e-ocr-"));
			const dir = createManagedDeployment(h.extDir, {
				managedPolicy: { policyId: "e2e-image-ocr", useNativeHost: true },
				grantedOrigins: [],
				grantedPermissions: ["nativeMessaging"],
			});
			let m;
			let registered = false;
			try {
				m = await launch({ extDir: dir });
				// The installed companion's OCR (venv, pinned manifest and its own windows_ocr.ps1 copy),
				// admitting only the test extension.
				const visual = structuredClone(companion.config.visual);
				visual.backend.windowsOcrScript = path.join(companion.dir, "app", "vision", "windows_ocr.ps1");
				const configPath = path.join(work, "host-config.json");
				fs.writeFileSync(
					configPath,
					JSON.stringify({ ...companion.config, allowedExtensionIds: [m.extensionId], visual }, null, 2),
				);
				const launcher = createDevLauncher({ configPath, outDir: work }).launcherPath;
				registerNativeHost({ hostPath: launcher, extensionIds: [m.extensionId], browsers: ["chromium"], manifestDir: work });
				registered = true;

				const page = await m.openSite(SITE);
				// Warm the host (start-up and first OCR pass) so the timings below are per picture.
				await m.sendMessage({ type: "NATIVE_SCAN", text: "warm up" });

				let baseline = await m.overlays(page, SITE);
				let mark = m.recorder.mark();
				let started = Date.now();
				await page.locator(SITES[SITE].fileInput).setInputFiles({
					name: "musteri-ekran.png",
					mimeType: "image/png",
					buffer: SENSITIVE_PNG(),
				});
				const bubble = await newOverlay(m, page, baseline, /personal or confidential data/, 60000);
				const blockedMs = Date.now() - started;
				checks.check("the sensitive screenshot is blocked", bubble, await m.overlays(page, SITE));
				checks.contains("the bubble names the T.C. kimlik number", bubble ?? "", /Turkish ID number/);
				checks.contains("the bubble names the IBAN", bubble ?? "", /IBAN/);
				checks.contains("the bubble names the e-mail address", bubble ?? "", /email/i);
				checks.check("it never reached the page", await noUpload(m, mark), m.recorder.apiSince(mark));
				// The values exist only as pixels; this guards against the OCR text leaking anywhere.
				assertNoLeaks(checks, m, mark, PICTURE_VALUES);

				baseline = await m.overlays(page, SITE);
				mark = m.recorder.mark();
				started = Date.now();
				await page.locator(SITES[SITE].fileInput).setInputFiles({
					name: "toplanti.png",
					mimeType: "image/png",
					buffer: CLEAN_PNG(),
				});
				const upload = await waitFor(() => m.recorder.apiSince(mark, { kind: "upload" })[0], {
					timeout: 60000,
					message: "the clean picture upload",
				}).catch(() => null);
				const cleanMs = Date.now() - started;
				checks.check("the clean screenshot is uploaded", upload, m.recorder.apiSince(mark));
				const toast = await newOverlay(m, page, baseline, /QR codes and barcodes/, 5000);
				checks.check(
					"its note says the text was clean (barcodes not checked on this endpoint) or none at all",
					toast !== null || installedCompanion()?.config.visual.policy.barcodeUnavailable === "allow",
					await m.overlays(page, SITE),
				);
				checks.check(`timings: sensitive ${blockedMs} ms, clean ${cleanMs} ms (upload to verdict)`, true, {
					blockedMs,
					cleanMs,
				});
				await page.close().catch(() => {});
			} finally {
				await m?.close().catch(() => {});
				if (registered) unregisterNativeHost({ browsers: ["chromium"] });
				checks.check(
					"no Chromium registration is left",
					!nativeHostStatus({ browsers: ["chromium"] }).browsers[0].registered,
					null,
				);
				fs.rmSync(dir, { recursive: true, force: true });
				fs.rmSync(work, { recursive: true, force: true });
			}
		},
	},
];
